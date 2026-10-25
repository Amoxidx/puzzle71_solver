//! curl-backed HTTP transport used by every networked claim step.
//!
//! The allowlist is checked before a process is started. Request URL, headers, and body travel
//! only on curl's stdin configuration (`-K -`), never on the argument list.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use crate::claim::memory::secure_zero;
use crate::claim::net::allowlist::{self, Method};
use crate::claim::net::error::NetError;

// A valid 4 MWU funding transaction needs at most about 8 MB as raw hex.
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
const CURL_STATUS_SUFFIX_BYTES: usize = 4; // `\n` plus exactly three HTTP-status digits.

/// HTTP response as seen by the claim pipeline: numeric status and UTF-8 body (without the
/// trailing status line curl appends via `-w`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Blocking HTTP execution. Production code uses [`CurlTransport`]; tests inject fakes.
pub trait Transport {
    fn execute(
        &self,
        method: Method,
        url: &str,
        json_body: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, NetError>;
}

/// Production transport: `/usr/bin/curl` with a locked-down argument list and stdin config.
pub struct CurlTransport;

impl Transport for CurlTransport {
    fn execute(
        &self,
        method: Method,
        url: &str,
        json_body: Option<&str>,
        timeout_secs: u64,
    ) -> Result<HttpResponse, NetError> {
        if !allowlist::is_allowed(method, url) {
            return Err(NetError::NotAllowed);
        }
        let (args, mut config) = build_invocation(method, url, json_body, timeout_secs)?;
        let result = run_curl(&args, &config);
        let mut config_bytes = std::mem::take(&mut config).into_bytes();
        secure_zero(&mut config_bytes);
        result
    }
}

/// Builds the curl argument list and stdin configuration.
///
/// Arguments never contain the URL, a header, or the body. Those values go in `config` after
/// escaping `\` and `"`. Control characters and a JSON body that starts with `@` are rejected.
pub(crate) fn build_invocation(
    method: Method,
    url: &str,
    json_body: Option<&str>,
    timeout_secs: u64,
) -> Result<(Vec<String>, String), NetError> {
    build_invocation_with(method, url, json_body, timeout_secs, TlsMode::Https)
}

#[cfg(test)]
pub(crate) fn build_invocation_insecure_http(
    method: Method,
    url: &str,
    json_body: Option<&str>,
    timeout_secs: u64,
) -> Result<(Vec<String>, String), NetError> {
    build_invocation_with(method, url, json_body, timeout_secs, TlsMode::PlainHttp)
}

#[derive(Clone, Copy)]
enum TlsMode {
    Https,
    #[cfg(test)]
    PlainHttp,
}

fn build_invocation_with(
    method: Method,
    url: &str,
    json_body: Option<&str>,
    timeout_secs: u64,
    tls: TlsMode,
) -> Result<(Vec<String>, String), NetError> {
    if let Some(body) = json_body
        && body.starts_with('@')
    {
        return Err(NetError::InvalidInput);
    }

    let mut args = vec!["-q".to_string(), "-sS".to_string(), "--globoff".to_string()];
    match tls {
        TlsMode::Https => {
            args.push("--tlsv1.2".to_string());
            args.push("--proto".to_string());
            args.push("=https".to_string());
            args.push("--proto-redir".to_string());
            args.push("=https".to_string());
        }
        #[cfg(test)]
        TlsMode::PlainHttp => {
            args.push("--proto".to_string());
            args.push("=http".to_string());
            args.push("--proto-redir".to_string());
            args.push("=http".to_string());
        }
    }
    args.push("--max-redirs".to_string());
    args.push("0".to_string());
    args.push("--noproxy".to_string());
    args.push("*".to_string());
    args.push("--max-time".to_string());
    args.push(timeout_secs.to_string());
    args.push("-w".to_string());
    args.push("\n%{http_code}".to_string());
    args.push("-K".to_string());
    args.push("-".to_string());

    let mut config = String::new();
    config.push_str("url = \"");
    let mut escaped_url = escape_config_value(url)?;
    config.push_str(&escaped_url);
    config.push_str("\"\n");
    let mut escaped_url_bytes = std::mem::take(&mut escaped_url).into_bytes();
    secure_zero(&mut escaped_url_bytes);
    if method == Method::PostJson {
        let body = json_body.ok_or(NetError::InvalidInput)?;
        config.push_str("header = \"Content-Type: application/json\"\n");
        config.push_str("data-binary = \"");
        let mut escaped_body = escape_config_value(body)?;
        config.push_str(&escaped_body);
        config.push_str("\"\n");
        let mut escaped_body_bytes = std::mem::take(&mut escaped_body).into_bytes();
        secure_zero(&mut escaped_body_bytes);
    }

    Ok((args, config))
}

fn escape_config_value(value: &str) -> Result<String, NetError> {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_control() {
            return Err(NetError::InvalidInput);
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    Ok(out)
}

fn run_curl(args: &[String], config: &str) -> Result<HttpResponse, NetError> {
    let mut command = Command::new("/usr/bin/curl");
    command.args(args);
    run_command(command, config)
}

fn run_command(mut command: Command, config: &str) -> Result<HttpResponse, NetError> {
    let child = command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| NetError::Spawn)?;
    finish_child(child, config)
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn finish_child(mut child: Child, config: &str) -> Result<HttpResponse, NetError> {
    let Some(mut stdin) = child.stdin.take() else {
        kill_and_reap(&mut child);
        return Err(NetError::Spawn);
    };
    if stdin.write_all(config.as_bytes()).is_err() {
        drop(stdin);
        kill_and_reap(&mut child);
        return Err(NetError::Transport { exit_code: None });
    }
    drop(stdin);

    let Some(stdout) = child.stdout.take() else {
        kill_and_reap(&mut child);
        return Err(NetError::Spawn);
    };
    read_child_response(child, stdout)
}

fn read_child_response(mut child: Child, stdout: impl Read) -> Result<HttpResponse, NetError> {
    // Drain stdout before waiting, but stop at one byte beyond body + curl's status suffix.
    // Stderr is discarded at spawn, so neither output pipe can fill while waiting on the other.
    let mut stdout = match read_curl_stdout(stdout) {
        Ok(stdout) => stdout,
        Err(error) => {
            kill_and_reap(&mut child);
            return Err(error);
        }
    };
    let status = match child.wait() {
        Ok(status) => status,
        Err(_) => {
            secure_zero(&mut stdout);
            kill_and_reap(&mut child);
            return Err(NetError::Spawn);
        }
    };
    if !status.success() {
        secure_zero(&mut stdout);
        return Err(NetError::Transport {
            exit_code: status.code(),
        });
    }

    let parsed = parse_curl_stdout(&stdout);
    secure_zero(&mut stdout);
    parsed
}

fn read_curl_stdout(stdout: impl Read) -> Result<Vec<u8>, NetError> {
    let max_output = MAX_RESPONSE_BODY_BYTES + CURL_STATUS_SUFFIX_BYTES;
    let mut bytes = Vec::new();
    if stdout
        .take((max_output + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        secure_zero(&mut bytes);
        return Err(NetError::Transport { exit_code: None });
    }
    if bytes.len() > max_output {
        secure_zero(&mut bytes);
        return Err(NetError::ResponseTooLarge);
    }
    Ok(bytes)
}

fn parse_curl_stdout(stdout: &[u8]) -> Result<HttpResponse, NetError> {
    let text = std::str::from_utf8(stdout).map_err(|_| NetError::BadResponse)?;
    let (body, status_line) = match text.rsplit_once('\n') {
        Some(parts) => parts,
        None => ("", text),
    };
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(NetError::ResponseTooLarge);
    }
    let status_line = status_line.trim_end_matches('\r');
    if status_line.len() != 3 || !status_line.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NetError::BadResponse);
    }
    let status: u16 = status_line.parse().map_err(|_| NetError::BadResponse)?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}

#[cfg(test)]
pub(crate) fn execute_insecure_http(
    method: Method,
    url: &str,
    json_body: Option<&str>,
    timeout_secs: u64,
) -> Result<HttpResponse, NetError> {
    let (args, mut config) = build_invocation_insecure_http(method, url, json_body, timeout_secs)?;
    let result = run_curl(&args, &config);
    let mut config_bytes = std::mem::take(&mut config).into_bytes();
    secure_zero(&mut config_bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::{
        CurlTransport, Transport, build_invocation, build_invocation_insecure_http,
        execute_insecure_http,
    };
    use crate::claim::net::allowlist::Method;
    use crate::claim::net::error::NetError;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn invocation_argument_list_is_exact_and_carries_no_url_token_or_body() {
        let url = "https://api.telegram.org/bot12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage";
        let body = r#"{"chat_id":"1","text":"secret-body"}"#;
        let (args, config) =
            build_invocation(Method::PostJson, url, Some(body), 30).expect("valid invocation");

        let expected = vec![
            "-q",
            "-sS",
            "--globoff",
            "--tlsv1.2",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--max-time",
            "30",
            "-w",
            "\n%{http_code}",
            "-K",
            "-",
        ];
        assert_eq!(args, expected);
        assert_eq!(args[0], "-q");
        for arg in &args {
            assert!(!arg.contains("telegram"), "{arg}");
            assert!(!arg.contains("12345:"), "{arg}");
            assert!(!arg.contains("secret-body"), "{arg}");
            assert!(!arg.contains("https://"), "{arg}");
            assert!(!arg.contains("Content-Type"), "{arg}");
        }
        assert!(config.contains(url));
        assert!(config.contains("secret-body"));
        assert!(config.contains("header = \"Content-Type: application/json\""));
        assert!(config.contains("data-binary = \""));
    }

    #[test]
    fn insecure_http_invocation_differs_only_in_proto_and_tls() {
        let url = "https://slipstream.mara.com/api/rates";
        let (https_args, https_cfg) =
            build_invocation(Method::Get, url, None, 9).expect("https invocation");
        let (http_args, http_cfg) =
            build_invocation_insecure_http(Method::Get, url, None, 9).expect("http invocation");

        assert!(https_args.contains(&"--tlsv1.2".to_string()));
        assert!(!http_args.contains(&"--tlsv1.2".to_string()));
        assert_eq!(https_args.iter().filter(|a| *a == "=https").count(), 2);
        assert_eq!(http_args.iter().filter(|a| *a == "=http").count(), 2);
        assert!(!http_args.iter().any(|a| *a == "=https"));
        assert!(!https_args.iter().any(|a| *a == "=http"));

        let https_rest: Vec<&str> = https_args
            .iter()
            .map(String::as_str)
            .filter(|a| *a != "--tlsv1.2" && *a != "=https")
            .collect();
        let http_rest: Vec<&str> = http_args
            .iter()
            .map(String::as_str)
            .filter(|a| *a != "=http")
            .collect();
        assert_eq!(https_rest, http_rest);
        assert_eq!(https_cfg, http_cfg);
    }

    #[test]
    fn escaping_quotes_and_backslashes_in_config_values() {
        let url = r#"https://example.com/foo"bar\baz"#;
        let (_args, config) =
            build_invocation(Method::Get, url, None, 5).expect("escapes are valid");
        assert!(config.contains(r#"url = "https://example.com/foo\"bar\\baz""#));
    }

    #[test]
    fn control_characters_are_invalid_input() {
        let err = build_invocation(Method::Get, "https://example.com/foo\nbar", None, 5)
            .expect_err("newline");
        assert_eq!(err, NetError::InvalidInput);
        let err =
            build_invocation(Method::Get, "https://example.com/foo\rbar", None, 5).expect_err("cr");
        assert_eq!(err, NetError::InvalidInput);
        let err = build_invocation(Method::Get, "https://example.com/foo\0bar", None, 5)
            .expect_err("nul");
        assert_eq!(err, NetError::InvalidInput);
    }

    #[test]
    fn json_body_starting_with_at_is_invalid_input() {
        let err = build_invocation(
            Method::PostJson,
            "https://slipstream.mara.com/api/transactions",
            Some("@/etc/passwd"),
            5,
        )
        .expect_err("@ body");
        assert_eq!(err, NetError::InvalidInput);
    }

    #[test]
    fn parse_curl_stdout_body_without_trailing_newline_status_line_and_embedded_status() {
        let parsed = super::parse_curl_stdout(b"hello\n200").expect("body plus status");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, "hello");

        let parsed = super::parse_curl_stdout(b"foo\n200\n200").expect("embedded status");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, "foo\n200");

        let parsed = super::parse_curl_stdout(b"200").expect("status only");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, "");
    }

    #[test]
    fn curl_transport_rejects_disallowed_url_without_starting_a_process() {
        let err = CurlTransport
            .execute(
                Method::PostJson,
                "https://mempool.space/api/tx",
                Some("{}"),
                5,
            )
            .expect_err("public broadcast must be denied");
        assert_eq!(err, NetError::NotAllowed);
    }

    struct Captured {
        method: String,
        path: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    fn spawn_once_server(
        respond: impl Fn(&Captured) -> (u16, Vec<u8>) + Send + 'static,
    ) -> (u16, mpsc::Receiver<Captured>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let captured = match read_http_request(&mut stream) {
                Some(c) => c,
                None => return,
            };
            let (status, body) = respond(&captured);
            let reason = if status == 200 { "OK" } else { "ERR" };
            let header = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = tx.send(captured);
        });
        (port, rx)
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> Option<Captured> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_double_crlf(&buf) {
                let header_bytes = &buf[..pos];
                let header_text = std::str::from_utf8(header_bytes).ok()?;
                let mut lines = header_text.split("\r\n");
                let request_line = lines.next()?;
                let mut parts = request_line.split(' ');
                let method = parts.next()?.to_string();
                let path = parts.next()?.to_string();
                let mut content_type = None;
                let mut content_length = 0usize;
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        match name.trim().to_ascii_lowercase().as_str() {
                            "content-type" => content_type = Some(value.trim().to_string()),
                            "content-length" => {
                                content_length = value.trim().parse().unwrap_or(0);
                            }
                            _ => {}
                        }
                    }
                }
                let mut body = buf[pos + 4..].to_vec();
                while body.len() < content_length {
                    let n = stream.read(&mut tmp).ok()?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                body.truncate(content_length);
                return Some(Captured {
                    method,
                    path,
                    content_type,
                    body,
                });
            }
            if buf.len() > 1024 * 1024 {
                return None;
            }
        }
        None
    }

    fn find_double_crlf(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    #[test]
    fn real_curl_posts_method_path_content_type_and_body_exactly() {
        let expected_body = br#"{"tx_hex":"00ff"}"#.to_vec();
        let (port, rx) = spawn_once_server({
            let expected_body = expected_body.clone();
            move |captured| {
                assert_eq!(captured.method, "POST");
                assert_eq!(captured.path, "/echo");
                assert_eq!(captured.content_type.as_deref(), Some("application/json"));
                assert_eq!(captured.body, expected_body);
                (200, b"{\"ok\":true}".to_vec())
            }
        });
        let url = format!("http://127.0.0.1:{port}/echo");
        let response =
            execute_insecure_http(Method::PostJson, &url, Some(r#"{"tx_hex":"00ff"}"#), 10)
                .expect("curl against local listener");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "{\"ok\":true}");
        let captured = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("server saw request");
        assert_eq!(captured.method, "POST");
        assert_eq!(captured.path, "/echo");
        assert_eq!(captured.body, expected_body);
    }

    #[test]
    fn real_curl_reads_a_response_body_of_at_least_256_kib_without_hanging() {
        let payload = vec![b'X'; 256 * 1024];
        let (port, _rx) = spawn_once_server({
            let payload = payload.clone();
            move |_| (200, payload.clone())
        });
        let url = format!("http://127.0.0.1:{port}/big");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = execute_insecure_http(Method::Get, &url, None, 15);
            let _ = tx.send(result);
        });
        let response = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("curl hung reading a 256 KiB body")
            .expect("curl status");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), payload.len());
        assert!(response.body.bytes().all(|b| b == b'X'));
    }

    fn streaming_response(body_len: usize, chunked: bool) -> (u16, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = read_http_request(&mut stream);
            let _ = (|| -> std::io::Result<()> {
                if chunked {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")?;
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                    )?;
                }
                let chunk = [b'X'; 8192];
                let mut remaining = body_len;
                while remaining > 0 {
                    let count = remaining.min(chunk.len());
                    if chunked {
                        write!(stream, "{count:x}\r\n")?;
                    }
                    stream.write_all(&chunk[..count])?;
                    if chunked {
                        stream.write_all(b"\r\n")?;
                    }
                    remaining -= count;
                }
                if chunked {
                    stream.write_all(b"0\r\n\r\n")?;
                }
                stream.flush()
            })();
            drop(stream);
            let _ = tx.send(());
        });
        (port, rx)
    }

    fn assert_real_response_bound(body_len: usize, chunked: bool) {
        let (port, done) = streaming_response(body_len, chunked);
        let response = execute_insecure_http(
            Method::Get,
            &format!("http://127.0.0.1:{port}/bounded"),
            None,
            15,
        );
        if body_len > super::MAX_RESPONSE_BODY_BYTES {
            assert!(
                matches!(response, Err(NetError::ResponseTooLarge)),
                "oversized response was not rejected"
            );
        } else {
            let response = response.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body.len(), body_len);
            assert!(response.body.bytes().all(|b| b == b'X'));
        }
        done.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn response_cap_content_length_below_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES - 1, false);
    }

    #[test]
    fn response_cap_content_length_at_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES, false);
    }

    #[test]
    fn response_cap_content_length_above_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES + 1, false);
    }

    #[test]
    fn response_cap_chunked_below_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES - 1, true);
    }

    #[test]
    fn response_cap_chunked_at_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES, true);
    }

    #[test]
    fn response_cap_chunked_above_limit() {
        assert_real_response_bound(super::MAX_RESPONSE_BODY_BYTES + 1, true);
    }

    #[test]
    fn response_cap_stops_reading_before_the_rest_of_an_oversized_stream() {
        struct CountingReader {
            read: std::rc::Rc<std::cell::Cell<usize>>,
            available: usize,
        }
        impl Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let count = buf.len().min(self.available);
                buf[..count].fill(b'X');
                self.available -= count;
                self.read.set(self.read.get() + count);
                Ok(count)
            }
        }
        let read = std::rc::Rc::new(std::cell::Cell::new(0));
        let limit = super::MAX_RESPONSE_BODY_BYTES + super::CURL_STATUS_SUFFIX_BYTES + 1;
        let result = super::read_curl_stdout(CountingReader {
            read: read.clone(),
            available: limit + 8192,
        });
        assert!(matches!(result, Err(NetError::ResponseTooLarge)));
        assert!(
            read.get() <= limit,
            "response was buffered beyond the limit"
        );
    }

    #[test]
    fn response_cap_checks_body_bytes_separately_from_the_status_suffix() {
        let mut stdout = vec![b'X'; super::MAX_RESPONSE_BODY_BYTES + 1];
        stdout.extend_from_slice(b"\n200");
        assert!(matches!(
            super::parse_curl_stdout(&stdout),
            Err(NetError::ResponseTooLarge)
        ));
    }

    fn spawn_test_child(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn assert_reaped(pid: u32) {
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn response_cap_kills_and_reaps_an_oversized_child() {
        // Ignoring SIGPIPE keeps this child alive after the reader closes its pipe: the
        // transport must terminate it rather than relying on a broken-pipe self-exit.
        let script = format!(
            "trap '' PIPE; i=0; while [ \"$i\" -lt 2049 ]; do printf '%s' '{}'; i=$((i+1)); done; exec /bin/sleep 2",
            "X".repeat(8192)
        );
        let child = spawn_test_child(&script);
        let pid = child.id();
        let started = std::time::Instant::now();
        assert_eq!(
            super::finish_child(child, ""),
            Err(NetError::ResponseTooLarge)
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "transport waited for the child's natural exit"
        );
        assert_reaped(pid);
    }

    #[test]
    fn response_read_error_kills_and_reaps_the_child() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("public test read failure"))
            }
        }
        let mut child = spawn_test_child("read unused");
        let pid = child.id();
        drop(child.stdout.take());
        assert_eq!(
            super::read_child_response(child, FailingReader),
            Err(NetError::Transport { exit_code: None })
        );
        assert_reaped(pid);
    }

    #[test]
    fn response_write_error_reaps_the_exited_child() {
        let child = spawn_test_child("exit 0");
        let pid = child.id();
        assert_eq!(
            super::finish_child(child, &"X".repeat(128 * 1024)),
            Err(NetError::Transport { exit_code: None })
        );
        assert_reaped(pid);
    }

    #[test]
    fn discarded_stderr_exceeding_pipe_capacity_does_not_block_stdout() {
        let script = format!(
            "i=0; while [ \"$i\" -lt 256 ]; do printf '%s' '{}' >&2; i=$((i+1)); done; printf 'ok\\n200'",
            "E".repeat(1024)
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        assert_eq!(
            super::run_command(command, ""),
            Ok(super::HttpResponse {
                status: 200,
                body: "ok".to_string()
            })
        );
    }

    #[test]
    fn transport_spawn_failure_is_sanitized() {
        assert_eq!(
            super::run_command(Command::new("/nonexistent/public-test-curl"), ""),
            Err(NetError::Spawn)
        );
    }
}
