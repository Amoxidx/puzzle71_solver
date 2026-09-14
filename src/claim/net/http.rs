//! curl-backed HTTP transport used by every networked claim step.
//!
//! The allowlist is checked before a process is started. Request URL, headers, and body travel
//! only on curl's stdin configuration (`-K -`), never on the argument list.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::claim::memory::secure_zero;
use crate::claim::net::allowlist::{self, Method};
use crate::claim::net::error::NetError;

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
    if let Some(body) = json_body {
        if body.starts_with('@') {
            return Err(NetError::InvalidInput);
        }
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
    let mut child = Command::new("/usr/bin/curl")
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| NetError::Spawn)?;

    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NetError::Spawn);
    };
    if stdin.write_all(config.as_bytes()).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(NetError::Transport { exit_code: None });
    }
    drop(stdin);

    // `wait_with_output` reads stdout and stderr concurrently. Calling `wait` first would
    // deadlock once the pipe buffer (~64 KiB) fills.
    let output = child.wait_with_output().map_err(|_| NetError::Spawn)?;
    let mut stdout = output.stdout;
    if !output.status.success() {
        secure_zero(&mut stdout);
        return Err(NetError::Transport {
            exit_code: output.status.code(),
        });
    }

    let parsed = parse_curl_stdout(&stdout);
    secure_zero(&mut stdout);
    parsed
}

fn parse_curl_stdout(stdout: &[u8]) -> Result<HttpResponse, NetError> {
    let text = std::str::from_utf8(stdout).map_err(|_| NetError::BadResponse)?;
    let (body, status_line) = match text.rsplit_once('\n') {
        Some(parts) => parts,
        None => ("", text),
    };
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
}
