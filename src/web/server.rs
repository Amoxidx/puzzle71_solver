//! Embedded loopback-only HTTP dashboard server.

use crate::crypto::cpu_engine::run_mini_puzzle_test;
use crate::power::controller::PowerMode;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const INDEX_HTML: &str = include_str!("static/index.html");
pub const STYLE_CSS: &str = include_str!("static/style.css");
pub const APP_JS: &str = include_str!("static/app.js");

const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct PublicHitStatus {
    pub bitcoin_address: String,
    pub saved_filename: String,
    pub timestamp_unix: u64,
}

#[derive(Clone)]
pub struct SharedSolverState {
    pub is_running: Arc<AtomicBool>,
    pub mode: Arc<Mutex<PowerMode>>,
    pub total_keys_tested: Arc<Mutex<u128>>,
    pub total_blocks_tested: Arc<AtomicU64>,
    pub current_keys_per_sec: Arc<Mutex<f64>>,
    pub avg_keys_per_sec: Arc<Mutex<f64>>,
    pub estimated_package_power_watts: Arc<Mutex<f32>>,
    pub estimated_soc_temp_celsius: Arc<Mutex<f32>>,
    pub process_cpu_load_pct: Arc<Mutex<f32>>,
    pub runtime_secs: Arc<Mutex<f64>>,
    pub target_gpu_duty_pct: Arc<Mutex<f32>>,
    pub last_gpu_active_ms: Arc<Mutex<f64>>,
    pub last_throttle_sleep_ms: Arc<Mutex<f64>>,
    pub checkpoint_saved_timestamp: Arc<AtomicU64>,
    pub hit: Arc<Mutex<Option<PublicHitStatus>>>,
    pub last_error: Arc<Mutex<Option<String>>>,
    selftest_running: Arc<AtomicBool>,
}

impl SharedSolverState {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(true)),
            mode: Arc::new(Mutex::new(PowerMode::Auto)),
            total_keys_tested: Arc::new(Mutex::new(0)),
            total_blocks_tested: Arc::new(AtomicU64::new(0)),
            current_keys_per_sec: Arc::new(Mutex::new(0.0)),
            avg_keys_per_sec: Arc::new(Mutex::new(0.0)),
            estimated_package_power_watts: Arc::new(Mutex::new(0.0)),
            estimated_soc_temp_celsius: Arc::new(Mutex::new(0.0)),
            process_cpu_load_pct: Arc::new(Mutex::new(0.0)),
            runtime_secs: Arc::new(Mutex::new(0.0)),
            target_gpu_duty_pct: Arc::new(Mutex::new(70.0)),
            last_gpu_active_ms: Arc::new(Mutex::new(0.0)),
            last_throttle_sleep_ms: Arc::new(Mutex::new(0.0)),
            checkpoint_saved_timestamp: Arc::new(AtomicU64::new(0)),
            hit: Arc::new(Mutex::new(None)),
            last_error: Arc::new(Mutex::new(None)),
            selftest_running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for SharedSolverState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct StatusResponse {
    is_running: bool,
    mode: String,
    total_keys_tested: String,
    total_blocks_tested: u64,
    current_keys_per_sec: f64,
    avg_keys_per_sec: f64,
    estimated_package_power_watts: f32,
    estimated_soc_temp_celsius: f32,
    process_cpu_load_pct: f32,
    runtime_secs: f64,
    target_gpu_duty_pct: f32,
    last_gpu_active_ms: f64,
    last_throttle_sleep_ms: f64,
    checkpoint_saved_timestamp: u64,
    hit: Option<PublicHitStatus>,
    last_error: Option<String>,
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
}

#[derive(Serialize)]
struct ApiMessage<'a> {
    status: &'a str,
}

#[derive(Serialize)]
struct ApiError<'a> {
    error: &'a str,
}

pub fn start_web_server(host: &str, port: u16, state: SharedSolverState) -> Result<(), String> {
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err(format!(
            "Refusing non-loopback dashboard bind '{}'; use 127.0.0.1",
            host
        ));
    }

    let bind_addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&bind_addr)
        .map_err(|e| format!("Failed to bind web server to {}: {}", bind_addr, e))?;

    println!("Web Dashboard running at: http://{}", bind_addr);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let state = state.clone();
            thread::spawn(move || handle_client(&mut stream, &state, port));
        }
    });

    Ok(())
}

fn handle_client(stream: &mut TcpStream, state: &SharedSolverState, port: u16) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(_) => {
            send_json(
                stream,
                "400 BAD REQUEST",
                &ApiError {
                    error: "invalid_request",
                },
            );
            return;
        }
    };

    let Some(first_line) = request.lines().next() else {
        return;
    };
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 {
        send_json(
            stream,
            "400 BAD REQUEST",
            &ApiError {
                error: "invalid_request",
            },
        );
        return;
    }

    let method = parts[0];
    let path = parts[1];
    if method == "POST" && !origin_is_allowed(&request, port) {
        send_json(
            stream,
            "403 FORBIDDEN",
            &ApiError {
                error: "cross_origin_request_denied",
            },
        );
        return;
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            send_response(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                INDEX_HTML.as_bytes(),
            );
        }
        ("GET", "/style.css") => {
            send_response(
                stream,
                "200 OK",
                "text/css; charset=utf-8",
                STYLE_CSS.as_bytes(),
            );
        }
        ("GET", "/app.js") => {
            send_response(
                stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                APP_JS.as_bytes(),
            );
        }
        ("GET", "/api/status") => {
            let status = StatusResponse {
                is_running: state.is_running.load(Ordering::SeqCst),
                mode: state.mode.lock().unwrap().name().to_string(),
                total_keys_tested: state.total_keys_tested.lock().unwrap().to_string(),
                total_blocks_tested: state.total_blocks_tested.load(Ordering::SeqCst),
                current_keys_per_sec: *state.current_keys_per_sec.lock().unwrap(),
                avg_keys_per_sec: *state.avg_keys_per_sec.lock().unwrap(),
                estimated_package_power_watts: *state.estimated_package_power_watts.lock().unwrap(),
                estimated_soc_temp_celsius: *state.estimated_soc_temp_celsius.lock().unwrap(),
                process_cpu_load_pct: *state.process_cpu_load_pct.lock().unwrap(),
                runtime_secs: *state.runtime_secs.lock().unwrap(),
                target_gpu_duty_pct: *state.target_gpu_duty_pct.lock().unwrap(),
                last_gpu_active_ms: *state.last_gpu_active_ms.lock().unwrap(),
                last_throttle_sleep_ms: *state.last_throttle_sleep_ms.lock().unwrap(),
                checkpoint_saved_timestamp: state.checkpoint_saved_timestamp.load(Ordering::SeqCst),
                hit: state.hit.lock().unwrap().clone(),
                last_error: state.last_error.lock().unwrap().clone(),
            };
            send_json(stream, "200 OK", &status);
        }
        ("POST", "/api/start") => {
            if state.hit.lock().unwrap().is_some() {
                send_json(
                    stream,
                    "409 CONFLICT",
                    &ApiError {
                        error: "solver_already_found_key",
                    },
                );
            } else if state.last_error.lock().unwrap().is_some() {
                send_json(
                    stream,
                    "409 CONFLICT",
                    &ApiError {
                        error: "solver_requires_restart",
                    },
                );
            } else {
                state.is_running.store(true, Ordering::SeqCst);
                send_json(stream, "200 OK", &ApiMessage { status: "started" });
            }
        }
        ("POST", "/api/stop") => {
            state.is_running.store(false, Ordering::SeqCst);
            send_json(
                stream,
                "200 OK",
                &ApiMessage {
                    status: "pause_requested",
                },
            );
        }
        ("POST", "/api/mode") => {
            let body = request
                .find("\r\n\r\n")
                .map(|start| &request[start + 4..])
                .unwrap_or_default();
            let parsed_mode = serde_json::from_str::<ModeRequest>(body)
                .ok()
                .and_then(|request| request.mode.parse::<PowerMode>().ok());

            if let Some(mode) = parsed_mode {
                *state.mode.lock().unwrap() = mode;
                send_json(
                    stream,
                    "200 OK",
                    &ApiMessage {
                        status: "mode_updated",
                    },
                );
            } else {
                send_json(
                    stream,
                    "400 BAD REQUEST",
                    &ApiError {
                        error: "invalid_mode",
                    },
                );
            }
        }
        ("POST", "/api/selftest") => {
            if state
                .selftest_running
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                send_json(
                    stream,
                    "409 CONFLICT",
                    &ApiError {
                        error: "selftest_already_running",
                    },
                );
                return;
            }

            let response = run_mini_puzzle_test();
            state.selftest_running.store(false, Ordering::SeqCst);
            match response {
                Ok(result) => {
                    #[derive(Serialize)]
                    struct SelfTestResponse {
                        success: bool,
                        elapsed_secs: f64,
                        keys_per_sec: f64,
                        keys_scanned: u64,
                        engine: &'static str,
                    }
                    send_json(
                        stream,
                        "200 OK",
                        &SelfTestResponse {
                            success: true,
                            elapsed_secs: result.elapsed_secs,
                            keys_per_sec: result.keys_per_sec,
                            keys_scanned: result.keys_scanned,
                            engine: "CPU",
                        },
                    );
                }
                Err(_) => send_json(
                    stream,
                    "500 INTERNAL SERVER ERROR",
                    &ApiError {
                        error: "selftest_failed",
                    },
                ),
            }
        }
        _ => send_response(
            stream,
            "404 NOT FOUND",
            "text/plain; charset=utf-8",
            b"Not Found",
        ),
    }
}

fn read_http_request<R: Read>(reader: &mut R) -> Result<String, String> {
    let mut request = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    let mut expected_total = None;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("request_read_failed: {error}"))?;
        if bytes_read == 0 {
            return Err("incomplete_request".to_string());
        }
        request.extend_from_slice(&buffer[..bytes_read]);

        if expected_total.is_none() {
            if let Some(header_end) = find_bytes(&request, b"\r\n\r\n") {
                if header_end > MAX_HTTP_HEADER_BYTES {
                    return Err("request_headers_too_large".to_string());
                }
                let headers = std::str::from_utf8(&request[..header_end])
                    .map_err(|_| "request_headers_not_utf8".to_string())?;
                let body_length = parse_content_length(headers)?;
                if body_length > MAX_HTTP_BODY_BYTES {
                    return Err("request_body_too_large".to_string());
                }
                expected_total = Some(header_end + 4 + body_length);
            } else if request.len() > MAX_HTTP_HEADER_BYTES {
                return Err("request_headers_too_large".to_string());
            }
        }

        if let Some(total) = expected_total
            && request.len() >= total
        {
            request.truncate(total);
            return String::from_utf8(request).map_err(|_| "request_body_not_utf8".to_string());
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_content_length(headers: &str) -> Result<usize, String> {
    let mut content_length = None;

    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed_request_header".to_string());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported_transfer_encoding".to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("duplicate_content_length".to_string());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid_content_length".to_string())?,
            );
        }
    }

    Ok(content_length.unwrap_or(0))
}

fn origin_is_allowed(request: &str, port: u16) -> bool {
    let origin = request.lines().find_map(|line| {
        line.strip_prefix("Origin:")
            .or_else(|| line.strip_prefix("origin:"))
            .map(str::trim)
    });
    let Some(origin) = origin else {
        return true;
    };

    [
        format!("http://127.0.0.1:{}", port),
        format!("http://localhost:{}", port),
        format!("http://[::1]:{}", port),
    ]
    .iter()
    .any(|allowed| origin == allowed)
}

fn send_json<T: Serialize>(stream: &mut TcpStream, status: &str, value: &T) {
    match serde_json::to_vec(value) {
        Ok(body) => send_response(stream, status, "application/json", &body),
        Err(_) => send_response(
            stream,
            "500 INTERNAL SERVER ERROR",
            "application/json",
            b"{\"error\":\"serialization_failed\"}",
        ),
    }
}

fn send_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'\r\nCross-Origin-Resource-Policy: same-origin\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;

    struct FragmentedReader {
        bytes: Vec<u8>,
        offset: usize,
        max_chunk_size: usize,
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let bytes_to_copy = cmp::min(
                self.max_chunk_size,
                cmp::min(buffer.len(), self.bytes.len() - self.offset),
            );
            buffer[..bytes_to_copy]
                .copy_from_slice(&self.bytes[self.offset..self.offset + bytes_to_copy]);
            self.offset += bytes_to_copy;
            Ok(bytes_to_copy)
        }
    }

    #[test]
    fn reads_mode_body_when_request_arrives_in_fragments() {
        let body = r#"{"mode":"full"}"#;
        let raw_request = format!(
            "POST /api/mode HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut reader = FragmentedReader {
            bytes: raw_request.into_bytes(),
            offset: 0,
            max_chunk_size: 7,
        };

        let request = read_http_request(&mut reader).unwrap();
        let parsed_body = request.split_once("\r\n\r\n").unwrap().1;
        let mode_request = serde_json::from_str::<ModeRequest>(parsed_body).unwrap();

        assert_eq!(mode_request.mode, "full");
    }

    #[test]
    fn rejects_oversized_http_bodies_before_reading_them() {
        let raw_request = format!(
            "POST /api/mode HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY_BYTES + 1
        );
        let mut reader = std::io::Cursor::new(raw_request.into_bytes());

        assert_eq!(
            read_http_request(&mut reader).unwrap_err(),
            "request_body_too_large"
        );
    }

    #[test]
    fn accepts_same_origin_and_headerless_local_clients() {
        assert!(origin_is_allowed("POST /api/stop HTTP/1.1\r\n\r\n", 8080));
        assert!(origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://127.0.0.1:8080\r\n\r\n",
            8080
        ));
    }

    #[test]
    fn rejects_cross_origin_mutations() {
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: https://attacker.example\r\n\r\n",
            8080
        ));
    }

    #[test]
    fn public_hit_status_contains_no_private_key_field() {
        let status = PublicHitStatus {
            bitcoin_address: "address".to_string(),
            saved_filename: "FOUND_KEY.txt".to_string(),
            timestamp_unix: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains("0x"));
    }
}
