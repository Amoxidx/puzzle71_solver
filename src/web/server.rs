//! Embedded loopback-only HTTP dashboard server.

use crate::claim::error::ClaimError;
use crate::claim::net::error::NetError;
use crate::claim::net::esplora::ClaimFetchError;
use crate::claim::net::slipstream::SubmitReceipt;
use crate::claim::service::{ClaimOps, ClaimState, ServiceError};
use crate::claim::verify::ClaimSummary;
use crate::crypto::cpu_engine::run_mini_puzzle_test;
use crate::power::controller::PowerMode;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
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
    pub claim: Arc<Mutex<Option<Box<dyn ClaimOps + Send>>>>,
    pub claim_snapshot: Arc<Mutex<Option<ClaimState>>>,
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
            claim: Arc::new(Mutex::new(None)),
            claim_snapshot: Arc::new(Mutex::new(None)),
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
    claim: Option<ClaimState>,
    claim_busy: bool,
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

#[derive(Serialize)]
struct ClaimApiError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_attempts: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
}

impl ClaimApiError {
    fn code(error: &str) -> Self {
        Self {
            error: error.to_string(),
            remaining_attempts: None,
            txid: None,
        }
    }
}

#[derive(Deserialize)]
struct PrepareRequest {
    destination: String,
}

#[derive(Deserialize)]
struct ConfirmRequest {
    destination: String,
    code: String,
}

#[derive(Serialize)]
struct PrepareResponse {
    summary: ClaimSummary,
}

#[derive(Serialize)]
struct ConfirmResponse {
    txid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimRequestDecision {
    Allowed,
    Forbidden,
    UnsupportedMediaType,
}

pub fn start_web_server(host: &str, port: u16, state: SharedSolverState) -> Result<(), String> {
    if host != "127.0.0.1" {
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

    if !host_is_allowed(&request, port) {
        send_json(
            stream,
            "403 FORBIDDEN",
            &ApiError {
                error: "host_not_allowed",
            },
        );
        return;
    }

    let is_claim_post = method == "POST"
        && matches!(
            path,
            "/api/claim/prepare" | "/api/claim/confirm" | "/api/claim/resend-code"
        );
    if is_claim_post {
        match claim_request_allowed(&request, port) {
            ClaimRequestDecision::Allowed => {
                let _ = stream.set_write_timeout(Some(Duration::from_secs(120)));
            }
            ClaimRequestDecision::Forbidden => {
                send_json(
                    stream,
                    "403 FORBIDDEN",
                    &ApiError {
                        error: "cross_origin_request_denied",
                    },
                );
                return;
            }
            ClaimRequestDecision::UnsupportedMediaType => {
                send_json(
                    stream,
                    "415 UNSUPPORTED MEDIA TYPE",
                    &ApiError {
                        error: "unsupported_media_type",
                    },
                );
                return;
            }
        }
    } else if method == "POST" && !origin_is_allowed(&request, port) {
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
            let (claim, claim_busy) = current_claim_state(state);
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
                claim,
                claim_busy,
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
        ("POST", "/api/claim/prepare") => handle_claim_prepare(stream, state, &request),
        ("POST", "/api/claim/confirm") => handle_claim_confirm(stream, state, &request),
        ("POST", "/api/claim/resend-code") => handle_claim_resend(stream, state),
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

fn http_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    let headers = request.split("\r\n\r\n").next().unwrap_or(request);
    for line in headers.lines().skip(1) {
        let Some((header_name, value)) = line.split_once(':') else {
            continue;
        };
        if header_name.eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn is_json_content_type(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower == "application/json" || lower.starts_with("application/json;")
}

fn host_is_allowed(request: &str, port: u16) -> bool {
    let headers = request.split("\r\n\r\n").next().unwrap_or(request);
    let mut host_count = 0;
    for line in headers.lines().skip(1) {
        let Some((header_name, _)) = line.split_once(':') else {
            continue;
        };
        if header_name.eq_ignore_ascii_case("Host") {
            host_count += 1;
        }
    }
    if host_count != 1 {
        return false;
    }
    let Some(host) = http_header(request, "Host") else {
        return false;
    };
    host == format!("127.0.0.1:{port}")
}

fn claim_request_allowed(request: &str, port: u16) -> ClaimRequestDecision {
    let Some(origin) = http_header(request, "origin") else {
        return ClaimRequestDecision::Forbidden;
    };
    if origin != format!("http://127.0.0.1:{port}") {
        return ClaimRequestDecision::Forbidden;
    }

    let Some(host) = http_header(request, "host") else {
        return ClaimRequestDecision::Forbidden;
    };
    if host != format!("127.0.0.1:{port}") {
        return ClaimRequestDecision::Forbidden;
    }

    match http_header(request, "content-type") {
        Some(content_type) if is_json_content_type(content_type) => ClaimRequestDecision::Allowed,
        _ => ClaimRequestDecision::UnsupportedMediaType,
    }
}

fn request_body(request: &str) -> &str {
    request
        .find("\r\n\r\n")
        .map(|start| &request[start + 4..])
        .unwrap_or_default()
}

fn current_claim_state(state: &SharedSolverState) -> (Option<ClaimState>, bool) {
    match state.claim.try_lock() {
        Ok(guard) => {
            let snap = guard.as_ref().map(|service| service.state());
            *state.claim_snapshot.lock().unwrap() = snap.clone();
            (snap, false)
        }
        Err(TryLockError::WouldBlock) => (state.claim_snapshot.lock().unwrap().clone(), true),
        Err(TryLockError::Poisoned(poisoned)) => {
            let guard = poisoned.into_inner();
            let snap = guard.as_ref().map(|service| service.state());
            *state.claim_snapshot.lock().unwrap() = snap.clone();
            (snap, false)
        }
    }
}

fn with_claim_service<T, F>(state: &SharedSolverState, op: F) -> Result<T, ClaimHandlerError>
where
    F: FnOnce(&mut dyn ClaimOps) -> Result<T, ServiceError>,
{
    if state.hit.lock().unwrap().is_none() {
        return Err(ClaimHandlerError::NoClaim);
    }
    let mut guard = match state.claim.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => return Err(ClaimHandlerError::Busy),
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };
    let Some(service) = guard.as_mut() else {
        return Err(ClaimHandlerError::NoClaim);
    };
    let result = op(service.as_mut());
    *state.claim_snapshot.lock().unwrap() = Some(service.state());
    result.map_err(ClaimHandlerError::Service)
}

enum ClaimHandlerError {
    NoClaim,
    Busy,
    Service(ServiceError),
}

fn handle_claim_prepare(stream: &mut TcpStream, state: &SharedSolverState, request: &str) {
    let parsed = match serde_json::from_str::<PrepareRequest>(request_body(request)) {
        Ok(body) => body,
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
    match with_claim_service(state, |service| service.prepare(&parsed.destination)) {
        Ok(summary) => send_json(stream, "200 OK", &PrepareResponse { summary }),
        Err(err) => send_claim_handler_error(stream, err),
    }
}

fn handle_claim_confirm(stream: &mut TcpStream, state: &SharedSolverState, request: &str) {
    let parsed = match serde_json::from_str::<ConfirmRequest>(request_body(request)) {
        Ok(body) => body,
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
    match with_claim_service(state, |service| {
        service.confirm(&parsed.destination, &parsed.code)
    }) {
        Ok(SubmitReceipt { txid }) => send_json(stream, "200 OK", &ConfirmResponse { txid }),
        Err(err) => send_claim_handler_error(stream, err),
    }
}

fn handle_claim_resend(stream: &mut TcpStream, state: &SharedSolverState) {
    match with_claim_service(state, |service| service.resend_alert()) {
        Ok(()) => send_json(
            stream,
            "200 OK",
            &ApiMessage {
                status: "code_sent",
            },
        ),
        Err(err) => send_claim_handler_error(stream, err),
    }
}

fn send_claim_handler_error(stream: &mut TcpStream, err: ClaimHandlerError) {
    match err {
        ClaimHandlerError::NoClaim => send_json(
            stream,
            "409 CONFLICT",
            &ApiError {
                error: "no_claim_available",
            },
        ),
        ClaimHandlerError::Busy => send_json(
            stream,
            "409 CONFLICT",
            &ApiError {
                error: "claim_busy",
            },
        ),
        ClaimHandlerError::Service(service_err) => {
            send_json(
                stream,
                service_error_http_status(&service_err),
                &map_service_error(&service_err),
            );
        }
    }
}

fn service_error_http_status(err: &ServiceError) -> &'static str {
    match err {
        ServiceError::Locked
        | ServiceError::NoCode
        | ServiceError::NotPrepared
        | ServiceError::InvalidState
        | ServiceError::ResendLimitReached
        | ServiceError::AlreadySubmittedDifferent { .. } => "409 CONFLICT",
        ServiceError::Storage => "500 INTERNAL SERVER ERROR",
        ServiceError::Fetch(_) | ServiceError::Net(_) => "503 SERVICE UNAVAILABLE",
        _ => "400 BAD REQUEST",
    }
}

fn map_service_error(err: &ServiceError) -> ClaimApiError {
    match err {
        ServiceError::Locked => ClaimApiError::code("locked"),
        ServiceError::NoCode => ClaimApiError::code("no_code"),
        ServiceError::NotPrepared => ClaimApiError::code("not_prepared"),
        ServiceError::DestinationMismatch => ClaimApiError::code("destination_mismatch"),
        ServiceError::WrongCode { remaining } => ClaimApiError {
            error: "wrong_code".to_string(),
            remaining_attempts: Some(*remaining),
            txid: None,
        },
        ServiceError::AlreadySubmittedDifferent { txid } => ClaimApiError {
            error: "already_submitted_different".to_string(),
            remaining_attempts: None,
            txid: Some(txid.clone()),
        },
        ServiceError::SummaryChanged => ClaimApiError::code("summary_changed"),
        ServiceError::BalanceBelowExpected => ClaimApiError::code("balance_below_expected"),
        ServiceError::FeeFloorTooHigh => ClaimApiError::code("fee_floor_too_high"),
        ServiceError::InvalidState => ClaimApiError::code("invalid_state"),
        ServiceError::ResendLimitReached => ClaimApiError::code("resend_limit_reached"),
        ServiceError::SubmissionRejected => ClaimApiError::code("submission_rejected"),
        ServiceError::SubmissionUnknown => ClaimApiError::code("submission_unknown"),
        ServiceError::Storage => ClaimApiError::code("storage_error"),
        ServiceError::CodeUnavailable => ClaimApiError::code("code_unavailable"),
        ServiceError::Claim(ClaimError::InvalidAddress) => ClaimApiError::code("invalid_address"),
        ServiceError::Claim(ClaimError::WrongNetwork) => ClaimApiError::code("wrong_network"),
        ServiceError::Claim(ClaimError::UnsupportedAddressType) => {
            ClaimApiError::code("unsupported_address_type")
        }
        ServiceError::Claim(ClaimError::DestinationIsPuzzleAddress) => {
            ClaimApiError::code("destination_is_puzzle_address")
        }
        ServiceError::Claim(_) => ClaimApiError::code("claim_build_failed"),
        ServiceError::Fetch(ClaimFetchError::Net(NetError::SourcesDisagree)) => {
            ClaimApiError::code("sources_disagree")
        }
        ServiceError::Fetch(_) | ServiceError::Net(_) => ClaimApiError::code("network_error"),
    }
}

fn origin_is_allowed(request: &str, port: u16) -> bool {
    let Some(origin) = http_header(request, "Origin") else {
        return true;
    };

    origin == format!("http://127.0.0.1:{}", port)
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
    use crate::claim::error::ClaimError;
    use crate::claim::find_verified_found_key;
    use crate::claim::net::error::NetError;
    use crate::claim::net::esplora::ClaimFetchError;
    use crate::claim::test_support::{self, TEST_SCALAR};
    use std::cmp;
    use std::io::Read;
    use std::ops::Deref;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

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
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nORIGIN: http://attacker.example\r\n\r\n",
            8080
        ));
    }

    fn host_request(host_line: &str) -> String {
        format!("GET /api/status HTTP/1.1\r\n{host_line}\r\n\r\n")
    }

    #[test]
    fn host_is_allowed_accepts_loopback_and_rejects_others() {
        assert!(host_is_allowed(&host_request("Host: 127.0.0.1:8080"), 8080));
        assert!(host_is_allowed(&host_request("HOST: 127.0.0.1:8080"), 8080));
        assert!(!host_is_allowed("GET /api/status HTTP/1.1\r\n\r\n", 8080));
        assert!(!host_is_allowed(
            &host_request("Host: localhost:8080"),
            8080
        ));
        assert!(!host_is_allowed(&host_request("Host: [::1]:8080"), 8080));
        assert!(!host_is_allowed(
            &host_request("Host: attacker.example:8080"),
            8080
        ));
        assert!(!host_is_allowed(&host_request("Host: 127.0.0.1"), 8080));
        assert!(!host_is_allowed(
            &host_request("Host: 127.0.0.1:8080x"),
            8080
        ));
        assert!(!host_is_allowed(
            &host_request("Host: 127.0.0.1:80800"),
            8080
        ));
    }

    #[test]
    fn host_is_allowed_rejects_duplicate_host_headers() {
        assert!(!host_is_allowed(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHost: 127.0.0.1:8080\r\n\r\n",
            8080
        ));
        assert!(!host_is_allowed(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHOST: 127.0.0.1:8080\r\n\r\n",
            8080
        ));
        assert!(host_is_allowed(&host_request("Host: 127.0.0.1:8080"), 8080));
    }

    #[test]
    fn origin_is_allowed_rejects_origin_prefix() {
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://127.0.0.1:8080x\r\n\r\n",
            8080
        ));
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://127.0.0.1:80800\r\n\r\n",
            8080
        ));
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://127.0.0.1:8080.evil.example\r\n\r\n",
            8080
        ));
    }

    #[test]
    fn origin_is_allowed_rejects_localhost_and_ipv6_loopback() {
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://localhost:8080\r\n\r\n",
            8080
        ));
        assert!(!origin_is_allowed(
            "POST /api/stop HTTP/1.1\r\nOrigin: http://[::1]:8080\r\n\r\n",
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

    fn claim_headers(origin: &str, host: &str, content_type: &str) -> String {
        format!(
            "POST /api/claim/prepare HTTP/1.1\r\nOrigin: {origin}\r\nHost: {host}\r\nContent-Type: {content_type}\r\n\r\n"
        )
    }

    #[test]
    fn claim_request_allowed_rejects_missing_and_foreign_origin() {
        let with_host_and_json = |origin_line: &str| {
            format!(
                "POST /api/claim/prepare HTTP/1.1\r\n{origin_line}Host: 127.0.0.1:8080\r\nContent-Type: application/json\r\n\r\n"
            )
        };
        assert_eq!(
            claim_request_allowed(&with_host_and_json(""), 8080),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &with_host_and_json("Origin: https://attacker.example\r\n"),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
    }

    #[test]
    fn claim_request_allowed_rejects_wrong_host() {
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080",
                    "attacker.example:8080",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080",
                    "127.0.0.1:9999",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
    }

    #[test]
    fn claim_request_allowed_rejects_wrong_content_type() {
        assert_eq!(
            claim_request_allowed(
                &claim_headers("http://127.0.0.1:8080", "127.0.0.1:8080", "text/plain"),
                8080
            ),
            ClaimRequestDecision::UnsupportedMediaType
        );
    }

    #[test]
    fn claim_request_allowed_accepts_loopback_json() {
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080",
                    "127.0.0.1:8080",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Allowed
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080",
                    "127.0.0.1:8080",
                    "application/json; charset=utf-8"
                ),
                8080
            ),
            ClaimRequestDecision::Allowed
        );
    }

    #[test]
    fn claim_request_allowed_rejects_localhost_and_ipv6_loopback() {
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://localhost:8080",
                    "localhost:8080",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers("http://[::1]:8080", "[::1]:8080", "application/json"),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080",
                    "localhost:8080",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://localhost:8080",
                    "127.0.0.1:8080",
                    "application/json"
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
    }

    #[test]
    fn claim_request_allowed_header_edge_cases() {
        assert_eq!(
            claim_request_allowed(
                "POST /api/claim/prepare HTTP/1.1\r\nOrigin: http://127.0.0.1:8080\r\nContent-Type: application/json\r\n\r\n",
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers("null", "127.0.0.1:8080", "application/json"),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:9999",
                    "127.0.0.1:8080",
                    "application/json",
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                "POST /api/claim/prepare HTTP/1.1\r\norigin: http://127.0.0.1:8080\r\nhost: 127.0.0.1:8080\r\ncontent-type: application/json\r\n\r\n",
                8080
            ),
            ClaimRequestDecision::Allowed
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers("http://127.0.0.1:8080", "127.0.0.1", "application/json"),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
    }

    #[test]
    fn claim_request_allowed_rejects_origin_prefix() {
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080x",
                    "127.0.0.1:8080",
                    "application/json",
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:8080.evil.example",
                    "127.0.0.1:8080",
                    "application/json",
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
        assert_eq!(
            claim_request_allowed(
                &claim_headers(
                    "http://127.0.0.1:80800",
                    "127.0.0.1:8080",
                    "application/json",
                ),
                8080
            ),
            ClaimRequestDecision::Forbidden
        );
    }

    #[test]
    fn start_web_server_rejects_localhost_and_ipv6_loopback() {
        for host in ["localhost", "::1"] {
            let err = start_web_server(host, 8080, SharedSolverState::new()).unwrap_err();
            assert!(err.contains(host) && err.contains("127.0.0.1"), "{err}");
        }
    }

    fn mapped_code(err: ServiceError) -> (String, Option<u8>, Option<String>) {
        let mapped = map_service_error(&err);
        (mapped.error, mapped.remaining_attempts, mapped.txid)
    }

    #[test]
    fn maps_every_service_error_variant_to_a_stable_json_code() {
        assert_eq!(
            mapped_code(ServiceError::Locked),
            ("locked".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::NoCode),
            ("no_code".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::NotPrepared),
            ("not_prepared".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::DestinationMismatch),
            ("destination_mismatch".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::WrongCode { remaining: 3 }),
            ("wrong_code".into(), Some(3), None)
        );
        assert_eq!(
            mapped_code(ServiceError::AlreadySubmittedDifferent {
                txid: "aa".repeat(32)
            }),
            (
                "already_submitted_different".into(),
                None,
                Some("aa".repeat(32))
            )
        );
        assert_eq!(
            mapped_code(ServiceError::SummaryChanged),
            ("summary_changed".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::BalanceBelowExpected),
            ("balance_below_expected".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::FeeFloorTooHigh),
            ("fee_floor_too_high".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::InvalidState),
            ("invalid_state".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::ResendLimitReached),
            ("resend_limit_reached".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::SubmissionRejected),
            ("submission_rejected".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::SubmissionUnknown),
            ("submission_unknown".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Storage),
            ("storage_error".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::CodeUnavailable),
            ("code_unavailable".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Claim(ClaimError::InvalidAddress)),
            ("invalid_address".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Claim(ClaimError::WrongNetwork)),
            ("wrong_network".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Claim(ClaimError::UnsupportedAddressType)),
            ("unsupported_address_type".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Claim(ClaimError::DestinationIsPuzzleAddress)),
            ("destination_is_puzzle_address".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Claim(ClaimError::PrevTxDecode)),
            ("claim_build_failed".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Fetch(ClaimFetchError::Net(
                NetError::SourcesDisagree
            ))),
            ("sources_disagree".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Fetch(ClaimFetchError::Net(
                NetError::BadResponse
            ))),
            ("network_error".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Fetch(ClaimFetchError::Claim(
                ClaimError::TxidMismatch
            ))),
            ("network_error".into(), None, None)
        );
        assert_eq!(
            mapped_code(ServiceError::Net(NetError::BadResponse)),
            ("network_error".into(), None, None)
        );
    }

    struct FakeClaim {
        state: ClaimState,
        prepare_calls: Arc<AtomicUsize>,
        confirm_calls: Arc<AtomicUsize>,
        resend_calls: Arc<AtomicUsize>,
    }

    impl FakeClaim {
        fn with_state(state: ClaimState) -> Self {
            Self {
                state,
                prepare_calls: Arc::new(AtomicUsize::new(0)),
                confirm_calls: Arc::new(AtomicUsize::new(0)),
                resend_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ClaimOps for FakeClaim {
        fn state(&self) -> ClaimState {
            self.state.clone()
        }
        fn on_verified_hit(&mut self) {}
        fn resend_alert(&mut self) -> Result<(), ServiceError> {
            self.resend_calls.fetch_add(1, Ordering::SeqCst);
            Err(ServiceError::InvalidState)
        }
        fn prepare(&mut self, _: &str) -> Result<ClaimSummary, ServiceError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            Err(ServiceError::InvalidState)
        }
        fn confirm(&mut self, _: &str, _: &str) -> Result<SubmitReceipt, ServiceError> {
            self.confirm_calls.fetch_add(1, Ordering::SeqCst);
            Err(ServiceError::InvalidState)
        }
        fn poll(&mut self) {}
    }

    fn sample_summary() -> ClaimSummary {
        ClaimSummary {
            network: "bitcoin".to_string(),
            destination: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            input_count: 1,
            total_input_sat: 710_000_000,
            output_sat: 709_400_000,
            fee_sat: 600_000,
            vsize: 300,
            effective_fee_rate_sat_vb: 2000.0,
            txid: "aa".repeat(32),
            excluded_dust_count: 0,
            excluded_dust_sat: 0,
        }
    }

    fn json_field_names(value: &serde_json::Value, names: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    names.push(key.to_ascii_lowercase());
                    json_field_names(child, names);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    json_field_names(child, names);
                }
            }
            _ => {}
        }
    }

    fn read_http_response(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn assert_status_json_has_no_secret_field_names(claim_state: ClaimState) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = SharedSolverState::new();
        *state.claim.lock().unwrap() = Some(Box::new(FakeClaim::with_state(claim_state)));
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_client(&mut stream, &state, addr.port());
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let request = format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);
        let response = read_http_response(&mut client);
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        let mut names = Vec::new();
        json_field_names(&json, &mut names);
        for forbidden in ["code", "pubkey", "hex", "private"] {
            assert!(
                names.iter().all(|name| !name.contains(forbidden)),
                "secret field {forbidden} in {names:?}"
            );
        }
        assert!(json.get("claim").is_some());
    }

    #[test]
    fn status_json_with_fake_claim_has_no_secret_field_names() {
        assert_status_json_has_no_secret_field_names(ClaimState::Submitted {
            txid: "SENTINELTXID0000000000000000000000000000000000000000000000000000".to_string(),
            submitted_at_unix: 1,
        });
    }

    #[test]
    fn status_json_with_prepared_claim_has_no_secret_field_names() {
        assert_status_json_has_no_secret_field_names(ClaimState::Prepared {
            summary: sample_summary(),
            alert_sent: true,
            alerts_remaining: 3,
            attempts_remaining: 5,
        });
    }

    fn get_status_json(state: SharedSolverState) -> serde_json::Value {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_client(&mut stream, &state, addr.port());
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let request = format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);
        let response = read_http_response(&mut client);
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn status_json_claim_busy_follows_the_claim_lock() {
        let state = SharedSolverState::new();
        let idle = get_status_json(state.clone());
        assert_eq!(
            idle.get("claim_busy").and_then(|value| value.as_bool()),
            Some(false)
        );

        let holder = state.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let held = thread::spawn(move || {
            let _guard = holder.claim.lock().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let busy = get_status_json(state.clone());
        assert_eq!(
            busy.get("claim_busy").and_then(|value| value.as_bool()),
            Some(true)
        );
        drop(release_tx);
        held.join().unwrap();
        let free = get_status_json(state);
        assert_eq!(
            free.get("claim_busy").and_then(|value| value.as_bool()),
            Some(false)
        );
    }

    fn seed_hit(state: &SharedSolverState) {
        *state.hit.lock().unwrap() = Some(PublicHitStatus {
            bitcoin_address: "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU".to_string(),
            saved_filename: "FOUND_KEY.txt".to_string(),
            timestamp_unix: 1,
        });
    }

    fn exchange_claim_http(
        state: SharedSolverState,
        request_for_port: impl FnOnce(u16) -> String,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_client(&mut stream, &state, port);
        });
        let payload = request_for_port(port);
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(payload.as_bytes()).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);
        read_http_response(&mut client)
    }

    fn claim_post_http(
        path: &str,
        origin: Option<String>,
        host: Option<String>,
        content_type: &str,
        body: &str,
    ) -> String {
        let mut request = format!("POST {path} HTTP/1.1\r\n");
        if let Some(origin) = origin {
            request.push_str(&format!("Origin: {origin}\r\n"));
        }
        if let Some(host) = host {
            request.push_str(&format!("Host: {host}\r\n"));
        }
        request.push_str(&format!(
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
        request
    }

    #[test]
    fn claim_prepare_tcp_gate_blocks_before_service() {
        let fake = FakeClaim::with_state(ClaimState::AwaitingOwner {
            alert_sent: true,
            alerts_remaining: 3,
            attempts_remaining: 5,
        });
        let count = fake.prepare_calls.clone();
        let state = SharedSolverState::new();
        seed_hit(&state);
        *state.claim.lock().unwrap() = Some(Box::new(fake));
        assert_claim_route_gated_on(
            state,
            "/api/claim/prepare",
            r#"{"destination":"bc1qtest"}"#,
            &count,
        );
    }

    #[test]
    fn claim_confirm_tcp_gate_blocks_before_service() {
        let fake = FakeClaim::with_state(ClaimState::Prepared {
            summary: sample_summary(),
            alert_sent: true,
            alerts_remaining: 3,
            attempts_remaining: 5,
        });
        let count = fake.confirm_calls.clone();
        let state = SharedSolverState::new();
        seed_hit(&state);
        *state.claim.lock().unwrap() = Some(Box::new(fake));
        assert_claim_route_gated_on(
            state,
            "/api/claim/confirm",
            r#"{"destination":"bc1qtest","code":"123456"}"#,
            &count,
        );
    }

    #[test]
    fn claim_resend_tcp_gate_blocks_before_service() {
        let fake = FakeClaim::with_state(ClaimState::AwaitingOwner {
            alert_sent: true,
            alerts_remaining: 3,
            attempts_remaining: 5,
        });
        let count = fake.resend_calls.clone();
        let state = SharedSolverState::new();
        seed_hit(&state);
        *state.claim.lock().unwrap() = Some(Box::new(fake));
        assert_claim_route_gated_on(state, "/api/claim/resend-code", "{}", &count);
    }

    #[test]
    fn status_tcp_gate_blocks_wrong_host() {
        let state = SharedSolverState::new();
        seed_hit(&state);

        let blocked = exchange_claim_http(state.clone(), |port| {
            format!("GET /api/status HTTP/1.1\r\nHost: attacker.example:{port}\r\n\r\n")
        });
        assert!(blocked.contains("403 FORBIDDEN"), "wrong Host: {blocked}");
        assert!(
            !blocked.contains("\"hit\""),
            "wrong Host leaked status: {blocked}"
        );

        let allowed = exchange_claim_http(state, |port| {
            format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
        });
        assert!(allowed.contains("200 OK"), "loopback Host: {allowed}");
    }

    fn assert_claim_route_gated_on(
        state: SharedSolverState,
        path: &'static str,
        body: &'static str,
        count: &Arc<AtomicUsize>,
    ) {
        let calls = || count.load(Ordering::SeqCst);
        let missing_origin = exchange_claim_http(state.clone(), |port| {
            claim_post_http(
                path,
                None,
                Some(format!("127.0.0.1:{port}")),
                "application/json",
                body,
            )
        });
        assert!(
            missing_origin.contains("403 FORBIDDEN"),
            "missing Origin: {missing_origin}"
        );
        assert_eq!(calls(), 0);

        let wrong_host = exchange_claim_http(state.clone(), |port| {
            claim_post_http(
                path,
                Some(format!("http://127.0.0.1:{port}")),
                Some(format!("attacker.example:{port}")),
                "application/json",
                body,
            )
        });
        assert!(
            wrong_host.contains("403 FORBIDDEN"),
            "wrong Host: {wrong_host}"
        );
        assert_eq!(calls(), 0);

        let wrong_type = exchange_claim_http(state.clone(), |port| {
            claim_post_http(
                path,
                Some(format!("http://127.0.0.1:{port}")),
                Some(format!("127.0.0.1:{port}")),
                "text/plain",
                body,
            )
        });
        assert!(
            wrong_type.contains("415 UNSUPPORTED MEDIA TYPE"),
            "text/plain: {wrong_type}"
        );
        assert_eq!(calls(), 0);

        let allowed = exchange_claim_http(state, |port| {
            claim_post_http(
                path,
                Some(format!("http://127.0.0.1:{port}")),
                Some(format!("127.0.0.1:{port}")),
                "application/json",
                body,
            )
        });
        assert!(
            !allowed.contains("403 FORBIDDEN") && !allowed.contains("415 UNSUPPORTED MEDIA TYPE"),
            "allowed request blocked: {allowed}"
        );
        assert_eq!(calls(), 1);
    }

    fn write_found_key_file(path: &Path, mode: u32, scalar: u128) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        write!(file, "PRIVATE KEY (HEX):       0x{scalar:018x}\n").unwrap();
    }

    static RECOVERY_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    struct RecoveryTempDir(std::path::PathBuf);

    impl Drop for RecoveryTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl Deref for RecoveryTempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    fn recovery_temp_dir() -> RecoveryTempDir {
        loop {
            let seq = RECOVERY_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "puzzle71-claim-recovery-{}-{}-{}",
                std::process::id(),
                nanos,
                seq
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => return RecoveryTempDir(dir),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create recovery temp dir: {err}"),
            }
        }
    }

    #[test]
    fn find_verified_found_key_none_without_files() {
        let dir = recovery_temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        assert_eq!(
            find_verified_found_key(&dir, hash, 0..=u128::MAX).found,
            None
        );
    }

    #[test]
    fn find_verified_found_key_rejects_world_readable_and_foreign_keys() {
        let dir = recovery_temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        write_found_key_file(&dir.join("FOUND_KEY.txt"), 0o644, TEST_SCALAR);
        assert_eq!(
            find_verified_found_key(&dir, hash, 0..=u128::MAX).found,
            None
        );
        write_found_key_file(&dir.join("FOUND_KEY_foreign.txt"), 0o600, TEST_SCALAR ^ 1);
        assert_eq!(
            find_verified_found_key(&dir, hash, 0..=u128::MAX).found,
            None
        );
    }

    #[test]
    fn find_verified_found_key_accepts_matching_test_file() {
        let dir = recovery_temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        write_found_key_file(&dir.join("FOUND_KEY.txt"), 0o600, TEST_SCALAR);
        let found = find_verified_found_key(&dir, hash, 0..=u128::MAX)
            .found
            .expect("valid");
        assert_eq!(found.file_name().unwrap(), "FOUND_KEY.txt");
    }
}
