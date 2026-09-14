//! Generalprobe binary: hit file → claim service → real Telegram alert → dashboard →
//! confirm → local bitcoind regtest.
//!
//! Never installed. Does not touch the product binary, `puzzle_config`, or frozen claim-core
//! files. Network use is Telegram (existing `CurlTransport`) and bitcoind JSON-RPC on
//! `127.0.0.1` only.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid};
use serde_json::{Value, json};

use puzzle71_solver::claim::{
    ClaimError, ClaimFetchError, ClaimKey, ClaimService, ClaimState, CurlTransport, KeySource,
    NetError, Notifier, SignedClaim, SubmitError, SubmitReceipt, Submitter, TelegramNotifier,
    TxStatus, UtxoSnapshot, UtxoSource, find_verified_found_key, p2pkh_script_for_hash160,
    verify_prevout,
};
use puzzle71_solver::puzzle_config::{RANGE_MAX, RANGE_MIN};
use puzzle71_solver::web::server::{PublicHitStatus, SharedSolverState, start_web_server};

/// Probe scalar inside the real Puzzle #71 range `2^70 ..= 2^71 - 1`.
const REHEARSAL_SCALAR: u128 = (1u128 << 70) + 0x5EED_1234;

const _: () = assert!(REHEARSAL_SCALAR >= RANGE_MIN);
const _: () = assert!(REHEARSAL_SCALAR <= RANGE_MAX);

const RPC_USER: &str = "p71";
const RPC_PASSWORD: &str = "p71regtest";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:18443";
const DEFAULT_SERVE_PORT: u16 = 18080;
const PRODUCTION_PORT: u16 = 8080;
const FOUND_KEY_FILENAME: &str = "FOUND_KEY.txt";
const FOUND_KEY_LINE_PREFIX: &str = "PRIVATE KEY (HEX):";
const RPC_TIMEOUT: Duration = Duration::from_secs(60);
const MARKER_FILENAME: &str = "CLAIM_SUBMITTED.json";

const _: () = assert!(PRODUCTION_PORT == 8080);

fn main() {
    match run(env::args().collect()) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match parse_args(&args)? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::WriteHit { dir } => cmd_write_hit(&dir),
        Command::Serve {
            port,
            dir,
            rpc,
            allow_production_port,
        } => cmd_serve(port, &dir, &rpc, allow_production_port),
    }
}

enum Command {
    Help,
    WriteHit {
        dir: PathBuf,
    },
    Serve {
        port: u16,
        dir: PathBuf,
        rpc: String,
        allow_production_port: bool,
    },
}

fn print_usage() {
    eprintln!(
        "Usage:
  rehearsal write-hit [--dir <path>]
  rehearsal serve [--port <p>] [--dir <path>] [--rpc <host:port>] [--i-know-this-is-the-production-port]"
    );
}

fn usage_err(msg: &str) -> String {
    format!("{msg}\n")
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let Some(cmd) = args.get(1).map(String::as_str) else {
        print_usage();
        return Err("missing command".to_string());
    };
    match cmd {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "write-hit" => {
            let mut dir = PathBuf::from(".");
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--dir" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| usage_err("--dir requires a path"))?;
                        if value.is_empty() {
                            return Err("--dir requires a path".to_string());
                        }
                        dir = PathBuf::from(value);
                        i += 2;
                    }
                    other => return Err(format!("unknown argument: {other}")),
                }
            }
            Ok(Command::WriteHit { dir })
        }
        "serve" => {
            let mut port = DEFAULT_SERVE_PORT;
            let mut dir = PathBuf::from(".");
            let mut rpc = None;
            let mut allow_production_port = false;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--port" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| usage_err("--port requires a value"))?;
                        port = value
                            .parse::<u16>()
                            .map_err(|_| format!("invalid port: {value}"))?;
                        if port == 0 {
                            return Err("port must be non-zero".to_string());
                        }
                        i += 2;
                    }
                    "--dir" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| usage_err("--dir requires a path"))?;
                        if value.is_empty() {
                            return Err("--dir requires a path".to_string());
                        }
                        dir = PathBuf::from(value);
                        i += 2;
                    }
                    "--rpc" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| usage_err("--rpc requires host:port"))?;
                        rpc = Some(parse_rpc_addr(value)?);
                        i += 2;
                    }
                    "--i-know-this-is-the-production-port" => {
                        allow_production_port = true;
                        i += 1;
                    }
                    other => return Err(format!("unknown argument: {other}")),
                }
            }
            let rpc = match rpc {
                Some(addr) => addr,
                None => default_rpc_addr()?,
            };
            Ok(Command::Serve {
                port,
                dir,
                rpc,
                allow_production_port,
            })
        }
        other => {
            print_usage();
            Err(format!("unknown command: {other}"))
        }
    }
}

fn default_rpc_addr() -> Result<String, String> {
    match env::var("PUZZLE71_REGTEST_RPC") {
        Ok(raw) => parse_rpc_addr(&raw),
        Err(env::VarError::NotPresent) => parse_rpc_addr(DEFAULT_RPC_ADDR),
        Err(_) => Err("PUZZLE71_REGTEST_RPC is not valid UTF-8".to_string()),
    }
}

fn parse_rpc_addr(raw: &str) -> Result<String, String> {
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| format!("rpc address must be host:port, got {raw}"))?;
    if host != "127.0.0.1" {
        return Err("rpc host must be 127.0.0.1".to_string());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid rpc port: {port}"))?;
    if port == 0 {
        return Err("rpc port must be non-zero".to_string());
    }
    Ok(format!("{host}:{port}"))
}

fn derive_hash160(scalar: u128) -> [u8; 20] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&scalar.to_be_bytes());
    let secret =
        SecretKey::from_slice(&bytes).expect("REHEARSAL_SCALAR must be a valid secp256k1 key");
    bytes.fill(0);
    let secp = Secp256k1::signing_only();
    let pubkey = secret.public_key(&secp);
    bitcoin::PublicKey::new(pubkey)
        .pubkey_hash()
        .to_byte_array()
}

fn rehearsal_p2pkh_address(hash160: [u8; 20]) -> Address {
    Address::p2pkh(
        bitcoin::PubkeyHash::from_byte_array(hash160),
        Network::Regtest,
    )
}

fn cmd_write_hit(dir: &Path) -> Result<(), String> {
    let address = write_hit_file(dir)?;
    eprintln!(
        "wrote {} (mode 0600)",
        dir.join(FOUND_KEY_FILENAME).display()
    );
    println!("{address}");
    Ok(())
}

fn write_hit_file(dir: &Path) -> Result<Address, String> {
    if !dir.is_dir() {
        return Err(format!("directory does not exist: {}", dir.display()));
    }
    let dest = dir.join(FOUND_KEY_FILENAME);
    match dest.try_exists() {
        Ok(true) => {
            return Err(format!("refusing to overwrite existing {}", dest.display()));
        }
        Ok(false) => {}
        Err(err) => {
            return Err(format!("cannot stat {}: {err}", dest.display()));
        }
    }

    let content = format!("{FOUND_KEY_LINE_PREFIX}0x{REHEARSAL_SCALAR:018x}\n");
    let temp_name = format!(
        ".{}.{}.{}.tmp",
        FOUND_KEY_FILENAME,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temp_path = dir.join(temp_name);

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(|e| format!("failed to create temporary key file: {e}"))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("failed to write temporary key file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("failed to sync temporary key file: {e}"))?;
        drop(file);
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set temporary key file permissions: {e}"))?;
        fs::rename(&temp_path, &dest).map_err(|e| format!("failed to install key file: {e}"))?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set key file permissions: {e}"))?;
        File::open(dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("failed to sync key directory: {e}"))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result?;

    Ok(rehearsal_p2pkh_address(derive_hash160(REHEARSAL_SCALAR)))
}

fn cmd_serve(port: u16, dir: &Path, rpc: &str, allow_production_port: bool) -> Result<(), String> {
    if port == PRODUCTION_PORT && !allow_production_port {
        return Err(format!(
            "refusing --port {PRODUCTION_PORT} without \
             --i-know-this-is-the-production-port (the production solver listens there)"
        ));
    }
    if !dir.is_dir() {
        return Err(format!("directory does not exist: {}", dir.display()));
    }

    unsafe {
        libc::signal(libc::SIGINT, handle_sigint as *const () as usize);
        libc::signal(libc::SIGTERM, handle_sigint as *const () as usize);
    }
    SHUTDOWN_SIGNAL.store(false, Ordering::SeqCst);

    let hash160 = derive_hash160(REHEARSAL_SCALAR);
    let address = rehearsal_p2pkh_address(hash160);
    let scan = find_verified_found_key(dir, hash160, RANGE_MIN..=RANGE_MAX);
    let Some(found_path) = scan.found else {
        let mut msg = format!(
            "no FOUND_KEY*.txt matched the rehearsal hash160 in {}",
            dir.display()
        );
        for (name, reason) in scan.unloadable {
            msg.push_str(&format!("\n  {name}: {reason}"));
        }
        return Err(msg);
    };

    let rpc_client = RpcClient::new(rpc.to_string())?;
    let utxo = RegtestUtxoSource::new(rpc_client.clone(), address.clone(), hash160);
    let submitter = RegtestSubmitter::new(rpc_client);
    let notifier = TelegramNotifier::new(CurlTransport, telegram_config_path());
    let key_source = RehearsalKeyFile {
        path: found_path.clone(),
        hash160,
    };
    let service = ClaimService::new(
        utxo,
        submitter,
        notifier,
        key_source,
        dir.join(MARKER_FILENAME),
    );

    let shared_state = SharedSolverState::new();
    shared_state.is_running.store(false, Ordering::SeqCst);
    let timestamp_unix = fs::metadata(&found_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let saved_filename = found_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(FOUND_KEY_FILENAME)
        .to_string();
    *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
        bitcoin_address: address.to_string(),
        saved_filename,
        timestamp_unix,
    });

    start_web_server("127.0.0.1", port, shared_state.clone())
        .map_err(|e| format!("could not start rehearsal dashboard on 127.0.0.1:{port}: {e}"))?;

    spawn_claim_threads(&shared_state, service);

    println!("Rehearsal dashboard: http://127.0.0.1:{port}");
    println!("Rehearsal P2PKH address (regtest): {address}");
    println!("Found key file: {}", found_path.display());
    println!("Press CTRL+C to exit.");

    while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(250));
    }
    println!("\nRehearsal shutdown.");
    Ok(())
}

fn spawn_claim_threads<U, S, N, K>(
    shared_state: &SharedSolverState,
    service: ClaimService<U, S, N, K>,
) where
    U: UtxoSource + Send + 'static,
    S: Submitter + Send + 'static,
    N: Notifier + Send + 'static,
    K: KeySource + Send + 'static,
{
    let skip_alert = matches!(service.state(), ClaimState::Submitted { .. });
    {
        let mut slot = shared_state.claim.lock().unwrap();
        *slot = Some(Box::new(service));
        if let Some(svc) = slot.as_ref() {
            *shared_state.claim_snapshot.lock().unwrap() = Some(svc.state());
        }
    }
    if !skip_alert {
        let claim = shared_state.claim.clone();
        let snapshot = shared_state.claim_snapshot.clone();
        thread::spawn(move || {
            let mut slot = match claim.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(svc) = slot.as_mut() {
                svc.on_verified_hit();
                *snapshot.lock().unwrap() = Some(svc.state());
            }
        });
    }
    let claim = shared_state.claim.clone();
    let snapshot = shared_state.claim_snapshot.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            let mut slot = match claim.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(svc) = slot.as_mut() else {
                continue;
            };
            svc.poll();
            *snapshot.lock().unwrap() = Some(svc.state());
        }
    });
}

fn telegram_config_path() -> PathBuf {
    let home = env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/puzzle71/telegram.json")
}

struct RehearsalKeyFile {
    path: PathBuf,
    hash160: [u8; 20],
}

impl KeySource for RehearsalKeyFile {
    fn load(&self) -> Result<ClaimKey, ClaimError> {
        ClaimKey::load_found_key_file(&self.path, self.hash160, RANGE_MIN..=RANGE_MAX)
    }
}

#[derive(Clone)]
struct RpcClient {
    addr: String,
}

enum RpcError {
    Transport,
    Rpc { code: i64, message: String },
    Decode,
}

impl RpcClient {
    fn new(addr: String) -> Result<Self, String> {
        let parsed: SocketAddr = addr
            .parse()
            .map_err(|_| format!("invalid rpc address: {addr}"))?;
        if parsed.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err("rpc host must be 127.0.0.1".to_string());
        }
        Ok(Self { addr })
    }

    fn call(&self, wallet: Option<&str>, method: &str, params: Value) -> Result<Value, RpcError> {
        let socket: SocketAddr = self.addr.parse().map_err(|_| RpcError::Decode)?;
        if socket.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(RpcError::Transport);
        }
        let mut stream =
            TcpStream::connect_timeout(&socket, RPC_TIMEOUT).map_err(|_| RpcError::Transport)?;
        stream
            .set_read_timeout(Some(RPC_TIMEOUT))
            .map_err(|_| RpcError::Transport)?;
        stream
            .set_write_timeout(Some(RPC_TIMEOUT))
            .map_err(|_| RpcError::Transport)?;

        let path = match wallet {
            Some(name) => format!("/wallet/{name}"),
            None => "/".to_string(),
        };
        let body = json!({
            "jsonrpc": "1.0",
            "id": "puzzle71-rehearsal",
            "method": method,
            "params": params,
        })
        .to_string();
        let auth = base64_encode(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes());
        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Basic {auth}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );

        stream
            .write_all(request.as_bytes())
            .map_err(|_| RpcError::Transport)?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|_| RpcError::Transport)?;

        let body_start = match response.find("\r\n\r\n") {
            Some(idx) => idx + 4,
            None => return Err(RpcError::Decode),
        };
        let response_body = &response[body_start..];
        let parsed: Value = serde_json::from_str(response_body).map_err(|_| RpcError::Decode)?;

        match parsed.get("error") {
            Some(error) if !error.is_null() => {
                let code = error
                    .get("code")
                    .and_then(Value::as_i64)
                    .ok_or(RpcError::Decode)?;
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Err(RpcError::Rpc { code, message })
            }
            _ => Ok(parsed["result"].clone()),
        }
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn classify_rpc_submit_error(code: i64, message: String) -> SubmitError {
    match code {
        -25 | -26 | -27 => SubmitError::Rejected(message),
        _ => SubmitError::Ambiguous(NetError::BadResponse),
    }
}

fn rpc_to_net_error(err: RpcError) -> NetError {
    match err {
        RpcError::Transport => NetError::Transport { exit_code: None },
        RpcError::Rpc { .. } | RpcError::Decode => NetError::BadResponse,
    }
}

fn rpc_to_fetch_error(err: RpcError) -> ClaimFetchError {
    ClaimFetchError::Net(rpc_to_net_error(err))
}

struct RegtestUtxoSource {
    rpc: RpcClient,
    address: Address,
    expected_script: ScriptBuf,
}

impl RegtestUtxoSource {
    fn new(rpc: RpcClient, address: Address, hash160: [u8; 20]) -> Self {
        Self {
            rpc,
            address,
            expected_script: p2pkh_script_for_hash160(hash160),
        }
    }
}

impl UtxoSource for RegtestUtxoSource {
    fn fetch_verified_prevouts(&self) -> Result<UtxoSnapshot, ClaimFetchError> {
        let descriptor = format!("addr({})", self.address);
        let result = self
            .rpc
            .call(None, "scantxoutset", json!(["start", [descriptor]]))
            .map_err(rpc_to_fetch_error)?;
        if result.get("success") == Some(&Value::Bool(false)) {
            return Err(ClaimFetchError::Net(NetError::BadResponse));
        }
        let unspents = result
            .get("unspents")
            .and_then(Value::as_array)
            .ok_or(ClaimFetchError::Net(NetError::BadResponse))?;

        let mut prevouts = Vec::with_capacity(unspents.len());
        for entry in unspents {
            let txid_str = entry
                .get("txid")
                .and_then(Value::as_str)
                .ok_or(ClaimFetchError::Net(NetError::BadResponse))?;
            let txid: Txid = txid_str
                .parse()
                .map_err(|_| ClaimFetchError::Net(NetError::BadResponse))?;
            let vout = entry
                .get("vout")
                .and_then(Value::as_u64)
                .ok_or(ClaimFetchError::Net(NetError::BadResponse))? as u32;
            let outpoint = OutPoint { txid, vout };

            let raw_value = self
                .rpc
                .call(
                    None,
                    "getrawtransaction",
                    json!([outpoint.txid.to_string(), false]),
                )
                .map_err(rpc_to_fetch_error)?;
            let raw_hex = raw_value
                .as_str()
                .ok_or(ClaimFetchError::Net(NetError::BadResponse))?;
            let raw = Vec::<u8>::from_hex(raw_hex)
                .map_err(|_| ClaimFetchError::Claim(ClaimError::PrevTxDecode))?;
            let verified = verify_prevout(outpoint, &raw, self.expected_script.as_script())?;
            prevouts.push(verified);
        }

        Ok(UtxoSnapshot {
            prevouts,
            unconfirmed_count: 0,
        })
    }
}

struct RegtestSubmitter {
    rpc: RpcClient,
}

impl RegtestSubmitter {
    fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }
}

impl Submitter for RegtestSubmitter {
    fn fee_floor_sat_vb(&self) -> Result<u64, NetError> {
        match env::var("REHEARSAL_FEE_FLOOR") {
            Ok(raw) => raw.parse::<u64>().map_err(|_| NetError::InvalidInput),
            Err(env::VarError::NotPresent) => Ok(1),
            Err(_) => Err(NetError::InvalidInput),
        }
    }

    fn submit(&self, claim: &SignedClaim) -> Result<SubmitReceipt, SubmitError> {
        let expected_txid = claim.summary().txid.clone();
        let hex = claim.raw_tx_bytes_for_submission().to_lower_hex_string();
        let result = self.rpc.call(None, "sendrawtransaction", json!([hex]));
        match result {
            Ok(value) => {
                let txid = value
                    .as_str()
                    .ok_or(SubmitError::Ambiguous(NetError::BadResponse))?;
                if txid != expected_txid {
                    return Err(SubmitError::Ambiguous(NetError::SubmitTxidMismatch));
                }
                Ok(SubmitReceipt {
                    txid: txid.to_string(),
                })
            }
            Err(RpcError::Rpc { code, message }) => Err(classify_rpc_submit_error(code, message)),
            Err(other) => Err(SubmitError::Ambiguous(rpc_to_net_error(other))),
        }
    }

    fn status(&self, txid: &str) -> Result<TxStatus, NetError> {
        match self
            .rpc
            .call(None, "getrawtransaction", json!([txid, true]))
        {
            Ok(value) => {
                let confirmations = value
                    .get("confirmations")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if confirmations == 0 {
                    return Ok(TxStatus::Pending);
                }
                let blockhash = value
                    .get("blockhash")
                    .and_then(Value::as_str)
                    .ok_or(NetError::BadResponse)?;
                let header = self
                    .rpc
                    .call(None, "getblockheader", json!([blockhash, true]))
                    .map_err(rpc_to_net_error)?;
                let block_height = header
                    .get("height")
                    .and_then(Value::as_u64)
                    .ok_or(NetError::BadResponse)?;
                Ok(TxStatus::Confirmed { block_height })
            }
            Err(RpcError::Rpc { code, .. }) if code == -5 => Ok(TxStatus::NotFound),
            Err(other) => Err(rpc_to_net_error(other)),
        }
    }
}

static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::AddressType;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "puzzle71-rehearsal-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        TempDir(dir)
    }

    #[test]
    fn rehearsal_scalar_derives_stable_hash160_and_p2pkh_in_puzzle_range() {
        assert!(
            (RANGE_MIN..=RANGE_MAX).contains(&REHEARSAL_SCALAR),
            "REHEARSAL_SCALAR must lie in 2^70 ..= 2^71-1"
        );

        let hash160_a = derive_hash160(REHEARSAL_SCALAR);
        let hash160_b = derive_hash160(REHEARSAL_SCALAR);
        assert_eq!(hash160_a, hash160_b);

        let address_a = rehearsal_p2pkh_address(hash160_a);
        let address_b = rehearsal_p2pkh_address(hash160_b);
        assert_eq!(address_a.to_string(), address_b.to_string());
        assert_eq!(address_a.address_type(), Some(AddressType::P2pkh));

        ClaimKey::from_u128(REHEARSAL_SCALAR, hash160_a)
            .expect("self-derived rehearsal hash160 must match the scalar");
    }

    #[test]
    fn rpc_submit_error_codes_map_to_rejected_or_ambiguous() {
        assert_eq!(
            classify_rpc_submit_error(-25, "missing-inputs".to_string()),
            SubmitError::Rejected("missing-inputs".to_string())
        );
        assert_eq!(
            classify_rpc_submit_error(-26, "txn-mempool-conflict".to_string()),
            SubmitError::Rejected("txn-mempool-conflict".to_string())
        );
        assert_eq!(
            classify_rpc_submit_error(-27, "txn-already-in-mempool".to_string()),
            SubmitError::Rejected("txn-already-in-mempool".to_string())
        );
        assert_eq!(
            classify_rpc_submit_error(-5, "no such tx".to_string()),
            SubmitError::Ambiguous(NetError::BadResponse)
        );
        assert_eq!(
            classify_rpc_submit_error(-1, "warmup".to_string()),
            SubmitError::Ambiguous(NetError::BadResponse)
        );
        assert_eq!(
            classify_rpc_submit_error(0, "ok?".to_string()),
            SubmitError::Ambiguous(NetError::BadResponse)
        );
    }

    #[test]
    fn write_hit_file_is_accepted_by_load_found_key_file() {
        let dir = temp_dir("hit");
        let address = write_hit_file(&dir.0).expect("write-hit must succeed in a fresh temp dir");
        let path = dir.0.join(FOUND_KEY_FILENAME);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let hash160 = derive_hash160(REHEARSAL_SCALAR);
        assert_eq!(address, rehearsal_p2pkh_address(hash160));

        ClaimKey::load_found_key_file(&path, hash160, RANGE_MIN..=RANGE_MAX)
            .expect("written FOUND_KEY.txt must load with the rehearsal hash160");

        let err = write_hit_file(&dir.0).unwrap_err();
        assert!(
            err.contains("overwrite"),
            "second write-hit must refuse to overwrite: {err}"
        );
    }
}
