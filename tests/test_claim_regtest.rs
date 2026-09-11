//! End-to-end regtest tests for the offline claim pipeline (`puzzle71_solver::claim`).
//!
//! All tests here are `#[ignore]`: they need a live bitcoind regtest node started by
//! `scripts/regtest-up.sh` and are therefore not part of `cargo test --all-targets`. Run with:
//!
//! ```text
//! scripts/regtest-down.sh; scripts/regtest-up.sh
//! cargo test --test test_claim_regtest -- --ignored --test-threads=1 --nocapture
//! scripts/regtest-down.sh
//! ```
//!
//! Each test uses its own fixed test scalar (and therefore its own puzzle P2PKH address), so the
//! three tests below never fund or spend each other's UTXOs within a single run. That does *not*
//! make them safe to run in parallel or to repeat against an already-used node: the scalars are
//! fixed constants, so a second run against the same node sends *additional* UTXOs to the same
//! puzzle addresses on top of what a prior run already sent, breaking every `assert_eq!(..., 5,
//! ...)` UTXO-count assertion below. Separately, `scantxoutset` (used by `scan_utxos`) does not
//! support concurrent scans against the same node. Hence: always start from a fresh node
//! (`regtest-down.sh` + `regtest-up.sh`) and always run with `--test-threads=1`.

use std::io::{Read, Write};
use std::net::TcpStream;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, Txid};
use puzzle71_solver::claim::{
    ClaimKey, VerifiedPrevout, build_signed_claim, p2pkh_script_for_hash160, parse_destination,
    verify_prevout,
};
use serde_json::{Value, json};

const RPC_USER: &str = "p71";
const RPC_PASSWORD: &str = "p71regtest";

fn rpc_addr() -> String {
    std::env::var("PUZZLE71_REGTEST_RPC").unwrap_or_else(|_| "127.0.0.1:18443".to_string())
}

// ---------------------------------------------------------------------------------------------
// Minimal JSON-RPC 1.0 client over a fresh TcpStream per call (no new crate: HTTP/1.1 framing,
// Basic-Auth, and base64 are all hand-rolled below).
// ---------------------------------------------------------------------------------------------

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

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have even length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte pair"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Calls `method` with `params` against bitcoind's JSON-RPC endpoint. `wallet` selects the
/// `/wallet/<name>` path bitcoind's multi-wallet dispatch requires for wallet-scoped RPCs;
/// `None` calls a node-level RPC at `/`. Returns `Err` for a JSON-RPC-level error response
/// (`error` field non-null); panics only for a transport/framing failure, since that always
/// means the harness itself is broken, not something a caller should recover from.
fn try_rpc(wallet: Option<&str>, method: &str, params: Value) -> Result<Value, String> {
    let addr = rpc_addr();
    let mut stream = TcpStream::connect(&addr)
        .unwrap_or_else(|e| panic!("connect to bitcoind RPC at {addr}: {e}"));

    let path = match wallet {
        Some(name) => format!("/wallet/{name}"),
        None => "/".to_string(),
    };
    let body = json!({
        "jsonrpc": "1.0",
        "id": "puzzle71-claim-regtest",
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
        .expect("write RPC request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read RPC response until connection close");

    let status_line = response.lines().next().unwrap_or_default().to_string();
    let body_start = response
        .find("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed HTTP response ({status_line}): {response}"))
        + 4;
    let response_body = &response[body_start..];
    let parsed: Value = serde_json::from_str(response_body).unwrap_or_else(|e| {
        panic!("parse RPC response body ({status_line}): {e}\nbody: {response_body}")
    });

    match parsed.get("error") {
        Some(error) if !error.is_null() => Err(error.to_string()),
        _ => Ok(parsed["result"].clone()),
    }
}

fn rpc(wallet: Option<&str>, method: &str, params: Value) -> Value {
    try_rpc(wallet, method, params)
        .unwrap_or_else(|e| panic!("RPC {method} (wallet={wallet:?}) failed: {e}"))
}

fn ensure_wallet(name: &str) {
    match try_rpc(None, "createwallet", json!([name])) {
        Ok(_) => {}
        Err(e) if e.contains("already exists") => {
            match try_rpc(None, "loadwallet", json!([name])) {
                Ok(_) => {}
                Err(e2) if e2.contains("already loaded") => {}
                Err(e2) => {
                    panic!("loadwallet {name} failed after createwallet reported it exists: {e2}")
                }
            }
        }
        Err(e) => panic!("createwallet {name} failed: {e}"),
    }
}

fn mine_blocks(wallet: &str, n: u64) {
    let address = rpc(Some(wallet), "getnewaddress", json!(["", "bech32"]))
        .as_str()
        .expect("getnewaddress returns a string")
        .to_string();
    rpc(None, "generatetoaddress", json!([n, address]));
}

// ---------------------------------------------------------------------------------------------
// Claim-flow specific helpers.
// ---------------------------------------------------------------------------------------------

/// Derives the compressed-pubkey HASH160 for a test scalar using only `bitcoin`/`secp256k1`
/// (the same primitives `ClaimKey::from_u128` uses internally), independently of `ClaimKey`.
fn hash160_for_scalar(scalar: u128) -> [u8; 20] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&scalar.to_be_bytes());
    let secret = SecretKey::from_slice(&bytes).expect("test scalar must be a valid secp256k1 key");
    let secp = Secp256k1::signing_only();
    let pubkey = secret.public_key(&secp);
    bitcoin::PublicKey::new(pubkey)
        .pubkey_hash()
        .to_byte_array()
}

/// One scanned, unspent output of `address` in the current UTXO set, as reported by
/// `scantxoutset` (confirmed UTXOs only — it scans chainstate, not the mempool).
struct ScannedUtxo {
    outpoint: OutPoint,
    amount_sat: u64,
}

fn scan_utxos(address: &Address) -> Vec<ScannedUtxo> {
    let descriptor = format!("addr({address})");
    let result = rpc(None, "scantxoutset", json!(["start", [descriptor]]));
    let unspents = result["unspents"]
        .as_array()
        .expect("scantxoutset result has 'unspents'");
    unspents
        .iter()
        .map(|u| {
            let txid = u["txid"]
                .as_str()
                .expect("unspent has 'txid'")
                .parse::<Txid>()
                .expect("valid txid hex");
            let vout = u["vout"].as_u64().expect("unspent has 'vout'") as u32;
            let amount_btc = u["amount"].as_f64().expect("unspent has 'amount'");
            let amount_sat = (amount_btc * 100_000_000.0).round() as u64;
            ScannedUtxo {
                outpoint: OutPoint { txid, vout },
                amount_sat,
            }
        })
        .collect()
}

/// Fetches the raw transaction for `outpoint.txid` (requires bitcoind's `-txindex=1`) and
/// independently verifies it into a `VerifiedPrevout` via the real `verify_prevout` — the exact
/// same function the offline claim pipeline itself uses, not a shortcut.
fn fetch_verified_prevout(
    outpoint: OutPoint,
    expected_script: &bitcoin::Script,
) -> VerifiedPrevout {
    let raw_hex = rpc(
        None,
        "getrawtransaction",
        json!([outpoint.txid.to_string(), false]),
    )
    .as_str()
    .expect("getrawtransaction returns hex")
    .to_string();
    let raw = hex_decode(&raw_hex);
    verify_prevout(outpoint, &raw, expected_script)
        .expect("a real, chain-confirmed prevout must pass verify_prevout")
}

/// Sends three economic amounts (1.0, 0.1, 0.01 BTC) and two dust amounts (1000, 5000 sat) to
/// `address` from `wallet`, then mines one block so `scantxoutset` (which only sees confirmed
/// UTXOs) picks them up.
fn fund_address_with_economic_and_dust_utxos(wallet: &str, address: &Address) {
    for amount_btc in ["1.0", "0.1", "0.01"] {
        rpc(
            Some(wallet),
            "sendtoaddress",
            json!([address.to_string(), amount_btc]),
        );
    }
    for amount_btc in ["0.00001", "0.00005"] {
        rpc(
            Some(wallet),
            "sendtoaddress",
            json!([address.to_string(), amount_btc]),
        );
    }
    mine_blocks(wallet, 1);
}

/// Sets up a funder/dest wallet pair (idempotent across repeated runs against the same node),
/// mines a fresh coinbase-maturity chain, and funds a fresh puzzle P2PKH address (derived from
/// `scalar`, unique per test so parallel/sequential test runs never contend over UTXOs) with
/// three economic and two dust outputs. Returns the puzzle address, its scriptPubkey, and the
/// matching `ClaimKey`.
fn setup(scalar: u128) -> (Address, bitcoin::ScriptBuf, ClaimKey) {
    ensure_wallet("funder");
    ensure_wallet("dest");
    mine_blocks("funder", 101);

    let hash160 = hash160_for_scalar(scalar);
    let puzzle_script = p2pkh_script_for_hash160(hash160);
    let puzzle_address = Address::p2pkh(
        bitcoin::PubkeyHash::from_byte_array(hash160),
        Network::Regtest,
    );

    fund_address_with_economic_and_dust_utxos("funder", &puzzle_address);

    let key = ClaimKey::from_u128(scalar, hash160)
        .expect("test scalar must derive a key matching its own hash160");

    (puzzle_address, puzzle_script, key)
}

/// Runs the full claim flow for `scalar` against a destination of `dest_address_type`
/// ("bech32" or "bech32m"), asserting every acceptance criterion from
/// `phase1-claim-core.md`'s regtest test plan.
fn run_successful_claim(scalar: u128, dest_address_type: &str) {
    let (puzzle_address, puzzle_script, key) = setup(scalar);

    let prevouts: Vec<VerifiedPrevout> = scan_utxos(&puzzle_address)
        .into_iter()
        .map(|u| fetch_verified_prevout(u.outpoint, &puzzle_script))
        .collect();
    assert_eq!(
        prevouts.len(),
        5,
        "expected 3 economic + 2 dust UTXOs on the puzzle address"
    );

    let dest_address_str = rpc(
        Some("dest"),
        "getnewaddress",
        json!(["", dest_address_type]),
    )
    .as_str()
    .expect("getnewaddress returns a string")
    .to_string();
    let destination = parse_destination(&dest_address_str, Network::Regtest, &puzzle_script)
        .expect("a freshly minted wallet address must be a valid, non-puzzle destination");

    let fee_rate_sat_vb = 2_000u64;
    let claim = build_signed_claim(&key, &prevouts, &destination, fee_rate_sat_vb)
        .expect("building the claim against real, verified regtest prevouts must succeed");
    let summary = claim.summary().clone();

    assert_eq!(
        summary.input_count, 3,
        "only the three economic UTXOs must be spent"
    );
    assert_eq!(
        summary.total_input_sat, 111_000_000,
        "1.0 + 0.1 + 0.01 BTC = 1.11 BTC"
    );
    assert_eq!(summary.excluded_dust_count, 2);
    assert_eq!(summary.excluded_dust_sat, 1_000 + 5_000);
    assert_eq!(
        summary.output_sat,
        summary.total_input_sat - summary.fee_sat
    );
    assert!(
        summary.effective_fee_rate_sat_vb >= fee_rate_sat_vb as f64,
        "effective fee rate {} must be at least the requested {fee_rate_sat_vb} sat/vB",
        summary.effective_fee_rate_sat_vb
    );

    let raw_hex = hex_encode(claim.raw_tx_bytes_for_submission());

    let mempool_check = rpc(None, "testmempoolaccept", json!([[raw_hex.clone()]]));
    let first = mempool_check
        .as_array()
        .and_then(|a| a.first())
        .expect("testmempoolaccept returns one result");
    assert_eq!(
        first["allowed"].as_bool(),
        Some(true),
        "testmempoolaccept must allow the built claim: {first}"
    );

    // Broadcasting is intentionally only ever done here, in the regtest test — never from
    // product code in `src/claim/` (see phase1-claim-core.md "Verbote").
    let sent_txid = rpc(None, "sendrawtransaction", json!([raw_hex]))
        .as_str()
        .expect("sendrawtransaction returns the txid")
        .to_string();
    assert_eq!(
        sent_txid, summary.txid,
        "broadcast txid must match the independently verified summary"
    );

    mine_blocks("funder", 1);

    // The destination must have received exactly summary.output_sat, confirmed on-chain.
    let dest_utxos = scan_utxos(&destination);
    let received = dest_utxos
        .iter()
        .find(|u| u.outpoint.txid.to_string() == summary.txid)
        .unwrap_or_else(|| panic!("destination must show the claim txid as an unspent output"));
    assert_eq!(received.amount_sat, summary.output_sat);

    // The two dust UTXOs on the puzzle address must remain untouched.
    let remaining_puzzle_utxos = scan_utxos(&puzzle_address);
    assert_eq!(
        remaining_puzzle_utxos.len(),
        2,
        "only the two dust UTXOs must remain unspent on the puzzle address"
    );

    // The claim transaction must be confirmed (not just broadcast).
    let verbose = rpc(None, "getrawtransaction", json!([summary.txid, true]));
    let confirmations = verbose["confirmations"].as_u64().unwrap_or(0);
    assert!(
        confirmations >= 1,
        "claim transaction must have at least 1 confirmation"
    );
}

#[test]
#[ignore = "needs bitcoind regtest, run scripts/regtest-up.sh"]
fn claims_economic_utxos_to_a_bech32_p2wpkh_destination() {
    run_successful_claim(0x82A7F3, "bech32");
}

#[test]
#[ignore = "needs bitcoind regtest, run scripts/regtest-up.sh"]
fn claims_economic_utxos_to_a_bech32m_p2tr_destination() {
    run_successful_claim(0x82A7F4, "bech32m");
}

#[test]
#[ignore = "needs bitcoind regtest, run scripts/regtest-up.sh"]
fn refuses_to_build_and_therefore_never_sends_when_a_prevout_is_tampered() {
    let (puzzle_address, puzzle_script, key) = setup(0x82A7F5);

    let scanned = scan_utxos(&puzzle_address);
    assert_eq!(
        scanned.len(),
        5,
        "expected 3 economic + 2 dust UTXOs on the puzzle address"
    );

    let prevouts: Vec<VerifiedPrevout> = scanned
        .into_iter()
        .map(|u| fetch_verified_prevout(u.outpoint, &puzzle_script))
        .collect();

    // Tamper with one already-verified prevout's recorded amount. `build_signed_claim` only
    // ever sees `VerifiedPrevout`s that came out of `verify_prevout`, so to exercise the
    // "manipulated raw bytes" rejection path end-to-end here we re-run `verify_prevout` with a
    // one-byte-tampered copy of the *real* raw transaction and confirm it is rejected before
    // ever reaching the builder or a `sendrawtransaction` call.
    let outpoint = prevouts[0].outpoint;
    let raw_hex = rpc(
        None,
        "getrawtransaction",
        json!([outpoint.txid.to_string(), false]),
    )
    .as_str()
    .expect("getrawtransaction returns hex")
    .to_string();
    let mut raw = hex_decode(&raw_hex);
    // Flip the low byte of the funding transaction's own version field — guaranteed to change
    // the computed txid without accidentally producing an undecodable transaction.
    raw[0] ^= 0xFF;

    let tampered = verify_prevout(outpoint, &raw, &puzzle_script);
    assert_eq!(
        tampered.unwrap_err(),
        puzzle71_solver::claim::ClaimError::TxidMismatch
    );

    // The untampered prevouts still build fine — proving the rejection above is specific to the
    // tampered bytes, not a broken test fixture — but nothing here calls sendrawtransaction.
    let dest_address_str = rpc(Some("dest"), "getnewaddress", json!(["", "bech32"]))
        .as_str()
        .expect("getnewaddress returns a string")
        .to_string();
    let destination = parse_destination(&dest_address_str, Network::Regtest, &puzzle_script)
        .expect("a freshly minted wallet address must be a valid, non-puzzle destination");
    let claim = build_signed_claim(&key, &prevouts, &destination, 2_000)
        .expect("untampered, real prevouts must still build a valid claim");
    let _ = claim; // built, but intentionally never broadcast in this test

    // Nothing from this test was ever sent: the mempool must be empty, and all 5 UTXOs
    // (3 economic + 2 dust) must still sit unspent on the puzzle address.
    let mempool = rpc(None, "getrawmempool", json!([]));
    let mempool_entries = mempool.as_array().expect("getrawmempool returns an array");
    assert!(
        mempool_entries.is_empty(),
        "mempool must be empty: nothing here was ever sent"
    );

    let remaining = scan_utxos(&puzzle_address);
    assert_eq!(
        remaining.len(),
        5,
        "all 5 UTXOs must remain unspent since nothing was sent"
    );
}
