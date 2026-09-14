//! Dual-source Esplora UTXO fetch with raw-transaction verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use bitcoin::hex::FromHex;
use bitcoin::{OutPoint, Txid};
use serde::Deserialize;

use crate::claim::error::ClaimError;
use crate::claim::memory::secure_zero;
use crate::claim::net::allowlist::Method;
use crate::claim::net::error::NetError;
use crate::claim::net::http::Transport;
use crate::claim::prevout::{VerifiedPrevout, p2pkh_script_for_hash160, verify_prevout};
use crate::puzzle_config::{TARGET_ADDRESS, TARGET_HASH160};

const BASES: [&str; 2] = ["https://mempool.space", "https://blockstream.info"];
const TIMEOUT_SECS: u64 = 30;

/// Independently verified confirmed previous outputs plus a count of unconfirmed UTXOs seen.
#[derive(Clone, Debug)]
pub struct UtxoSnapshot {
    pub prevouts: Vec<VerifiedPrevout>,
    pub unconfirmed_count: usize,
}

/// Failure to fetch or verify previous outputs from the two Esplora sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimFetchError {
    Net(NetError),
    Claim(ClaimError),
}

impl fmt::Display for ClaimFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimFetchError::Net(err) => write!(f, "{err}"),
            ClaimFetchError::Claim(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ClaimFetchError {}

impl From<NetError> for ClaimFetchError {
    fn from(value: NetError) -> Self {
        ClaimFetchError::Net(value)
    }
}

impl From<ClaimError> for ClaimFetchError {
    fn from(value: ClaimError) -> Self {
        ClaimFetchError::Claim(value)
    }
}

/// Source of independently verified previous outputs.
pub trait UtxoSource {
    fn fetch_verified_prevouts(&self) -> Result<UtxoSnapshot, ClaimFetchError>;
}

/// Fetches the puzzle address's UTXOs from mempool.space and blockstream.info, requires the
/// confirmed sets to agree, then loads each unique previous transaction and verifies it.
pub struct EsploraUtxoSource<T: Transport> {
    transport: T,
}

impl<T: Transport> EsploraUtxoSource<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    fn get(&self, url: &str) -> Result<crate::claim::net::http::HttpResponse, NetError> {
        self.transport.execute(Method::Get, url, None, TIMEOUT_SECS)
    }

    fn fetch_utxo_list(&self, base: &str) -> Result<Vec<EsploraUtxo>, NetError> {
        let url = format!("{base}/api/address/{TARGET_ADDRESS}/utxo");
        let response = self.get(&url)?;
        if response.status != 200 {
            return Err(NetError::HttpStatus(response.status));
        }
        serde_json::from_str(&response.body).map_err(|_| NetError::BadResponse)
    }

    fn fetch_raw_tx(&self, base: &str, txid: &str) -> Result<Vec<u8>, ClaimFetchError> {
        if !crate::claim::net::allowlist::is_64_lower_hex(txid) {
            return Err(NetError::BadResponse.into());
        }
        let url = format!("{base}/api/tx/{txid}/hex");
        let response = self.get(&url)?;
        if response.status != 200 {
            return Err(NetError::HttpStatus(response.status).into());
        }
        let mut body = response.body;
        let trimmed = body.trim();
        let bytes = Vec::<u8>::from_hex(trimmed).map_err(|_| ClaimError::PrevTxDecode)?;
        let mut body_bytes = std::mem::take(&mut body).into_bytes();
        secure_zero(&mut body_bytes);
        Ok(bytes)
    }

    fn load_raw_tx(&self, txid: &str) -> Result<Vec<u8>, ClaimFetchError> {
        match self.fetch_and_require(BASES[0], txid) {
            Ok(bytes) => Ok(bytes),
            Err(_) => self.fetch_and_require(BASES[1], txid),
        }
    }

    fn fetch_and_require(&self, base: &str, txid: &str) -> Result<Vec<u8>, ClaimFetchError> {
        let mut bytes = self.fetch_raw_tx(base, txid)?;
        match verify_txid_of_raw(&bytes, txid) {
            Ok(()) => Ok(bytes),
            Err(err) => {
                secure_zero(&mut bytes);
                Err(err.into())
            }
        }
    }
}

fn verify_txid_of_raw(raw: &[u8], expected_txid: &str) -> Result<(), ClaimError> {
    let expected = Txid::from_str(expected_txid).map_err(|_| ClaimError::PrevTxDecode)?;
    // `verify_prevout` re-checks this per outpoint; a cheap pre-check here decides whether to
    // fall back to the second source before we iterate vouts.
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(raw).map_err(|_| ClaimError::PrevTxDecode)?;
    if tx.compute_txid() != expected {
        return Err(ClaimError::TxidMismatch);
    }
    Ok(())
}

impl<T: Transport> UtxoSource for EsploraUtxoSource<T> {
    fn fetch_verified_prevouts(&self) -> Result<UtxoSnapshot, ClaimFetchError> {
        let list_a = self.fetch_utxo_list(BASES[0])?;
        let list_b = self.fetch_utxo_list(BASES[1])?;

        let (set_a, unconfirmed_a) = unique_confirmed(&list_a)?;
        let (set_b, _unconfirmed_b) = unique_confirmed(&list_b)?;
        if set_a != set_b {
            return Err(NetError::SourcesDisagree.into());
        }

        let script = p2pkh_script_for_hash160(TARGET_HASH160);
        let unique_txids: BTreeSet<String> =
            set_a.iter().map(|(txid, _, _)| txid.clone()).collect();
        let mut raw_by_txid: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for txid in unique_txids {
            let raw = self.load_raw_tx(&txid)?;
            raw_by_txid.insert(txid, raw);
        }

        let mut prevouts = Vec::with_capacity(set_a.len());
        for (txid_key, vout, value) in &set_a {
            let txid = Txid::from_str(txid_key).map_err(|_| NetError::BadResponse)?;
            let outpoint = OutPoint { txid, vout: *vout };
            let raw = raw_by_txid.get(txid_key).ok_or(NetError::BadResponse)?;
            let verified = verify_prevout(outpoint, raw, script.as_script())?;
            if verified.txout.value.to_sat() != *value {
                return Err(NetError::SourceValueMismatch.into());
            }
            prevouts.push(verified);
        }

        for raw in raw_by_txid.values_mut() {
            secure_zero(raw);
        }

        Ok(UtxoSnapshot {
            prevouts,
            unconfirmed_count: unconfirmed_a,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: EsploraStatus,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct EsploraStatus {
    confirmed: Option<bool>,
}

fn unique_confirmed(
    list: &[EsploraUtxo],
) -> Result<(BTreeSet<(String, u32, u64)>, usize), NetError> {
    let mut by_outpoint: BTreeMap<(String, u32), u64> = BTreeMap::new();
    let mut unconfirmed = 0usize;
    for utxo in list {
        if utxo.status.confirmed != Some(true) {
            unconfirmed += 1;
            continue;
        }
        let key = (utxo.txid.to_ascii_lowercase(), utxo.vout);
        if let Some(previous) = by_outpoint.get(&key) {
            if *previous != utxo.value {
                return Err(NetError::SourcesDisagree);
            }
        } else {
            by_outpoint.insert(key, utxo.value);
        }
    }
    let confirmed = by_outpoint
        .into_iter()
        .map(|((txid, vout), value)| (txid, vout, value))
        .collect();
    Ok((confirmed, unconfirmed))
}

#[cfg(test)]
mod tests {
    use super::{BASES, ClaimFetchError, EsploraUtxoSource, UtxoSource};
    use crate::claim::error::ClaimError;
    use crate::claim::net::allowlist::Method;
    use crate::claim::net::error::NetError;
    use crate::claim::net::http::{CurlTransport, HttpResponse, Transport};
    use crate::claim::prevout::p2pkh_script_for_hash160;
    use crate::claim::service::MIN_EXPECTED_ECONOMIC_TOTAL_SAT;
    use crate::puzzle_config::{TARGET_ADDRESS, TARGET_HASH160};
    use bitcoin::hex::DisplayHex;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        consensus, transaction,
    };
    use std::collections::HashMap;

    struct FakeTransport {
        routes: HashMap<String, Result<HttpResponse, NetError>>,
    }

    impl FakeTransport {
        fn new(routes: HashMap<String, Result<HttpResponse, NetError>>) -> Self {
            Self { routes }
        }
    }

    impl Transport for FakeTransport {
        fn execute(
            &self,
            _method: Method,
            url: &str,
            _json_body: Option<&str>,
            _timeout_secs: u64,
        ) -> Result<HttpResponse, NetError> {
            self.routes
                .get(url)
                .cloned()
                .unwrap_or(Err(NetError::HttpStatus(404)))
        }
    }

    fn funding(value: u64) -> (Transaction, String, String) {
        let script = p2pkh_script_for_hash160(TARGET_HASH160);
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            }],
        };
        let raw = consensus::serialize(&tx);
        let txid = tx.compute_txid().to_string();
        let hex = raw.to_lower_hex_string();
        (tx, txid, hex)
    }

    fn utxo_json(entries: &[(&str, u32, u64, bool)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(txid, vout, value, confirmed)| {
                format!(
                    r#"{{"txid":"{txid}","vout":{vout},"value":{value},"status":{{"confirmed":{confirmed}}}}}"#
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    fn ok(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.to_string(),
        }
    }

    fn route_ok(body: &str) -> Result<HttpResponse, NetError> {
        Ok(ok(body))
    }

    fn route_status(status: u16, body: &str) -> Result<HttpResponse, NetError> {
        Ok(HttpResponse {
            status,
            body: body.to_string(),
        })
    }

    fn utxo_url(base: &str) -> String {
        format!("{base}/api/address/{TARGET_ADDRESS}/utxo")
    }

    fn hex_url(base: &str, txid: &str) -> String {
        format!("{base}/api/tx/{txid}/hex")
    }

    #[test]
    fn success_fetches_both_sources_and_verifies_prevouts() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        for base in BASES {
            routes.insert(utxo_url(base), route_ok(&list));
            routes.insert(hex_url(base, &txid), route_ok(&hex));
        }
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source.fetch_verified_prevouts().expect("agreeing sources");
        assert_eq!(snapshot.prevouts.len(), 1);
        assert_eq!(snapshot.prevouts[0].txout.value.to_sat(), 100_000);
        assert_eq!(snapshot.unconfirmed_count, 0);
    }

    #[test]
    fn sources_disagree_on_confirmed_set() {
        let (_tx, txid, hex) = funding(100_000);
        let list_a = utxo_json(&[(&txid, 0, 100_000, true)]);
        let list_b = utxo_json(&[(&txid, 0, 100_001, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list_a));
        routes.insert(utxo_url(BASES[1]), route_ok(&list_b));
        routes.insert(hex_url(BASES[0], &txid), route_ok(&hex));
        routes.insert(hex_url(BASES[1], &txid), route_ok(&hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("disagree");
        assert_eq!(err, ClaimFetchError::Net(NetError::SourcesDisagree));
    }

    #[test]
    fn falls_back_to_source_two_when_source_one_raw_tx_is_manipulated() {
        let (_tx, txid, hex) = funding(100_000);
        let (_other, _other_txid, other_hex) = funding(50_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list));
        routes.insert(utxo_url(BASES[1]), route_ok(&list));
        routes.insert(hex_url(BASES[0], &txid), route_ok(&other_hex));
        routes.insert(hex_url(BASES[1], &txid), route_ok(&hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source
            .fetch_verified_prevouts()
            .expect("source 2 must rescue");
        assert_eq!(snapshot.prevouts[0].txout.value.to_sat(), 100_000);
    }

    #[test]
    fn both_raw_txs_manipulated_yields_txid_mismatch() {
        let (_tx, txid, _hex) = funding(100_000);
        let (_other, _other_txid, other_hex) = funding(50_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list));
        routes.insert(utxo_url(BASES[1]), route_ok(&list));
        routes.insert(hex_url(BASES[0], &txid), route_ok(&other_hex));
        routes.insert(hex_url(BASES[1], &txid), route_ok(&other_hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("both bad");
        assert_eq!(err, ClaimFetchError::Claim(ClaimError::TxidMismatch));
    }

    #[test]
    fn api_value_mismatch_against_raw_tx_is_source_value_mismatch() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 99_999, true)]);
        let mut routes = HashMap::new();
        for base in BASES {
            routes.insert(utxo_url(base), route_ok(&list));
            routes.insert(hex_url(base, &txid), route_ok(&hex));
        }
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("value lie");
        assert_eq!(err, ClaimFetchError::Net(NetError::SourceValueMismatch));
    }

    #[test]
    fn unconfirmed_utxos_are_excluded_and_counted() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true), (&txid, 1, 1, false)]);
        let mut routes = HashMap::new();
        for base in BASES {
            routes.insert(utxo_url(base), route_ok(&list));
            routes.insert(hex_url(base, &txid), route_ok(&hex));
        }
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source.fetch_verified_prevouts().expect("confirmed only");
        assert_eq!(snapshot.prevouts.len(), 1);
        assert_eq!(snapshot.unconfirmed_count, 1);
    }

    #[test]
    fn http_500_on_utxo_list_is_http_status() {
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_status(500, "nope"));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("500");
        assert_eq!(err, ClaimFetchError::Net(NetError::HttpStatus(500)));
    }

    #[test]
    fn raw_tx_http_429_on_source_one_falls_back_to_source_two() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list));
        routes.insert(utxo_url(BASES[1]), route_ok(&list));
        routes.insert(hex_url(BASES[0], &txid), route_status(429, "slow"));
        routes.insert(hex_url(BASES[1], &txid), route_ok(&hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source.fetch_verified_prevouts().expect("429 fallback");
        assert_eq!(snapshot.prevouts.len(), 1);
        assert_eq!(snapshot.prevouts[0].txout.value.to_sat(), 100_000);
    }

    #[test]
    fn raw_tx_transport_error_on_source_one_falls_back_to_source_two() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list));
        routes.insert(utxo_url(BASES[1]), route_ok(&list));
        routes.insert(
            hex_url(BASES[0], &txid),
            Err(NetError::Transport { exit_code: Some(7) }),
        );
        routes.insert(hex_url(BASES[1], &txid), route_ok(&hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source
            .fetch_verified_prevouts()
            .expect("transport fallback");
        assert_eq!(snapshot.prevouts.len(), 1);
    }

    #[test]
    fn raw_tx_http_500_on_both_sources_is_http_status() {
        let (_tx, txid, _hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list));
        routes.insert(utxo_url(BASES[1]), route_ok(&list));
        routes.insert(hex_url(BASES[0], &txid), route_status(500, "a"));
        routes.insert(hex_url(BASES[1], &txid), route_status(500, "b"));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("both 500");
        assert_eq!(err, ClaimFetchError::Net(NetError::HttpStatus(500)));
    }

    #[test]
    fn duplicate_list_entry_on_source_one_collapses_to_one_prevout() {
        let (_tx, txid, hex) = funding(100_000);
        let list_a = utxo_json(&[(&txid, 0, 100_000, true), (&txid, 0, 100_000, true)]);
        let list_b = utxo_json(&[(&txid, 0, 100_000, true)]);
        let mut routes = HashMap::new();
        routes.insert(utxo_url(BASES[0]), route_ok(&list_a));
        routes.insert(utxo_url(BASES[1]), route_ok(&list_b));
        routes.insert(hex_url(BASES[0], &txid), route_ok(&hex));
        routes.insert(hex_url(BASES[1], &txid), route_ok(&hex));
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source.fetch_verified_prevouts().expect("deduped");
        assert_eq!(snapshot.prevouts.len(), 1);
        assert_eq!(snapshot.prevouts[0].txout.value.to_sat(), 100_000);
    }

    #[test]
    fn same_outpoint_with_conflicting_values_in_one_source_is_sources_disagree() {
        let (_tx, txid, hex) = funding(100_000);
        let list = utxo_json(&[(&txid, 0, 100_000, true), (&txid, 0, 99_000, true)]);
        let mut routes = HashMap::new();
        for base in BASES {
            routes.insert(utxo_url(base), route_ok(&list));
            routes.insert(hex_url(base, &txid), route_ok(&hex));
        }
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let err = source.fetch_verified_prevouts().expect_err("conflict");
        assert_eq!(err, ClaimFetchError::Net(NetError::SourcesDisagree));
    }

    fn funding_two(v0: u64, v1: u64) -> (Transaction, String, String) {
        let script = p2pkh_script_for_hash160(TARGET_HASH160);
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(v0),
                    script_pubkey: script.clone(),
                },
                TxOut {
                    value: Amount::from_sat(v1),
                    script_pubkey: script,
                },
            ],
        };
        let raw = consensus::serialize(&tx);
        let txid = tx.compute_txid().to_string();
        let hex = raw.to_lower_hex_string();
        (tx, txid, hex)
    }

    #[test]
    fn two_confirmed_vouts_of_the_same_txid_both_land_in_prevouts() {
        let (_tx, txid, hex) = funding_two(80_000, 20_000);
        let list = utxo_json(&[(&txid, 0, 80_000, true), (&txid, 1, 20_000, true)]);
        let mut routes = HashMap::new();
        for base in BASES {
            routes.insert(utxo_url(base), route_ok(&list));
            routes.insert(hex_url(base, &txid), route_ok(&hex));
        }
        let source = EsploraUtxoSource::new(FakeTransport::new(routes));
        let snapshot = source.fetch_verified_prevouts().expect("both vouts");
        assert_eq!(snapshot.prevouts.len(), 2);
        let values: Vec<u64> = snapshot
            .prevouts
            .iter()
            .map(|p| p.txout.value.to_sat())
            .collect();
        assert!(values.contains(&80_000), "{values:?}");
        assert!(values.contains(&20_000), "{values:?}");
        assert_eq!(
            snapshot.prevouts[0].outpoint.txid,
            snapshot.prevouts[1].outpoint.txid
        );
        assert_ne!(
            snapshot.prevouts[0].outpoint.vout,
            snapshot.prevouts[1].outpoint.vout
        );
    }

    #[test]
    #[ignore = "live network"]
    fn live_fetch_verified_prevouts_from_both_sources() {
        let source = EsploraUtxoSource::new(CurlTransport);
        let snapshot = source
            .fetch_verified_prevouts()
            .expect("live dual-source fetch");
        assert!(
            !snapshot.prevouts.is_empty(),
            "expected at least one confirmed prevout"
        );
        let expected_script = p2pkh_script_for_hash160(TARGET_HASH160);
        let mut total_sat = 0u64;
        for prevout in &snapshot.prevouts {
            assert_eq!(
                prevout.txout.script_pubkey.as_script(),
                expected_script.as_script()
            );
            total_sat += prevout.txout.value.to_sat();
        }
        assert!(
            total_sat >= MIN_EXPECTED_ECONOMIC_TOTAL_SAT,
            "economic total {total_sat} sat is below {MIN_EXPECTED_ECONOMIC_TOTAL_SAT}"
        );
        println!(
            "confirmed_count={} total_sat={} unconfirmed_count={}",
            snapshot.prevouts.len(),
            total_sat,
            snapshot.unconfirmed_count
        );
    }
}
