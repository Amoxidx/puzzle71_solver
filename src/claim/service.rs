//! Owner-driven claim flow: address, verified preview, explicit submission, and status.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::ops::RangeInclusive;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::claim::builder::build_signed_claim;
use crate::claim::destination::parse_destination;
use crate::claim::error::ClaimError;
use crate::claim::key::ClaimKey;
use crate::claim::net::error::NetError;
use crate::claim::net::esplora::{ClaimFetchError, UtxoSource};
use crate::claim::net::slipstream::{SubmitError, SubmitReceipt, Submitter, TxStatus};
use crate::claim::policy::{DEFAULT_FEE_RATE_SAT_VB, MAX_FEE_RATE_SAT_VB};
use crate::claim::prevout::p2pkh_script_for_hash160;
use crate::claim::verify::ClaimSummary;
use crate::puzzle_config::{RANGE_MAX, RANGE_MIN, TARGET_HASH160};

/// Confirmed economic inputs must total at least this many satoshis (7.10 BTC).
pub const MIN_EXPECTED_ECONOMIC_TOTAL_SAT: u64 = 710_000_000;
/// Consecutive `NotFound` polls in `Submitted` before the claim is treated as missing
/// (at a 60-second poll interval this is about 30 minutes).
pub const MAX_NOT_FOUND_POLLS: u32 = 30;

static TEMP_NAME_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_temp_name_seq() -> u64 {
    TEMP_NAME_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Loads the puzzle private key for signing.
pub trait KeySource {
    fn load(&self) -> Result<ClaimKey, ClaimError>;
}

/// Production key source: a `FOUND_KEY.txt`-style file at `path`.
pub struct FoundKeyFile {
    path: PathBuf,
}

impl FoundKeyFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeySource for FoundKeyFile {
    fn load(&self) -> Result<ClaimKey, ClaimError> {
        ClaimKey::load_found_key_file(&self.path, TARGET_HASH160, RANGE_MIN..=RANGE_MAX)
    }
}

/// Scan of `FOUND_KEY*.txt` files: the first loadable match, plus unloadable names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKeyScan {
    /// First file (sorted by path) that loaded as a matching key.
    pub found: Option<PathBuf>,
    /// Files that existed but could not be loaded, in sorted path order.
    /// Each pair is `(file_name, reason)` — no directory path and no key material.
    pub unloadable: Vec<(String, ClaimError)>,
}

/// First `FOUND_KEY*.txt` in `dir` (sorted by path) that loads as a key matching
/// `expected_hash160` inside `range`. Permission, format, and mismatch failures skip the file
/// and are recorded in [`FoundKeyScan::unloadable`].
pub fn find_verified_found_key(
    dir: &Path,
    expected_hash160: [u8; 20],
    range: RangeInclusive<u128>,
) -> FoundKeyScan {
    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("FOUND_KEY") && name.ends_with(".txt"))
            })
            .collect(),
        Err(_) => {
            return FoundKeyScan {
                found: None,
                unloadable: Vec::new(),
            };
        }
    };
    paths.sort();
    let mut unloadable = Vec::new();
    for path in paths {
        match ClaimKey::load_found_key_file(&path, expected_hash160, range.clone()) {
            Ok(_) => {
                return FoundKeyScan {
                    found: Some(path),
                    unloadable,
                };
            }
            Err(reason) => {
                let file_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("FOUND_KEY.txt")
                    .to_string();
                unloadable.push((file_name, reason));
            }
        }
    }
    FoundKeyScan {
        found: None,
        unloadable,
    }
}

/// Public claim state; authorization never depends on an out-of-band code.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub enum ClaimState {
    Idle,
    AwaitingOwner,
    Prepared {
        summary: ClaimSummary,
    },
    Submitted {
        txid: String,
        submitted_at_unix: u64,
    },
    Confirmed {
        txid: String,
        block_height: u64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    NotPrepared,
    DestinationMismatch,
    PreparedTxidMismatch,
    AlreadySubmittedDifferent { txid: String },
    SummaryChanged,
    BalanceBelowExpected,
    FeeFloorTooHigh,
    InvalidState,
    SubmissionRejected,
    SubmissionUnknown,
    Storage,
    Claim(ClaimError),
    Fetch(ClaimFetchError),
    Net(NetError),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrepared => f.write_str("claim is not prepared"),
            Self::DestinationMismatch => f.write_str("destination does not match preview"),
            Self::PreparedTxidMismatch => f.write_str("transaction does not match preview"),
            Self::AlreadySubmittedDifferent { txid } => write!(f, "already submitted as {txid}"),
            Self::SummaryChanged => f.write_str("claim summary changed"),
            Self::BalanceBelowExpected => f.write_str("balance below expected minimum"),
            Self::FeeFloorTooHigh => f.write_str("fee floor exceeds maximum"),
            Self::InvalidState => f.write_str("invalid state for this operation"),
            Self::SubmissionRejected => f.write_str("submission rejected"),
            Self::SubmissionUnknown => f.write_str("submission outcome unknown"),
            Self::Storage => f.write_str("marker storage failed"),
            Self::Claim(err) => write!(f, "{err}"),
            Self::Fetch(err) => write!(f, "{err}"),
            Self::Net(err) => write!(f, "{err}"),
        }
    }
}
impl std::error::Error for ServiceError {}
impl From<ClaimError> for ServiceError {
    fn from(value: ClaimError) -> Self {
        Self::Claim(value)
    }
}
impl From<ClaimFetchError> for ServiceError {
    fn from(value: ClaimFetchError) -> Self {
        Self::Fetch(value)
    }
}
impl From<NetError> for ServiceError {
    fn from(value: NetError) -> Self {
        Self::Net(value)
    }
}

enum Phase {
    Idle,
    AwaitingOwner {
        pending: Option<(String, u64)>,
    },
    Prepared {
        destination: String,
        fee_rate_sat_vb: u64,
        summary: ClaimSummary,
        pending: Option<(String, u64)>,
    },
    Submitted {
        txid: String,
        submitted_at_unix: u64,
        not_found_polls: u32,
    },
    Confirmed {
        txid: String,
        block_height: u64,
        submitted_at_unix: u64,
    },
    Failed {
        reason: String,
        pending: Option<(String, u64)>,
    },
}

/// A prepared transaction is an exact preview, not an authorization to send it.
/// Only `confirm(destination, prepared_txid)` can submit, after a fresh rebuild.
pub struct ClaimService<U: UtxoSource, S: Submitter, K: KeySource> {
    utxo: U,
    submitter: S,
    key_source: K,
    marker_path: PathBuf,
    phase: Phase,
    network: Network,
    submitted_destination: Option<String>,
    directory_sync: fn(&Path) -> std::io::Result<()>,
}

#[derive(Serialize, Deserialize)]
struct MarkerFile {
    txid: String,
    destination: String,
    fee_rate_sat_vb: u64,
    written_at_unix: u64,
    outcome: String,
}

impl<U: UtxoSource, S: Submitter, K: KeySource> ClaimService<U, S, K> {
    pub fn new(utxo: U, submitter: S, key_source: K, marker_path: PathBuf) -> Self {
        Self::new_for_network(utxo, submitter, key_source, marker_path, Network::Bitcoin)
    }

    /// The caller fixes the network at construction. HTTP requests cannot choose it.
    /// Production uses `new`; the isolated regtest rehearsal uses `Network::Regtest`.
    pub fn new_for_network(
        utxo: U,
        submitter: S,
        key_source: K,
        marker_path: PathBuf,
        network: Network,
    ) -> Self {
        let mut submitted_destination = None;
        let phase = match read_marker(&marker_path) {
            Ok(Some(marker)) if marker.outcome == "pending" => {
                submitted_destination = Some(marker.destination);
                Phase::Submitted {
                    txid: marker.txid,
                    submitted_at_unix: marker.written_at_unix,
                    not_found_polls: 0,
                }
            }
            Ok(_) => Phase::Idle,
            Err(_) => Phase::Failed {
                reason: "marker_unreadable".to_string(),
                pending: None,
            },
        };
        Self {
            utxo,
            submitter,
            key_source,
            marker_path,
            phase,
            network,
            submitted_destination,
            directory_sync: sync_directory,
        }
    }

    pub fn state(&self) -> ClaimState {
        match &self.phase {
            Phase::Idle => ClaimState::Idle,
            Phase::AwaitingOwner { .. } => ClaimState::AwaitingOwner,
            Phase::Prepared { summary, .. } => ClaimState::Prepared {
                summary: summary.clone(),
            },
            Phase::Submitted {
                txid,
                submitted_at_unix,
                ..
            } => ClaimState::Submitted {
                txid: txid.clone(),
                submitted_at_unix: *submitted_at_unix,
            },
            Phase::Confirmed {
                txid, block_height, ..
            } => ClaimState::Confirmed {
                txid: txid.clone(),
                block_height: *block_height,
            },
            Phase::Failed { reason, .. } => ClaimState::Failed {
                reason: reason.clone(),
            },
        }
    }

    pub fn on_verified_hit(&mut self) {
        if matches!(self.phase, Phase::Idle) {
            self.phase = Phase::AwaitingOwner { pending: None };
        }
    }

    pub fn prepare(&mut self, destination: &str) -> Result<ClaimSummary, ServiceError> {
        let pending = match &self.phase {
            Phase::AwaitingOwner { pending }
            | Phase::Prepared { pending, .. }
            | Phase::Failed { pending, .. } => pending.clone(),
            _ => return Err(ServiceError::InvalidState),
        };
        // Invalidate the previous preview before any fallible work, even a failed re-prepare.
        self.phase = Phase::AwaitingOwner {
            pending: pending.clone(),
        };
        let key = self.key_source.load()?;
        let puzzle_script = p2pkh_script_for_hash160(key.hash160());
        let address = parse_destination(destination, self.network, puzzle_script.as_script())?;
        let fee_rate = DEFAULT_FEE_RATE_SAT_VB.max(self.submitter.fee_floor_sat_vb()?);
        if fee_rate > MAX_FEE_RATE_SAT_VB {
            return Err(ServiceError::FeeFloorTooHigh);
        }
        let snapshot = self.utxo.fetch_verified_prevouts()?;
        let claim = build_signed_claim(&key, &snapshot.prevouts, &address, fee_rate)?;
        if claim.summary().total_input_sat < MIN_EXPECTED_ECONOMIC_TOTAL_SAT {
            return Err(ServiceError::BalanceBelowExpected);
        }
        let summary = claim.summary().clone();
        self.phase = Phase::Prepared {
            destination: address.to_string(),
            fee_rate_sat_vb: fee_rate,
            summary: summary.clone(),
            pending,
        };
        Ok(summary)
    }

    pub fn confirm(
        &mut self,
        destination: &str,
        prepared_txid: &str,
    ) -> Result<SubmitReceipt, ServiceError> {
        // Repeated clicks for an already submitted exact transaction return its receipt,
        // rather than signing or sending it again.
        if let Phase::Submitted { txid, .. } | Phase::Confirmed { txid, .. } = &self.phase {
            if txid != prepared_txid {
                return Err(ServiceError::NotPrepared);
            }
            let puzzle_script = p2pkh_script_for_hash160(TARGET_HASH160);
            let address = parse_destination(destination, self.network, puzzle_script.as_script())?;
            if self.submitted_destination.as_deref() != Some(address.to_string().as_str()) {
                return Err(ServiceError::DestinationMismatch);
            }
            return Ok(SubmitReceipt { txid: txid.clone() });
        }
        let (prepared_dest, prepared_rate, prepared_summary, pending) = match &self.phase {
            Phase::Prepared {
                destination,
                fee_rate_sat_vb,
                summary,
                pending,
            } => (
                destination.clone(),
                *fee_rate_sat_vb,
                summary.clone(),
                pending.clone(),
            ),
            _ => return Err(ServiceError::NotPrepared),
        };
        let puzzle_script = p2pkh_script_for_hash160(TARGET_HASH160);
        let address = parse_destination(destination, self.network, puzzle_script.as_script())?;
        if address.to_string() != prepared_dest {
            return Err(ServiceError::DestinationMismatch);
        }
        if prepared_txid != prepared_summary.txid {
            return Err(ServiceError::PreparedTxidMismatch);
        }

        let file_marker = read_marker(&self.marker_path)?;
        if let Some(marker) = &file_marker
            && marker.outcome == "pending"
            && marker.txid != prepared_summary.txid
        {
            return Err(ServiceError::AlreadySubmittedDifferent {
                txid: marker.txid.clone(),
            });
        }
        if let Some((txid, _)) = &pending
            && txid != &prepared_summary.txid
        {
            return Err(ServiceError::AlreadySubmittedDifferent { txid: txid.clone() });
        }
        let resubmitting = file_marker
            .as_ref()
            .is_some_and(|m| m.outcome == "pending" && m.txid == prepared_summary.txid)
            || pending
                .as_ref()
                .is_some_and(|(id, _)| id == &prepared_summary.txid);
        if self.submitter.fee_floor_sat_vb()? > prepared_rate {
            self.phase = Phase::AwaitingOwner { pending };
            return Err(ServiceError::SummaryChanged);
        }
        let key = self.key_source.load()?;
        let snapshot = self.utxo.fetch_verified_prevouts()?;
        let claim = build_signed_claim(&key, &snapshot.prevouts, &address, prepared_rate)?;
        if claim.summary().total_input_sat < MIN_EXPECTED_ECONOMIC_TOTAL_SAT {
            self.phase = Phase::AwaitingOwner { pending };
            return Err(ServiceError::BalanceBelowExpected);
        }
        if claim.summary().txid != prepared_summary.txid {
            self.phase = Phase::AwaitingOwner { pending };
            return Err(ServiceError::SummaryChanged);
        }
        let written_at = unix_secs();
        let marker = MarkerFile {
            txid: prepared_summary.txid.clone(),
            destination: prepared_dest.clone(),
            fee_rate_sat_vb: prepared_rate,
            written_at_unix: written_at,
            outcome: "pending".to_string(),
        };
        // Both file and containing directory must be durable before the first outbound byte.
        write_marker_with_sync(&self.marker_path, &marker, self.directory_sync)?;
        self.submitted_destination = Some(prepared_dest);
        match self.submitter.submit(&claim) {
            Ok(receipt) => {
                self.phase = Phase::Submitted {
                    txid: receipt.txid.clone(),
                    submitted_at_unix: written_at,
                    not_found_polls: 0,
                };
                Ok(receipt)
            }
            Err(SubmitError::Rejected(_)) if !resubmitting => {
                match self.submitter.status(&prepared_summary.txid) {
                    Ok(TxStatus::Pending) => {
                        self.phase = Phase::Submitted {
                            txid: prepared_summary.txid.clone(),
                            submitted_at_unix: written_at,
                            not_found_polls: 0,
                        };
                        Ok(SubmitReceipt {
                            txid: prepared_summary.txid,
                        })
                    }
                    Ok(TxStatus::Confirmed { block_height }) => {
                        self.phase = Phase::Confirmed {
                            txid: prepared_summary.txid.clone(),
                            block_height,
                            submitted_at_unix: written_at,
                        };
                        Ok(SubmitReceipt {
                            txid: prepared_summary.txid,
                        })
                    }
                    Ok(TxStatus::NotFound) => {
                        let mut rejected = marker;
                        rejected.outcome = "rejected".to_string();
                        // Failure to persist rejection leaves the safer pending guard in place.
                        if write_marker_with_sync(&self.marker_path, &rejected, self.directory_sync)
                            .is_err()
                        {
                            self.phase = Phase::Failed {
                                reason: "submission_unknown".to_string(),
                                pending: Some((prepared_summary.txid, written_at)),
                            };
                            return Err(ServiceError::SubmissionUnknown);
                        }
                        self.phase = Phase::Failed {
                            reason: "submission_rejected".to_string(),
                            pending: None,
                        };
                        Err(ServiceError::SubmissionRejected)
                    }
                    Err(_) => {
                        self.phase = Phase::Failed {
                            reason: "submission_unknown".to_string(),
                            pending: Some((prepared_summary.txid, written_at)),
                        };
                        Err(ServiceError::SubmissionUnknown)
                    }
                }
            }
            Err(SubmitError::Rejected(_) | SubmitError::Ambiguous(_)) => {
                self.phase = Phase::Failed {
                    reason: "submission_unknown".to_string(),
                    pending: Some((prepared_summary.txid, written_at)),
                };
                Err(ServiceError::SubmissionUnknown)
            }
        }
    }

    pub fn poll(&mut self) {
        let (txid, submitted_at, misses, from_submitted, from_confirmed) = match &self.phase {
            Phase::Submitted {
                txid,
                submitted_at_unix,
                not_found_polls,
            } => (
                txid.clone(),
                *submitted_at_unix,
                *not_found_polls,
                true,
                false,
            ),
            Phase::AwaitingOwner {
                pending: Some((id, at)),
            }
            | Phase::Prepared {
                pending: Some((id, at)),
                ..
            }
            | Phase::Failed {
                pending: Some((id, at)),
                ..
            } => (id.clone(), *at, 0, false, false),
            Phase::Confirmed {
                txid,
                submitted_at_unix,
                ..
            } => (txid.clone(), *submitted_at_unix, 0, false, true),
            _ => return,
        };
        match self.submitter.status(&txid) {
            Ok(TxStatus::Confirmed { block_height }) => {
                self.phase = Phase::Confirmed {
                    txid,
                    block_height,
                    submitted_at_unix: submitted_at,
                }
            }
            Ok(TxStatus::Pending) => {
                self.phase = Phase::Submitted {
                    txid,
                    submitted_at_unix: submitted_at,
                    not_found_polls: 0,
                }
            }
            Ok(TxStatus::NotFound) if from_confirmed || from_submitted => {
                let next = misses.saturating_add(1);
                self.phase = if next >= MAX_NOT_FOUND_POLLS {
                    Phase::Failed {
                        reason: "submission_not_found".to_string(),
                        pending: Some((txid, submitted_at)),
                    }
                } else {
                    Phase::Submitted {
                        txid,
                        submitted_at_unix: submitted_at,
                        not_found_polls: next,
                    }
                };
            }
            Ok(TxStatus::NotFound) | Err(_) => {}
        }
    }
}

pub trait ClaimOps: Send {
    fn state(&self) -> ClaimState;
    fn on_verified_hit(&mut self);
    fn prepare(&mut self, destination: &str) -> Result<ClaimSummary, ServiceError>;
    fn confirm(
        &mut self,
        destination: &str,
        prepared_txid: &str,
    ) -> Result<SubmitReceipt, ServiceError>;
    fn poll(&mut self);
}
impl<U: UtxoSource + Send, S: Submitter + Send, K: KeySource + Send> ClaimOps
    for ClaimService<U, S, K>
{
    fn state(&self) -> ClaimState {
        self.state()
    }
    fn on_verified_hit(&mut self) {
        self.on_verified_hit();
    }
    fn prepare(&mut self, destination: &str) -> Result<ClaimSummary, ServiceError> {
        self.prepare(destination)
    }
    fn confirm(
        &mut self,
        destination: &str,
        prepared_txid: &str,
    ) -> Result<SubmitReceipt, ServiceError> {
        self.confirm(destination, prepared_txid)
    }
    fn poll(&mut self) {
        self.poll();
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn read_marker(path: &Path) -> Result<Option<MarkerFile>, ServiceError> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let marker: MarkerFile =
                serde_json::from_str(&raw).map_err(|_| ServiceError::Storage)?;
            if marker.outcome != "pending" && marker.outcome != "rejected" {
                return Err(ServiceError::Storage);
            }
            Ok(Some(marker))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ServiceError::Storage),
    }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
fn write_marker(path: &Path, marker: &MarkerFile) -> Result<(), ServiceError> {
    write_marker_with_sync(path, marker, sync_directory)
}

fn write_marker_with_sync(
    path: &Path,
    marker: &MarkerFile,
    directory_sync: fn(&Path) -> std::io::Result<()>,
) -> Result<(), ServiceError> {
    let json = serde_json::to_string(marker).map_err(|_| ServiceError::Storage)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("claim-marker");
    const MAX_TEMP_ATTEMPTS: u32 = 128;
    let mut opened: Option<File> = None;
    let mut temp_path = PathBuf::new();
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let candidate = parent.join(format!(
            ".{}.{}.{}.{}.tmp",
            file_name,
            std::process::id(),
            unix_nanos(),
            next_temp_name_seq()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                opened = Some(file);
                temp_path = candidate;
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ServiceError::Storage),
        }
    }
    let Some(mut file) = opened else {
        return Err(ServiceError::Storage);
    };
    if file.write_all(json.as_bytes()).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(ServiceError::Storage);
    }
    if file.sync_all().is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(ServiceError::Storage);
    }
    drop(file);
    if fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600)).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(ServiceError::Storage);
    }
    if fs::rename(&temp_path, path).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(ServiceError::Storage);
    }
    directory_sync(parent).map_err(|_| ServiceError::Storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimService, ClaimState, KeySource, MAX_NOT_FOUND_POLLS, MarkerFile, Phase, ServiceError,
        find_verified_found_key, read_marker, write_marker,
    };
    use crate::claim::error::ClaimError;
    use crate::claim::key::ClaimKey;
    use crate::claim::net::error::NetError;
    use crate::claim::net::esplora::{ClaimFetchError, UtxoSnapshot, UtxoSource};
    use crate::claim::net::slipstream::{SubmitError, SubmitReceipt, Submitter, TxStatus};
    use crate::claim::policy::{self, DEFAULT_FEE_RATE_SAT_VB};
    use crate::claim::prevout::{VerifiedPrevout, p2pkh_script_for_hash160};
    use crate::claim::test_support::{self, TEST_SCALAR};
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::ops::{Deref, DerefMut};
    use std::path::{Path, PathBuf};

    const DEST: &str = "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY";
    const DEST2: &str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";

    struct FakeKey;

    impl KeySource for FakeKey {
        fn load(&self) -> Result<ClaimKey, ClaimError> {
            Ok(test_support::test_claim_key())
        }
    }

    struct FakeUtxos {
        prevouts: RefCell<Vec<VerifiedPrevout>>,
        fail_remaining: Cell<u32>,
    }

    impl UtxoSource for FakeUtxos {
        fn fetch_verified_prevouts(&self) -> Result<UtxoSnapshot, ClaimFetchError> {
            if self.fail_remaining.get() > 0 {
                self.fail_remaining.set(self.fail_remaining.get() - 1);
                return Err(ClaimFetchError::Net(NetError::Transport {
                    exit_code: Some(1),
                }));
            }
            Ok(UtxoSnapshot {
                prevouts: self.prevouts.borrow().clone(),
                unconfirmed_count: 0,
            })
        }
    }

    #[derive(Clone, Copy)]
    enum SubmitMode {
        Success,
        Rejected,
        Ambiguous,
    }

    struct FakeSubmitter {
        submit_count: Cell<u32>,
        fee_floor: Cell<u64>,
        mode: Cell<SubmitMode>,
        status: Cell<TxStatus>,
        status_err: Cell<bool>,
    }

    impl Submitter for FakeSubmitter {
        fn fee_floor_sat_vb(&self) -> Result<u64, NetError> {
            Ok(self.fee_floor.get())
        }

        fn submit(
            &self,
            claim: &crate::claim::builder::SignedClaim,
        ) -> Result<SubmitReceipt, SubmitError> {
            self.submit_count.set(self.submit_count.get() + 1);
            match self.mode.get() {
                SubmitMode::Success => Ok(SubmitReceipt {
                    txid: claim.summary().txid.clone(),
                }),
                SubmitMode::Rejected => Err(SubmitError::Rejected("nope".to_string())),
                SubmitMode::Ambiguous => Err(SubmitError::Ambiguous(NetError::HttpStatus(500))),
            }
        }

        fn status(&self, _txid: &str) -> Result<TxStatus, NetError> {
            if self.status_err.get() {
                return Err(NetError::Transport { exit_code: Some(1) });
            }
            Ok(self.status.get())
        }
    }

    fn economic_prevouts() -> Vec<VerifiedPrevout> {
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        vec![test_support::funded_prevout(hash160, 710_000_000)]
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    struct Harness {
        service: ClaimService<FakeUtxos, FakeSubmitter, FakeKey>,
        _tmp: TempDir,
    }

    impl Deref for Harness {
        type Target = ClaimService<FakeUtxos, FakeSubmitter, FakeKey>;
        fn deref(&self) -> &Self::Target {
            &self.service
        }
    }

    impl DerefMut for Harness {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.service
        }
    }

    fn temp_dir() -> TempDir {
        loop {
            let dir = std::env::temp_dir().join(format!(
                "puzzle71-claim-service-{}-{}-{}",
                std::process::id(),
                super::unix_nanos(),
                super::next_temp_name_seq()
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return TempDir(dir),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create service temp dir: {err}"),
            }
        }
    }

    fn service_at(marker: PathBuf) -> ClaimService<FakeUtxos, FakeSubmitter, FakeKey> {
        ClaimService::new(
            FakeUtxos {
                prevouts: RefCell::new(economic_prevouts()),
                fail_remaining: Cell::new(0),
            },
            FakeSubmitter {
                submit_count: Cell::new(0),
                fee_floor: Cell::new(1),
                mode: Cell::new(SubmitMode::Success),
                status: Cell::new(TxStatus::Confirmed { block_height: 1 }),
                status_err: Cell::new(false),
            },
            FakeKey,
            marker,
        )
    }

    fn harness() -> Harness {
        let dir = temp_dir();
        let marker = dir.join("marker.json");
        Harness {
            service: service_at(marker),
            _tmp: dir,
        }
    }

    fn prepared_txid(service: &ClaimService<FakeUtxos, FakeSubmitter, FakeKey>) -> String {
        match &service.phase {
            Phase::Prepared { summary, .. } => summary.txid.clone(),
            _ => "00".repeat(32),
        }
    }

    fn expect_marker(path: &Path) -> MarkerFile {
        read_marker(path)
            .expect("read marker")
            .expect("marker present")
    }

    fn write_test_marker(path: &Path, txid: &str, outcome: &str) {
        let marker = MarkerFile {
            txid: txid.to_string(),
            destination: DEST.to_string(),
            fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
            written_at_unix: 1,
            outcome: outcome.to_string(),
        };
        write_marker(path, &marker).expect("write test marker");
    }

    #[test]
    fn happy_path_hit_prepare_confirm_poll_confirmed() {
        let mut service = harness();
        service.on_verified_hit();
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
        let summary = service.prepare(DEST).expect("prepare");
        assert_eq!(summary.total_input_sat, 710_000_000);
        let preview_txid = prepared_txid(&service);
        let receipt = service.confirm(DEST, &preview_txid).expect("confirm");
        assert_eq!(receipt.txid, summary.txid);
        assert_eq!(service.submitter.submit_count.get(), 1);
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid: summary.txid,
                block_height: 1
            }
        );
    }

    #[test]
    fn confirm_without_prepare_or_with_another_destination_never_submits() {
        let mut service = harness();
        service.on_verified_hit();
        let preview_txid = prepared_txid(&service);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("not prepared");
        assert_eq!(err, ServiceError::NotPrepared);
        assert_eq!(service.submitter.submit_count.get(), 0);

        service.prepare(DEST).expect("prepare");
        let err = service.confirm(DEST2, &preview_txid).expect_err("dest");
        assert_eq!(err, ServiceError::DestinationMismatch);
        assert_eq!(service.submitter.submit_count.get(), 0);
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
    }

    #[test]
    fn prepare_stores_canonical_bech32_and_confirm_accepts_uppercase() {
        // Crate test vector: bitcoin-0.32.11/src/address/mod.rs:1051
        // Fully uppercase bech32 is accepted; bech32-0.11.1/src/primitives/decode.rs:675-703
        // rejects mixed case only.
        const BECH32: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
        const BECH32_UPPER: &str = "BC1QVZVKJN4Q3NSZQXRV3NRAGA2R822XJTY3YKVKUW";
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(BECH32_UPPER).expect("prepare uppercase");
        assert_eq!(summary.destination, BECH32);
        match &service.phase {
            Phase::Prepared { destination, .. } => assert_eq!(destination, BECH32),
            _ => panic!("expected Prepared after prepare"),
        }
        let preview_txid = prepared_txid(&service);
        service
            .confirm(BECH32_UPPER, &preview_txid)
            .expect("uppercase confirm matches canonical store");
        assert_eq!(service.submitter.submit_count.get(), 1);

        let mut other = harness();
        other.on_verified_hit();
        other.prepare(BECH32_UPPER).expect("prepare");
        let preview_txid = prepared_txid(&other);
        let err = other
            .confirm(DEST2, &preview_txid)
            .expect_err("different destination");
        assert_eq!(err, ServiceError::DestinationMismatch);
        assert_eq!(other.submitter.submit_count.get(), 0);
    }

    #[test]
    fn summary_changed_when_a_utxo_is_added_between_prepare_and_confirm() {
        let mut service = harness();
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let extra =
            test_support::funded_prevout(test_support::derive_hash160(TEST_SCALAR), 7_100_000);
        service.utxo.prevouts.borrow_mut().push(extra);
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("changed");
        assert_eq!(err, ServiceError::SummaryChanged);
        assert_eq!(service.submitter.submit_count.get(), 0);
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
        let refreshed = service.prepare(DEST).expect("prepare after summary change");
        service
            .confirm(DEST, &refreshed.txid)
            .expect("fresh preview confirmed");
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn balance_below_expected_does_not_enter_prepared() {
        let mut service = harness();
        service
            .utxo
            .prevouts
            .replace(vec![test_support::funded_prevout(
                test_support::derive_hash160(TEST_SCALAR),
                690_000_000,
            )]);
        service.on_verified_hit();
        let err = service.prepare(DEST).expect_err("6.9 btc");
        assert_eq!(err, ServiceError::BalanceBelowExpected);
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
    }

    #[test]
    fn pending_marker_with_a_different_txid_blocks_submit() {
        let mut service = harness();
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        write_test_marker(&service.marker_path, &"ab".repeat(32), "pending");
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("marker");
        assert!(matches!(
            err,
            ServiceError::AlreadySubmittedDifferent { .. }
        ));
        assert_eq!(service.submitter.submit_count.get(), 0);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("still blocked");
        assert!(matches!(
            err,
            ServiceError::AlreadySubmittedDifferent { .. }
        ));
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn rejected_marker_with_a_different_txid_does_not_bind() {
        let mut service = harness();
        write_test_marker(&service.marker_path, &"cd".repeat(32), "rejected");
        assert_eq!(service.state(), ClaimState::Idle);
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        service
            .confirm(DEST, &preview_txid)
            .expect("rejected marker ignored");
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn rejected_submit_rewrites_marker_and_failed_ambiguous_recovers_via_poll() {
        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Rejected);
        service.submitter.status.set(TxStatus::NotFound);
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("rejected");
        assert_eq!(err, ServiceError::SubmissionRejected);
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_rejected".to_string()
            }
        );
        let marker = expect_marker(&service.marker_path);
        assert_eq!(marker.outcome, "rejected");

        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Ambiguous);
        service.submitter.status.set(TxStatus::Pending);
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("ambiguous");
        assert_eq!(err, ServiceError::SubmissionUnknown);
        let marker = expect_marker(&service.marker_path);
        assert_eq!(marker.outcome, "pending");
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_unknown".to_string()
            }
        );
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Submitted {
                txid: summary.txid,
                submitted_at_unix: marker.written_at_unix
            }
        );
    }

    #[test]
    fn new_with_pending_marker_is_submitted_and_blocks_prepare_and_hit() {
        let dir = temp_dir();
        let marker_path = dir.join("marker.json");
        let txid = "ee".repeat(32);
        write_test_marker(&marker_path, &txid, "pending");
        let mut service = Harness {
            service: {
                let created = service_at(marker_path);
                created.submitter.status.set(TxStatus::Pending);
                created
            },
            _tmp: dir,
        };
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid: t, .. } if t == txid
        ));
        assert_eq!(
            service.prepare(DEST).unwrap_err(),
            ServiceError::InvalidState
        );
        service.on_verified_hit();
        assert!(matches!(service.state(), ClaimState::Submitted { .. }));
    }

    #[test]
    fn prepare_from_confirmed_and_idle_is_invalid_state() {
        let mut idle = harness();
        assert_eq!(idle.prepare(DEST).unwrap_err(), ServiceError::InvalidState);

        let mut confirmed = harness();
        confirmed.phase = Phase::Confirmed {
            txid: "ff".repeat(32),
            block_height: 2,
            submitted_at_unix: 1,
        };
        assert_eq!(
            confirmed.prepare(DEST).unwrap_err(),
            ServiceError::InvalidState
        );
    }

    #[test]
    fn fee_floor_above_max_is_fee_floor_too_high() {
        let mut service = harness();
        service
            .submitter
            .fee_floor
            .set(policy::MAX_FEE_RATE_SAT_VB + 1);
        service.on_verified_hit();
        assert_eq!(
            service.prepare(DEST).unwrap_err(),
            ServiceError::FeeFloorTooHigh
        );
    }

    #[test]
    fn confirm_retries_same_preview_after_utxo_net_error() {
        let mut service = harness();
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        service.utxo.fail_remaining.set(1);
        let err = service.confirm(DEST, &preview_txid).expect_err("net error");
        assert!(
            matches!(
                err,
                ServiceError::Fetch(ClaimFetchError::Net(NetError::Transport { .. }))
            ),
            "{err:?}"
        );
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
        assert_eq!(service.submitter.submit_count.get(), 0);
        service.confirm(DEST, &preview_txid).expect("retry");
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn poll_not_found_and_err_leave_submitted_below_the_threshold() {
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        service.confirm(DEST, &preview_txid).unwrap();
        service.submitter.status.set(TxStatus::NotFound);
        service.poll();
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
        service.submitter.status_err.set(true);
        service.poll();
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
    }

    #[test]
    fn prepare_from_failed_rejected_is_allowed() {
        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Rejected);
        service.submitter.status.set(TxStatus::NotFound);
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        service.confirm(DEST, &preview_txid).expect_err("rejected");
        assert!(matches!(service.state(), ClaimState::Failed { .. }));
        service.submitter.mode.set(SubmitMode::Success);
        let summary = service.prepare(DEST).expect("prepare from failed");
        assert_eq!(summary.total_input_sat, 710_000_000);
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
    }

    fn restart_with_pending(txid: &str, status: TxStatus) -> Harness {
        let dir = temp_dir();
        let marker_path = dir.join("marker.json");
        write_test_marker(&marker_path, txid, "pending");
        let created = service_at(marker_path);
        created.submitter.status.set(status);
        Harness {
            service: created,
            _tmp: dir,
        }
    }

    #[test]
    fn thirty_not_found_polls_after_restart_fail_then_same_txid_resubmits() {
        let mut probe = harness();
        probe.on_verified_hit();
        let summary = probe.prepare(DEST).unwrap();
        let txid = summary.txid.clone();
        drop(probe);

        let mut service = restart_with_pending(&txid, TxStatus::NotFound);
        for _ in 0..MAX_NOT_FOUND_POLLS {
            service.poll();
        }
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_not_found".to_string()
            }
        );
        service.prepare(DEST).expect("prepare after not found");
        let preview_txid = prepared_txid(&service);
        service
            .confirm(DEST, &preview_txid)
            .expect("same txid resubmit");
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn thirty_not_found_then_confirm_with_different_txid_is_already_submitted() {
        let mut probe = harness();
        probe.on_verified_hit();
        let summary = probe.prepare(DEST).unwrap();
        let txid = summary.txid.clone();
        drop(probe);

        let mut service = restart_with_pending(&txid, TxStatus::NotFound);
        for _ in 0..MAX_NOT_FOUND_POLLS {
            service.poll();
        }
        let extra =
            test_support::funded_prevout(test_support::derive_hash160(TEST_SCALAR), 7_100_000);
        service.utxo.prevouts.borrow_mut().push(extra);
        service.prepare(DEST).expect("new summary");
        let preview_txid = prepared_txid(&service);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("different txid");
        assert!(matches!(
            err,
            ServiceError::AlreadySubmittedDifferent { txid: t } if t == txid
        ));
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn prepare_from_failed_pending_polls_to_confirmed() {
        let txid = "ab".repeat(32);
        let mut service = restart_with_pending(&txid, TxStatus::NotFound);
        for _ in 0..MAX_NOT_FOUND_POLLS {
            service.poll();
        }
        assert!(matches!(
            service.state(),
            ClaimState::Failed { reason } if reason == "submission_not_found"
        ));
        service.prepare(DEST).expect("prepare carries pending");
        service
            .submitter
            .status
            .set(TxStatus::Confirmed { block_height: 9 });
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid,
                block_height: 9
            }
        );
    }

    #[test]
    fn new_with_rejected_marker_is_idle_then_hit_and_prepare() {
        let dir = temp_dir();
        let marker_path = dir.join("marker.json");
        write_test_marker(&marker_path, &"cd".repeat(32), "rejected");
        let mut service = Harness {
            service: service_at(marker_path),
            _tmp: dir,
        };
        assert_eq!(service.state(), ClaimState::Idle);
        service.on_verified_hit();
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
        service.prepare(DEST).expect("prepare allowed");
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
    }

    #[test]
    fn pending_poll_resets_the_not_found_counter() {
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        service.confirm(DEST, &preview_txid).unwrap();
        service.submitter.status.set(TxStatus::NotFound);
        for _ in 0..29 {
            service.poll();
        }
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
        service.submitter.status.set(TxStatus::Pending);
        service.poll();
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
        service.submitter.status.set(TxStatus::NotFound);
        for _ in 0..29 {
            service.poll();
        }
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_not_found".to_string()
            }
        );
    }

    #[test]
    fn confirm_keeps_the_preview_when_the_marker_cannot_be_written() {
        let mut service = harness();
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let missing = service
            .marker_path
            .parent()
            .expect("parent")
            .join("no-such-dir")
            .join("marker.json");
        service.marker_path = missing;
        let err = service.confirm(DEST, &preview_txid).expect_err("storage");
        assert_eq!(err, ServiceError::Storage);
        assert_eq!(service.submitter.submit_count.get(), 0);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("still storage");
        assert_eq!(err, ServiceError::Storage);
        assert_eq!(service.submitter.submit_count.get(), 0);
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
    }

    #[test]
    fn resubmit_rejected_keeps_pending_and_blocks_a_different_txid() {
        let mut service = harness();
        service.on_verified_hit();
        let summary_a = service.prepare(DEST).unwrap();
        let txid_a = summary_a.txid.clone();
        let preview_txid = prepared_txid(&service);
        service.submitter.mode.set(SubmitMode::Ambiguous);
        service.confirm(DEST, &preview_txid).expect_err("ambiguous");
        assert_eq!(service.submitter.submit_count.get(), 1);

        service.submitter.mode.set(SubmitMode::Rejected);
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("rejected resubmit");
        assert_eq!(err, ServiceError::SubmissionUnknown);
        assert_eq!(service.submitter.submit_count.get(), 2);
        let marker = expect_marker(&service.marker_path);
        assert_eq!(marker.outcome, "pending");
        assert_eq!(marker.txid, txid_a);

        let extra =
            test_support::funded_prevout(test_support::derive_hash160(TEST_SCALAR), 7_100_000);
        service.utxo.prevouts.borrow_mut().push(extra);
        service.prepare(DEST).expect("prepare B");
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("B blocked");
        assert!(matches!(
            err,
            ServiceError::AlreadySubmittedDifferent { txid } if txid == txid_a
        ));
        assert_eq!(service.submitter.submit_count.get(), 2);
    }

    #[test]
    fn first_rejected_submit_with_pending_status_becomes_submitted() {
        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Rejected);
        service.submitter.status.set(TxStatus::Pending);
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let receipt = service
            .confirm(DEST, &preview_txid)
            .expect("treated as submitted");
        assert_eq!(receipt.txid, summary.txid);
        assert_eq!(service.submitter.submit_count.get(), 1);
        assert!(matches!(
            service.state(),
            ClaimState::Submitted { txid, .. } if txid == summary.txid
        ));
        let marker = expect_marker(&service.marker_path);
        assert_eq!(marker.outcome, "pending");
    }

    #[test]
    fn first_rejected_submit_with_not_found_rejects_the_marker() {
        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Rejected);
        service.submitter.status.set(TxStatus::NotFound);
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("rejected");
        assert_eq!(err, ServiceError::SubmissionRejected);
        assert_eq!(service.submitter.submit_count.get(), 1);
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_rejected".to_string()
            }
        );
        assert_eq!(expect_marker(&service.marker_path).outcome, "rejected");
    }

    #[test]
    fn first_rejected_submit_with_status_error_keeps_pending() {
        let mut service = harness();
        service.submitter.mode.set(SubmitMode::Rejected);
        service.submitter.status_err.set(true);
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let err = service
            .confirm(DEST, &preview_txid)
            .expect_err("status err");
        assert_eq!(err, ServiceError::SubmissionUnknown);
        assert_eq!(service.submitter.submit_count.get(), 1);
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_unknown".to_string()
            }
        );
        let marker = expect_marker(&service.marker_path);
        assert_eq!(marker.outcome, "pending");
        assert_eq!(marker.txid, summary.txid);
    }

    #[test]
    fn poll_confirms_pending_after_fee_floor_summary_change() {
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let txid = summary.txid.clone();
        let preview_txid = prepared_txid(&service);
        service.submitter.mode.set(SubmitMode::Ambiguous);
        service.confirm(DEST, &preview_txid).expect_err("ambiguous");
        service.submitter.mode.set(SubmitMode::Success);
        service.prepare(DEST).expect("prepare");
        service.submitter.fee_floor.set(DEFAULT_FEE_RATE_SAT_VB + 1);
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("floor");
        assert_eq!(err, ServiceError::SummaryChanged);
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
        assert_eq!(service.submitter.submit_count.get(), 1);
        service
            .submitter
            .status
            .set(TxStatus::Confirmed { block_height: 11 });
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid,
                block_height: 11
            }
        );
    }

    #[test]
    fn poll_confirms_pending_after_txid_summary_change() {
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let txid = summary.txid.clone();
        let preview_txid = prepared_txid(&service);
        service.submitter.mode.set(SubmitMode::Ambiguous);
        service.confirm(DEST, &preview_txid).expect_err("ambiguous");
        service.submitter.mode.set(SubmitMode::Success);
        service.prepare(DEST).expect("prepare");
        let extra =
            test_support::funded_prevout(test_support::derive_hash160(TEST_SCALAR), 7_100_000);
        service.utxo.prevouts.borrow_mut().push(extra);
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("changed");
        assert_eq!(err, ServiceError::SummaryChanged);
        assert!(matches!(service.state(), ClaimState::AwaitingOwner));
        assert_eq!(service.submitter.submit_count.get(), 1);
        service
            .submitter
            .status
            .set(TxStatus::Confirmed { block_height: 12 });
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid,
                block_height: 12
            }
        );
    }

    #[test]
    fn poll_from_confirmed_returns_to_submitted_when_the_tx_is_pending_again() {
        let mut service = harness();
        let txid = "ab".repeat(32);
        let submitted_at_unix = 1_700_000_000;
        service.phase = Phase::Confirmed {
            txid: txid.clone(),
            block_height: 103,
            submitted_at_unix,
        };
        service.submitter.status.set(TxStatus::Pending);
        service.poll();
        match &service.phase {
            Phase::Submitted {
                txid: got_txid,
                submitted_at_unix: got_at,
                not_found_polls,
            } => {
                assert_eq!(got_txid, &txid);
                assert_eq!(*got_at, submitted_at_unix);
                assert_eq!(*not_found_polls, 0);
            }
            _ => panic!("expected Submitted after reorg to pending"),
        }
        assert_eq!(
            service.state(),
            ClaimState::Submitted {
                txid,
                submitted_at_unix
            }
        );
    }

    #[test]
    fn poll_from_confirmed_updates_the_block_height() {
        let mut service = harness();
        let txid = "cd".repeat(32);
        service.phase = Phase::Confirmed {
            txid: txid.clone(),
            block_height: 103,
            submitted_at_unix: 1,
        };
        service
            .submitter
            .status
            .set(TxStatus::Confirmed { block_height: 104 });
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid,
                block_height: 104
            }
        );
        match &service.phase {
            Phase::Confirmed {
                submitted_at_unix, ..
            } => assert_eq!(*submitted_at_unix, 1),
            _ => panic!("expected Confirmed with preserved submitted_at_unix"),
        }
    }

    #[test]
    fn poll_from_confirmed_with_not_found_counts_towards_failure() {
        let mut service = harness();
        let txid = "ef".repeat(32);
        let submitted_at_unix = 1;
        service.phase = Phase::Confirmed {
            txid: txid.clone(),
            block_height: 103,
            submitted_at_unix,
        };
        service.submitter.status.set(TxStatus::NotFound);
        service.poll();
        match &service.phase {
            Phase::Submitted {
                txid: got_txid,
                submitted_at_unix: got_at,
                not_found_polls,
            } => {
                assert_eq!(got_txid, &txid);
                assert_eq!(*got_at, submitted_at_unix);
                assert_eq!(*not_found_polls, 1);
            }
            _ => panic!("expected Submitted with not_found_polls = 1"),
        }
        for _ in 0..(MAX_NOT_FOUND_POLLS - 1) {
            service.poll();
        }
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "submission_not_found".to_string()
            }
        );
    }

    #[test]
    fn poll_from_confirmed_keeps_state_on_transport_error() {
        let mut service = harness();
        let txid = "aa".repeat(32);
        service.phase = Phase::Confirmed {
            txid: txid.clone(),
            block_height: 103,
            submitted_at_unix: 1,
        };
        service.submitter.status_err.set(true);
        service.poll();
        assert_eq!(
            service.state(),
            ClaimState::Confirmed {
                txid,
                block_height: 103
            }
        );
        match &service.phase {
            Phase::Confirmed {
                submitted_at_unix, ..
            } => assert_eq!(*submitted_at_unix, 1),
            _ => panic!("expected Confirmed unchanged on transport error"),
        }
    }

    #[test]
    fn confirm_does_not_submit_when_the_marker_path_is_a_directory() {
        let mut service = harness();
        service.on_verified_hit();
        service.prepare(DEST).unwrap();
        let preview_txid = prepared_txid(&service);
        let as_dir = temp_dir();
        service.marker_path = as_dir.0.clone();
        let err = service.confirm(DEST, &preview_txid).expect_err("storage");
        assert_eq!(err, ServiceError::Storage);
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn new_with_broken_marker_json_is_unreadable() {
        let dir = temp_dir();
        let marker_path = dir.join("marker.json");
        fs::write(&marker_path, "{not json").unwrap();
        let mut service = Harness {
            service: service_at(marker_path),
            _tmp: dir,
        };
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "marker_unreadable".to_string()
            }
        );
        service.prepare(DEST).expect("prepare allowed");
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("storage");
        assert_eq!(err, ServiceError::Storage);
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn new_with_garbage_outcome_is_unreadable() {
        let dir = temp_dir();
        let marker_path = dir.join("marker.json");
        write_test_marker(&marker_path, &"ab".repeat(32), "garbage");
        let mut service = Harness {
            service: service_at(marker_path),
            _tmp: dir,
        };
        assert_eq!(
            service.state(),
            ClaimState::Failed {
                reason: "marker_unreadable".to_string()
            }
        );
        service.prepare(DEST).expect("prepare allowed");
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("storage");
        assert_eq!(err, ServiceError::Storage);
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn memory_pending_blocks_a_different_txid_when_the_marker_file_is_gone() {
        let mut service = harness();
        service.on_verified_hit();
        let summary_a = service.prepare(DEST).unwrap();
        let txid_a = summary_a.txid.clone();
        let preview_txid = prepared_txid(&service);
        service.submitter.mode.set(SubmitMode::Ambiguous);
        service.confirm(DEST, &preview_txid).expect_err("ambiguous");
        assert_eq!(service.submitter.submit_count.get(), 1);
        fs::remove_file(&service.marker_path).expect("delete marker");

        let extra =
            test_support::funded_prevout(test_support::derive_hash160(TEST_SCALAR), 7_100_000);
        service.utxo.prevouts.borrow_mut().push(extra);
        service.prepare(DEST).expect("prepare B");
        let preview_txid = prepared_txid(&service);
        let err = service.confirm(DEST, &preview_txid).expect_err("B blocked");
        assert!(matches!(
            err,
            ServiceError::AlreadySubmittedDifferent { txid } if txid == txid_a
        ));
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    fn write_found_key(path: &Path, mode: u32, scalar: u128) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        writeln!(file, "PRIVATE KEY (HEX):       0x{scalar:018x}").unwrap();
    }

    #[test]
    fn find_verified_found_key_none_without_files() {
        let dir = temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        let scan = find_verified_found_key(&dir, hash, 0..=u128::MAX);
        assert_eq!(scan.found, None);
        assert!(scan.unloadable.is_empty());
    }

    #[test]
    fn find_verified_found_key_skips_world_readable_and_foreign_keys() {
        let dir = temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        write_found_key(&dir.join("FOUND_KEY.txt"), 0o644, TEST_SCALAR);
        let world_readable = find_verified_found_key(&dir, hash, 0..=u128::MAX);
        assert_eq!(world_readable.found, None);
        assert_eq!(
            world_readable.unloadable,
            vec![("FOUND_KEY.txt".into(), ClaimError::KeyFilePermissions)]
        );

        let foreign = TEST_SCALAR ^ 1;
        write_found_key(&dir.join("FOUND_KEY_foreign.txt"), 0o600, foreign);
        let both_unloadable = find_verified_found_key(&dir, hash, 0..=u128::MAX);
        assert_eq!(both_unloadable.found, None);
        assert_eq!(
            both_unloadable.unloadable,
            vec![
                ("FOUND_KEY.txt".into(), ClaimError::KeyFilePermissions),
                (
                    "FOUND_KEY_foreign.txt".into(),
                    ClaimError::KeyDoesNotMatchTarget,
                ),
            ]
        );
    }

    #[test]
    fn find_verified_found_key_returns_first_valid_sorted_file() {
        let dir = temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        write_found_key(&dir.join("FOUND_KEY_a.txt"), 0o644, TEST_SCALAR);
        write_found_key(&dir.join("FOUND_KEY_c.txt"), 0o600, TEST_SCALAR);
        write_found_key(&dir.join("FOUND_KEY_b.txt"), 0o600, TEST_SCALAR);
        let scan = find_verified_found_key(&dir, hash, 0..=u128::MAX);
        let found = scan.found.expect("valid key");
        assert_eq!(found.file_name().unwrap(), "FOUND_KEY_b.txt");
        assert_eq!(
            scan.unloadable,
            vec![("FOUND_KEY_a.txt".into(), ClaimError::KeyFilePermissions)]
        );
    }

    #[test]
    fn find_verified_found_key_reports_unloadable_when_none_load() {
        let dir = temp_dir();
        let hash = test_support::derive_hash160(TEST_SCALAR);
        write_found_key(&dir.join("FOUND_KEY.txt"), 0o644, TEST_SCALAR);
        let scan = find_verified_found_key(&dir, hash, 0..=u128::MAX);
        assert_eq!(scan.found, None);
        assert_eq!(scan.unloadable.len(), 1);
        assert_eq!(scan.unloadable[0].0, "FOUND_KEY.txt");
        assert_eq!(scan.unloadable[0].1, ClaimError::KeyFilePermissions);
        let warning = format!(
            "WARNING: FOUND_KEY file present but not loadable ({}: {:?})",
            scan.unloadable[0].0, scan.unloadable[0].1
        );
        assert_eq!(
            warning,
            "WARNING: FOUND_KEY file present but not loadable (FOUND_KEY.txt: KeyFilePermissions)"
        );
        assert!(!warning.to_ascii_lowercase().contains("private"));
        assert!(!warning.contains("0x"));
    }
    #[test]
    fn wallet_preview_needs_no_notifier_and_prepare_never_submits() {
        let mut service = harness();
        service.on_verified_hit();
        assert_eq!(service.state(), ClaimState::AwaitingOwner);
        let preview = service.prepare(DEST).unwrap();
        assert_eq!(preview.destination, DEST);
        assert_eq!(service.submitter.submit_count.get(), 0);
        assert!(
            !serde_json::to_string(&service.state())
                .unwrap()
                .contains("code")
        );
        service.confirm(DEST, &preview.txid).unwrap();
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn confirming_a_different_prepared_txid_does_not_submit() {
        let mut service = harness();
        service.on_verified_hit();
        let a = service.prepare(DEST).unwrap();
        let b = service.prepare(DEST2).unwrap();
        assert_ne!(a.txid, b.txid);
        assert_eq!(
            service.confirm(DEST2, &a.txid).unwrap_err(),
            ServiceError::PreparedTxidMismatch
        );
        assert_eq!(
            service.confirm(DEST2, "").unwrap_err(),
            ServiceError::PreparedTxidMismatch
        );
        assert_eq!(service.submitter.submit_count.get(), 0);
        service.confirm(DEST2, &b.txid).unwrap();
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn failed_reprepare_invalidates_the_old_preview() {
        let mut service = harness();
        service.on_verified_hit();
        let a = service.prepare(DEST).unwrap();
        assert!(service.prepare("invalid destination").is_err());
        assert_eq!(
            service.confirm(DEST, &a.txid).unwrap_err(),
            ServiceError::NotPrepared
        );
        assert_eq!(service.submitter.submit_count.get(), 0);
    }

    #[test]
    fn duplicate_confirm_returns_receipt_without_a_second_submit() {
        let mut service = harness();
        service.on_verified_hit();
        let preview = service.prepare(DEST).unwrap();
        let first = service.confirm(DEST, &preview.txid).unwrap();
        let second = service.confirm(DEST, &preview.txid).unwrap();
        assert_eq!(first.txid, second.txid);
        assert_eq!(service.submitter.submit_count.get(), 1);
        assert_eq!(
            service.confirm(DEST2, &preview.txid).unwrap_err(),
            ServiceError::DestinationMismatch
        );
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn marker_directory_sync_error_prevents_submission_and_can_be_retried() {
        fn fail_sync(_: &Path) -> std::io::Result<()> {
            Err(std::io::Error::other("injected directory sync failure"))
        }
        let mut service = harness();
        service.on_verified_hit();
        let preview = service.prepare(DEST).unwrap();
        service.directory_sync = fail_sync;
        assert_eq!(
            service.confirm(DEST, &preview.txid).unwrap_err(),
            ServiceError::Storage
        );
        assert_eq!(service.submitter.submit_count.get(), 0);
        assert!(matches!(service.state(), ClaimState::Prepared { .. }));
        assert_eq!(expect_marker(&service.marker_path).txid, preview.txid);
        service.directory_sync = super::sync_directory;
        service.confirm(DEST, &preview.txid).unwrap();
        assert_eq!(service.submitter.submit_count.get(), 1);
    }

    #[test]
    fn claim_state_never_serializes_signing_material() {
        use bitcoin::hex::DisplayHex;
        let mut service = harness();
        service.on_verified_hit();
        let summary = service.prepare(DEST).unwrap();
        let key = test_support::test_claim_key();
        let address = crate::claim::parse_destination(
            DEST,
            bitcoin::Network::Bitcoin,
            p2pkh_script_for_hash160(key.hash160()).as_script(),
        )
        .unwrap();
        let signed = crate::claim::build_signed_claim(
            &key,
            &economic_prevouts(),
            &address,
            DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap();
        let pubkey_hex = key.compressed_pubkey_bytes().to_lower_hex_string();
        let raw_hex = signed.raw_tx_bytes_for_submission().to_lower_hex_string();
        for state in [
            service.state(),
            ClaimState::AwaitingOwner,
            ClaimState::Submitted {
                txid: summary.txid,
                submitted_at_unix: 1,
            },
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert!(!json.contains(&pubkey_hex));
            assert!(!json.contains(&raw_hex));
            for forbidden in ["code", "private", "pubkey", "raw_tx"] {
                assert!(
                    !json.contains(forbidden),
                    "unexpected secret field in {json}"
                );
            }
        }
    }
}
