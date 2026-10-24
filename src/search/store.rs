//! Durable incremental progress, with compatible JSON snapshots and a checksummed journal.

use crate::crypto::sha256::sha256;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_MAX, RANGE_MIN, RANGE_SIZE};
use crate::search::checkpoint::{
    CheckpointState, require_single_link_regular_file, save_atomic_json,
};
use crate::search::duplicate_filter::{DuplicateFilter, IntervalSet};
use crate::search::recheck::{RecheckIdentity, RecheckPlan, RecheckProgress};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FORMAT_VERSION: u32 = 1;
const SCOPED_FORMAT_VERSION: u32 = 2;
const COMPACTION_INTERVAL: Duration = Duration::from_secs(3600);
const COMPACTION_BYTES: u64 = 1024 * 1024;
const MAX_REPLAY_BYTES: u64 = 8 * 1024 * 1024;

/// Owns the exclusive writer lock for one snapshot and journal, including claim recovery.
/// The lock file is deliberately retained: removing its inode could admit another writer.
pub struct CheckpointLock {
    snapshot_path: PathBuf,
    _file: File,
}

impl CheckpointLock {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, String> {
        Self::acquire_with_plan(path.as_ref(), None)
    }

    /// Protect the plan source before opening/chmodding a scoped writer lock.
    pub fn acquire_recheck(path: impl AsRef<Path>, plan: &RecheckPlan) -> Result<Self, String> {
        Self::acquire_with_plan(path.as_ref(), Some(plan))
    }

    fn acquire_with_plan(path: &Path, plan: Option<&RecheckPlan>) -> Result<Self, String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().ok_or("Checkpoint path needs a filename")?;
        let snapshot_path = fs::canonicalize(parent)
            .map_err(|e| format!("Failed to resolve checkpoint directory: {e}"))?
            .join(file_name);
        let lock_path = snapshot_path.with_extension("lock");
        if let Some(plan) = plan
            && plan.is_source_file(&lock_path)?
        {
            return Err("Refusing writer lock alias of immutable recheck source".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| format!("Failed to open checkpoint writer lock: {e}"))?;
        require_single_link_regular_file(&file, "checkpoint writer lock")?;
        if let Some(plan) = plan {
            plan.reject_source_fd(&file)?;
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to secure checkpoint writer lock: {e}"))?;
        // SAFETY: this is a live owned file descriptor. The nonblocking flock is released
        // when its File is dropped, and the lock file itself is never unlinked here.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "Another solver owns this checkpoint, or its writer lock failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            snapshot_path,
            _file: file,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHeader {
    format: u32,
    puzzle_number: u32,
    range_min: String,
    range_max: String,
    block_size: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recheck: Option<RecheckIdentity>,
}

impl JournalHeader {
    fn for_block_size(block_size: u128) -> Self {
        Self {
            format: FORMAT_VERSION,
            puzzle_number: PUZZLE_NUMBER,
            range_min: RANGE_MIN.to_string(),
            range_max: RANGE_MAX.to_string(),
            block_size: block_size.to_string(),
            recheck: None,
        }
    }

    fn for_scope(block_size: u128, recheck: Option<&RecheckState>) -> Self {
        let mut header = Self::for_block_size(block_size);
        if let Some(recheck) = recheck {
            header.format = SCOPED_FORMAT_VERSION;
            header.recheck = Some(recheck.plan.identity().clone());
        }
        header
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    completed_block: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recheck_ordinal: Option<u64>,
    total_runtime_secs: f64,
    saved_timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedSnapshot {
    format: u32,
    recheck: RecheckProgress,
    checkpoint: CheckpointState,
}

struct RecheckState {
    plan: RecheckPlan,
    completed: u64,
}

/// The only production writer for checkpoint coverage. Only successful, completely
/// searched blocks may be passed to `complete_block`; partial dispatches stay in memory.
pub struct CheckpointStore {
    snapshot_path: PathBuf,
    journal_path: PathBuf,
    journal: File,
    block_size: u128,
    filter: DuplicateFilter,
    total_blocks: u64,
    total_runtime_secs: f64,
    last_saved_timestamp: u64,
    last_compaction: Instant,
    poisoned: bool,
    recheck: Option<RecheckState>,
    _lock: CheckpointLock,
}

impl CheckpointStore {
    pub fn open(lock: CheckpointLock, block_size: u128) -> Result<Self, String> {
        Self::open_impl(lock, block_size, None)
    }

    pub fn open_recheck(
        lock: CheckpointLock,
        block_size: u128,
        plan: RecheckPlan,
    ) -> Result<Self, String> {
        Self::open_impl(lock, block_size, Some(plan))
    }

    /// Initialize a NEW scope from a validated, owned copy of an existing snapshot+journal.
    /// The archived plan source is read-only and must never be supplied as that copy.
    pub fn initialize_recheck(
        lock: CheckpointLock,
        block_size: u128,
        plan: RecheckPlan,
        copied_history_snapshot: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let copied_history = copied_history_snapshot.as_ref();
        if plan.identity().block_size != block_size.to_string() {
            return Err("Recheck plan block size identity mismatch".into());
        }
        for path in [
            copied_history.to_path_buf(),
            copied_history.with_extension("journal"),
        ] {
            if plan.is_source_file(&path)? {
                return Err(
                    "Recheck history copy must not alias the immutable source archive".into(),
                );
            }
            if !fs::metadata(&path).is_ok_and(|meta| meta.is_file()) {
                return Err(
                    "Recheck initialization requires an existing history snapshot AND journal copy"
                        .into(),
                );
            }
        }
        for path in [
            &lock.snapshot_path,
            &lock.snapshot_path.with_extension("journal"),
            &lock.snapshot_path.with_extension("tmp"),
        ] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err("Recheck initialization requires a fresh destination snapshot, journal and temp path".into()),
            }
        }
        let history = Self::open(
            CheckpointLock::acquire_recheck(copied_history, &plan)?,
            block_size,
        )?;
        if !plan.is_covered_by(&history.filter.intervals) {
            return Err("Recheck source blocks are absent from the copied global history".into());
        }
        let mut checkpoint = history.snapshot();
        checkpoint.last_saved_timestamp = timestamp().max(checkpoint.last_saved_timestamp);
        let snapshot = ScopedSnapshot {
            format: SCOPED_FORMAT_VERSION,
            recheck: RecheckProgress {
                identity: plan.identity().clone(),
                completed: 0,
            },
            checkpoint,
        };
        // Complete validation precedes any destination write. If initialization stops
        // after this snapshot, open_recheck rejects a missing journal, never starts fresh.
        save_atomic_json(&snapshot, &lock.snapshot_path)?;
        let journal_path = lock.snapshot_path.with_extension("journal");
        let journal = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&journal_path)
            .map_err(|e| format!("Failed to create scoped journal: {e}"))?;
        require_single_link_regular_file(&journal, "scoped checkpoint journal")?;
        plan.reject_source_fd(&journal)?;
        journal
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| journal.sync_all())
            .map_err(|e| format!("Failed to secure and sync scoped journal: {e}"))?;
        sync_parent(&journal_path)?;
        drop(journal);
        Self::open_recheck(lock, block_size, plan)
    }

    fn open_impl(
        lock: CheckpointLock,
        block_size: u128,
        plan: Option<RecheckPlan>,
    ) -> Result<Self, String> {
        if block_size == 0
            || block_size > RANGE_SIZE
            || !RANGE_SIZE.is_multiple_of(block_size)
            || RANGE_SIZE / block_size > u64::MAX as u128
        {
            return Err(
                "Checkpoint block size must divide the puzzle range and fit u64 block indices"
                    .into(),
            );
        }
        let (mut snapshot, recheck) = if let Some(plan) = plan {
            let bytes = fs::read(&lock.snapshot_path)
                .map_err(|e| format!("Recheck requires an existing scoped snapshot: {e}"))?;
            let scoped: ScopedSnapshot = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid scoped checkpoint wrapper: {e}"))?;
            if scoped.format != SCOPED_FORMAT_VERSION
                || scoped.recheck.identity != *plan.identity()
                || plan.identity().block_size != block_size.to_string()
                || scoped.recheck.completed > plan.identity().total_blocks
            {
                return Err("Scoped checkpoint identity, format or cursor mismatch".into());
            }
            (
                scoped.checkpoint,
                Some(RecheckState {
                    plan,
                    completed: scoped.recheck.completed,
                }),
            )
        } else {
            (CheckpointState::load_from_file(&lock.snapshot_path)?, None)
        };
        if snapshot.puzzle_number != PUZZLE_NUMBER {
            return Err("Checkpoint puzzle number mismatch".into());
        }
        snapshot.validate_for_block_size(block_size)?;
        if recheck
            .as_ref()
            .is_some_and(|r| !r.plan.is_covered_by(&snapshot.to_interval_set()))
        {
            return Err("Scoped checkpoint lost global coverage of its recheck source".into());
        }
        if Duration::try_from_secs_f64(snapshot.total_runtime_secs).is_err() {
            return Err("Checkpoint runtime exceeds the supported duration".into());
        }
        if !lock.snapshot_path.exists() {
            snapshot.save_to_file(&lock.snapshot_path)?;
        }
        let intervals = IntervalSet {
            intervals: std::mem::take(&mut snapshot.scanned_intervals),
        };
        let journal_path = lock.snapshot_path.with_extension("journal");
        let journal = OpenOptions::new()
            .read(true)
            .append(true)
            .create(recheck.is_none())
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&journal_path)
            .map_err(|e| format!("Failed to open checkpoint journal: {e}"))?;
        require_single_link_regular_file(&journal, "checkpoint journal")?;
        if let Some(recheck) = &recheck {
            recheck.plan.reject_source_fd(&journal)?;
        }
        journal
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to secure checkpoint journal: {e}"))?;
        if journal
            .metadata()
            .map_err(|e| format!("Failed to inspect checkpoint journal: {e}"))?
            .len()
            > MAX_REPLAY_BYTES
        {
            return Err(
                "Checkpoint journal exceeds the bounded replay size; preserve it for repair".into(),
            );
        }
        let mut store = Self {
            snapshot_path: lock.snapshot_path.clone(),
            journal_path,
            journal,
            block_size,
            filter: DuplicateFilter::from_intervals(intervals),
            total_blocks: snapshot.total_blocks_tested,
            total_runtime_secs: snapshot.total_runtime_secs,
            last_saved_timestamp: snapshot.last_saved_timestamp,
            last_compaction: Instant::now(),
            poisoned: false,
            recheck,
            _lock: lock,
        };
        store.replay_and_repair_tail()?;
        Ok(store)
    }

    pub fn total_blocks_tested(&self) -> u64 {
        self.total_blocks
    }
    pub fn total_keys_tested(&self) -> u128 {
        self.total_blocks as u128 * self.block_size
    }
    pub fn total_runtime_secs(&self) -> f64 {
        self.total_runtime_secs
    }
    pub fn last_saved_timestamp(&self) -> u64 {
        self.last_saved_timestamp
    }
    pub fn is_scanned(&self, block_index: u64) -> bool {
        self.filter.is_scanned(block_index)
    }
    pub fn is_complete(&self) -> bool {
        self.next_recheck_block().is_none()
            && self.total_blocks as u128 == RANGE_SIZE / self.block_size
    }

    pub fn next_recheck_block(&self) -> Option<u64> {
        self.recheck
            .as_ref()
            .and_then(|r| r.plan.block_at(r.completed))
    }

    pub fn recheck_progress(&self) -> Option<RecheckProgress> {
        self.recheck.as_ref().map(|r| RecheckProgress {
            identity: r.plan.identity().clone(),
            completed: r.completed,
        })
    }

    pub fn complete_block(
        &mut self,
        block_index: u64,
        absolute_runtime: f64,
    ) -> Result<(), String> {
        self.complete_block_with_sync(block_index, absolute_runtime, File::sync_all)?;
        self.maybe_compact()
    }

    fn complete_block_with_sync<F>(
        &mut self,
        block_index: u64,
        absolute_runtime: f64,
        sync: F,
    ) -> Result<(), String>
    where
        F: FnOnce(&File) -> std::io::Result<()>,
    {
        self.ensure_healthy()?;
        self.validate_runtime(absolute_runtime)?;
        if block_index as u128 >= RANGE_SIZE / self.block_size {
            return Err("Completed checkpoint block lies outside the puzzle range".into());
        }
        let recheck_ordinal = if let Some(expected) = self.next_recheck_block() {
            if block_index != expected {
                return Err("Completed block is not the next ordered recheck block".into());
            }
            Some(self.recheck.as_ref().expect("pending recheck").completed)
        } else {
            None
        };
        if recheck_ordinal.is_none() && self.filter.is_scanned(block_index) {
            return self.persist_runtime(absolute_runtime);
        }
        let record = JournalRecord {
            completed_block: Some(block_index),
            recheck_ordinal,
            total_runtime_secs: absolute_runtime,
            saved_timestamp: timestamp().max(self.last_saved_timestamp),
        };
        self.append_record_with_sync(&record, sync)?;
        // A completed block becomes visible only after its full record has been synced.
        if !self.filter.is_scanned(block_index) {
            self.filter.mark_scanned(block_index);
            self.total_blocks += 1;
        }
        if recheck_ordinal.is_some() {
            self.recheck.as_mut().expect("pending recheck").completed += 1;
        }
        self.apply_runtime(&record);
        Ok(())
    }

    pub fn persist_runtime(&mut self, absolute_runtime: f64) -> Result<(), String> {
        self.ensure_healthy()?;
        self.validate_runtime(absolute_runtime)?;
        if absolute_runtime != self.total_runtime_secs {
            let record = JournalRecord {
                completed_block: None,
                recheck_ordinal: None,
                total_runtime_secs: absolute_runtime,
                saved_timestamp: timestamp().max(self.last_saved_timestamp),
            };
            self.append_record_with_sync(&record, File::sync_all)?;
            self.apply_runtime(&record);
        }
        self.maybe_compact()
    }

    fn validate_runtime(&self, runtime: f64) -> Result<(), String> {
        if Duration::try_from_secs_f64(runtime).is_err() || runtime < self.total_runtime_secs {
            return Err("Checkpoint runtime must be finite and monotonic".into());
        }
        Ok(())
    }

    fn apply_runtime(&mut self, record: &JournalRecord) {
        self.total_runtime_secs = self.total_runtime_secs.max(record.total_runtime_secs);
        self.last_saved_timestamp = self.last_saved_timestamp.max(record.saved_timestamp);
    }

    fn ensure_healthy(&self) -> Result<(), String> {
        if self.poisoned {
            return Err(
                "Checkpoint journal encountered an I/O failure; restart to validate recovery"
                    .into(),
            );
        }
        Ok(())
    }

    fn append_record_with_sync<F>(&mut self, record: &JournalRecord, sync: F) -> Result<(), String>
    where
        F: FnOnce(&File) -> std::io::Result<()>,
    {
        if let Err(error) = self.ensure_journal_safe() {
            self.poisoned = true;
            return Err(error);
        }
        let bytes = encode_line(record)?;
        if let Err(error) = self
            .journal
            .write_all(&bytes)
            .and_then(|()| sync(&self.journal))
        {
            self.poisoned = true;
            return Err(format!(
                "Failed to write and sync checkpoint journal: {error}"
            ));
        }
        Ok(())
    }

    fn replay_and_repair_tail(&mut self) -> Result<(), String> {
        self.ensure_journal_safe()?;
        let mut bytes = Vec::new();
        self.journal
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read checkpoint journal: {e}"))?;
        let header = JournalHeader::for_scope(self.block_size, self.recheck.as_ref());
        let expected_header = encode_line(&header)?;
        let complete_len = bytes
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |index| index + 1);
        if complete_len == 0 {
            if !expected_header.starts_with(&bytes) {
                return Err(
                    "Checkpoint journal contains an invalid or foreign partial header".into(),
                );
            }
            self.ensure_journal_safe()?;
            self.journal
                .set_len(0)
                .map_err(|e| format!("Failed to repair incomplete journal header: {e}"))?;
            self.write_header()?;
            return Ok(());
        }
        let mut lines = bytes[..complete_len - 1].split(|&byte| byte == b'\n');
        let found_header: JournalHeader =
            decode_line(lines.next().ok_or("Missing journal header")?)?;
        if found_header != header {
            return Err("Checkpoint journal identity does not match this puzzle, range, block size or format".into());
        }
        let mut previous_runtime = None;
        let mut previous_ordinal = None;
        for line in lines {
            let record: JournalRecord = decode_line(line)?;
            if Duration::try_from_secs_f64(record.total_runtime_secs).is_err()
                || previous_runtime.is_some_and(|previous| record.total_runtime_secs < previous)
            {
                return Err("Checkpoint journal runtime is invalid or decreases".into());
            }
            previous_runtime = Some(record.total_runtime_secs);
            if let Some(ordinal) = record.recheck_ordinal {
                let recheck = self
                    .recheck
                    .as_mut()
                    .ok_or("Unscoped journal contains a recheck ordinal")?;
                if recheck.plan.block_at(ordinal) != record.completed_block
                    || ordinal >= recheck.plan.identity().total_blocks
                    || previous_ordinal
                        .is_some_and(|prior: u64| prior.checked_add(1) != Some(ordinal))
                    || ordinal > recheck.completed
                {
                    return Err("Checkpoint recheck ordinal, order or source block mismatch".into());
                }
                previous_ordinal = Some(ordinal);
                if ordinal == recheck.completed {
                    recheck.completed += 1;
                }
            } else if record.completed_block.is_some() && self.next_recheck_block().is_some() {
                return Err(
                    "Global checkpoint block precedes completion of ordered recheck".into(),
                );
            }
            if let Some(index) = record.completed_block {
                if index as u128 >= RANGE_SIZE / self.block_size {
                    return Err("Checkpoint journal block is outside the puzzle range".into());
                }
                if !self.filter.is_scanned(index) {
                    self.filter.mark_scanned(index);
                    self.total_blocks += 1;
                }
            }
            self.apply_runtime(&record);
        }
        if complete_len < bytes.len() {
            // A missing newline means the last frame was never completed. Repair it before
            // any later append, or that interrupted tail would become middle corruption.
            self.ensure_journal_safe()?;
            self.journal
                .set_len(complete_len as u64)
                .and_then(|()| self.journal.sync_all())
                .map_err(|e| format!("Failed to repair incomplete checkpoint journal tail: {e}"))?;
        }
        Ok(())
    }

    fn write_header(&mut self) -> Result<(), String> {
        self.ensure_journal_safe()?;
        let bytes = encode_line(&JournalHeader::for_scope(
            self.block_size,
            self.recheck.as_ref(),
        ))?;
        self.journal
            .write_all(&bytes)
            .and_then(|()| self.journal.sync_all())
            .map_err(|e| format!("Failed to initialize checkpoint journal: {e}"))?;
        sync_parent(&self.journal_path)
    }

    fn maybe_compact(&mut self) -> Result<(), String> {
        if self.last_compaction.elapsed() >= COMPACTION_INTERVAL
            || self
                .journal
                .metadata()
                .map_err(|e| format!("Failed to inspect journal size: {e}"))?
                .len()
                >= COMPACTION_BYTES
        {
            self.compact()?;
        }
        Ok(())
    }

    pub fn compact(&mut self) -> Result<(), String> {
        let progress = self.recheck_progress();
        self.compact_with_snapshot(move |state, path| {
            if let Some(recheck) = progress {
                state.last_saved_timestamp = timestamp().max(state.last_saved_timestamp);
                save_atomic_json(
                    &ScopedSnapshot {
                        format: SCOPED_FORMAT_VERSION,
                        recheck,
                        checkpoint: state.clone(),
                    },
                    path,
                )
            } else {
                state.save_to_file(path)
            }
        })
    }

    fn compact_with_snapshot<F>(&mut self, save: F) -> Result<(), String>
    where
        F: FnOnce(&mut CheckpointState, &Path) -> Result<(), String>,
    {
        self.ensure_healthy()?;
        self.ensure_journal_safe()?;
        if let Some(recheck) = &self.recheck
            && recheck.plan.is_source_file(&self.snapshot_path)?
        {
            return Err("Refusing snapshot replacement of immutable recheck source".into());
        }
        let mut snapshot = self.snapshot();
        // save_to_file syncs both the new JSON file and its parent directory. The old
        // journal must survive until that entire operation has succeeded.
        save(&mut snapshot, &self.snapshot_path)?;
        self.last_saved_timestamp = self.last_saved_timestamp.max(snapshot.last_saved_timestamp);
        self.ensure_journal_safe()?;
        if let Err(error) = self
            .journal
            .set_len(0)
            .and_then(|()| self.journal.sync_all())
        {
            self.poisoned = true;
            return Err(format!(
                "Failed to truncate checkpoint journal after snapshot: {error}"
            ));
        }
        if let Err(error) = self.write_header() {
            self.poisoned = true;
            return Err(error);
        }
        self.last_compaction = Instant::now();
        Ok(())
    }
    fn ensure_journal_safe(&self) -> Result<(), String> {
        require_single_link_regular_file(&self.journal, "checkpoint journal")?;
        if let Some(recheck) = &self.recheck {
            recheck.plan.reject_source_fd(&self.journal)?;
        }
        Ok(())
    }

    fn snapshot(&self) -> CheckpointState {
        CheckpointState {
            puzzle_number: PUZZLE_NUMBER,
            total_keys_tested: self.total_keys_tested(),
            total_blocks_tested: self.total_blocks,
            total_runtime_secs: self.total_runtime_secs,
            scanned_intervals: self.filter.intervals.intervals.clone(),
            last_saved_timestamp: self.last_saved_timestamp,
        }
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("Failed to sync checkpoint directory: {e}"))
}

fn checksum(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|e| format!("Failed to encode checkpoint journal: {e}"))?;
    let digest = checksum(&bytes);
    bytes.push(b'\t');
    bytes.extend_from_slice(digest.as_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_line<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let split = bytes
        .iter()
        .rposition(|&byte| byte == b'\t')
        .ok_or("Checkpoint journal record has no checksum")?;
    let (body, suffix) = bytes.split_at(split);
    if &suffix[1..] != checksum(body).as_bytes() {
        return Err("Checkpoint journal checksum mismatch".into());
    }
    serde_json::from_slice(body)
        .map_err(|e| format!("Invalid complete checkpoint journal record: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BLOCK_SIZE: u128 = 1 << 24;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        dir: PathBuf,
        path: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "p71-store-{}-{}-{}",
                std::process::id(),
                timestamp(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            let path = dir.join("checkpoint.json");
            Self { dir, path }
        }
        fn open(&self) -> CheckpointStore {
            CheckpointStore::open(CheckpointLock::acquire(&self.path).unwrap(), BLOCK_SIZE).unwrap()
        }
        fn raw_journal(&self) -> Vec<u8> {
            fs::read(self.path.with_extension("journal")).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    #[test]
    fn imports_legacy_snapshot_and_small_appends_do_not_rewrite_it() {
        let fixture = Fixture::new();
        let mut legacy = CheckpointState::new();
        legacy.total_blocks_tested = 2;
        legacy.total_keys_tested = 2 * BLOCK_SIZE;
        legacy.total_runtime_secs = 5.0;
        legacy.scanned_intervals = vec![(2, 3)];
        legacy.save_to_file(&fixture.path).unwrap();
        let old_json = fs::read(&fixture.path).unwrap();
        {
            let mut store = fixture.open();
            assert!(store.is_scanned(2));
            store.complete_block(20, 6.0).unwrap();
            store.persist_runtime(7.0).unwrap();
            assert_eq!(store.total_keys_tested(), 3 * BLOCK_SIZE);
            assert_eq!(fs::read(&fixture.path).unwrap(), old_json);
            assert!(fixture.raw_journal().len() < 1024);
        }
        let recovered = fixture.open();
        assert_eq!(recovered.total_blocks_tested(), 3);
        assert_eq!(recovered.total_runtime_secs(), 7.0);
        assert!(recovered.is_scanned(20));
    }

    #[test]
    fn journal_identity_rejects_a_different_block_size() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let lock = CheckpointLock::acquire(&fixture.path).unwrap();
        let result = CheckpointStore::open(lock, BLOCK_SIZE * 2);
        assert!(result.err().unwrap().contains("identity"));
    }

    #[test]
    fn a_partial_expected_header_is_repaired_but_a_foreign_header_is_rejected() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let header = fixture.raw_journal();
        fs::write(
            fixture.path.with_extension("journal"),
            &header[..header.len() - 1],
        )
        .unwrap();
        {
            let mut repaired = fixture.open();
            repaired.complete_block(11, 1.0).unwrap();
        }
        assert!(fixture.open().is_scanned(11));

        let mut foreign = JournalHeader::for_block_size(BLOCK_SIZE);
        foreign.puzzle_number += 1;
        fs::write(
            fixture.path.with_extension("journal"),
            encode_line(&foreign).unwrap(),
        )
        .unwrap();
        let lock = CheckpointLock::acquire(&fixture.path).unwrap();
        assert!(
            CheckpointStore::open(lock, BLOCK_SIZE)
                .err()
                .unwrap()
                .contains("identity")
        );
    }

    #[test]
    fn replay_of_snapshot_and_old_duplicate_journal_is_idempotent() {
        let fixture = Fixture::new();
        let old_journal;
        {
            let mut store = fixture.open();
            store.complete_block(17, 12.0).unwrap();
            store.complete_block(18, 13.0).unwrap();
            old_journal = fixture.raw_journal();
            store.compact().unwrap();
        }
        // Simulate a crash after durable snapshot replacement but before truncation.
        fs::write(fixture.path.with_extension("journal"), old_journal).unwrap();
        let mut recovered = fixture.open();
        assert_eq!(recovered.total_blocks_tested(), 2);
        assert_eq!(recovered.total_runtime_secs(), 13.0);
        recovered.complete_block(17, 14.0).unwrap();
        assert_eq!(recovered.total_blocks_tested(), 2);
        assert_eq!(recovered.total_runtime_secs(), 14.0);
    }

    #[test]
    fn repairs_incomplete_tail_before_appending_a_new_record() {
        let fixture = Fixture::new();
        {
            let mut store = fixture.open();
            store.complete_block(1, 1.0).unwrap();
        }
        OpenOptions::new()
            .append(true)
            .open(fixture.path.with_extension("journal"))
            .unwrap()
            .write_all(b"{\"completed_block\":99,")
            .unwrap();
        {
            let mut recovered = fixture.open();
            assert_eq!(recovered.total_blocks_tested(), 1);
            recovered.complete_block(2, 2.0).unwrap();
        }
        let recovered = fixture.open();
        assert_eq!(recovered.total_blocks_tested(), 2);
        assert!(!recovered.is_scanned(99));
    }

    #[test]
    fn rejects_checksum_corruption_and_complete_malformed_or_empty_records() {
        for corruption in [
            b"bad\n".as_slice(),
            b"\n".as_slice(),
            b"{}\tbad\n".as_slice(),
        ] {
            let fixture = Fixture::new();
            drop(fixture.open());
            OpenOptions::new()
                .append(true)
                .open(fixture.path.with_extension("journal"))
                .unwrap()
                .write_all(corruption)
                .unwrap();
            let lock = CheckpointLock::acquire(&fixture.path).unwrap();
            assert!(CheckpointStore::open(lock, BLOCK_SIZE).is_err());
        }
    }

    #[test]
    fn rejects_a_tampered_valid_json_record_and_middle_corruption() {
        let fixture = Fixture::new();
        {
            let mut store = fixture.open();
            store.complete_block(12, 1.0).unwrap();
            store.complete_block(13, 2.0).unwrap();
        }
        let mut journal = fixture.raw_journal();
        let offset = journal
            .windows(b"\"completed_block\":12".len())
            .position(|s| s == b"\"completed_block\":12")
            .unwrap();
        journal[offset + b"\"completed_block\":".len()] = b'2';
        fs::write(fixture.path.with_extension("journal"), journal).unwrap();
        let lock = CheckpointLock::acquire(&fixture.path).unwrap();
        assert!(
            CheckpointStore::open(lock, BLOCK_SIZE)
                .err()
                .unwrap()
                .contains("checksum")
        );
    }

    #[test]
    fn failed_journal_sync_does_not_publish_completed_work() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let result = store.complete_block_with_sync(7, 4.0, |_| {
            Err(std::io::Error::other("injected sync failure"))
        });
        assert!(result.is_err());
        assert_eq!(store.total_blocks_tested(), 0);
        assert!(!store.is_scanned(7));
        assert_eq!(store.total_runtime_secs(), 0.0);
        assert!(store.persist_runtime(5.0).is_err());
    }

    #[test]
    fn runtime_cannot_decrease_or_become_nonfinite_or_out_of_range() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.persist_runtime(4.0).unwrap();
        let before = fixture.raw_journal();
        for invalid in [3.0, -1.0, f64::NAN, f64::INFINITY, f64::MAX] {
            assert!(store.persist_runtime(invalid).is_err());
        }
        assert_eq!(store.total_runtime_secs(), 4.0);
        assert_eq!(fixture.raw_journal(), before);
    }

    #[test]
    fn snapshot_failure_retains_journal_and_truncation_occurs_only_after_snapshot_save() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.complete_block(27, 8.0).unwrap();
        let before = fixture.raw_journal();
        let result = store.compact_with_snapshot(|_, _| {
            assert_eq!(fixture.raw_journal(), before);
            Err("injected snapshot sync failure".into())
        });
        assert!(result.is_err());
        assert_eq!(fixture.raw_journal(), before);
        drop(store);
        let recovered = fixture.open();
        assert_eq!(recovered.total_blocks_tested(), 1);
        assert!(recovered.is_scanned(27));
    }

    #[test]
    fn writer_lock_excludes_a_second_writer_and_survives_release_as_an_inode() {
        let fixture = Fixture::new();
        let first = CheckpointLock::acquire(&fixture.path).unwrap();
        assert!(CheckpointLock::acquire(&fixture.path).is_err());
        drop(first);
        assert!(fixture.path.with_extension("lock").exists());
        assert!(CheckpointLock::acquire(&fixture.path).is_ok());
    }

    #[test]
    fn completed_range_and_out_of_range_blocks_are_distinguished() {
        let fixture = Fixture::new();
        let lock = CheckpointLock::acquire(&fixture.path).unwrap();
        let mut store = CheckpointStore::open(lock, RANGE_SIZE).unwrap();
        assert!(!store.is_complete());
        assert!(store.complete_block(1, 1.0).is_err());
        store.complete_block(0, 1.0).unwrap();
        assert!(store.is_complete());
        assert_eq!(store.total_keys_tested(), RANGE_SIZE);
    }

    #[test]
    fn a_fully_covered_legacy_snapshot_loads_without_enumerating_its_blocks() {
        let fixture = Fixture::new();
        let total_blocks = (RANGE_SIZE / BLOCK_SIZE) as u64;
        let mut snapshot = CheckpointState::new();
        snapshot.total_blocks_tested = total_blocks;
        snapshot.total_keys_tested = RANGE_SIZE;
        snapshot.scanned_intervals = vec![(0, total_blocks - 1)];
        snapshot.save_to_file(&fixture.path).unwrap();
        let store = fixture.open();
        assert!(store.is_complete());
        assert_eq!(store.total_keys_tested(), RANGE_SIZE);
    }
    fn recheck_fixture() -> (Fixture, RecheckPlan, PathBuf) {
        let fixture = Fixture::new();
        let source = fixture.dir.join("legacy.json");
        let mut legacy = CheckpointState::new();
        legacy.scanned_intervals = vec![(2, 3), (7, 7)];
        legacy.total_blocks_tested = 3;
        legacy.total_keys_tested = 3 * BLOCK_SIZE;
        legacy.save_to_file(&source).unwrap();
        let history_path = fixture.dir.join("copied-history.json");
        let mut history =
            CheckpointStore::open(CheckpointLock::acquire(&history_path).unwrap(), BLOCK_SIZE)
                .unwrap();
        for (runtime, id) in [2, 3, 7, 99].into_iter().enumerate() {
            history.complete_block(id, runtime as f64 + 1.0).unwrap();
        }
        drop(history);
        let plan = RecheckPlan::load(&source, BLOCK_SIZE).unwrap();
        (fixture, plan, history_path)
    }

    fn initialize_scope(fixture: &Fixture, plan: RecheckPlan, history: &Path) -> CheckpointStore {
        CheckpointStore::initialize_recheck(
            CheckpointLock::acquire(&fixture.path).unwrap(),
            BLOCK_SIZE,
            plan,
            history,
        )
        .unwrap()
    }

    fn reopen_scope(fixture: &Fixture, plan: RecheckPlan) -> Result<CheckpointStore, String> {
        CheckpointStore::open_recheck(
            CheckpointLock::acquire(&fixture.path).unwrap(),
            BLOCK_SIZE,
            plan,
        )
    }

    fn progress(store: &CheckpointStore) -> u64 {
        store.recheck_progress().unwrap().completed
    }

    #[test]
    fn scoped_recheck_revisits_global_blocks_in_order_then_counts_only_new_coverage() {
        let (fixture, plan, history) = recheck_fixture();
        let original_source = fs::read(fixture.dir.join("legacy.json")).unwrap();
        {
            let mut store = initialize_scope(&fixture, plan.clone(), &history);
            assert_eq!(store.total_blocks_tested(), 4);
            assert_eq!(progress(&store), 0);
            assert_eq!(store.next_recheck_block(), Some(2));
            assert!(store.is_scanned(2)); // old global history MUST NOT skip this target
            store.persist_runtime(5.0).unwrap();
            assert_eq!(progress(&store), 0);
            for unexpected in [3, 7, 99, 100] {
                assert!(store.complete_block(unexpected, 6.0).is_err());
            }
            for (offset, id) in [2, 3, 7].into_iter().enumerate() {
                assert_eq!(store.next_recheck_block(), Some(id));
                store.complete_block(id, 6.0 + offset as f64).unwrap();
                assert_eq!(progress(&store), offset as u64 + 1);
                assert_eq!(store.total_blocks_tested(), 4);
                assert_eq!(store.total_keys_tested(), 4 * BLOCK_SIZE);
            }
            assert_eq!(store.next_recheck_block(), None);
            store.complete_block(100, 9.0).unwrap();
            assert_eq!(store.total_blocks_tested(), 5);
        }
        let recovered = reopen_scope(&fixture, plan).unwrap();
        assert_eq!(progress(&recovered), 3);
        assert_eq!(recovered.next_recheck_block(), None);
        assert!(recovered.is_scanned(100));
        assert_eq!(recovered.total_blocks_tested(), 5);
        assert_eq!(
            fs::read(fixture.dir.join("legacy.json")).unwrap(),
            original_source
        );
        assert!(!fixture.dir.join("legacy.journal").exists());
        assert!(!fixture.dir.join("legacy.lock").exists());
    }

    #[test]
    fn scoped_fsync_failure_does_not_publish_cursor_or_runtime_and_poison_blocks_writes() {
        let (fixture, plan, history) = recheck_fixture();
        let mut store = initialize_scope(&fixture, plan, &history);
        let error = store
            .complete_block_with_sync(2, 8.0, |_| Err(std::io::Error::other("scoped fsync fault")))
            .unwrap_err();
        assert!(error.contains("scoped fsync fault"));
        assert_eq!(progress(&store), 0);
        assert_eq!(store.next_recheck_block(), Some(2));
        assert_eq!(store.total_blocks_tested(), 4);
        assert_eq!(store.total_runtime_secs(), 4.0);
        assert!(store.complete_block(2, 9.0).is_err());
        assert!(store.persist_runtime(9.0).is_err());
        assert!(store.compact().is_err());
    }

    #[test]
    fn scoped_restart_repairs_partial_recheck_tail_without_advancing_it() {
        let (fixture, plan, history) = recheck_fixture();
        {
            let mut store = initialize_scope(&fixture, plan.clone(), &history);
            store.complete_block(2, 5.0).unwrap();
        }
        let partial = encode_line(&JournalRecord {
            completed_block: Some(3),
            recheck_ordinal: Some(1),
            total_runtime_secs: 6.0,
            saved_timestamp: 10,
        })
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(fixture.path.with_extension("journal"))
            .unwrap()
            .write_all(&partial[..partial.len() - 1])
            .unwrap();
        {
            let mut store = reopen_scope(&fixture, plan.clone()).unwrap();
            assert_eq!(progress(&store), 1);
            assert_eq!(store.next_recheck_block(), Some(3));
            store.complete_block(3, 7.0).unwrap();
        }
        let recovered = reopen_scope(&fixture, plan).unwrap();
        assert_eq!(progress(&recovered), 2);
        assert_eq!(recovered.next_recheck_block(), Some(7));
    }

    #[test]
    fn scoped_compaction_replays_old_journal_idempotently_and_legacy_parser_rejects_wrapper() {
        let (fixture, plan, history) = recheck_fixture();
        let old_journal;
        {
            let mut store = initialize_scope(&fixture, plan.clone(), &history);
            store.complete_block(2, 5.0).unwrap();
            store.complete_block(3, 6.0).unwrap();
            old_journal = fixture.raw_journal();
            store.compact().unwrap();
        }
        assert!(CheckpointState::load_from_file(&fixture.path).is_err());
        assert!(
            CheckpointStore::open(CheckpointLock::acquire(&fixture.path).unwrap(), BLOCK_SIZE)
                .is_err()
        );
        fs::write(fixture.path.with_extension("journal"), old_journal).unwrap();
        {
            let mut store = reopen_scope(&fixture, plan.clone()).unwrap();
            assert_eq!(progress(&store), 2);
            assert_eq!(store.total_blocks_tested(), 4);
            store.complete_block(7, 7.0).unwrap();
            store.complete_block(100, 8.0).unwrap();
            let post_phase_journal = fixture.raw_journal();
            store.compact().unwrap();
            fs::write(fixture.path.with_extension("journal"), post_phase_journal).unwrap();
        }
        let recovered = reopen_scope(&fixture, plan).unwrap();
        assert_eq!(progress(&recovered), 3);
        assert_eq!(recovered.total_blocks_tested(), 5);
    }

    #[test]
    fn scoped_compaction_empty_journal_repair_retains_scope_and_cursor() {
        let (fixture, plan, history) = recheck_fixture();
        {
            let mut store = initialize_scope(&fixture, plan.clone(), &history);
            store.complete_block(2, 5.0).unwrap();
            store.compact().unwrap();
        }
        fs::write(fixture.path.with_extension("journal"), b"").unwrap();
        let store = reopen_scope(&fixture, plan).unwrap();
        assert_eq!(progress(&store), 1);
        assert_eq!(store.next_recheck_block(), Some(3));
        let header: JournalHeader =
            decode_line(fixture.raw_journal().strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(header.format, 2);
        assert!(header.recheck.is_some());
        assert!(CheckpointState::load_from_file(&fixture.path).is_err());
    }

    #[test]
    fn scoped_journal_rejects_skipped_duplicate_wrong_block_and_premature_global_records() {
        let cases = [
            vec![(Some(2), Some(1))], // skipped first ordinal and wrong source mapping
            vec![(Some(3), Some(0))], // wrong source block
            vec![(Some(2), Some(0)), (Some(2), Some(0))], // duplicate
            vec![(Some(2), Some(0)), (Some(7), Some(2))], // ordinal gap
            vec![(Some(100), None)],  // new global block while recheck pending
            vec![(None, Some(0))],    // runtime cannot be a certified block
            vec![(None, Some(3))],    // out-of-range ordinal, no source mapping
        ];
        for records in cases {
            let (fixture, plan, history) = recheck_fixture();
            drop(initialize_scope(&fixture, plan.clone(), &history));
            let mut bytes = fixture.raw_journal();
            for (n, (completed_block, recheck_ordinal)) in records.into_iter().enumerate() {
                bytes.extend(
                    encode_line(&JournalRecord {
                        completed_block,
                        recheck_ordinal,
                        total_runtime_secs: 5.0 + n as f64,
                        saved_timestamp: 100,
                    })
                    .unwrap(),
                );
            }
            fs::write(fixture.path.with_extension("journal"), bytes).unwrap();
            assert!(reopen_scope(&fixture, plan).is_err());
        }
    }

    #[test]
    fn scoped_open_requires_matching_source_format_identity_cursor_and_existing_pair() {
        for field in [
            "format",
            "cursor",
            "source",
            "target",
            "kernel",
            "range",
            "blocksize",
            "puzzle",
            "coverage",
            "missing-journal",
        ] {
            let (fixture, plan, history) = recheck_fixture();
            drop(initialize_scope(&fixture, plan.clone(), &history));
            let mut snapshot: ScopedSnapshot =
                serde_json::from_slice(&fs::read(&fixture.path).unwrap()).unwrap();
            match field {
                "format" => snapshot.format = 1,
                "cursor" => snapshot.recheck.completed = 4,
                "source" => snapshot.recheck.identity.source_sha256 = "foreign".into(),
                "target" => snapshot.recheck.identity.target_hash160 = "foreign".into(),
                "kernel" => snapshot.recheck.identity.kernel_sha256 = "foreign".into(),
                "range" => snapshot.recheck.identity.range_max = "0".into(),
                "blocksize" => snapshot.recheck.identity.block_size = "128".into(),
                "puzzle" => snapshot.checkpoint.puzzle_number = 70,
                "coverage" => {
                    snapshot.checkpoint.scanned_intervals = vec![(99, 99)];
                    snapshot.checkpoint.total_blocks_tested = 1;
                    snapshot.checkpoint.total_keys_tested = BLOCK_SIZE;
                }
                "missing-journal" => {
                    fs::remove_file(fixture.path.with_extension("journal")).unwrap()
                }
                _ => unreachable!(),
            }
            fs::write(&fixture.path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
            assert!(reopen_scope(&fixture, plan).is_err(), "accepted {field}");
        }
    }

    #[test]
    fn scoped_snapshot_and_journal_both_bind_source_identity() {
        let (fixture, plan, history) = recheck_fixture();
        drop(initialize_scope(&fixture, plan.clone(), &history));
        let mut header = JournalHeader::for_block_size(BLOCK_SIZE);
        header.format = SCOPED_FORMAT_VERSION;
        header.recheck = Some(plan.identity().clone());
        header.recheck.as_mut().unwrap().kernel_sha256 = "wrong-kernel".into();
        fs::write(
            fixture.path.with_extension("journal"),
            encode_line(&header).unwrap(),
        )
        .unwrap();
        assert!(
            reopen_scope(&fixture, plan)
                .err()
                .unwrap()
                .contains("identity")
        );
    }

    #[test]
    fn scoped_open_never_treats_global_old_history_equal_to_source_as_recheck_progress() {
        let (fixture, plan, history) = recheck_fixture();
        let source = fixture.dir.join("legacy.json");
        fs::copy(&source, &history).unwrap();
        fs::write(
            history.with_extension("journal"),
            encode_line(&JournalHeader::for_block_size(BLOCK_SIZE)).unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read(&source).unwrap(), fs::read(&history).unwrap());
        assert!(
            CheckpointStore::open_recheck(
                CheckpointLock::acquire(&history).unwrap(),
                BLOCK_SIZE,
                plan.clone()
            )
            .is_err()
        );
        let empty = Fixture::new();
        assert!(reopen_scope(&empty, plan).is_err());
        assert!(!empty.path.exists());
        assert!(!empty.path.with_extension("journal").exists());
        drop(fixture);
    }

    #[test]
    fn scoped_initialization_requires_existing_pair_and_full_source_coverage_before_writes() {
        for damage in [
            "missing-snapshot",
            "missing-journal",
            "missing-source-block",
        ] {
            let (fixture, plan, history) = recheck_fixture();
            match damage {
                "missing-snapshot" => fs::remove_file(&history).unwrap(),
                "missing-journal" => fs::remove_file(history.with_extension("journal")).unwrap(),
                "missing-source-block" => {
                    let mut incomplete = CheckpointState::new();
                    incomplete.total_blocks_tested = 1;
                    incomplete.total_keys_tested = BLOCK_SIZE;
                    incomplete.scanned_intervals = vec![(99, 99)];
                    incomplete.save_to_file(&history).unwrap();
                    fs::write(
                        history.with_extension("journal"),
                        encode_line(&JournalHeader::for_block_size(BLOCK_SIZE)).unwrap(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let result = CheckpointStore::initialize_recheck(
                CheckpointLock::acquire(&fixture.path).unwrap(),
                BLOCK_SIZE,
                plan,
                &history,
            );
            assert!(result.is_err(), "accepted {damage}");
            assert!(!fixture.path.exists());
            assert!(!fixture.path.with_extension("journal").exists());
        }
    }

    #[test]
    fn scoped_initialization_rejects_archive_aliases_by_canonical_path_and_inode() {
        for alias in ["source", "symlink", "hardlink", "journal-hardlink"] {
            let (fixture, plan, history) = recheck_fixture();
            let source = fixture.dir.join("legacy.json");
            let before = fs::read(&source).unwrap();
            let input = match alias {
                "source" => source.clone(),
                "symlink" => {
                    let alias = fixture.dir.join("alias.json");
                    std::os::unix::fs::symlink(&source, &alias).unwrap();
                    alias
                }
                "hardlink" => {
                    let alias = fixture.dir.join("alias.json");
                    fs::hard_link(&source, &alias).unwrap();
                    alias
                }
                "journal-hardlink" => {
                    fs::remove_file(history.with_extension("journal")).unwrap();
                    fs::hard_link(&source, history.with_extension("journal")).unwrap();
                    history.clone()
                }
                _ => unreachable!(),
            };
            if alias != "journal-hardlink" {
                fs::write(
                    input.with_extension("journal"),
                    encode_line(&JournalHeader::for_block_size(BLOCK_SIZE)).unwrap(),
                )
                .unwrap();
            }
            fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
            let had_lock = input.with_extension("lock").exists();
            let error = CheckpointStore::initialize_recheck(
                CheckpointLock::acquire(&fixture.path).unwrap(),
                BLOCK_SIZE,
                plan,
                &input,
            )
            .err()
            .unwrap();
            assert!(
                error.contains("must not alias"),
                "wrong rejection for {alias}: {error}"
            );
            assert_eq!(fs::read(&source).unwrap(), before);
            assert_eq!(
                fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o400
            );
            assert!(!fixture.path.exists());
            assert_eq!(input.with_extension("lock").exists(), had_lock);
        }
    }

    #[test]
    fn scoped_pending_recheck_prevents_complete_even_when_global_range_is_full() {
        let fixture = Fixture::new();
        let source = fixture.dir.join("legacy.json");
        let history = fixture.dir.join("history.json");
        let mut snapshot = CheckpointState::new();
        snapshot.total_blocks_tested = 1;
        snapshot.total_keys_tested = RANGE_SIZE;
        snapshot.scanned_intervals = vec![(0, 0)];
        snapshot.save_to_file(&source).unwrap();
        snapshot.save_to_file(&history).unwrap();
        drop(
            CheckpointStore::open(CheckpointLock::acquire(&history).unwrap(), RANGE_SIZE).unwrap(),
        );
        let plan = RecheckPlan::load(&source, RANGE_SIZE).unwrap();
        let mut store = CheckpointStore::initialize_recheck(
            CheckpointLock::acquire(&fixture.path).unwrap(),
            RANGE_SIZE,
            plan,
            history,
        )
        .unwrap();
        assert!(!store.is_complete());
        assert_eq!(store.next_recheck_block(), Some(0));
        store.complete_block(0, 1.0).unwrap();
        assert!(store.is_complete());
        assert_eq!(store.total_keys_tested(), RANGE_SIZE);
    }
    #[test]
    fn scoped_resume_rejects_changed_source_bytes_even_when_coverage_is_identical() {
        let (fixture, plan, history) = recheck_fixture();
        drop(initialize_scope(&fixture, plan, &history));
        let source = fixture.dir.join("legacy.json");
        let mut bytes = fs::read(&source).unwrap();
        bytes.push(b'\n');
        fs::write(&source, bytes).unwrap();
        let changed = RecheckPlan::load(&source, BLOCK_SIZE).unwrap();
        assert!(
            reopen_scope(&fixture, changed)
                .err()
                .unwrap()
                .contains("identity")
        );
    }

    #[test]
    fn unscoped_journal_rejects_any_recheck_ordinal_without_promoting_coverage() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let mut journal = fixture.raw_journal();
        journal.extend(
            encode_line(&JournalRecord {
                completed_block: Some(2),
                recheck_ordinal: Some(0),
                total_runtime_secs: 1.0,
                saved_timestamp: 100,
            })
            .unwrap(),
        );
        fs::write(fixture.path.with_extension("journal"), journal).unwrap();
        assert!(
            CheckpointStore::open(CheckpointLock::acquire(&fixture.path).unwrap(), BLOCK_SIZE)
                .err()
                .unwrap()
                .contains("Unscoped")
        );
        assert_eq!(
            CheckpointState::load_from_file(&fixture.path)
                .unwrap()
                .total_blocks_tested,
            0
        );
    }
    #[test]
    fn scoped_initialization_sets_private_permissions_before_reopen_under_umask_0400() {
        const CHILD: &str = "PUZZLE71_RECHECK_UMASK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let (fixture, plan, history) = recheck_fixture();
            let lock = CheckpointLock::acquire(&fixture.path).unwrap();
            // SAFETY: this subprocess runs only this exact test, so no concurrent
            // test can create files under the temporary process-wide umask.
            let old_mask = unsafe { libc::umask(0o400) };
            let result = CheckpointStore::initialize_recheck(lock, BLOCK_SIZE, plan, &history);
            // SAFETY: restore before any assertion or fixture cleanup.
            unsafe { libc::umask(old_mask) };
            assert!(
                result.is_ok(),
                "scope must initialize under umask0400: {:?}",
                result.err()
            );
            for path in [&fixture.path, &fixture.path.with_extension("journal")] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "search::store::tests::scoped_initialization_sets_private_permissions_before_reopen_under_umask_0400"])
            .env(CHILD, "1").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "umask0400 child failed scoped initialization"
                );
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("umask0400 child blocked initialization");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    #[test]
    fn scoped_compaction_preserves_archive_bytes_and_mode_behind_existing_temp_hardlink() {
        let (fixture, plan, history) = recheck_fixture();
        drop(initialize_scope(&fixture, plan.clone(), &history));
        let source = fixture.dir.join("legacy.json");
        let before = fs::read(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let foreign_temp = fixture.path.with_extension("tmp");
        fs::hard_link(&source, &foreign_temp).unwrap();
        let before_inode = fs::metadata(&foreign_temp).unwrap().ino();
        let mut store = reopen_scope(&fixture, plan).unwrap();
        let result = store.compact();
        assert_eq!(
            fs::read(&source).unwrap(),
            before,
            "foreign .tmp hardlink must never be truncated"
        );
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(&foreign_temp).unwrap().ino(),
            before_inode,
            "foreign temp must not be removed"
        );
        assert!(
            result.is_ok(),
            "own fresh temporary file should permit compaction: {result:?}"
        );
    }

    #[test]
    fn scoped_compaction_temp_symlink_cannot_change_archive_bytes_or_mode() {
        let (fixture, plan, history) = recheck_fixture();
        drop(initialize_scope(&fixture, plan.clone(), &history));
        let source = fixture.dir.join("legacy.json");
        let before = fs::read(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let foreign_temp = fixture.path.with_extension("tmp");
        std::os::unix::fs::symlink(&source, &foreign_temp).unwrap();
        let mut store = reopen_scope(&fixture, plan).unwrap();
        let _result = store.compact(); // old O_NOFOLLOW safely rejects; new own temp may succeed
        assert_eq!(fs::read(&source).unwrap(), before);
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read_link(&foreign_temp).unwrap(), source);
    }

    #[test]
    fn scoped_history_lock_alias_is_rejected_before_archive_permission_change() {
        for symbolic in [false, true] {
            let (fixture, plan, history) = recheck_fixture();
            let source = fixture.dir.join("legacy.json");
            let before = fs::read(&source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
            let lock_path = history.with_extension("lock");
            fs::remove_file(&lock_path).unwrap();
            if symbolic {
                std::os::unix::fs::symlink(&source, &lock_path).unwrap();
            } else {
                fs::hard_link(&source, &lock_path).unwrap();
            }
            let result = CheckpointStore::initialize_recheck(
                CheckpointLock::acquire(&fixture.path).unwrap(),
                BLOCK_SIZE,
                plan,
                &history,
            );
            assert_eq!(
                fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o640,
                "archive mode changed via copied-history lock"
            );
            assert_eq!(fs::read(&source).unwrap(), before);
            assert!(result.is_err());
            assert!(!fixture.path.exists());
            assert!(!fixture.path.with_extension("journal").exists());
        }
    }

    #[test]
    fn scoped_destination_lock_alias_is_rejected_before_archive_permission_change() {
        for symbolic in [false, true] {
            let (fixture, plan, history) = recheck_fixture();
            drop(initialize_scope(&fixture, plan.clone(), &history));
            let source = fixture.dir.join("legacy.json");
            let before = fs::read(&source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
            let lock_path = fixture.path.with_extension("lock");
            fs::remove_file(&lock_path).unwrap();
            if symbolic {
                std::os::unix::fs::symlink(&source, &lock_path).unwrap();
            } else {
                fs::hard_link(&source, &lock_path).unwrap();
            }
            let result = CheckpointLock::acquire(&fixture.path)
                .and_then(|lock| CheckpointStore::open_recheck(lock, BLOCK_SIZE, plan));
            assert_eq!(
                fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o640,
                "archive mode changed via destination lock"
            );
            assert_eq!(fs::read(&source).unwrap(), before);
            assert!(result.is_err());
        }
    }

    #[test]
    fn scoped_resume_journal_alias_is_rejected_before_archive_permission_change() {
        for symbolic in [false, true] {
            let (fixture, plan, history) = recheck_fixture();
            drop(initialize_scope(&fixture, plan.clone(), &history));
            let source = fixture.dir.join("legacy.json");
            let before = fs::read(&source).unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
            let journal_path = fixture.path.with_extension("journal");
            fs::remove_file(&journal_path).unwrap();
            if symbolic {
                std::os::unix::fs::symlink(&source, &journal_path).unwrap();
            } else {
                fs::hard_link(&source, &journal_path).unwrap();
            }
            let result = reopen_scope(&fixture, plan);
            assert_eq!(
                fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o640,
                "archive mode changed via resume journal before parser rejection"
            );
            assert_eq!(fs::read(&source).unwrap(), before);
            assert!(result.is_err());
        }
    }
    #[test]
    fn scoped_lock_acquisition_rejects_direct_source_path_with_only_one_link() {
        let fixture = Fixture::new();
        let source = fixture.path.with_extension("lock");
        let mut checkpoint = CheckpointState::new();
        checkpoint.scanned_intervals = vec![(2, 2)];
        checkpoint.total_blocks_tested = 1;
        checkpoint.total_keys_tested = BLOCK_SIZE;
        checkpoint.save_to_file(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::read(&source).unwrap();
        let plan = RecheckPlan::load(&source, BLOCK_SIZE).unwrap();
        assert_eq!(fs::metadata(&source).unwrap().nlink(), 1);
        let result = CheckpointLock::acquire_recheck(&fixture.path, &plan);
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read(&source).unwrap(), before);
        assert!(result.err().unwrap().contains("source"));
    }

    #[test]
    fn scoped_resume_rejects_source_inode_moved_to_journal_even_with_one_link() {
        let (fixture, plan, history) = recheck_fixture();
        drop(initialize_scope(&fixture, plan.clone(), &history));
        let source = fixture.dir.join("legacy.json");
        let before = fs::read(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let journal = fixture.path.with_extension("journal");
        fs::remove_file(&journal).unwrap();
        fs::rename(&source, &journal).unwrap();
        assert_eq!(fs::metadata(&journal).unwrap().nlink(), 1);
        let result = reopen_scope(&fixture, plan);
        assert_eq!(
            fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read(&journal).unwrap(), before);
        assert!(result.err().unwrap().contains("source"));
    }

    #[test]
    fn scoped_journal_linked_after_open_cannot_be_appended_or_truncated() {
        let (fixture, plan, history) = recheck_fixture();
        let mut store = initialize_scope(&fixture, plan, &history);
        let before = fixture.raw_journal();
        let protected = fixture.dir.join("protected-journal-copy");
        fs::hard_link(fixture.path.with_extension("journal"), &protected).unwrap();
        assert!(store.complete_block(2, 5.0).is_err());
        assert_eq!(progress(&store), 0);
        assert_eq!(fixture.raw_journal(), before);
        assert_eq!(fs::read(&protected).unwrap(), before);
        assert!(store.compact().is_err());
        assert_eq!(fs::read(&protected).unwrap(), before);
    }
    #[test]
    fn scoped_compaction_rejects_source_inode_moved_to_snapshot_target() {
        let (fixture, plan, history) = recheck_fixture();
        let mut store = initialize_scope(&fixture, plan, &history);
        let source = fixture.dir.join("legacy.json");
        let before = fs::read(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let inode = fs::metadata(&source).unwrap().ino();
        fs::rename(&source, &fixture.path).unwrap();
        assert_eq!(fs::metadata(&fixture.path).unwrap().nlink(), 1);
        let journal_before = fixture.raw_journal();
        let result = store.compact();
        assert!(
            fs::read(&fixture.path).unwrap() == before,
            "snapshot rename must not replace the last link of the source inode"
        );
        assert_eq!(fs::metadata(&fixture.path).unwrap().ino(), inode);
        assert_eq!(
            fs::metadata(&fixture.path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(result.err().unwrap().contains("source"));
        assert_eq!(fixture.raw_journal(), journal_before);
        assert_eq!(progress(&store), 0);
        assert_eq!(store.total_blocks_tested(), 4);
    }
}
