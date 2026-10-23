//! Durable incremental progress, with compatible JSON snapshots and a checksummed journal.

use crate::crypto::sha256::sha256;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_MAX, RANGE_MIN, RANGE_SIZE};
use crate::search::checkpoint::CheckpointState;
use crate::search::duplicate_filter::{DuplicateFilter, IntervalSet};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FORMAT_VERSION: u32 = 1;
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
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().ok_or("Checkpoint path needs a filename")?;
        let snapshot_path = fs::canonicalize(parent)
            .map_err(|e| format!("Failed to resolve checkpoint directory: {e}"))?
            .join(file_name);
        let lock_path = snapshot_path.with_extension("lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| format!("Failed to open checkpoint writer lock: {e}"))?;
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
}

impl JournalHeader {
    fn for_block_size(block_size: u128) -> Self {
        Self {
            format: FORMAT_VERSION,
            puzzle_number: PUZZLE_NUMBER,
            range_min: RANGE_MIN.to_string(),
            range_max: RANGE_MAX.to_string(),
            block_size: block_size.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    completed_block: Option<u64>,
    total_runtime_secs: f64,
    saved_timestamp: u64,
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
    _lock: CheckpointLock,
}

impl CheckpointStore {
    pub fn open(lock: CheckpointLock, block_size: u128) -> Result<Self, String> {
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
        let mut snapshot = CheckpointState::load_from_file(&lock.snapshot_path)?;
        snapshot.validate_for_block_size(block_size)?;
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
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&journal_path)
            .map_err(|e| format!("Failed to open checkpoint journal: {e}"))?;
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
        self.total_blocks as u128 == RANGE_SIZE / self.block_size
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
        if self.filter.is_scanned(block_index) {
            return self.persist_runtime(absolute_runtime);
        }
        let record = JournalRecord {
            completed_block: Some(block_index),
            total_runtime_secs: absolute_runtime,
            saved_timestamp: timestamp().max(self.last_saved_timestamp),
        };
        self.append_record_with_sync(&record, sync)?;
        // A completed block becomes visible only after its full record has been synced.
        self.filter.mark_scanned(block_index);
        self.total_blocks += 1;
        self.apply_runtime(&record);
        Ok(())
    }

    pub fn persist_runtime(&mut self, absolute_runtime: f64) -> Result<(), String> {
        self.ensure_healthy()?;
        self.validate_runtime(absolute_runtime)?;
        if absolute_runtime != self.total_runtime_secs {
            let record = JournalRecord {
                completed_block: None,
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
        let mut bytes = Vec::new();
        self.journal
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read checkpoint journal: {e}"))?;
        let header = JournalHeader::for_block_size(self.block_size);
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
        for line in lines {
            let record: JournalRecord = decode_line(line)?;
            if Duration::try_from_secs_f64(record.total_runtime_secs).is_err()
                || previous_runtime.is_some_and(|previous| record.total_runtime_secs < previous)
            {
                return Err("Checkpoint journal runtime is invalid or decreases".into());
            }
            previous_runtime = Some(record.total_runtime_secs);
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
            self.journal
                .set_len(complete_len as u64)
                .and_then(|()| self.journal.sync_all())
                .map_err(|e| format!("Failed to repair incomplete checkpoint journal tail: {e}"))?;
        }
        Ok(())
    }

    fn write_header(&mut self) -> Result<(), String> {
        let bytes = encode_line(&JournalHeader::for_block_size(self.block_size))?;
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
        self.compact_with_snapshot(|state, path| state.save_to_file(path))
    }

    fn compact_with_snapshot<F>(&mut self, save: F) -> Result<(), String>
    where
        F: FnOnce(&mut CheckpointState, &Path) -> Result<(), String>,
    {
        self.ensure_healthy()?;
        let mut snapshot = CheckpointState {
            puzzle_number: PUZZLE_NUMBER,
            total_keys_tested: self.total_keys_tested(),
            total_blocks_tested: self.total_blocks,
            total_runtime_secs: self.total_runtime_secs,
            scanned_intervals: self.filter.intervals.intervals.clone(),
            last_saved_timestamp: self.last_saved_timestamp,
        };
        // save_to_file syncs both the new JSON file and its parent directory. The old
        // journal must survive until that entire operation has succeeded.
        save(&mut snapshot, &self.snapshot_path)?;
        self.last_saved_timestamp = self.last_saved_timestamp.max(snapshot.last_saved_timestamp);
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
}
