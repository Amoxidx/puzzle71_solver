//! Atomic Checkpointing and State Persistence.
//!
//! Features:
//! - Atomic write via temporary file + fsync + atomic rename.
//! - Strict Unix permissions (0600: read/write owner only).
//! - Clean recovery on crash or shutdown.

use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_SIZE};
use crate::search::duplicate_filter::IntervalSet;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_CHECKPOINT_FILE: &str = "puzzle71_checkpoint.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointState {
    pub puzzle_number: u32,
    pub total_keys_tested: u128,
    pub total_blocks_tested: u64,
    pub total_runtime_secs: f64,
    pub scanned_intervals: Vec<(u64, u64)>,
    pub last_saved_timestamp: u64,
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointState {
    pub fn new() -> Self {
        Self {
            puzzle_number: PUZZLE_NUMBER,
            total_keys_tested: 0,
            total_blocks_tested: 0,
            total_runtime_secs: 0.0,
            scanned_intervals: Vec::new(),
            last_saved_timestamp: current_timestamp(),
        }
    }

    pub fn save_to_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        self.last_saved_timestamp = current_timestamp().max(self.last_saved_timestamp);
        save_atomic_json(self, path)
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::new());
        }

        let mut file =
            File::open(path).map_err(|e| format!("Failed to open checkpoint file: {}", e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| format!("Failed to read checkpoint file: {}", e))?;

        Self::from_json(content.as_bytes())
    }

    pub(crate) fn from_json(content: &[u8]) -> Result<Self, String> {
        let state: CheckpointState = serde_json::from_slice(content)
            .map_err(|e| format!("Failed to parse checkpoint JSON: {e}"))?;

        if state.puzzle_number != PUZZLE_NUMBER {
            return Err(format!(
                "Checkpoint is for Puzzle #{}, but solver is configured for Puzzle #{}",
                state.puzzle_number, PUZZLE_NUMBER
            ));
        }

        Ok(state)
    }

    pub fn to_interval_set(&self) -> IntervalSet {
        let mut set = IntervalSet::new();
        set.intervals = self.scanned_intervals.clone();
        set
    }

    pub fn validate_for_block_size(&self, block_size: u128) -> Result<(), String> {
        if block_size == 0 {
            return Err("Checkpoint validation requires a non-zero block size".to_string());
        }

        if !self.total_runtime_secs.is_finite() || self.total_runtime_secs < 0.0 {
            return Err("Checkpoint runtime must be finite and non-negative".to_string());
        }

        let available_blocks_u128 = RANGE_SIZE / block_size;
        if available_blocks_u128 > u64::MAX as u128 {
            return Err(
                "Block size creates more block indices than the u64 format supports".to_string(),
            );
        }
        let available_blocks = available_blocks_u128 as u64;
        let mut covered_blocks = 0u64;
        let mut previous_end = None;
        for &(start, end) in &self.scanned_intervals {
            if start > end {
                return Err(format!(
                    "Checkpoint interval is reversed: {}..{}",
                    start, end
                ));
            }
            if end >= available_blocks {
                return Err(format!(
                    "Checkpoint interval ends outside the keyspace: {} >= {}",
                    end, available_blocks
                ));
            }
            if previous_end.is_some_and(|previous| start <= previous) {
                return Err("Checkpoint intervals must be sorted and non-overlapping".to_string());
            }
            covered_blocks = covered_blocks
                .checked_add(end - start + 1)
                .ok_or_else(|| "Checkpoint block count overflow".to_string())?;
            previous_end = Some(end);
        }
        if self.total_blocks_tested != covered_blocks {
            return Err(format!(
                "Checkpoint block count mismatch: counter={}, intervals={}",
                self.total_blocks_tested, covered_blocks
            ));
        }

        let expected_keys = (covered_blocks as u128)
            .checked_mul(block_size)
            .ok_or_else(|| "Checkpoint key count overflow".to_string())?;
        if self.total_keys_tested != expected_keys {
            return Err(format!(
                "Checkpoint contains partial or inconsistent blocks: keys={}, expected={}",
                self.total_keys_tested, expected_keys
            ));
        }

        Ok(())
    }
}

/// Shared atomic writer for the legacy state and explicitly versioned scoped snapshots.
pub(crate) fn save_atomic_json(value: &impl Serialize, path: &Path) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("Checkpoint serialization error: {e}"))?;
    let mut temporary = CheckpointTemporary::create(path)?;
    temporary.ensure_owned()?;
    temporary
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to secure checkpoint temporary file: {e}"))?;
    temporary.ensure_owned()?;
    temporary
        .file
        .write_all(&json)
        .and_then(|()| temporary.file.sync_all())
        .map_err(|e| format!("Failed to write and sync checkpoint: {e}"))?;
    temporary.ensure_owned()?;
    std::fs::rename(&temporary.path, path)
        .map_err(|e| format!("Failed to atomically rename checkpoint: {e}"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("Failed to sync checkpoint directory: {e}"))
}

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

struct CheckpointTemporary {
    path: PathBuf,
    file: File,
}

impl CheckpointTemporary {
    fn create(destination: &Path) -> Result<Self, String> {
        for _ in 0..128 {
            let serial = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let path = destination.with_extension(format!("tmp.{}.{serial}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "Failed to create owned checkpoint temporary file: {error}"
                    ));
                }
            }
        }
        Err("Checkpoint temporary filename collision limit reached".into())
    }

    fn ensure_owned(&self) -> Result<(), String> {
        require_single_link_regular_file(&self.file, "checkpoint temporary file")?;
        let owned = self
            .file
            .metadata()
            .map_err(|e| format!("Failed to inspect owned checkpoint temporary file: {e}"))?;
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(|e| format!("Failed to inspect checkpoint temporary pathname: {e}"))?;
        if !current.is_file() || (current.dev(), current.ino()) != (owned.dev(), owned.ino()) {
            return Err("Checkpoint temporary pathname no longer names its owned file".into());
        }
        Ok(())
    }
}

impl Drop for CheckpointTemporary {
    fn drop(&mut self) {
        // Remove only the pathname still naming our exclusively created inode.
        // Same-user processes may still race these checks; this is not a sandbox.
        if self.ensure_owned().is_ok() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn require_single_link_regular_file(file: &File, label: &str) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to inspect {label}: {e}"))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(format!(
            "Refusing {label}: expected an exclusive regular file with one link"
        ));
    }
    Ok(())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn temp_checkpoint_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "puzzle71-checkpoint-{}-{}-{}.json",
            label,
            std::process::id(),
            current_timestamp()
        ))
    }

    #[test]
    fn rejects_partial_block_counters() {
        let mut state = CheckpointState::new();
        state.total_blocks_tested = 1;
        state.total_keys_tested = 99;
        state.scanned_intervals = vec![(7, 7)];

        let error = state.validate_for_block_size(100).unwrap_err();
        assert!(error.contains("partial or inconsistent"));
    }

    #[test]
    fn accepts_exact_completed_blocks() {
        let mut state = CheckpointState::new();
        state.total_blocks_tested = 2;
        state.total_keys_tested = 200;
        state.scanned_intervals = vec![(7, 8)];

        assert!(state.validate_for_block_size(100).is_ok());
    }

    #[test]
    fn rejects_overlapping_or_out_of_range_intervals() {
        let block_size = 1u128 << 64;
        let mut state = CheckpointState::new();
        state.total_blocks_tested = 3;
        state.total_keys_tested = 3 * block_size;
        state.scanned_intervals = vec![(1, 2), (2, 2)];
        assert!(state.validate_for_block_size(block_size).is_err());

        state.scanned_intervals = vec![(64, 64)];
        state.total_blocks_tested = 1;
        state.total_keys_tested = block_size;
        assert!(state.validate_for_block_size(block_size).is_err());
    }

    #[test]
    fn save_updates_timestamp_and_enforces_owner_only_permissions() {
        let path = temp_checkpoint_path("permissions");
        let mut state = CheckpointState::new();
        state.last_saved_timestamp = 0;
        state.save_to_file(&path).expect("save checkpoint");

        let metadata = std::fs::metadata(&path).expect("checkpoint metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(state.last_saved_timestamp > 0);
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH + Duration::from_secs(state.last_saved_timestamp))
                .expect("timestamp not in future")
                < Duration::from_secs(5)
        );

        std::fs::remove_file(path).expect("remove checkpoint fixture");
    }
    #[test]
    fn existing_foreign_temp_names_are_never_truncated_or_removed() {
        const CHILD: &str = "PUZZLE71_CHECKPOINT_TEMP_COLLISION_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            let dir = std::path::PathBuf::from(dir);
            let source = dir.join("immutable-archive");
            let destination = dir.join("snapshot.json");
            let legacy_temp = destination.with_extension("tmp");
            let first_candidate =
                destination.with_extension(format!("tmp.{}.0", std::process::id()));
            std::fs::hard_link(&source, &legacy_temp).unwrap();
            std::fs::hard_link(&source, &first_candidate).unwrap();
            let before = std::fs::read(&source).unwrap();
            let mut state = CheckpointState::new();
            let result = state.save_to_file(&destination);
            assert!(
                std::fs::read(&source).unwrap() == before,
                "existing temporary hardlink changed archive bytes"
            );
            assert_eq!(
                std::fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o640
            );
            for foreign in [&legacy_temp, &first_candidate] {
                assert_eq!(
                    std::fs::metadata(foreign).unwrap().ino(),
                    std::fs::metadata(&source).unwrap().ino()
                );
            }
            assert!(
                result.is_ok(),
                "fresh exclusive temp should bypass stable filename collisions: {result:?}"
            );
            assert!(CheckpointState::load_from_file(&destination).is_ok());
            return;
        }
        let directory = temp_checkpoint_path("foreign-temp").with_extension("dir");
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("immutable-archive");
        std::fs::write(&source, b"public immutable checkpoint archive fixture").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "search::checkpoint::tests::existing_foreign_temp_names_are_never_truncated_or_removed", "--nocapture"])
            .env(CHILD, &directory).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                std::fs::remove_dir_all(&directory).unwrap();
                assert!(status.success(), "foreign temporary collision child failed");
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                std::fs::remove_dir_all(&directory).unwrap();
                panic!("foreign temporary collision child blocked checkpoint save");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    #[test]
    fn replaced_temporary_path_is_rejected_and_foreign_name_survives_cleanup() {
        let directory = temp_checkpoint_path("replaced-temp").with_extension("dir");
        std::fs::create_dir(&directory).unwrap();
        let destination = directory.join("snapshot.json");
        let temporary = CheckpointTemporary::create(&destination).unwrap();
        let own_path = directory.join("retained-owned-temp");
        std::fs::rename(&temporary.path, &own_path).unwrap();
        let archive = directory.join("immutable-archive");
        std::fs::write(&archive, b"public immutable archive fixture").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&archive, &temporary.path).unwrap();
        let foreign_path = temporary.path.clone();
        let result = temporary.ensure_owned();
        drop(temporary);
        assert!(
            foreign_path.exists(),
            "cleanup must leave the replacement foreign pathname intact"
        );
        assert!(result.is_err(), "FD/path inode mismatch must fail closed");
        assert_eq!(
            std::fs::read(&archive).unwrap(),
            b"public immutable archive fixture"
        );
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
