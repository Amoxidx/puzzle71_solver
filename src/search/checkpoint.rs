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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
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
        let tmp_path = path.with_extension("tmp");

        self.last_saved_timestamp = current_timestamp();

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Open with 0600 permissions
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to open temp checkpoint file: {}", e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write checkpoint: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync checkpoint to disk: {}", e))?;
        drop(file);

        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to secure checkpoint permissions: {}", e))?;

        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to atomically rename checkpoint: {}", e))?;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to secure final checkpoint permissions: {}", e))?;

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("Failed to sync checkpoint directory: {}", e))?;

        Ok(())
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

        let state: CheckpointState = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse checkpoint JSON: {}", e))?;

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
}
