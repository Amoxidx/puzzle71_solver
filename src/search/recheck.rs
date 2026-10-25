//! Identity-bound, ordered search of an immutable archive or explicit target list.

use crate::crypto::sha256::sha256;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_MAX, RANGE_MIN, RANGE_SIZE, TARGET_HASH160};
use crate::search::checkpoint::CheckpointState;
use crate::search::duplicate_filter::IntervalSet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;

/// This is a search request, never evidence of previously completed work.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnverifiedTargets {
    #[serde(rename = "type")]
    source_type: String,
    format: u32,
    puzzle_number: u32,
    range_min: String,
    range_max: String,
    block_size: String,
    target_hash160: String,
    block_indices: Vec<u64>,
}

#[derive(Clone, Debug)]
enum PlanBlocks {
    Legacy {
        intervals: Vec<(u64, u64)>,
        ordinal_ends: Vec<u64>,
    },
    UnverifiedTargets(Vec<u64>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecheckIdentity {
    pub source_sha256: String,
    pub total_blocks: u64,
    pub puzzle_number: u32,
    pub range_min: String,
    pub range_max: String,
    pub block_size: String,
    pub target_hash160: String,
    pub kernel_sha256: String,
}

/// A public, non-secret status. Global coverage is independent of this cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecheckProgress {
    pub identity: RecheckIdentity,
    pub completed: u64,
}

#[derive(Clone, Debug)]
pub struct RecheckPlan {
    identity: RecheckIdentity,
    blocks: PlanBlocks,
    source_path: PathBuf,
    source_file: (u64, u64),
}

impl RecheckPlan {
    /// Read the exact source bytes once. This never creates a journal or writer lock.
    pub fn load(path: impl AsRef<Path>, block_size: u128) -> Result<Self, String> {
        if block_size == 0
            || block_size > RANGE_SIZE
            || !RANGE_SIZE.is_multiple_of(block_size)
            || RANGE_SIZE / block_size > u64::MAX as u128
        {
            return Err(
                "Recheck block size must divide the puzzle range and fit u64 indices".into(),
            );
        }
        let source_path = fs::canonicalize(path.as_ref())
            .map_err(|e| format!("Failed to resolve recheck source: {e}"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&source_path)
            .map_err(|e| format!("Failed to open recheck source: {e}"))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("Failed to inspect recheck source: {e}"))?;
        if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
            return Err("Recheck source must be a regular file of at most 32 MiB".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read recheck source: {e}"))?;
        if bytes.len() as u64 > MAX_SOURCE_BYTES {
            return Err("Recheck source grew beyond the 32 MiB limit".into());
        }
        // Inspect only the top-level discriminator; deserialize the original bytes
        // again so duplicate fields and unknown target fields cannot be normalized away.
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid recheck source JSON: {e}"))?;
        let explicit_source = value.get("type").is_some() || value.get("format").is_some();
        let (blocks, total_blocks) = if explicit_source {
            let targets: UnverifiedTargets = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid unverified-target manifest: {e}"))?;
            if targets.source_type != "puzzle71-unverified-targets"
                || targets.format != 1
                || targets.puzzle_number != PUZZLE_NUMBER
                || targets.range_min != RANGE_MIN.to_string()
                || targets.range_max != RANGE_MAX.to_string()
                || targets.block_size != block_size.to_string()
                || targets.target_hash160 != target_hash160()
            {
                return Err(
                    "Unverified-target manifest type, format or puzzle binding mismatch".into(),
                );
            }
            if targets.block_indices.is_empty() {
                return Err("Unverified-target manifest requires at least one block".into());
            }
            let mut unique = HashSet::with_capacity(targets.block_indices.len());
            for &index in &targets.block_indices {
                if index as u128 >= RANGE_SIZE / block_size || !unique.insert(index) {
                    return Err(
                        "Unverified-target blocks must be unique and inside the puzzle range"
                            .into(),
                    );
                }
            }
            let total = targets.block_indices.len() as u64;
            (PlanBlocks::UnverifiedTargets(targets.block_indices), total)
        } else {
            let state = CheckpointState::from_json(&bytes)?;
            state.validate_for_block_size(block_size)?;
            if state.total_blocks_tested == 0 {
                return Err("Recheck source must contain at least one complete block".into());
            }
            let mut total = 0u64;
            let ordinal_ends = state
                .scanned_intervals
                .iter()
                .map(|&(start, end)| {
                    total += end - start + 1; // validated checked total in CheckpointState
                    total
                })
                .collect();
            (
                PlanBlocks::Legacy {
                    intervals: state.scanned_intervals,
                    ordinal_ends,
                },
                total,
            )
        };
        Ok(Self {
            identity: RecheckIdentity {
                source_sha256: digest(&bytes),
                total_blocks,
                puzzle_number: PUZZLE_NUMBER,
                range_min: RANGE_MIN.to_string(),
                range_max: RANGE_MAX.to_string(),
                block_size: block_size.to_string(),
                target_hash160: target_hash160(),
                kernel_sha256: digest(include_bytes!("../metal_engine/kernel.metal")),
            },
            blocks,
            source_path,
            source_file: (metadata.dev(), metadata.ino()),
        })
    }

    pub fn identity(&self) -> &RecheckIdentity {
        &self.identity
    }

    pub fn block_at(&self, ordinal: u64) -> Option<u64> {
        if ordinal >= self.identity.total_blocks {
            return None;
        }
        match &self.blocks {
            PlanBlocks::UnverifiedTargets(indices) => indices.get(ordinal as usize).copied(),
            PlanBlocks::Legacy {
                intervals,
                ordinal_ends,
            } => {
                let index = ordinal_ends.partition_point(|&end| end <= ordinal);
                let previous = if index == 0 {
                    0
                } else {
                    ordinal_ends[index - 1]
                };
                Some(intervals[index].0 + ordinal - previous)
            }
        }
    }

    /// Keep target scopes unreadable to programs that only understand legacy scopes.
    pub(crate) fn scoped_format(&self) -> u32 {
        match &self.blocks {
            PlanBlocks::Legacy { .. } => 2,
            PlanBlocks::UnverifiedTargets(_) => 3,
        }
    }

    /// Legacy archives claim all their blocks were counted before preparation.
    /// Explicit targets claim no history, but every completed prefix block must exist.
    pub(crate) fn required_coverage_is_present(
        &self,
        global: &IntervalSet,
        completed: u64,
    ) -> bool {
        if completed > self.identity.total_blocks {
            return false;
        }
        match &self.blocks {
            PlanBlocks::Legacy { .. } => self.is_covered_by(global),
            PlanBlocks::UnverifiedTargets(indices) => indices[..completed as usize]
                .iter()
                .all(|&index| global.contains(index)),
        }
    }

    pub(crate) fn is_source_file(&self, path: &Path) -> Result<bool, String> {
        if fs::canonicalize(path).is_ok_and(|p| p == self.source_path) {
            return Ok(true);
        }
        match fs::metadata(path) {
            Ok(meta) => Ok((meta.dev(), meta.ino()) == self.source_file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!(
                "Failed to inspect history/source identity: {error}"
            )),
        }
    }

    pub(crate) fn reject_source_fd(&self, file: &File) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|e| format!("Failed to inspect mutable recheck file: {e}"))?;
        if (metadata.dev(), metadata.ino()) == self.source_file {
            return Err(
                "Refusing mutable file descriptor alias of immutable recheck source".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn is_covered_by(&self, global: &IntervalSet) -> bool {
        let intervals = match &self.blocks {
            PlanBlocks::Legacy { intervals, .. } => intervals,
            PlanBlocks::UnverifiedTargets(indices) => {
                return indices.iter().all(|&id| global.contains(id));
            }
        };
        let mut index = 0;
        for &(start, end) in intervals {
            while index < global.intervals.len() && global.intervals[index].1 < start {
                index += 1;
            }
            let mut covered_through = start;
            loop {
                let Some(&(global_start, global_end)) = global.intervals.get(index) else {
                    return false;
                };
                if global_start > covered_through {
                    return false;
                }
                if global_end >= end {
                    break;
                }
                covered_through = global_end + 1;
                index += 1;
            }
        }
        true
    }
}

fn target_hash160() -> String {
    TARGET_HASH160.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    const BLOCK_SIZE: u128 = 1 << 24;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "p71-recheck-plan-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn source(&self) -> PathBuf {
            self.0.join("legacy.json")
        }
        fn write(&self, intervals: Vec<(u64, u64)>) {
            let mut state = CheckpointState::new();
            state.total_blocks_tested = intervals.iter().map(|&(s, e)| e - s + 1).sum();
            state.total_keys_tested = state.total_blocks_tested as u128 * BLOCK_SIZE;
            state.scanned_intervals = intervals;
            state.save_to_file(self.source()).unwrap();
        }
        fn write_targets(&self, indices: &[u64]) -> serde_json::Value {
            let value = serde_json::json!({
                "type": "puzzle71-unverified-targets",
                "format": 1,
                "puzzle_number": PUZZLE_NUMBER,
                "range_min": RANGE_MIN.to_string(),
                "range_max": RANGE_MAX.to_string(),
                "block_size": BLOCK_SIZE.to_string(),
                "target_hash160": target_hash160(),
                "block_indices": indices,
            });
            fs::write(self.source(), serde_json::to_vec(&value).unwrap()).unwrap();
            value
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn plan_maps_ordinals_across_intervals_and_binds_exact_bytes_target_and_kernel() {
        let f = Fixture::new();
        f.write(vec![(2, 3), (7, 9)]);
        let before = fs::read(f.source()).unwrap();
        let plan = RecheckPlan::load(f.source(), BLOCK_SIZE).unwrap();
        assert_eq!(
            (0..=5).map(|n| plan.block_at(n)).collect::<Vec<_>>(),
            vec![Some(2), Some(3), Some(7), Some(8), Some(9), None]
        );
        assert_eq!(plan.identity().source_sha256, digest(&before));
        assert_eq!(plan.identity().total_blocks, 5);
        assert_eq!(plan.identity().puzzle_number, 71);
        assert_eq!(plan.identity().range_min, RANGE_MIN.to_string());
        assert_eq!(plan.identity().range_max, RANGE_MAX.to_string());
        assert_eq!(
            plan.identity().target_hash160,
            "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
        );
        assert_eq!(
            plan.identity().kernel_sha256,
            digest(include_bytes!("../metal_engine/kernel.metal"))
        );
        assert!(plan.is_covered_by(&IntervalSet {
            intervals: vec![(1, 2), (3, 4), (6, 10)]
        }));
        assert!(!plan.is_covered_by(&IntervalSet {
            intervals: vec![(1, 2), (4, 4), (6, 10)]
        }));
        assert_eq!(fs::read(f.source()).unwrap(), before);
        assert!(!f.source().with_extension("journal").exists());
        assert!(!f.source().with_extension("lock").exists());
    }

    #[test]
    fn plan_uses_existing_checkpoint_validation_and_rejects_empty_missing_or_oversized_sources() {
        let f = Fixture::new();
        assert!(RecheckPlan::load(f.source(), BLOCK_SIZE).is_err());
        f.write(vec![]);
        assert!(RecheckPlan::load(f.source(), BLOCK_SIZE).is_err());
        f.write(vec![(1, 1)]);
        assert!(RecheckPlan::load(f.source(), BLOCK_SIZE * 2).is_err());
        for size in [0, 3, 64, RANGE_SIZE * 2] {
            assert!(RecheckPlan::load(f.source(), size).is_err());
        }
        let file = File::create(f.source()).unwrap();
        file.set_len(MAX_SOURCE_BYTES + 1).unwrap();
        assert!(
            RecheckPlan::load(f.source(), BLOCK_SIZE)
                .unwrap_err()
                .contains("32 MiB")
        );
    }

    #[test]
    fn same_coverage_different_source_bytes_get_different_identity() {
        let f = Fixture::new();
        f.write(vec![(2, 3)]);
        let first = RecheckPlan::load(f.source(), BLOCK_SIZE).unwrap();
        let mut bytes = fs::read(f.source()).unwrap();
        bytes.push(b'\n');
        fs::write(f.source(), bytes).unwrap();
        let second = RecheckPlan::load(f.source(), BLOCK_SIZE).unwrap();
        assert_ne!(first.identity(), second.identity());
        assert_eq!(first.block_at(1), second.block_at(1));
    }

    #[test]
    fn unverified_targets_preserve_declared_order_and_bind_exact_bytes_without_claiming_history() {
        let f = Fixture::new();
        f.write_targets(&[7, 2, 100, 3]);
        let bytes = fs::read(f.source()).unwrap();
        let plan = RecheckPlan::load(f.source(), BLOCK_SIZE).unwrap();
        assert_eq!(plan.scoped_format(), 3);
        assert_eq!(plan.identity().source_sha256, digest(&bytes));
        assert_eq!(
            plan.identity().kernel_sha256,
            digest(include_bytes!("../metal_engine/kernel.metal"))
        );
        assert_eq!(
            (0..=4).map(|i| plan.block_at(i)).collect::<Vec<_>>(),
            vec![Some(7), Some(2), Some(100), Some(3), None]
        );
        let global = IntervalSet {
            intervals: vec![(2, 3), (7, 7)],
        };
        assert!(plan.required_coverage_is_present(&IntervalSet::new(), 0));
        assert!(plan.required_coverage_is_present(&global, 2));
        assert!(!plan.required_coverage_is_present(&global, 3));
        assert!(!plan.required_coverage_is_present(&global, 4));
        assert!(!plan.required_coverage_is_present(&global, 5));
        assert_eq!(fs::read(f.source()).unwrap(), bytes);
        assert!(!f.source().with_extension("journal").exists());
        assert!(!f.source().with_extension("lock").exists());
        assert!(CheckpointState::load_from_file(f.source()).is_err());
        let mut different_bytes = bytes;
        different_bytes.push(b'\n');
        fs::write(f.source(), different_bytes).unwrap();
        let changed = RecheckPlan::load(f.source(), BLOCK_SIZE).unwrap();
        assert_ne!(plan.identity(), changed.identity());
        assert_eq!(plan.block_at(2), changed.block_at(2));
    }

    #[test]
    fn unverified_targets_reject_unknown_fields_bindings_duplicates_and_invalid_indices() {
        let f = Fixture::new();
        let valid = f.write_targets(&[0, (RANGE_SIZE / BLOCK_SIZE - 1) as u64]);
        assert!(RecheckPlan::load(f.source(), BLOCK_SIZE).is_ok());
        for (field, wrong) in [
            ("type", serde_json::json!("unknown-search-request")),
            ("format", serde_json::json!(2)),
            ("puzzle_number", serde_json::json!(70)),
            ("range_min", serde_json::json!("0")),
            ("range_max", serde_json::json!("0")),
            (
                "block_size",
                serde_json::json!((BLOCK_SIZE * 2).to_string()),
            ),
            ("block_size", serde_json::json!(BLOCK_SIZE as u64)),
            ("target_hash160", serde_json::json!("00".repeat(20))),
            ("unknown", serde_json::json!(true)),
            ("block_indices", serde_json::json!([])),
            ("block_indices", serde_json::json!([1, 1])),
            (
                "block_indices",
                serde_json::json!([RANGE_SIZE / BLOCK_SIZE]),
            ),
            ("block_indices", serde_json::json!([-1])),
            ("block_indices", serde_json::json!([1.5])),
            ("block_indices", serde_json::json!(["1"])),
        ] {
            let mut damaged = valid.clone();
            damaged[field] = wrong;
            fs::write(f.source(), serde_json::to_vec(&damaged).unwrap()).unwrap();
            assert!(
                RecheckPlan::load(f.source(), BLOCK_SIZE).is_err(),
                "accepted {field}: {damaged}"
            );
        }
        let duplicate_field = serde_json::to_string(&valid)
            .unwrap()
            .replace("\"format\":1", "\"format\":1,\"format\":1");
        fs::write(f.source(), duplicate_field).unwrap();
        assert!(RecheckPlan::load(f.source(), BLOCK_SIZE).is_err());
    }
    #[test]
    fn fifo_source_returns_regular_file_error_without_waiting_for_a_writer() {
        const CHILD: &str = "PUZZLE71_RECHECK_FIFO_CHILD";
        if let Some(fifo_path) = std::env::var_os(CHILD) {
            let error =
                RecheckPlan::load(std::path::PathBuf::from(fifo_path), BLOCK_SIZE).unwrap_err();
            assert!(
                error.contains("regular file"),
                "FIFO must be rejected by FD file-type check: {error}"
            );
            return;
        }
        let fixture = Fixture::new();
        let fifo_path = fixture.source();
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a live NUL-terminated pathname inside this owned fixture.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "search::recheck::tests::fifo_source_returns_regular_file_error_without_waiting_for_a_writer", "--nocapture"])
            .env(CHILD, &fifo_path).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "FIFO child did not return a regular-file rejection"
                );
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "loader was observed blocking for 2 seconds while opening a FIFO without a writer"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
