//! Exercise scope preparation through the real binary without starting GPU work.
use puzzle71_solver::search::checkpoint::CheckpointState;
use puzzle71_solver::search::recheck::RecheckPlan;
use puzzle71_solver::search::store::{CheckpointLock, CheckpointStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf, process::Command};
const BLOCK: u128 = 16384;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    source: PathBuf,
    history: PathBuf,
    target: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "p71-cli-recheck-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("legacy.json");
        let history = dir.join("history.json");
        let target = dir.join("target");
        fs::create_dir(&target).unwrap();
        let mut archived = CheckpointState::new();
        archived.total_keys_tested = 2 * BLOCK;
        archived.total_blocks_tested = 2;
        archived.scanned_intervals = vec![(2, 3)];
        archived.save_to_file(&source).unwrap();
        let mut copy =
            CheckpointStore::open(CheckpointLock::acquire(&history).unwrap(), BLOCK).unwrap();
        for (n, id) in [2, 3, 7].into_iter().enumerate() {
            copy.complete_block(id, n as f64 + 1.0).unwrap();
        }
        drop(copy);
        Self {
            dir,
            source,
            history,
            target,
        }
    }
    fn prepare(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_puzzle71_solver"))
            .args(["--block-size", "16384", "--recheck-source"])
            .arg(&self.source)
            .arg("--prepare-recheck-from")
            .arg(&self.history)
            .current_dir(&self.target)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}
#[test]
fn real_prepare_preserves_global_history_and_starts_the_recheck_cursor_at_zero_without_search() {
    let f = Fixture::new();
    let original = fs::read(&f.source).unwrap();
    let output = f.prepare();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Executing mandatory"));
    assert!(stdout.contains("No search started"));
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(f.target.join("puzzle71_checkpoint.json")).unwrap())
            .unwrap();
    assert_eq!(snapshot["format"], 2);
    assert_eq!(snapshot["recheck"]["completed"], 0);
    assert_eq!(snapshot["recheck"]["identity"]["total_blocks"], 2);
    assert_eq!(snapshot["checkpoint"]["total_blocks_tested"], 3);
    assert_eq!(
        snapshot["checkpoint"]["total_keys_tested"],
        (3 * BLOCK) as u64
    );
    assert_eq!(fs::read(&f.source).unwrap(), original);
    assert!(f.target.join("puzzle71_checkpoint.journal").exists());
}
#[test]
fn missing_history_journal_is_rejected_without_creating_a_fresh_scope() {
    let f = Fixture::new();
    fs::remove_file(f.history.with_extension("journal")).unwrap();
    let output = f.prepare();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("snapshot AND journal"));
    assert!(!f.target.join("puzzle71_checkpoint.json").exists());
    assert!(!f.target.join("puzzle71_checkpoint.journal").exists());
}
#[test]
fn preparation_refuses_an_existing_destination_without_overwriting_it() {
    let f = Fixture::new();
    let path = f.target.join("puzzle71_checkpoint.json");
    fs::write(&path, b"keep-existing-history").unwrap();
    let output = f.prepare();
    assert!(!output.status.success());
    assert_eq!(fs::read(path).unwrap(), b"keep-existing-history");
}

#[test]
fn real_prepare_accepts_unverified_targets_without_importing_them_as_global_history() {
    let f = Fixture::new();
    let manifest = serde_json::json!({
        "type": "puzzle71-unverified-targets", "format": 1,
        "puzzle_number": 71,
        "range_min": puzzle71_solver::puzzle_config::RANGE_MIN.to_string(),
        "range_max": puzzle71_solver::puzzle_config::RANGE_MAX.to_string(),
        "block_size": BLOCK.to_string(),
        "target_hash160": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
        "block_indices": [7, 2, 9, 1],
    });
    fs::write(&f.source, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let original = fs::read(&f.source).unwrap();
    let output = f.prepare();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("4 blocks"));
    assert!(stdout.contains("No search started"));
    assert!(!stdout.contains("Executing mandatory"));
    let path = f.target.join("puzzle71_checkpoint.json");
    let snapshot: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(snapshot["format"], 3);
    assert_eq!(snapshot["recheck"]["completed"], 0);
    assert_eq!(snapshot["checkpoint"]["total_blocks_tested"], 3);
    assert_eq!(
        snapshot["checkpoint"]["total_keys_tested"],
        (3 * BLOCK) as u64
    );
    let plan = RecheckPlan::load(&f.source, BLOCK).unwrap();
    let store = CheckpointStore::open_recheck(CheckpointLock::acquire(&path).unwrap(), BLOCK, plan)
        .unwrap();
    assert_eq!(store.next_recheck_block(), Some(7));
    assert!(!store.is_scanned(9));
    assert!(!store.is_scanned(1));
    assert_eq!(fs::read(&f.source).unwrap(), original);
}
