//! Independent CPU verification and retryable, owner-only persistence of puzzle hits.

use crate::claim::secure_zero;
use crate::crypto::address::privkey_u128_to_address;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_MAX, RANGE_MIN, TARGET_ADDRESS, TARGET_HASH160};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::ops::RangeInclusive;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FOUND_KEY_FILENAME: &str = "FOUND_KEY.txt";
const COMPLETE_MARKER: &str = "END VERIFIED HIT\n";
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A CPU-verified hit stays owned until persistence succeeds. Never serialized or cloned.
pub struct VerifiedHit {
    key: u128,
    hash160: [u8; 20],
    bitcoin_address: String,
    timestamp_unix: u64,
    staged_path: Option<PathBuf>,
    staged_complete: bool,
    installed_path: Option<PathBuf>,
    recovered_content: Option<SensitiveText>,
}

impl fmt::Debug for VerifiedHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedHit(<redacted>)")
    }
}

impl Drop for VerifiedHit {
    fn drop(&mut self) {
        // Best effort: compiler/register and cryptographic-library copies may remain.
        unsafe { std::ptr::write_volatile(&mut self.key, 0) };
    }
}

struct SensitiveText(Vec<u8>);
impl Drop for SensitiveText {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
    }
}

impl VerifiedHit {
    pub fn bitcoin_address(&self) -> &str {
        &self.bitcoin_address
    }
    pub fn timestamp_unix(&self) -> u64 {
        self.timestamp_unix
    }

    fn content(&self) -> SensitiveText {
        if let Some(content) = self.recovered_content.as_ref() {
            return SensitiveText(content.0.clone());
        }
        SensitiveText(
            format!(
                "CONFIDENTIAL PRIVATE KEY - DO NOT UPLOAD OR SHARE\n\
             PUZZLE NUMBER:           #{PUZZLE_NUMBER}\n\
             TIMESTAMP (UNIX):        {}\n\
             PRIVATE KEY (HEX):       0x{:018x}\n\
             HASH160 (HEX):           {}\n\
             BITCOIN ADDRESS (P2PKH): {}\n\
             CPU VERIFICATION STATUS: PASSED\n{}",
                self.timestamp_unix,
                self.key,
                hex_encode(&self.hash160),
                self.bitcoin_address,
                COMPLETE_MARKER
            )
            .into_bytes(),
        )
    }

    fn validate_record(&self, file: &mut File) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|error| format!("Cannot inspect retained hit record: {error}"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("Retained hit record is not an owner-only regular file".to_string());
        }
        let mut bytes = SensitiveText(Vec::new());
        file.take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut bytes.0)
            .map_err(|error| format!("Cannot verify retained hit record: {error}"))?;
        if bytes.0 != self.content().0 {
            return Err("Hit record no longer matches the retained candidate".to_string());
        }
        Ok(())
    }

    fn ensure_staged(
        &mut self,
        preferred: &Path,
        sync_file: fn(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        if self.staged_complete {
            let path = self.staged_path.as_ref().expect("complete staging path");
            let mut file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.staged_path = None;
                    self.staged_complete = false;
                    return self.ensure_staged(preferred, sync_file);
                }
                Err(error) => {
                    return Err(format!("Cannot reopen verified hit staging file: {error}"));
                }
            };
            self.validate_record(&mut file)?;
            // A complete record recovered from page cache is not yet proof of durable bytes.
            sync_file(&file)
                .map_err(|error| format!("Cannot synchronize recovered hit: {error}"))?;
            return sync_directory(parent_dir(path));
        }
        let content = self.content();
        if self.staged_path.is_none() {
            let name = preferred
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(FOUND_KEY_FILENAME);
            for _ in 0..100 {
                let path = parent_dir(preferred).join(format!(
                    ".{name}.{}.{}.tmp",
                    std::process::id(),
                    TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                {
                    Ok(file) => {
                        self.staged_path = Some(path);
                        drop(file);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(format!("Cannot create secure hit file: {error}")),
                }
            }
        }
        let path = self
            .staged_path
            .as_ref()
            .ok_or_else(|| "Cannot allocate a secure hit filename".to_string())?;
        // A partial file is rewritten on retry; a replaced symlink is never followed.
        let mut file = match OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.staged_path = None;
                return Err("Staged hit file disappeared; persistence will retry".to_string());
            }
            Err(error) => return Err(format!("Cannot open secure hit staging file: {error}")),
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Cannot secure hit staging file: {error}"))?;
        file.write_all(&content.0)
            .map_err(|error| format!("Cannot write verified hit: {error}"))?;
        sync_file(&file).map_err(|error| format!("Cannot synchronize verified hit: {error}"))?;
        self.staged_complete = true;
        sync_directory(parent_dir(path))
    }

    /// Storage errors retain this candidate and its complete staging file for another attempt.
    pub fn persist(&mut self, preferred: &Path) -> Result<PathBuf, String> {
        self.persist_with_file_sync(preferred, File::sync_all)
    }

    fn persist_with_file_sync(
        &mut self,
        preferred: &Path,
        sync_file: fn(&File) -> std::io::Result<()>,
    ) -> Result<PathBuf, String> {
        if let Some(installed) = self.installed_path.as_ref() {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(installed)
            {
                Ok(mut file) => {
                    self.validate_record(&mut file)?;
                    sync_file(&file)
                        .map_err(|error| format!("Cannot synchronize installed hit: {error}"))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A prior link succeeded, but its directory sync/cleanup did not finish.
                    // Never discard the staging link based only on that remembered pathname.
                    self.installed_path = None;
                }
                Err(error) => return Err(format!("Cannot reopen installed hit: {error}")),
            }
        }
        if self.installed_path.is_none() {
            self.ensure_staged(preferred, sync_file)?;
            let staged = self.staged_path.as_ref().expect("completed staging file");
            for attempt in 0..100 {
                let candidate = candidate_path(preferred, self.timestamp_unix, attempt);
                match std::fs::hard_link(staged, &candidate) {
                    Ok(()) => {
                        self.installed_path = Some(candidate);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(format!("Cannot install verified hit: {error}")),
                }
            }
        }
        let installed = self
            .installed_path
            .as_ref()
            .ok_or_else(|| "Cannot allocate a non-overwriting hit filename".to_string())?;
        sync_directory(parent_dir(installed))?;
        if let Some(staged) = self.staged_path.as_ref() {
            match std::fs::remove_file(staged) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "Cannot clean up installed hit staging link: {error}"
                    ));
                }
            }
            sync_directory(parent_dir(installed))?;
            self.staged_path = None;
        }
        Ok(installed.clone())
    }
}

/// Production verification is always bound to Puzzle #71 and its exact range.
pub fn verify_candidate(key: u128) -> Result<VerifiedHit, String> {
    verify_for_target(key, TARGET_ADDRESS, TARGET_HASH160, RANGE_MIN..=RANGE_MAX)
}

fn verify_for_target(
    key: u128,
    expected_address: &str,
    expected_hash160: [u8; 20],
    range: RangeInclusive<u128>,
) -> Result<VerifiedHit, String> {
    if !range.contains(&key) {
        return Err(
            "CPU verification failed: candidate is outside the permitted range".to_string(),
        );
    }
    let (address, hash160, mut compressed_pubkey) = privkey_u128_to_address(key);
    secure_zero(&mut compressed_pubkey);
    if hash160 != expected_hash160 || address != expected_address {
        return Err(
            "CPU verification failed: candidate does not match the configured target".to_string(),
        );
    }
    Ok(VerifiedHit {
        key,
        hash160,
        bitcoin_address: address,
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        staged_path: None,
        staged_complete: false,
        installed_path: None,
        recovered_content: None,
    })
}

/// Recover complete, secure staging files only after independent target/range verification.
pub fn recover_staged_hit(dir: &Path) -> Result<Option<VerifiedHit>, String> {
    recover_for_target(dir, TARGET_ADDRESS, TARGET_HASH160, RANGE_MIN..=RANGE_MAX)
}

fn recover_for_target(
    dir: &Path,
    address: &str,
    hash: [u8; 20],
    range: RangeInclusive<u128>,
) -> Result<Option<VerifiedHit>, String> {
    let mut paths = std::fs::read_dir(dir)
        .map_err(|error| format!("Cannot inspect hit staging files: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".FOUND_KEY") && name.ends_with(".tmp"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            continue;
        }
        let mut content = SensitiveText(Vec::new());
        if file
            .take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut content.0)
            .is_err()
            || content.0.len() as u64 > MAX_KEY_FILE_BYTES
        {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&content.0) else {
            continue;
        };
        if !text.ends_with(COMPLETE_MARKER) {
            continue;
        }
        let values = text
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("PRIVATE KEY (HEX):")
                    .map(str::trim)
            })
            .collect::<Vec<_>>();
        if values.len() != 1 {
            continue;
        }
        let Some(hex) = values[0].strip_prefix("0x") else {
            continue;
        };
        let Ok(key) = u128::from_str_radix(hex, 16) else {
            continue;
        };
        let Ok(mut hit) = verify_for_target(key, address, hash, range.clone()) else {
            continue;
        };
        hit.staged_path = Some(path);
        hit.staged_complete = true;
        // Keep the exact verified record, including its original timestamp, across retries.
        hit.recovered_content = Some(content);
        return Ok(Some(hit));
    }
    Ok(None)
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| format!("Cannot synchronize hit directory: {error}"))
}
fn candidate_path(preferred: &Path, timestamp: u64, attempt: u32) -> PathBuf {
    if attempt == 0 {
        return preferred.to_path_buf();
    }
    let stem = preferred
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("FOUND_KEY");
    let ext = preferred
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("txt");
    parent_dir(preferred).join(format!("{stem}.{timestamp}.{attempt}.{ext}"))
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    const ADDRESS: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    const HASH: [u8; 20] = [
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3,
        0x23, 0xf1, 0x43, 0x3b, 0xd6,
    ];
    fn fixture() -> VerifiedHit {
        verify_for_target(1, ADDRESS, HASH, 1..=1).unwrap()
    }
    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "puzzle71-hit-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn verified_candidate_survives_create_failure_then_persists_same_key() {
        let dir = temp_dir("retry");
        let missing = dir.join("missing");
        let path = missing.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        assert!(hit.persist(&path).is_err());
        assert_eq!(format!("{hit:?}"), "VerifiedHit(<redacted>)");
        assert_eq!(hit.bitcoin_address(), ADDRESS);
        std::fs::create_dir(&missing).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&missing).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovered_hit_requires_file_sync_before_install_and_retries_after_failure() {
        let dir = temp_dir("recovered-sync");
        let staged = dir.join(".FOUND_KEY.recovered.tmp");
        let bytes = fixture().content();
        // Emulate complete surviving page-cache bytes without claiming a prior fsync.
        std::fs::write(&staged, &bytes.0).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut hit = recover_for_target(&dir, ADDRESS, HASH, 1..=1)
            .unwrap()
            .unwrap();
        let path = dir.join(FOUND_KEY_FILENAME);
        assert!(
            hit.persist_with_file_sync(&path, |_| {
                Err(std::io::Error::other(
                    "injected recovered-file sync failure",
                ))
            })
            .is_err()
        );
        assert!(!path.exists(), "no installed path before file durability");
        assert!(
            staged.exists(),
            "the only recoverable staging file must survive"
        );
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovered_original_record_survives_an_installed_link_retry() {
        let dir = temp_dir("recovered-installed-retry");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut original = fixture();
        original.timestamp_unix = 1;
        original.ensure_staged(&path, File::sync_all).unwrap();
        let staged = original.staged_path.clone().unwrap();
        let original_bytes = SensitiveText(std::fs::read(&staged).unwrap());
        drop(original);
        let mut recovered = recover_for_target(&dir, ADDRESS, HASH, 1..=1)
            .unwrap()
            .unwrap();
        std::fs::hard_link(&staged, &path).unwrap();
        recovered.installed_path = Some(path.clone());
        assert_eq!(recovered.persist(&path).unwrap(), path);
        assert!(std::fs::read(&path).unwrap() == original_bytes.0);
        assert!(!staged.exists());
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retained_hit_recreates_a_disappeared_complete_staging_file() {
        let dir = temp_dir("restage");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        hit.ensure_staged(&path, File::sync_all).unwrap();
        std::fs::remove_file(hit.staged_path.as_ref().unwrap()).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn installed_retry_fixture(dir: &Path) -> (VerifiedHit, PathBuf, PathBuf) {
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        hit.ensure_staged(&path, File::sync_all).unwrap();
        let staged = hit.staged_path.clone().unwrap();
        std::fs::hard_link(&staged, &path).unwrap();
        // State retained after installation succeeds but directory synchronization fails.
        hit.installed_path = Some(path.clone());
        (hit, path, staged)
    }

    #[test]
    fn complete_staging_replacement_is_rejected_without_installing_foreign_bytes() {
        let dir = temp_dir("replaced-staging");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        hit.ensure_staged(&path, File::sync_all).unwrap();
        let staged = hit.staged_path.clone().unwrap();
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&staged, b"unrelated replacement").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(hit.persist(&path).is_err());
        assert!(!path.exists());
        assert_eq!(std::fs::read(&staged).unwrap(), b"unrelated replacement");
        std::fs::remove_file(&staged).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_reinstalls_a_disappeared_final_link_before_removing_staging() {
        let dir = temp_dir("missing-installed");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert!(!staged.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_recreates_both_disappeared_links_from_the_retained_key() {
        let dir = temp_dir("missing-both-links");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&staged).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_rejects_replaced_final_bytes_and_preserves_the_valid_staging_link() {
        let dir = temp_dir("replaced-installed");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"unrelated replacement").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(hit.persist(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"unrelated replacement");
        crate::claim::ClaimKey::load_found_key_file(&staged, HASH, 1..=1).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_rejects_a_final_symlink_even_when_it_targets_valid_staging_bytes() {
        let dir = temp_dir("symlink-installed");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&staged, &path).unwrap();
        assert!(hit.persist(&path).is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        crate::claim::ClaimKey::load_found_key_file(&staged, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_requires_installed_file_sync_before_removing_staging() {
        let dir = temp_dir("installed-sync");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        assert!(
            hit.persist_with_file_sync(&path, |_| {
                Err(std::io::Error::other(
                    "injected installed-file sync failure",
                ))
            })
            .is_err()
        );
        crate::claim::ClaimKey::load_found_key_file(&staged, HASH, 1..=1).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        assert!(!staged.exists());
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retry_rejects_public_installed_permissions_without_removing_staging() {
        let dir = temp_dir("installed-mode");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(hit.persist(&path).is_err());
        assert!(staged.exists());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replaced_fifo_does_not_block_installation_retry_or_staging_recovery() {
        const CHILD_MODE: &str = "PUZZLE71_FIFO_TEST_CHILD";
        if let Ok(mode) = std::env::var(CHILD_MODE) {
            use std::os::unix::ffi::OsStrExt;
            let dir = temp_dir("fifo");
            let (mut hit, path, staged) = installed_retry_fixture(&dir);
            let target = if mode == "staging" { &staged } else { &path };
            std::fs::remove_file(target).unwrap();
            let cpath = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
            // SAFETY: cpath is a valid, NUL-terminated pathname in our private fixture directory.
            assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
            if mode == "installed" {
                assert!(hit.persist(&path).is_err());
                assert!(staged.exists());
            } else if mode == "staging" {
                assert!(
                    recover_for_target(&dir, ADDRESS, HASH, 1..=1)
                        .unwrap()
                        .is_none()
                );
            } else {
                assert!(crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).is_err());
            }
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        for mode in ["installed", "staging", "claim"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "hit_handler::tests::replaced_fifo_does_not_block_installation_retry_or_staging_recovery"])
                .env(CHILD_MODE, mode)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "{mode} FIFO was not safely rejected");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("{mode} FIFO blocked the hit persistence/recovery path");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn installation_failure_preserves_complete_recoverable_staging_file() {
        let dir = temp_dir("recover");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        for attempt in 0..100 {
            std::fs::create_dir(candidate_path(&path, hit.timestamp_unix(), attempt)).unwrap();
        }
        assert!(hit.persist(&path).is_err());
        let staged = hit.staged_path.clone().unwrap();
        assert!(staged.exists());
        drop(hit);
        std::fs::remove_dir(&path).unwrap();
        let mut recovered = recover_for_target(&dir, ADDRESS, HASH, 1..=1)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.persist(&path).unwrap(), path);
        assert!(!staged.exists());
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn incomplete_foreign_and_symlink_staging_files_are_not_recovered() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("invalid");
        let path = dir.join(".FOUND_KEY.invalid.tmp");
        let hit = fixture();
        let bytes = hit.content();
        std::fs::write(&path, &bytes.0[..bytes.0.len() - COMPLETE_MARKER.len()]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            recover_for_target(&dir, ADDRESS, HASH, 1..=1)
                .unwrap()
                .is_none()
        );
        std::fs::write(&path, &bytes.0).unwrap();
        assert!(
            recover_for_target(&dir, TARGET_ADDRESS, TARGET_HASH160, RANGE_MIN..=RANGE_MAX)
                .unwrap()
                .is_none()
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            recover_for_target(&dir, ADDRESS, HASH, 1..=1)
                .unwrap()
                .is_none()
        );
        let outside = dir.join("outside.txt");
        std::fs::rename(&path, &outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, &path).unwrap();
        assert!(
            recover_for_target(&dir, ADDRESS, HASH, 1..=1)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hit_files_are_owner_only_and_never_overwritten() {
        let dir = temp_dir("no-overwrite");
        let path = dir.join(FOUND_KEY_FILENAME);
        let first = fixture().persist(&path).unwrap();
        let original = std::fs::read(&first).unwrap();
        let second = fixture().persist(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read(&first).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&second).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verification_rejects_wrong_target_and_out_of_range_candidate() {
        assert!(verify_candidate(1).is_err());
        assert!(verify_for_target(1, TARGET_ADDRESS, TARGET_HASH160, 1..=1).is_err());
        assert!(verify_for_target(1, ADDRESS, HASH, 2..=2).is_err());
    }
}
