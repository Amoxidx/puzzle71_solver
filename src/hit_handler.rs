//! Independent CPU verification and retryable, owner-only persistence of puzzle hits.

use crate::claim::key::{MAX_KEY_FILE_BYTES, parse_found_key_record};
use crate::claim::secure_zero;
use crate::crypto::address::privkey_u128_to_address;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_MAX, RANGE_MIN, TARGET_ADDRESS, TARGET_HASH160};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FOUND_KEY_FILENAME: &str = "FOUND_KEY.txt";
const COMPLETE_MARKER: &str = "END VERIFIED HIT\n";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The production path and fault tests use the same ordering of writes and synchronization.
trait PersistenceIo {
    fn write_record(&mut self, file: &mut File, content: &[u8]) -> std::io::Result<()> {
        file.write_all(content)
    }
    fn sync_file(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
    fn sync_directory(&mut self, path: &Path) -> Result<(), String> {
        sync_directory(path)
    }
}

struct FilesystemIo;
impl PersistenceIo for FilesystemIo {}

#[cfg(test)]
struct FileSyncIo(fn(&File) -> std::io::Result<()>);
#[cfg(test)]
impl PersistenceIo for FileSyncIo {
    fn sync_file(&mut self, file: &File) -> std::io::Result<()> {
        (self.0)(file)
    }
}

/// A CPU-verified hit stays owned until persistence succeeds. Never serialized or cloned.
pub struct VerifiedHit {
    key: u128,
    hash160: [u8; 20],
    bitcoin_address: String,
    timestamp_unix: u64,
    staged_path: Option<PathBuf>,
    // Keep the inode alive across retries; a remembered dev/inode pair alone permits reuse.
    staged_file: Option<File>,
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

    fn clear_staged(&mut self) {
        self.staged_path = None;
        self.staged_complete = false;
        self.staged_file = None;
    }

    /// Checks namespace changes between retries. This is not an atomic defense against a
    /// malicious process with the same account actively replacing paths during a syscall.
    fn owns_staged_path(&self) -> Result<bool, String> {
        let (Some(path), Some(owned)) = (&self.staged_path, &self.staged_file) else {
            return Ok(false);
        };
        let retained = owned
            .metadata()
            .map_err(|error| format!("Cannot inspect owned hit staging file: {error}"))?;
        match std::fs::symlink_metadata(path) {
            Ok(current) => Ok(same_regular_file(&retained, &current)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("Cannot inspect hit staging pathname: {error}")),
        }
    }

    #[cfg(test)]
    fn ensure_staged(
        &mut self,
        preferred: &Path,
        sync_file: fn(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        self.ensure_staged_with_io(preferred, &mut FileSyncIo(sync_file))
    }

    fn ensure_staged_with_io(
        &mut self,
        preferred: &Path,
        io: &mut impl PersistenceIo,
    ) -> Result<(), String> {
        if self.staged_path.is_some() && !self.owns_staged_path()? {
            // Preserve a foreign replacement and allocate our own fresh path automatically.
            self.clear_staged();
        }
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
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                {
                    Ok(file) => {
                        self.staged_path = Some(path);
                        self.staged_file = Some(file);
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
        // Opening must not truncate or chmod anything until the opened descriptor has been
        // compared with the retained one. Partial bytes on our own inode are retryable.
        let mut file = OpenOptions::new()
            .read(self.staged_complete)
            .write(!self.staged_complete)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| format!("Cannot open secure hit staging file: {error}"))?;
        let retained = self.staged_file.as_ref().expect("owned staging descriptor");
        if !same_regular_file(
            &retained.metadata().map_err(|error| error.to_string())?,
            &file.metadata().map_err(|error| error.to_string())?,
        ) {
            self.clear_staged();
            return Err("Hit staging pathname changed; persistence will retry".to_string());
        }
        if self.staged_complete {
            self.validate_record(&mut file)?;
            // Surviving page-cache bytes do not prove that the file was synchronized.
            io.sync_file(&file)
                .map_err(|error| format!("Cannot synchronize recovered hit: {error}"))?;
            return io.sync_directory(parent_dir(path));
        }
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
            .map_err(|error| format!("Cannot reset owned hit staging file: {error}"))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Cannot secure hit staging file: {error}"))?;
        io.write_record(&mut file, &self.content().0)
            .map_err(|error| format!("Cannot write verified hit: {error}"))?;
        io.sync_file(&file)
            .map_err(|error| format!("Cannot synchronize verified hit: {error}"))?;
        self.staged_complete = true;
        io.sync_directory(parent_dir(path))
    }

    /// Storage errors retain this candidate and its complete staging file for another attempt.
    pub fn persist(&mut self, preferred: &Path) -> Result<PathBuf, String> {
        self.persist_with_io(preferred, &mut FilesystemIo)
    }

    #[cfg(test)]
    fn persist_with_file_sync(
        &mut self,
        preferred: &Path,
        sync_file: fn(&File) -> std::io::Result<()>,
    ) -> Result<PathBuf, String> {
        self.persist_with_io(preferred, &mut FileSyncIo(sync_file))
    }

    fn persist_with_io(
        &mut self,
        preferred: &Path,
        io: &mut impl PersistenceIo,
    ) -> Result<PathBuf, String> {
        if let Some(installed) = self.installed_path.as_ref() {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(installed)
            {
                Ok(mut file) => {
                    self.validate_record(&mut file)?;
                    io.sync_file(&file)
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
            self.ensure_staged_with_io(preferred, io)?;
            for attempt in 0..100 {
                if !self.owns_staged_path()? {
                    self.clear_staged();
                    return Err("Hit staging pathname changed before installation".to_string());
                }
                let staged = self.staged_path.as_ref().expect("completed staging file");
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
            .ok_or_else(|| "Cannot allocate a non-overwriting hit filename".to_string())?
            .clone();
        io.sync_directory(parent_dir(&installed))?;
        if let Some(staged) = self.staged_path.clone() {
            if !self.owns_staged_path()? {
                // The installed record is durable. Leave the foreign staging name alone.
                self.clear_staged();
                return Ok(installed);
            }
            match std::fs::remove_file(&staged) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "Cannot clean up installed hit staging link: {error}"
                    ));
                }
            }
            // The unlink succeeded even if the following directory synchronization fails.
            self.clear_staged();
            io.sync_directory(parent_dir(&staged))?;
        }
        Ok(installed)
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
        staged_file: None,
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
        let Ok(mut file) = OpenOptions::new()
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
        if (&mut file)
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
        let Ok((key, timestamp)) = parse_found_key_record(&content.0) else {
            continue;
        };
        let Ok(mut hit) = verify_for_target(key, address, hash, range.clone()) else {
            continue;
        };
        hit.staged_path = Some(path);
        hit.staged_file = Some(file);
        hit.staged_complete = true;
        hit.timestamp_unix = timestamp.unwrap_or(0);
        // Keep the exact verified record, including its original timestamp, across retries.
        hit.recovered_content = Some(content);
        return Ok(Some(hit));
    }
    Ok(None)
}

fn same_regular_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.is_file() && right.is_file() && left.dev() == right.dev() && left.ino() == right.ino()
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
    fn complete_staging_replacement_is_preserved_while_a_fresh_record_is_installed() {
        let dir = temp_dir("replaced-staging");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        hit.ensure_staged(&path, File::sync_all).unwrap();
        let staged = hit.staged_path.clone().unwrap();
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&staged, b"unrelated replacement").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        assert_eq!(std::fs::read(&staged).unwrap(), b"unrelated replacement");
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

    fn foreign_partial_stage_fixture() -> (PathBuf, VerifiedHit, PathBuf, PathBuf, PathBuf) {
        let dir = temp_dir("audit-partial-foreign");
        let path = dir.join(FOUND_KEY_FILENAME);
        let foreign = dir.join("unrelated.txt");
        let sentinel = b"unrelated public fixture bytes";
        let mut hit = fixture();
        assert!(
            hit.persist_with_file_sync(&path, |_| Err(std::io::Error::other(
                "injected sync failure"
            )))
            .is_err()
        );
        let staged = hit.staged_path.clone().unwrap();
        let retained_inode = hit.staged_file.as_ref().unwrap().metadata().unwrap().ino();
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&foreign, sentinel).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&foreign, &staged).unwrap();
        // The production-owned descriptor keeps the unlinked inode alive, preventing ABA.
        assert_eq!(
            hit.staged_file.as_ref().unwrap().metadata().unwrap().ino(),
            retained_inode
        );
        assert_ne!(std::fs::metadata(&staged).unwrap().ino(), retained_inode);
        (dir, hit, path, staged, foreign)
    }

    #[test]
    fn audit_regression_partial_retry_preserves_a_foreign_hardlink() {
        let (dir, mut hit, path, _staged, foreign) = foreign_partial_stage_fixture();
        let _retry = hit.persist(&path);
        assert!(
            std::fs::read(&foreign).unwrap() == b"unrelated public fixture bytes",
            "partial retry overwrote unrelated hardlink target"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_partial_retry_preserves_foreign_permissions() {
        let (dir, mut hit, path, _staged, foreign) = foreign_partial_stage_fixture();
        let _retry = hit.persist(&path);
        assert_eq!(
            std::fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_partial_retry_finishes_without_deleting_the_foreign_stage() {
        let (dir, mut hit, path, staged, foreign) = foreign_partial_stage_fixture();
        let result = hit.persist(&path).or_else(|_| hit.persist(&path));
        assert_eq!(result.unwrap(), path);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert!(staged.exists());
        assert!(std::fs::read(&foreign).unwrap() == b"unrelated public fixture bytes");
        assert_eq!(
            std::fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_installed_retry_preserves_foreign_stage_name() {
        let dir = temp_dir("audit-cleanup-foreign");
        let (mut hit, path, staged) = installed_retry_fixture(&dir);
        let retained_inode = File::open(&staged).unwrap();
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&staged, b"only copy of unrelated public fixture").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        let retry = hit.persist(&path).or_else(|_| hit.persist(&path));
        assert_eq!(retry.unwrap(), path);
        assert!(staged.exists(), "cleanup deleted a foreign replacement");
        assert!(std::fs::read(&staged).unwrap() == b"only copy of unrelated public fixture");
        assert_eq!(
            std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o644
        );
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        drop(retained_inode);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_recovery_preserves_original_public_timestamp() {
        let dir = temp_dir("audit-timestamp");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut original = fixture();
        original.timestamp_unix = 42;
        let original_bytes = original.content();
        original.ensure_staged(&path, File::sync_all).unwrap();
        let mut recovered = recover_for_target(&dir, ADDRESS, HASH, 1..=1)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.timestamp_unix(),
            42,
            "public timestamp must match retained original record"
        );
        recovered.persist(&path).unwrap();
        assert!(std::fs::read(&path).unwrap() == original_bytes.0);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct ShortWriteIo;
    impl PersistenceIo for ShortWriteIo {
        fn write_record(&mut self, file: &mut File, content: &[u8]) -> std::io::Result<()> {
            file.write_all(&content[..17])?;
            Err(std::io::Error::other(
                "injected error after a real short write",
            ))
        }
    }

    #[test]
    fn audit_regression_own_short_write_retries_on_the_same_owned_inode() {
        let dir = temp_dir("short-write");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        assert!(hit.persist_with_io(&path, &mut ShortWriteIo).is_err());
        let staged = hit.staged_path.clone().unwrap();
        let inode = std::fs::metadata(&staged).unwrap().ino();
        assert_eq!(std::fs::metadata(&staged).unwrap().len(), 17);
        assert!(!hit.staged_complete);
        assert!(!path.exists());
        assert_eq!(hit.persist(&path).unwrap(), path);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        assert!(!staged.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_short_write_foreign_replacement_survives_automatic_retry() {
        let dir = temp_dir("short-write-foreign");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        assert!(hit.persist_with_io(&path, &mut ShortWriteIo).is_err());
        let staged = hit.staged_path.clone().unwrap();
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&staged, b"unrelated public replacement").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            hit.persist(&path).or_else(|_| hit.persist(&path)).unwrap(),
            path
        );
        assert!(std::fs::read(&staged).unwrap() == b"unrelated public replacement");
        assert_eq!(
            std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o644
        );
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct FailDirectorySync {
        calls: usize,
        fail_at: usize,
    }
    impl PersistenceIo for FailDirectorySync {
        fn sync_directory(&mut self, path: &Path) -> Result<(), String> {
            self.calls += 1;
            if self.calls == self.fail_at {
                return Err("injected hit directory synchronization failure".to_string());
            }
            sync_directory(path)
        }
    }

    #[test]
    fn audit_regression_post_unlink_sync_failure_clears_owned_stage_before_retry() {
        let dir = temp_dir("post-unlink-sync");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        hit.ensure_staged(&path, File::sync_all).unwrap();
        let staged = hit.staged_path.clone().unwrap();
        let mut io = FailDirectorySync {
            calls: 0,
            fail_at: 3,
        };
        // Reopen-stage sync, final-link sync, then unlink and the failing directory sync.
        assert!(hit.persist_with_io(&path, &mut io).is_err());
        assert_eq!(io.calls, 3);
        assert!(!staged.exists());
        assert!(path.exists());
        assert!(hit.staged_path.is_none());
        assert!(hit.staged_file.is_none());
        assert!(!hit.staged_complete);
        std::fs::write(&staged, b"new unrelated public record").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        assert!(std::fs::read(&staged).unwrap() == b"new unrelated public record");
        assert_eq!(
            std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o644
        );
        crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_failed_final_directory_sync_keeps_the_only_stage_link() {
        let dir = temp_dir("pre-unlink-sync");
        let path = dir.join(FOUND_KEY_FILENAME);
        let mut hit = fixture();
        let mut io = FailDirectorySync {
            calls: 0,
            fail_at: 2,
        };
        assert!(hit.persist_with_io(&path, &mut io).is_err());
        let staged = hit.staged_path.clone().unwrap();
        assert!(staged.exists());
        assert!(hit.staged_file.is_some());
        crate::claim::ClaimKey::load_found_key_file(&staged, HASH, 1..=1).unwrap();
        assert_eq!(hit.persist(&path).unwrap(), path);
        assert!(!staged.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_regression_invalid_timestamp_metadata_keeps_a_valid_staged_key() {
        for metadata in [
            "",
            "TIMESTAMP (UNIX): invalid\n",
            "TIMESTAMP (UNIX): 18446744073709551616\n",
            "TIMESTAMP (UNIX): 42\nTIMESTAMP (UNIX): 42\n",
            "TIMESTAMP (UNIX): broken\nTIMESTAMP (UNIX): 42\n",
        ] {
            let dir = temp_dir("invalid-time");
            let staged = dir.join(".FOUND_KEY.public-fixture.tmp");
            let bytes = format!("{metadata}PRIVATE KEY (HEX): 0x1\n{COMPLETE_MARKER}");
            std::fs::write(&staged, bytes.as_bytes()).unwrap();
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut hit = recover_for_target(&dir, ADDRESS, HASH, 1..=1)
                .unwrap()
                .unwrap();
            assert_eq!(hit.timestamp_unix(), 0);
            let path = dir.join(FOUND_KEY_FILENAME);
            assert_eq!(hit.persist(&path).unwrap(), path);
            assert!(std::fs::read(&path).unwrap() == bytes.as_bytes());
            let (_, timestamp) =
                crate::claim::ClaimKey::load_found_key_file_with_timestamp(&path, HASH, 1..=1)
                    .unwrap();
            assert_eq!(timestamp, None);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn audit_regression_partial_stage_saves_under_umask_0400_in_subprocess() {
        const CHILD_MODE: &str = "PUZZLE71_UMASK_TEST_CHILD";
        if std::env::var_os(CHILD_MODE).is_some() {
            // Only this isolated child changes its process-wide umask. Keep directory
            // permissions independent of the file-creation case under examination.
            let dir = temp_dir("umask-write-only");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join(FOUND_KEY_FILENAME);
            let mut hit = fixture();
            // SAFETY: the child runs only this test; no parallel test can inherit this mask.
            let previous_mask = unsafe { libc::umask(0o400) };
            let first = hit.persist(&path);
            if first.is_err() {
                let staged = hit.staged_path.as_ref().expect("own initial staging file");
                assert_eq!(
                    std::fs::metadata(staged).unwrap().permissions().mode() & 0o777,
                    0o200,
                    "the failed reopen must have left the initial write-only mode"
                );
            }
            let result = first.or_else(|_| hit.persist(&path));
            // SAFETY: restore the child process's original mask before assertions/cleanup.
            unsafe { libc::umask(previous_mask) };
            assert_eq!(
                result.expect("a write-only initial stage must save without manual repair"),
                path
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            crate::claim::ClaimKey::load_found_key_file(&path, HASH, 1..=1).unwrap();
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "hit_handler::tests::audit_regression_partial_stage_saves_under_umask_0400_in_subprocess"])
            .env(CHILD_MODE, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "umask0400 child could not durably save its candidate"
                );
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("umask0400 child blocked the hit persistence path");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
