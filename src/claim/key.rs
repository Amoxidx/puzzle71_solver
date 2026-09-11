//! Loading and independently deriving the puzzle's private key for claim signing.
//!
//! [`ClaimKey`] never implements `Clone` or `Serialize`, and its `Debug` output never contains
//! key material (see its `Debug` impl below). The wrapped secret scalar is best-effort erased
//! on `Drop` via `secp256k1::SecretKey::non_secure_erase`
//! (secp256k1-0.29.1/src/key.rs:972, macro at src/macros.rs:56-70).

use std::fmt;
use std::ops::RangeInclusive;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::claim::error::ClaimError;
use crate::claim::memory::secure_zero;

const FOUND_KEY_LABEL: &str = "PRIVATE KEY (HEX):";

/// An independently derived, target-matching private key for the puzzle address.
///
/// Not `Clone`. Not `Serialize`. `Debug` always prints `ClaimKey(<redacted>)`, never the key.
/// The secret scalar itself, and the compressed pubkey/hash160 derived from it, are reachable
/// only from within `src/claim/` (via `pub(in crate::claim)` accessors) — never from outside
/// this module tree.
pub struct ClaimKey {
    secret: SecretKey,
    pubkey_compressed: [u8; 33],
    hash160: [u8; 20],
}

impl ClaimKey {
    /// Encodes `key` as a 32-byte big-endian scalar, derives its compressed public key and
    /// HASH160 using only `bitcoin`/`secp256k1`, and checks the result against
    /// `expected_hash160`.
    pub fn from_u128(key: u128, expected_hash160: [u8; 20]) -> Result<ClaimKey, ClaimError> {
        // u128 is 16 bytes; left-pad with 16 zero bytes to get the 32-byte big-endian scalar
        // `SecretKey::from_slice` expects.
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&key.to_be_bytes());
        let secret = SecretKey::from_slice(&bytes).map_err(|_| ClaimError::KeyOutOfRange)?;
        secure_zero(&mut bytes);

        let secp = Secp256k1::signing_only();
        let secp_pubkey = secret.public_key(&secp);
        let pubkey_compressed = secp_pubkey.serialize();
        let hash160 = bitcoin::PublicKey::new(secp_pubkey)
            .pubkey_hash()
            .to_byte_array();

        if hash160 != expected_hash160 {
            return Err(ClaimError::KeyDoesNotMatchTarget);
        }

        Ok(ClaimKey {
            secret,
            pubkey_compressed,
            hash160,
        })
    }

    /// Loads a `FOUND_KEY.txt`-formatted file (see `src/hit_handler.rs:88-110` for the exact
    /// format this parses): requires file permissions to be exactly `0o600`, exactly one
    /// `PRIVATE KEY (HEX):` line whose `0x`-prefixed hex value lies within `range`, then derives
    /// and checks the key as in [`ClaimKey::from_u128`].
    pub fn load_found_key_file(
        path: &Path,
        expected_hash160: [u8; 20],
        range: RangeInclusive<u128>,
    ) -> Result<ClaimKey, ClaimError> {
        let metadata = std::fs::metadata(path).map_err(|_| ClaimError::KeyFileFormat)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ClaimError::KeyFilePermissions);
        }

        let content = std::fs::read_to_string(path).map_err(|_| ClaimError::KeyFileFormat)?;
        let mut found: Option<u128> = None;
        // Collected instead of returned early from inside the loop so that every path below —
        // success or a malformed line partway through the file — still reaches the
        // `secure_zero(&mut content_bytes)` call right after the loop; `content` holds the raw
        // file text, including the key hex, until then.
        let mut parse_result: Result<(), ClaimError> = Ok(());
        for line in content.lines() {
            let Some(rest) = line.trim().strip_prefix(FOUND_KEY_LABEL) else {
                continue;
            };
            if found.is_some() {
                parse_result = Err(ClaimError::KeyFileFormat);
                break;
            }
            let Some(hex_digits) = rest.trim().strip_prefix("0x") else {
                parse_result = Err(ClaimError::KeyFileFormat);
                break;
            };
            match u128::from_str_radix(hex_digits, 16) {
                Ok(parsed) => found = Some(parsed),
                Err(_) => {
                    parse_result = Err(ClaimError::KeyFileFormat);
                    break;
                }
            }
        }

        // Best effort (see `memory.rs`): erase the file's raw text, which contains the key hex,
        // on every path from here on, not only the success path.
        let mut content_bytes = content.into_bytes();
        secure_zero(&mut content_bytes);

        parse_result?;
        let key = found.ok_or(ClaimError::KeyFileFormat)?;
        if !range.contains(&key) {
            return Err(ClaimError::KeyOutOfRange);
        }

        ClaimKey::from_u128(key, expected_hash160)
    }

    /// The secret scalar. Restricted to `src/claim/` — used only to sign claim inputs.
    pub(in crate::claim) fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// The compressed public key matching this secret, as raw 33 bytes. Restricted to
    /// `src/claim/` — used only to build scriptSigs.
    pub(in crate::claim) fn compressed_pubkey_bytes(&self) -> [u8; 33] {
        self.pubkey_compressed
    }

    /// HASH160 of the compressed public key, i.e. the puzzle address's pubkey hash. Not secret
    /// on its own (it *is* the public address), but still restricted to `src/claim/` since it is
    /// only ever needed internally to reconstruct the expected input script.
    pub(in crate::claim) fn hash160(&self) -> [u8; 20] {
        self.hash160
    }
}

impl fmt::Debug for ClaimKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimKey(<redacted>)")
    }
}

impl Drop for ClaimKey {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
        secure_zero(&mut self.pubkey_compressed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    /// A fixed, arbitrary test scalar. Its only relevant property is being a valid secp256k1
    /// scalar; it is unrelated to the real puzzle key.
    const TEST_SCALAR: u128 = 0x82A7F3;

    fn test_hash160() -> [u8; 20] {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&TEST_SCALAR.to_be_bytes());
        let secret = SecretKey::from_slice(&bytes).unwrap();
        let secp = Secp256k1::signing_only();
        let pubkey = secret.public_key(&secp);
        bitcoin::PublicKey::new(pubkey)
            .pubkey_hash()
            .to_byte_array()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "puzzle71-claim-key-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn write_key_file(path: &std::path::Path, mode: u32, content: &str) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn from_u128_accepts_a_key_matching_its_own_target_hash160() {
        let key = ClaimKey::from_u128(TEST_SCALAR, test_hash160()).unwrap();
        assert_eq!(format!("{key:?}"), "ClaimKey(<redacted>)");
    }

    #[test]
    fn from_u128_rejects_a_wrong_target_hash160() {
        let mut wrong = test_hash160();
        wrong[0] ^= 0xFF;
        let err = ClaimKey::from_u128(TEST_SCALAR, wrong).unwrap_err();
        assert_eq!(err, ClaimError::KeyDoesNotMatchTarget);
    }

    #[test]
    fn load_found_key_file_rejects_permissions_other_than_0600() {
        let dir = temp_dir("perms");
        let path = dir.join("FOUND_KEY.txt");
        write_key_file(
            &path,
            0o644,
            &format!("PRIVATE KEY (HEX):       0x{TEST_SCALAR:018x}\n"),
        );

        let err = ClaimKey::load_found_key_file(&path, test_hash160(), 0..=u128::MAX).unwrap_err();
        assert_eq!(err, ClaimError::KeyFilePermissions);

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn load_found_key_file_rejects_a_missing_key_line() {
        let dir = temp_dir("missing");
        let path = dir.join("FOUND_KEY.txt");
        write_key_file(&path, 0o600, "PUZZLE NUMBER:           #71\n");

        let err = ClaimKey::load_found_key_file(&path, test_hash160(), 0..=u128::MAX).unwrap_err();
        assert_eq!(err, ClaimError::KeyFileFormat);

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn load_found_key_file_rejects_a_duplicated_key_line() {
        let dir = temp_dir("duplicate");
        let path = dir.join("FOUND_KEY.txt");
        write_key_file(
            &path,
            0o600,
            &format!(
                "PRIVATE KEY (HEX):       0x{TEST_SCALAR:018x}\nPRIVATE KEY (HEX):       0x{TEST_SCALAR:018x}\n"
            ),
        );

        let err = ClaimKey::load_found_key_file(&path, test_hash160(), 0..=u128::MAX).unwrap_err();
        assert_eq!(err, ClaimError::KeyFileFormat);

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn load_found_key_file_rejects_a_value_outside_the_range() {
        let dir = temp_dir("range");
        let path = dir.join("FOUND_KEY.txt");
        write_key_file(
            &path,
            0o600,
            &format!("PRIVATE KEY (HEX):       0x{TEST_SCALAR:018x}\n"),
        );

        let err =
            ClaimKey::load_found_key_file(&path, test_hash160(), (TEST_SCALAR + 1)..=u128::MAX)
                .unwrap_err();
        assert_eq!(err, ClaimError::KeyOutOfRange);

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn load_found_key_file_accepts_a_well_formed_0600_file() {
        let dir = temp_dir("ok");
        let path = dir.join("FOUND_KEY.txt");
        write_key_file(
            &path,
            0o600,
            &format!(
                "================================================================================\n\
                 PUZZLE NUMBER:           #71\n\
                 PRIVATE KEY (HEX):       0x{TEST_SCALAR:018x}\n\
                 PRIVATE KEY (DECIMAL):   {TEST_SCALAR}\n\
                 ================================================================================\n"
            ),
        );

        let key = ClaimKey::load_found_key_file(&path, test_hash160(), TEST_SCALAR..=TEST_SCALAR)
            .unwrap();
        assert_eq!(key.hash160(), test_hash160());

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
