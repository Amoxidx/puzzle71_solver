//! Independent Verification and Secure Storage of Discovered Private Keys.
//!
//! Per safety and audit requirements:
//! - Immediate halt of all GPU/CPU search workers upon hit detection.
//! - Independent, pure-CPU re-verification from raw private key to Bitcoin address.
//! - Strict local storage to `FOUND_KEY.txt` with mode 0600 (owner read/write only).
//! - Zero network transmission, zero telemetry, zero automated transaction broadcast.

use crate::crypto::address::privkey_u128_to_address;
use crate::puzzle_config::{PUZZLE_NUMBER, TARGET_ADDRESS, TARGET_HASH160};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FOUND_KEY_FILENAME: &str = "FOUND_KEY.txt";

#[derive(Debug, Clone)]
pub struct VerifiedHit {
    pub puzzle_number: u32,
    pub private_key: u128,
    pub private_key_hex: String,
    pub private_key_dec: String,
    pub public_key_compressed_hex: String,
    pub bitcoin_address: String,
    pub hash160_hex: String,
    pub timestamp_unix: u64,
    pub saved_filename: String,
}

/// Perform complete, independent CPU verification of a candidate key
/// and save to FOUND_KEY.txt if valid.
pub fn verify_and_save_candidate(candidate_key: u128) -> Result<VerifiedHit, String> {
    // Step 1: Independent CPU derivation
    let (derived_addr, derived_h160, comp_pubkey) = privkey_u128_to_address(candidate_key);

    // Step 2: Exact HASH160 verification
    if derived_h160 != TARGET_HASH160 {
        return Err(format!(
            "CPU Verification FAILED: HASH160 mismatch! Derived: {:?}, Target: {:?}",
            derived_h160, TARGET_HASH160
        ));
    }

    // Step 3: Exact Bitcoin P2PKH Address verification
    if derived_addr != TARGET_ADDRESS {
        return Err(format!(
            "CPU Verification FAILED: Address mismatch! Derived: {}, Target: {}",
            derived_addr, TARGET_ADDRESS
        ));
    }

    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let hex_key = format!("0x{:018x}", candidate_key);
    let dec_key = format!("{}", candidate_key);
    let pubkey_hex = hex_encode(&comp_pubkey);
    let h160_hex = hex_encode(&derived_h160);

    let mut hit = VerifiedHit {
        puzzle_number: PUZZLE_NUMBER,
        private_key: candidate_key,
        private_key_hex: hex_key.clone(),
        private_key_dec: dec_key.clone(),
        public_key_compressed_hex: pubkey_hex.clone(),
        bitcoin_address: derived_addr.clone(),
        hash160_hex: h160_hex.clone(),
        timestamp_unix,
        saved_filename: String::new(),
    };

    // Step 4: Write to FOUND_KEY.txt atomically with restrictive 0600 permissions.
    let saved_path = write_verified_hit(&hit, Path::new(FOUND_KEY_FILENAME))?;
    hit.saved_filename = saved_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(FOUND_KEY_FILENAME)
        .to_string();

    Ok(hit)
}

fn write_verified_hit(hit: &VerifiedHit, path: &Path) -> Result<PathBuf, String> {
    let file_content = format!(
        "================================================================================\n\
         !!! WARNING: CONFIDENTIAL PRIVATE KEY - DO NOT UPLOAD OR SHARE THIS FILE !!!\n\
         ================================================================================\n\
         PUZZLE NUMBER:           #{}\n\
         TIMESTAMP (UNIX):        {}\n\
         PRIVATE KEY (HEX):       {}\n\
         PRIVATE KEY (DECIMAL):   {}\n\
         PUBLIC KEY (COMPRESSED): {}\n\
         HASH160 (HEX):           {}\n\
         BITCOIN ADDRESS (P2PKH): {}\n\
         TARGET ADDRESS MATCH:    VERIFIED EXACT MATCH\n\
         CPU VERIFICATION STATUS: PASSED (100% INDEPENDENT DERIVATION)\n\
         CLAIM INSTRUCTIONS:      SWEEP VIA OFFLINE AIR-GAPPED WALLET ONLY\n\
         ================================================================================\n",
        hit.puzzle_number,
        hit.timestamp_unix,
        hit.private_key_hex,
        hit.private_key_dec,
        hit.public_key_compressed_hex,
        hit.hash160_hex,
        hit.bitcoin_address
    );

    let temp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("FOUND_KEY"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temp_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| format!("Failed to create secure temporary key file: {}", e))?;

    file.write_all(file_content.as_bytes())
        .map_err(|e| format!("Failed to write private-key file: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync private-key file: {}", e))?;
    drop(file);

    std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to secure temporary key file: {}", e))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("FOUND_KEY");
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("txt");
    let mut installed_path = None;
    for attempt in 0..100u32 {
        let candidate = if attempt == 0 {
            path.to_path_buf()
        } else {
            parent.join(format!(
                "{}.{}.{}.{}",
                stem, hit.timestamp_unix, attempt, extension
            ))
        };
        match std::fs::hard_link(&temp_path, &candidate) {
            Ok(()) => {
                installed_path = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(format!(
                    "Failed to atomically install private-key file without overwrite: {}",
                    error
                ));
            }
        }
    }
    let Some(installed_path) = installed_path else {
        let _ = std::fs::remove_file(&temp_path);
        return Err("Could not allocate a unique private-key filename".to_string());
    };
    std::fs::remove_file(&temp_path)
        .map_err(|e| format!("Failed to remove temporary private-key link: {}", e))?;
    std::fs::set_permissions(&installed_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to secure final private-key file: {}", e))?;

    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("Failed to sync private-key directory: {}", e))?;

    Ok(installed_path)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hit() -> VerifiedHit {
        VerifiedHit {
            puzzle_number: 71,
            private_key: 42,
            private_key_hex: "0x00000000000000002a".to_string(),
            private_key_dec: "42".to_string(),
            public_key_compressed_hex: "02deadbeef".to_string(),
            bitcoin_address: TARGET_ADDRESS.to_string(),
            hash160_hex: hex_encode(&TARGET_HASH160),
            timestamp_unix: 1,
            saved_filename: String::new(),
        }
    }

    #[test]
    fn key_file_is_owner_only_and_never_overwritten() {
        let directory = std::env::temp_dir().join(format!(
            "puzzle71-hit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("FOUND_KEY.txt");
        let hit = fixture_hit();

        let first_path = write_verified_hit(&hit, &path).expect("write key fixture");
        assert_eq!(first_path, path);
        let permissions = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(permissions, 0o600);
        let original = std::fs::read_to_string(&path).unwrap();
        let second_path = write_verified_hit(&hit, &path).expect("write unique fallback");
        assert_ne!(second_path, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(std::fs::read_to_string(&second_path).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&second_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(second_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
