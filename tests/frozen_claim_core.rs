//! Stolperdraht for the frozen claim core ("Kern fest, Einreichweg tauschbar").
//!
//! `cargo test` fails as soon as a core file, the core-file list, the core module
//! wiring, or a security-relevant core dependency drifts. A deliberate core change
//! must reset the manifest **and** the expected values in this file:
//!
//! ```text
//! shasum -a 256 src/claim/{builder,destination,error,key,memory,net/allowlist,net/http,policy,prevout,verify}.rs > claim-core.sha256
//! ```
//!
//! This is tamper-evidence, not protection against admin access. The HTTP
//! allowlist and transport are frozen with the core; service, web, UI, and the
//! rest of the submission path sit outside this freeze. Cargo config files are
//! checked from `CARGO_MANIFEST_DIR` through every ancestor directory and,
//! when `CARGO_HOME` is set, in that directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use bitcoin::hashes::{Hash, sha256};

const FROZEN_CORE_FILES: &[&str] = &[
    "src/claim/builder.rs",
    "src/claim/destination.rs",
    "src/claim/error.rs",
    "src/claim/key.rs",
    "src/claim/memory.rs",
    "src/claim/net/allowlist.rs",
    "src/claim/net/http.rs",
    "src/claim/policy.rs",
    "src/claim/prevout.rs",
    "src/claim/verify.rs",
];

const CRATES_IO_INDEX: &str = "registry+https://github.com/rust-lang/crates.io-index";

const PINNED_CORE_DEPENDENCIES: &[(&str, &str, &str, &str)] = &[
    (
        "bitcoin",
        "0.32.11",
        CRATES_IO_INDEX,
        "7ca0f87890d2398219d15182cb6af9681722bd891758dab4ca01896e2038a510",
    ),
    (
        "bitcoin_hashes",
        "0.14.101",
        CRATES_IO_INDEX,
        "bca4c7abb40c8817d77403c880988cfd484f23ab2365726afb2f798363e2c4a2",
    ),
    (
        "bitcoinconsensus",
        "0.105.0+25.1",
        CRATES_IO_INDEX,
        "f260ac8fb2c621329013fc0ed371c940fcc512552dcbcb9095ed0179098c9e18",
    ),
    (
        "secp256k1",
        "0.29.1",
        CRATES_IO_INDEX,
        "9465315bc9d4566e1724f0fffcbcc446268cb522e60f9a27bcded6b19c108113",
    ),
    (
        "secp256k1-sys",
        "0.10.1",
        CRATES_IO_INDEX,
        "d4387882333d3aa8cb20530a17c69a3752e97837832f34f6dccc760e715001d9",
    ),
];

struct LockPackage {
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read_string(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|e| panic!("failed to read {relative}: {e}"))
}

/// Non-empty line must be `<64 [0-9a-f]><two spaces>` then
/// `src/claim/<[a-z_]+>.rs` or `src/claim/net/<[a-z_]+>.rs`.
fn parse_manifest_line(line: &str) -> Result<(String, String), String> {
    if line.len() < 64 || !line.is_char_boundary(64) {
        return Err(format!(
            "expected 64 hex chars, two spaces, then a core path, got {line:?}"
        ));
    }
    let hash = &line[..64];
    let rest = &line[64..];
    if !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("hash is not 64 lowercase hex chars: {hash:?}"));
    }
    let Some(path) = rest.strip_prefix("  ") else {
        return Err(format!("expected two spaces after the hash, got {rest:?}"));
    };
    if !is_core_rel_path(path) {
        return Err(format!(
            "path is not src/claim/<[a-z_]+>.rs or src/claim/net/<[a-z_]+>.rs: {path:?}"
        ));
    }
    Ok((hash.to_string(), path.to_string()))
}

fn is_core_rel_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("src/claim/") else {
        return false;
    };
    let Some(stem) = rest.strip_suffix(".rs") else {
        return false;
    };
    let stem = stem.strip_prefix("net/").unwrap_or(stem);
    !stem.is_empty() && stem.bytes().all(|b| matches!(b, b'a'..=b'z' | b'_'))
}

fn parse_manifest() -> Vec<(String, String)> {
    let text = read_string("claim-core.sha256");
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        match parse_manifest_line(line) {
            Ok(entry) => entries.push(entry),
            Err(msg) => errors.push(format!("line {}: {msg}", idx + 1)),
        }
    }
    if !errors.is_empty() {
        panic!("claim-core.sha256 has invalid lines: {}", errors.join("; "));
    }
    entries
}

fn package_identities(lock: &str) -> BTreeMap<String, Vec<LockPackage>> {
    let mut map: BTreeMap<String, Vec<LockPackage>> = BTreeMap::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_source: Option<String> = None;
    let mut current_checksum: Option<String> = None;

    let flush = |map: &mut BTreeMap<String, Vec<LockPackage>>,
                 name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 checksum: &mut Option<String>| {
        let source = source.take();
        let checksum = checksum.take();
        if let (Some(name), Some(version)) = (name.take(), version.take()) {
            map.entry(name).or_default().push(LockPackage {
                version,
                source,
                checksum,
            });
        }
    };

    for raw in lock.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            flush(
                &mut map,
                &mut current_name,
                &mut current_version,
                &mut current_source,
                &mut current_checksum,
            );
            continue;
        }
        if let Some(name) = quoted_field(line, "name") {
            current_name = Some(name.to_string());
        } else if let Some(version) = quoted_field(line, "version") {
            current_version = Some(version.to_string());
        } else if let Some(source) = quoted_field(line, "source") {
            current_source = Some(source.to_string());
        } else if let Some(checksum) = quoted_field(line, "checksum") {
            current_checksum = Some(checksum.to_string());
        }
    }
    flush(
        &mut map,
        &mut current_name,
        &mut current_version,
        &mut current_source,
        &mut current_checksum,
    );
    map
}

fn quoted_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .strip_prefix(" = \"")?
        .strip_suffix('"')
}

fn without_spaces(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

fn frozen_claim_module_name(path: &str) -> Option<&str> {
    let name = path.strip_prefix("src/claim/")?.strip_suffix(".rs")?;
    if !name.is_empty() && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'_')) {
        Some(name)
    } else {
        None
    }
}

fn mod_decl_count(src: &str, name: &str) -> usize {
    let pub_decl = format!("pub mod {name};");
    let priv_decl = format!("mod {name};");
    src.lines()
        .map(str::trim)
        .filter(|line| *line == pub_decl || *line == priv_decl)
        .count()
}

fn rel_display(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .map(|rel| rel.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn collect_claim_rs_paths(dir: &Path, files: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) => {
            problems.push(format!("failed to read {}: {e}", rel_display(dir)));
            return;
        }
    };
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in read {
        match entry {
            Ok(entry) => entries.push(entry.path()),
            Err(e) => problems.push(format!("failed to read entry in {}: {e}", rel_display(dir))),
        }
    }
    entries.sort();
    for path in entries {
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                problems.push(format!("failed to stat {}: {e}", rel_display(&path)));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            problems.push(format!("{} is a symlink", rel_display(&path)));
            continue;
        }
        if meta.is_dir() {
            collect_claim_rs_paths(&path, files, problems);
            continue;
        }
        if meta.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn manifest_lists_exactly_the_frozen_core_files() {
    let entries = parse_manifest();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, path) in &entries {
        *counts.entry(path.clone()).or_insert(0) += 1;
    }

    let seen: BTreeSet<String> = counts.keys().cloned().collect();
    let expected: BTreeSet<String> = FROZEN_CORE_FILES.iter().map(|s| (*s).to_string()).collect();

    let missing: Vec<String> = expected.difference(&seen).cloned().collect();
    let extra: Vec<String> = seen.difference(&expected).cloned().collect();
    let duplicates: Vec<String> = counts
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(path, n)| format!("{path} ({n} times)"))
        .collect();

    assert!(
        missing.is_empty() && extra.is_empty() && duplicates.is_empty(),
        "claim-core.sha256 path set mismatch: missing={missing:?} extra={extra:?} duplicates={duplicates:?}"
    );
}

#[test]
fn frozen_core_files_match_manifest() {
    let entries = parse_manifest();
    let mut mismatches = Vec::new();

    for (expected_hex, rel) in entries {
        let path = repo_path(&rel);
        if !path.is_file() {
            mismatches.push(format!("{rel}: file missing at {}", path.display()));
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("failed to read {rel}: {e}"));
        let actual_hex = sha256::Hash::hash(&bytes).to_string();
        if actual_hex != expected_hex {
            mismatches.push(format!("{rel}: expected {expected_hex}, got {actual_hex}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "frozen core file hash mismatch:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn core_dependencies_are_pinned() {
    let packages = package_identities(&read_string("Cargo.lock"));
    let mut mismatches = Vec::new();

    for (name, version, source, checksum) in PINNED_CORE_DEPENDENCIES {
        match packages.get(*name).map(Vec::as_slice) {
            None | Some([]) => mismatches.push(format!(
                "{name}: no [[package]] entry in Cargo.lock (expected version {version})"
            )),
            Some([pkg]) => {
                if pkg.version != *version {
                    mismatches.push(format!(
                        "{name}: expected version {version}, found {}",
                        pkg.version
                    ));
                }
                match pkg.source.as_deref() {
                    Some(actual) if actual == *source => {}
                    Some(actual) => mismatches.push(format!(
                        "{name}: expected source {source}, found {actual}"
                    )),
                    None => mismatches.push(format!(
                        "{name}: missing source (expected {source})"
                    )),
                }
                match pkg.checksum.as_deref() {
                    Some(actual) if actual == *checksum => {}
                    Some(actual) => mismatches.push(format!(
                        "{name}: expected checksum {checksum}, found {actual}"
                    )),
                    None => mismatches.push(format!(
                        "{name}: missing checksum (expected {checksum})"
                    )),
                }
            }
            Some(found) => mismatches.push(format!(
                "{name}: expected exactly one [[package]] entry with version {version}, found {} ({})",
                found.len(),
                found
                    .iter()
                    .map(|pkg| pkg.version.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    assert!(
        mismatches.is_empty(),
        "pinned core dependency mismatch:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn no_dependency_overrides() {
    let cargo_toml = read_string("Cargo.toml");
    let forbidden_tables: Vec<&str> = cargo_toml
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("[patch") || trimmed.starts_with("[replace")
        })
        .collect();
    assert!(
        forbidden_tables.is_empty(),
        "Cargo.toml must not contain [patch]/[replace] tables, found: {forbidden_tables:?}"
    );

    let forbidden_paths: Vec<&str> = cargo_toml
        .lines()
        .filter(|line| {
            let compact = without_spaces(line);
            compact.starts_with("path=")
                || compact.starts_with("build=")
                || compact.contains("path=\"")
                || compact.contains("build=\"")
        })
        .collect();
    assert!(
        forbidden_paths.is_empty(),
        "Cargo.toml must not contain path=/build= entries, found: {forbidden_paths:?}"
    );

    assert!(
        !repo_path("build.rs").exists(),
        "build.rs must not exist at the repo root"
    );

    let mut dir = repo_root();
    loop {
        for name in ["config", "config.toml"] {
            let path = dir.join(".cargo").join(name);
            assert!(
                !path.exists(),
                "{} must not exist (cargo source overrides)",
                path.display()
            );
        }
        if !dir.pop() {
            break;
        }
    }

    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        if !cargo_home.is_empty() {
            let home = PathBuf::from(cargo_home);
            for name in ["config", "config.toml"] {
                let path = home.join(name);
                assert!(
                    !path.exists(),
                    "CARGO_HOME {} must not exist (cargo source overrides)",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn claim_module_has_no_direct_process_or_socket_use() {
    const FORBIDDEN: &[&str] = &[
        "process::Command",
        "Command::new",
        "std::net",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "unix::net",
        "libc::socket",
        "libc::connect",
    ];
    let http = repo_path("src/claim/net/http.rs");
    let mut files = Vec::new();
    let mut problems = Vec::new();
    collect_claim_rs_paths(&repo_path("src/claim"), &mut files, &mut problems);
    files.sort();
    for path in files {
        if path == http {
            continue;
        }
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(e) => {
                problems.push(format!("failed to read {}: {e}", rel_display(&path)));
                continue;
            }
        };
        let hits: Vec<&str> = FORBIDDEN
            .iter()
            .copied()
            .filter(|needle| source.contains(needle))
            .collect();
        if !hits.is_empty() {
            problems.push(format!(
                "{} contains {}",
                rel_display(&path),
                hits.join(", ")
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "claim module must not use process/socket APIs outside net/http.rs:\n{}",
        problems.join("\n")
    );
}

#[test]
fn core_module_wiring_is_not_redirected() {
    let lib = read_string("src/lib.rs");
    let claim_mod = read_string("src/claim/mod.rs");
    let net_mod = read_string("src/claim/net/mod.rs");
    let mut problems = Vec::new();

    for (label, src) in [
        ("src/lib.rs", lib.as_str()),
        ("src/claim/mod.rs", claim_mod.as_str()),
        ("src/claim/net/mod.rs", net_mod.as_str()),
    ] {
        let compact = without_spaces(src);
        for marker in ["#[path", "path=", "include!"] {
            if compact.contains(marker) {
                problems.push(format!("{label} contains {marker} after removing spaces"));
            }
        }
    }

    if !lib.lines().any(|line| line.trim() == "pub mod claim;") {
        problems.push("src/lib.rs has no line `pub mod claim;`".to_string());
    }

    let mut claim_names: Vec<&str> = FROZEN_CORE_FILES
        .iter()
        .copied()
        .filter_map(frozen_claim_module_name)
        .collect();
    claim_names.push("net");
    for name in claim_names {
        let count = mod_decl_count(&claim_mod, name);
        if count != 1 {
            problems.push(format!(
                "src/claim/mod.rs: expected exactly one `pub mod {name};` or `mod {name};`, found {count}"
            ));
        }
    }

    for name in ["allowlist", "http"] {
        let count = mod_decl_count(&net_mod, name);
        if count != 1 {
            problems.push(format!(
                "src/claim/net/mod.rs: expected exactly one `pub mod {name};` or `mod {name};`, found {count}"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "core module wiring mismatch:\n{}",
        problems.join("\n")
    );
}
