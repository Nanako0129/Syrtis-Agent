//! Dependency provenance guard (SA-2B1a acceptance 9).
//!
//! The candidate-digest manifest used to freeze `Cargo.toml` and `Cargo.lock`
//! byte for byte. Runtime slices must edit both, so that guard moved here:
//! every package in the `793f3d9` lock is snapshotted in
//! `fixtures/v1/runtime/storage/cargo-lock-baseline.json` (itself frozen by the
//! manifest), and the checkers below reject any changed, removed or
//! unlisted package and any unpinned dependency, with their own assertions
//! rather than a cargo parse error.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

const LOCK: &str = include_str!("../Cargo.lock");
const MANIFEST: &str = include_str!("../Cargo.toml");
const BASELINE: &str = include_str!("fixtures/v1/runtime/storage/cargo-lock-baseline.json");
const PROVENANCE: &str = include_str!("fixtures/v1/security/provenance.json");

/// Packages this slice may add beyond the baseline. Empty: `libc 0.2.189` was
/// already in the `793f3d9` lock as a transitive dependency.
const NEW_PACKAGE_ALLOWLIST: &[&str] = &[];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn parse_lock(text: &str) -> Result<Vec<Package>, String> {
    let mut packages = Vec::new();
    let mut current: Option<BTreeMap<String, String>> = None;
    for line in text.lines() {
        if line.starts_with('[') {
            if let Some(fields) = current.take() {
                packages.push(package_from(fields)?);
            }
            if line == "[[package]]" {
                current = Some(BTreeMap::new());
            }
            continue;
        }
        let Some(fields) = current.as_mut() else {
            continue;
        };
        for key in ["name", "version", "source", "checksum"] {
            if let Some(value) = line
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(" = \""))
                .and_then(|rest| rest.strip_suffix('"'))
            {
                if fields.insert(key.to_owned(), value.to_owned()).is_some() {
                    return Err(format!("duplicate {key} in a lock package"));
                }
            }
        }
    }
    if let Some(fields) = current.take() {
        packages.push(package_from(fields)?);
    }
    Ok(packages)
}

fn package_from(mut fields: BTreeMap<String, String>) -> Result<Package, String> {
    Ok(Package {
        name: fields.remove("name").ok_or("lock package without name")?,
        version: fields
            .remove("version")
            .ok_or("lock package without version")?,
        source: fields.remove("source"),
        checksum: fields.remove("checksum"),
    })
}

fn baseline() -> Vec<Package> {
    let value: Value = serde_json::from_str(BASELINE).unwrap();
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let text = |key: &str| entry[key].as_str().map(str::to_owned);
            Package {
                name: text("name").unwrap(),
                version: text("version").unwrap(),
                source: text("source"),
                checksum: text("checksum"),
            }
        })
        .collect()
}

/// Every baseline package must still be in the lock with the same source and
/// checksum; every other package must be on the allowlist.
fn check_lock(lock_text: &str, baseline: &[Package], allowlist: &[&str]) -> Result<(), String> {
    let lock = parse_lock(lock_text)?;
    let mut by_identity = BTreeMap::new();
    for package in &lock {
        let identity = (package.name.as_str(), package.version.as_str());
        if by_identity.insert(identity, package).is_some() {
            return Err(format!("duplicate lock package {identity:?}"));
        }
    }
    for expected in baseline {
        let identity = (expected.name.as_str(), expected.version.as_str());
        match by_identity.get(&identity) {
            Some(actual) if *actual == expected => {}
            Some(_) => return Err(format!("baseline package changed: {identity:?}")),
            None => return Err(format!("baseline package missing: {identity:?}")),
        }
    }
    let known: BTreeSet<(&str, &str)> = baseline
        .iter()
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect();
    for package in &lock {
        if !known.contains(&(package.name.as_str(), package.version.as_str()))
            && !allowlist.contains(&package.name.as_str())
        {
            return Err(format!(
                "package not in baseline or allowlist: {} {}",
                package.name, package.version
            ));
        }
    }
    Ok(())
}

fn is_dependency_table(header: &str) -> bool {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    KINDS.contains(&header)
        || header.strip_prefix("target.").is_some_and(|rest| {
            KINDS.iter().any(|kind| {
                rest.strip_suffix(kind)
                    .is_some_and(|cfg| cfg.ends_with('.'))
            })
        })
}

fn quoted_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = line[start..].strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

/// Every dependency in every dependency table is `=`-pinned and comes from the
/// registry; no `[patch]` or `[replace]`; `snow` appears exactly once, with
/// default features off and exactly the frozen feature set.
fn check_manifest(manifest: &str) -> Result<(), String> {
    let provenance: Value = serde_json::from_str(PROVENANCE).unwrap();
    let snow_version = format!("={}", provenance["snow"]["version"].as_str().unwrap());
    let snow_features: BTreeSet<String> = provenance["snow"]["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|feature| feature.as_str().unwrap().to_owned())
        .collect();
    let mut table: Option<String> = None;
    let mut snow_count = 0;
    for line in manifest.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            if header.starts_with("patch") || header.starts_with("replace") {
                return Err(format!("forbidden table [{header}]"));
            }
            if header.contains("dependencies.") {
                return Err(format!("unsupported dependency layout [{header}]"));
            }
            table = Some(header.to_owned());
            continue;
        }
        if !table.as_deref().is_some_and(is_dependency_table) {
            continue;
        }
        let (name, spec) = line
            .split_once(" = ")
            .ok_or_else(|| format!("unparsed dependency line: {line}"))?;
        if spec.starts_with('{') != spec.ends_with('}') {
            return Err(format!("multi-line dependency: {name}"));
        }
        for forbidden in ["git", "path", "registry", "package", "branch", "rev", "tag"] {
            if spec.contains(&format!("{forbidden} =")) {
                return Err(format!("{name}: forbidden key {forbidden}"));
            }
        }
        let version = if spec.starts_with('"') {
            spec.trim_matches('"')
        } else {
            quoted_after(spec, "version = ").ok_or_else(|| format!("{name}: no version"))?
        };
        if !version.starts_with('=') {
            return Err(format!("{name}: version {version} is not an exact pin"));
        }
        if name == "snow" {
            snow_count += 1;
            let features: BTreeSet<String> = spec
                .split_once("features = [")
                .and_then(|(_, rest)| rest.split_once(']'))
                .map(|(list, _)| {
                    list.split(',')
                        .map(|item| item.trim().trim_matches('"').to_owned())
                        .filter(|item| !item.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if version != snow_version
                || !spec.contains("default-features = false")
                || features != snow_features
            {
                return Err("snow version, default features or feature set changed".into());
            }
        }
    }
    if snow_count == 1 {
        Ok(())
    } else {
        Err(format!("snow declared {snow_count} times"))
    }
}

#[test]
fn the_lock_keeps_every_baseline_package_and_adds_none_unlisted() {
    let baseline = baseline();
    assert_eq!(
        baseline.len(),
        50,
        "baseline must cover the whole 793f3d9 lock"
    );
    check_lock(LOCK, &baseline, NEW_PACKAGE_ALLOWLIST).unwrap();
}

#[test]
fn the_lock_checker_rejects_a_changed_checksum_or_version() {
    let baseline = baseline();
    // Negative controls run against an in-test copy of the lock, so the
    // checker's own assertion rejects them, not cargo.
    let sha2 = "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283";
    assert!(LOCK.contains(sha2));
    let tampered = LOCK.replace(sha2, &"0".repeat(64));
    assert_eq!(
        check_lock(&tampered, &baseline, NEW_PACKAGE_ALLOWLIST).unwrap_err(),
        r#"baseline package changed: ("sha2", "0.10.9")"#
    );

    let dalek = "name = \"curve25519-dalek\"\nversion = \"4.1.3\"";
    assert!(LOCK.contains(dalek));
    let bumped = LOCK.replace(dalek, "name = \"curve25519-dalek\"\nversion = \"4.1.4\"");
    assert_eq!(
        check_lock(&bumped, &baseline, NEW_PACKAGE_ALLOWLIST).unwrap_err(),
        r#"baseline package missing: ("curve25519-dalek", "4.1.3")"#
    );

    let extra = format!(
        "{LOCK}\n[[package]]\nname = \"windows-sys\"\nversion = \"0.59.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
        "1".repeat(64)
    );
    assert_eq!(
        check_lock(&extra, &baseline, NEW_PACKAGE_ALLOWLIST).unwrap_err(),
        "package not in baseline or allowlist: windows-sys 0.59.0"
    );
    // Control: the same addition passes once allowlisted, so the rejection
    // above came from the allowlist and nothing else.
    check_lock(&extra, &baseline, &["windows-sys"]).unwrap();
}

#[test]
fn the_manifest_pins_every_dependency_and_snow_exactly_once() {
    check_manifest(MANIFEST).unwrap();
    assert!(
        MANIFEST.contains("[target.'cfg(unix)'.dependencies]\nlibc = { version = \"=0.2.189\"")
    );
}

#[test]
fn the_manifest_checker_rejects_unpinned_patched_or_duplicated_dependencies() {
    let cases = [
        (
            MANIFEST.replace("version = \"=0.10.0\"", "version = \"0.10.0\""),
            "snow: version 0.10.0 is not an exact pin",
        ),
        (
            MANIFEST.replace("version = \"=0.2.189\"", "version = \"0.2.189\""),
            "libc: version 0.2.189 is not an exact pin",
        ),
        (
            format!("{MANIFEST}\n[patch.crates-io]\nsha2 = {{ path = \"../sha2\" }}\n"),
            "forbidden table [patch.crates-io]",
        ),
        (
            format!("{MANIFEST}\n[replace]\n"),
            "forbidden table [replace]",
        ),
        (
            MANIFEST.replace(", \"use-getrandom\"]", "]"),
            "snow version, default features or feature set changed",
        ),
        (
            MANIFEST.replace(
                "[dev-dependencies]\n",
                "[dev-dependencies]\nsnow = { version = \"=0.10.0\", default-features = false, features = [\"use-chacha20poly1305\", \"use-blake2\", \"use-curve25519\", \"use-getrandom\"] }\n",
            ),
            "snow declared 2 times",
        ),
        (
            MANIFEST.replace(
                "libc = { version = \"=0.2.189\", default-features = false }",
                "libc = { git = \"https://example.invalid/libc\" }",
            ),
            "libc: forbidden key git",
        ),
    ];
    for (tampered, expected) in cases {
        assert_ne!(tampered, MANIFEST, "mutation did not apply: {expected}");
        assert_eq!(check_manifest(&tampered).unwrap_err(), expected);
    }
}
