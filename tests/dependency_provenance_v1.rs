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

/// The only tables the manifest may contain, spelled exactly. Anything else
/// (`[features]`, `[profile.*]`, `[patch.*]`, `[replace]`, `[workspace]`, a
/// dotted or quoted spelling, a header with a trailing comment) is refused
/// rather than skipped. SA-2B1b extends this list for its Windows table.
const TABLES: [&str; 4] = [
    "package",
    "dependencies",
    "target.'cfg(unix)'.dependencies",
    "dev-dependencies",
];
/// `[package]` keys. `build`, `links`, `workspace` and the rest are refused.
const PACKAGE_KEYS: [&str; 5] = ["name", "version", "edition", "rust-version", "license"];

/// The only keys a dependency's inline table may hold. `git`, `path`,
/// `registry`, `registry-index`, `package`, `artifact`, `lib`, `target`,
/// `branch`, `rev`, `tag` and anything else are refused, quoted or not.
const DEPENDENCY_KEYS: [&str; 4] = ["version", "default-features", "features", "optional"];

/// Byte offsets of `separator` outside strings and brackets. `None` when a
/// string or bracket is left open.
fn top_level_positions(text: &str, separator: u8) -> Option<Vec<usize>> {
    let (mut positions, mut depth, mut quote, mut escaped) = (Vec::new(), 0usize, None, false);
    for (index, byte) in text.bytes().enumerate() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' && open == b'"' {
                escaped = true;
            } else if byte == open {
                quote = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' => quote = Some(byte),
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth = depth.checked_sub(1)?,
            _ if byte == separator && depth == 0 => positions.push(index),
            _ => {}
        }
    }
    (quote.is_none() && depth == 0).then_some(positions)
}

/// The keys of a one-line inline table `{ k = v, … }`, with surrounding
/// whitespace and quotes stripped. `None` when it cannot be parsed: an open
/// string or bracket, an empty item, or an item with no `=` outside a string.
fn inline_table_keys(spec: &str) -> Option<Vec<String>> {
    let inner = spec.strip_prefix('{')?.strip_suffix('}')?;
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut bounds = vec![0];
    for position in top_level_positions(inner, b',')? {
        bounds.extend([position, position + 1]);
    }
    bounds.push(inner.len());
    bounds
        .chunks(2)
        .map(|pair| {
            let item = &inner[pair[0]..pair[1]];
            let equals = *top_level_positions(item, b'=')?.first()?;
            let (key, value) = (item[..equals].trim(), item[equals + 1..].trim());
            let key = ['"', '\'']
                .iter()
                .find_map(|q| key.strip_prefix(*q)?.strip_suffix(*q))
                .unwrap_or(key);
            (!key.is_empty() && !value.is_empty()).then(|| key.to_owned())
        })
        .collect()
}

fn quoted_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = line[start..].strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

/// Only the allowlisted tables and `[package]` keys, `[package]` first; every
/// dependency `=`-pinned and from the registry; `snow` exactly once, with
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
    let mut table: Option<&str> = None;
    let mut snow_count = 0;
    for line in manifest.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let header = line
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .filter(|h| TABLES.contains(h))
                .ok_or_else(|| format!("table not allowed: {line}"))?;
            if table.is_none() && header != "package" {
                return Err(format!("line before [package]: {line}"));
            }
            table = Some(header);
            continue;
        }
        match table {
            None => return Err(format!("line before [package]: {line}")),
            Some("package") => {
                let key = line.split_once(" = ").map_or(line, |(key, _)| key);
                if !PACKAGE_KEYS.contains(&key) {
                    return Err(format!("package key not allowed: {key}"));
                }
                continue;
            }
            Some(_) => {}
        }
        let (name, spec) = line
            .split_once(" = ")
            .ok_or_else(|| format!("unparsed dependency line: {line}"))?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
        {
            return Err(format!("unsupported dependency key: {name}"));
        }
        if spec.starts_with('{') != spec.ends_with('}') {
            return Err(format!("multi-line dependency: {name}"));
        }
        if spec.starts_with('{') {
            let keys =
                inline_table_keys(spec).ok_or_else(|| format!("{name}: unparsed inline table"))?;
            let mut seen = BTreeSet::new();
            for key in keys {
                if !DEPENDENCY_KEYS.contains(&key.as_str()) {
                    return Err(format!("{name}: forbidden key {key}"));
                }
                if !seen.insert(key.clone()) {
                    return Err(format!("{name}: duplicate key {key}"));
                }
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
            "table not allowed: [patch.crates-io]",
        ),
        (
            format!("{MANIFEST}\n[replace]\n"),
            "table not allowed: [replace]",
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
        // A table the checker does not know is refused, not skipped.
        (
            format!("{MANIFEST}\n[features]\ndefault = [\"snow/use-sha2\"]\n"),
            "table not allowed: [features]",
        ),
        (
            MANIFEST.replace("[dependencies]\n", "[ dependencies ]\n"),
            "table not allowed: [ dependencies ]",
        ),
        (
            MANIFEST.replace("[dependencies]\n", "[dependencies] # runtime\n"),
            "table not allowed: [dependencies] # runtime",
        ),
        (
            format!("{MANIFEST}\n[\"patch\".crates-io]\nsha2 = {{ path = \"../sha2\" }}\n"),
            "table not allowed: [\"patch\".crates-io]",
        ),
        (
            format!("{MANIFEST}\n[profile.release]\ndebug = true\n"),
            "table not allowed: [profile.release]",
        ),
        (
            MANIFEST.replace("license = \"MIT\"\n", "license = \"MIT\"\nbuild = \"x.rs\"\n"),
            "package key not allowed: build",
        ),
        (
            format!("cargo-features = [\"x\"]\n{MANIFEST}"),
            "line before [package]: cargo-features = [\"x\"]",
        ),
        (
            MANIFEST.replace("[dependencies]\n", "[dependencies]\nsnow.default-features = true\n"),
            "unsupported dependency key: snow.default-features",
        ),
    ];
    for (tampered, expected) in cases {
        assert_ne!(tampered, MANIFEST, "mutation did not apply: {expected}");
        assert_eq!(check_manifest(&tampered).unwrap_err(), expected);
    }
}

/// Every dependency key outside the allowlist is refused, however it is
/// spelled: quoted, without spaces, or a key no denylist would name; and an
/// inline table that cannot be parsed is refused. Control: the same in-test
/// copy with the key renamed to an allowed one passes, so the refusal came
/// from the key check.
#[test]
fn the_manifest_checker_rejects_any_dependency_key_outside_the_allowlist() {
    let libc = "libc = { version = \"=0.2.189\", default-features = false }";
    assert!(MANIFEST.contains(libc));
    let with = |extra: &str| {
        let tampered = MANIFEST.replace(
            libc,
            &format!("libc = {{ version = \"=0.2.189\", default-features = false, {extra} }}"),
        );
        assert_ne!(tampered, MANIFEST);
        tampered
    };
    for (extra, key) in [
        ("\"git\" = \"https://example.invalid/libc\"", "git"),
        ("git=\"https://example.invalid/libc\"", "git"),
        (
            "registry-index = \"https://example.invalid/index\"",
            "registry-index",
        ),
        ("artifact = \"bin\"", "artifact"),
        ("path = \"../libc\"", "path"),
        ("'lib' = true", "lib"),
    ] {
        assert_eq!(
            check_manifest(&with(extra)).unwrap_err(),
            format!("libc: forbidden key {key}"),
            "{extra}"
        );
        let renamed = extra.replacen(key, "optional", 1);
        check_manifest(&with(&renamed)).unwrap_or_else(|error| panic!("{renamed}: {error}"));
    }
    for extra in ["git", "features = [\"std\"", "version = \"=1\" = 2 \"x", ""] {
        assert_eq!(
            check_manifest(&with(extra)).unwrap_err(),
            "libc: unparsed inline table",
            "{extra:?}"
        );
    }
    assert_eq!(
        check_manifest(&with("version = \"=0.2.189\"")).unwrap_err(),
        "libc: duplicate key version"
    );
}
