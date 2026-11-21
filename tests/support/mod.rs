//! Temporary homes for the integration tests, on macOS, Linux and Windows
//! (W3b). Each test file that needs one says `mod support;`.
#![allow(dead_code)]

use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Creates a fresh, empty directory `<base>/<tag>-<pid>-<n>` and returns
/// its path; the caller removes it (only what it created).
///
/// macOS and Linux: below the real `/tmp` (canonical, so no component is a
/// symlink, and short, so a control socket path fits `sun_path`), mode
/// `0700`. Windows: below the temp directory in its long, non-verbatim
/// form (`X:\…`, no 8.3 component), with the DACL it inherits there, which
/// the secure root's base rule accepts; no `chmod` exists or is needed.
pub fn new_home(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = base().join(format!(
        "{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap_or_else(|error| panic!("create {path:?}: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

#[cfg(unix)]
fn base() -> PathBuf {
    std::fs::canonicalize("/tmp").unwrap()
}

/// `canonicalize` resolves 8.3 names and junctions but returns the
/// verbatim form; the `\\?\` of a drive path is removed again (`open_under`
/// and the engine both take `X:\…`).
#[cfg(windows)]
fn base() -> PathBuf {
    let temp = std::env::temp_dir();
    let long = std::fs::canonicalize(&temp)
        .unwrap_or_else(|error| panic!("canonicalize {temp:?}: {error}"));
    let text = long
        .to_str()
        .unwrap_or_else(|| panic!("{long:?} is not UTF-8"));
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => panic!("unexpected temp directory form {long:?} (from {temp:?})"),
    }
}
