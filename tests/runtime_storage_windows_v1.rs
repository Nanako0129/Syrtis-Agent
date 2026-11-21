//! W1 (`SA-2B1b`) Windows storage acceptance through the public API only.
//!
//! Guard-bypass negative controls need test-only seams, so they live in the
//! unit tests of `src/secure_fs/windows.rs`. The platform-independent store
//! acceptance reruns on Windows in `tests/runtime_storage_v1.rs` (`disk`).
#![cfg(windows)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use syrtis_agent::{
    secure_fs::{STATE_SUFFIX, SecureRoot, StorageError, default_root_path, trusted_home},
    security::{Platform, RootMetadata, resolve_secure_root},
};

/// No spaces, the same shape as the frozen suffix plus one level.
const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];

/// A temporary base below the temp directory. Only directories this helper
/// created are removed.
struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "syrtis-agent-win-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn root(&self) -> PathBuf {
        SUFFIX
            .iter()
            .fold(self.path.clone(), |path, part| path.join(part))
    }

    fn open(&self) -> Result<SecureRoot, StorageError> {
        SecureRoot::open_under(&self.path, SUFFIX)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run(program: &str, args: &[&std::ffi::OsStr]) {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Re-runs this test binary as a child with `env` set and returns what
/// `default_root_path` gave it.
fn child_root(env: &[(&str, &str)]) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_process_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SYRTIS_WIN_CHILD", "1")
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stdout}");
    let start = stdout.find("ROOT:").unwrap_or_else(|| panic!("{stdout}")) + "ROOT:".len();
    stdout[start..].lines().next().unwrap_or("").to_owned()
}

/// The child side of `child_root`. A no-op in a normal test run.
#[test]
fn child_process_entry() {
    if std::env::var_os("SYRTIS_WIN_CHILD").is_none() {
        return;
    }
    println!("ROOT:{:?}", default_root_path());
}

/// The root is the frozen `Nyanako\Syrtis Agent` below the current token's
/// LocalAppData known folder, computed without opening anything.
#[test]
fn the_production_root_is_the_frozen_suffix_below_localappdata() {
    let home = trusted_home().unwrap();
    let path = default_root_path().unwrap();
    assert_eq!(STATE_SUFFIX, ["Nyanako", "Syrtis Agent"]);
    let verified = RootMetadata {
        absolute: true,
        local_filesystem: true,
        owner_matches: true,
        no_symlink_or_reparse: true,
        private_permissions: true,
    };
    let frozen = resolve_secure_root(Platform::Windows, home.to_str(), None, verified).unwrap();
    assert_eq!(format!("{}\\", path.display()), frozen);
}

/// F-B7: a child with `LOCALAPPDATA` pointed elsewhere resolves the same
/// root.
#[test]
fn localappdata_does_not_change_the_root() {
    let ours = format!("{:?}", default_root_path());
    assert!(ours.starts_with("Ok("), "{ours}");
    let theirs = child_root(&[("LOCALAPPDATA", r"C:\syrtis-attacker-localappdata")]);
    assert_eq!(theirs, ours);
}

/// R-7: the measured `USERPROFILE` result. The known folder is asked with
/// the process token; this asserts that a child with `USERPROFILE` pointed
/// elsewhere still resolves the same root. If this fails on CI, the spec's
/// `USERPROFILE` sentence changes (first-contact budget), not this test.
#[test]
fn userprofile_does_not_change_the_root() {
    let ours = format!("{:?}", default_root_path());
    let theirs = child_root(&[("USERPROFILE", r"C:\syrtis-attacker-profile")]);
    assert_eq!(theirs, ours);
}

/// UNC, device, relative and `..` bases fail closed before anything is
/// opened or created.
#[test]
fn only_absolute_drive_paths_are_accepted_as_a_base() {
    let home = TempHome::new();
    for bad in [
        r"\\localhost\C$\Windows\Temp".to_owned(),
        r"\\?\UNC\localhost\C$\Windows\Temp".to_owned(),
        r"\\.\C:\Windows\Temp".to_owned(),
        r"relative\dir".to_owned(),
        format!(r"{}\..\x", home.path.display()),
    ] {
        assert_eq!(
            SecureRoot::open_under(Path::new(&bad), SUFFIX).err(),
            Some(StorageError::UnsafeState),
            "{bad}"
        );
    }
    assert!(!home.path.join(SUFFIX[0]).exists());
    // Control: the same base as a plain drive path opens.
    drop(home.open().unwrap());
}

/// A junctioned agent root fails closed, and nothing is written through it.
#[test]
fn a_junctioned_root_fails_closed() {
    let decoy = TempHome::new();
    drop(decoy.open().unwrap());
    let home = TempHome::new();
    drop(home.open().unwrap());
    std::fs::rename(home.root(), home.path.join("moved")).unwrap();
    run(
        "cmd",
        &[
            "/c".as_ref(),
            "mklink".as_ref(),
            "/J".as_ref(),
            home.root().as_os_str(),
            decoy.root().as_os_str(),
        ],
    );
    assert_eq!(home.open().err(), Some(StorageError::UnsafeState));
    assert_eq!(
        SecureRoot::open_read_only(&home.path, SUFFIX).err(),
        Some(StorageError::UnsafeState)
    );
    assert!(!decoy.root().join("state.json").exists());
}

/// A root made by something other than the agent (here `create_dir_all`)
/// inherits its parents' ACEs and is not protected: refused and left as
/// found, for manual repair.
#[test]
fn a_root_the_agent_did_not_create_fails_closed() {
    let home = TempHome::new();
    std::fs::create_dir_all(home.root()).unwrap();
    assert_eq!(home.open().err(), Some(StorageError::UnsafeState));
    assert!(home.root().is_dir());
    assert!(!home.root().join("owner.lock").exists());
}

/// BUILTIN\Users granted write on an intermediate directory: refused.
/// Control: the same layout opened before the grant.
#[test]
fn an_intermediate_granting_users_write_fails_closed() {
    let home = TempHome::new();
    drop(home.open().unwrap());
    let library = home.path.join(SUFFIX[0]);
    run(
        "icacls",
        &[
            library.as_os_str(),
            "/grant".as_ref(),
            "*S-1-5-32-545:(W)".as_ref(),
        ],
    );
    assert_eq!(home.open().err(), Some(StorageError::UnsafeState));
}

/// W4: a base that INHERITS an ACE granting BUILTIN\Users Modify and
/// delete-child (the shape OpenAI's Codex sandbox leaves on the profile)
/// opens; the same grant on the existing intermediate directory is still
/// refused.
#[test]
fn a_base_others_may_modify_opens_but_such_an_intermediate_does_not() {
    let parent = TempHome::new();
    run(
        "icacls",
        &[
            parent.path.as_os_str(),
            "/grant".as_ref(),
            "*S-1-5-32-545:(OI)(CI)(M,DC)".as_ref(),
        ],
    );
    let base = parent.path.join("base");
    std::fs::create_dir(&base).unwrap();
    let root = SecureRoot::open_under(&base, SUFFIX)
        .unwrap_or_else(|e| panic!("open_under below {base:?} failed: {e:?}"));
    drop(root);
    run(
        "icacls",
        &[
            base.join(SUFFIX[0]).as_os_str(),
            "/grant".as_ref(),
            "*S-1-5-32-545:(OI)(CI)(M,DC)".as_ref(),
        ],
    );
    assert_eq!(
        SecureRoot::open_under(&base, SUFFIX).err(),
        Some(StorageError::UnsafeState)
    );
}

/// The lock holds against a second opener while the first is open, and is
/// released on drop.
#[test]
fn the_owner_lock_is_exclusive_and_released_on_drop() {
    let home = TempHome::new();
    let first = home.open().unwrap();
    assert_eq!(home.open().err(), Some(StorageError::Busy));
    let read_only = SecureRoot::open_read_only(&home.path, SUFFIX).unwrap();
    assert!(read_only.is_some(), "a read-only open takes no lock");
    drop(first);
    drop(home.open().unwrap());
}
