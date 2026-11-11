//! Owner-only secure root for the agent's durable state.
//!
//! macOS and Linux open every object descriptor-relative and no-follow below a
//! trusted home (`unix.rs`). Every other platform, Windows included until
//! `SA-2B1b`, fails closed (`windows.rs`): no root can be opened, so no state
//! can be read, written or served. See `spec/state-store-v1.md`.

use crate::security::SecurityError;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use unix::*;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod windows;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub use windows::*;

/// Stable storage errors. They carry no path, OS error text or file content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// A root, directory or file failed the ownership, type, mode, link-count
    /// or filesystem policy, or could not be verified.
    UnsafeState,
    /// Another process holds the root's owner lock.
    Busy,
    /// A commit failed part-way. Sticky until the process restarts.
    Unknown,
    /// The state file is not state schema 1.
    Incompatible,
    /// The state file is oversize, not canonical, or violates a load invariant.
    Corrupt,
    /// The reference transition refused the change; nothing was written.
    Refused(SecurityError),
    /// The OS clock or CSPRNG is unavailable.
    Unavailable,
}

/// Points in the commit sequence. Every commit system call runs through
/// `shim`, which in test builds lets a hook record, fail, pause or abort it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Step {
    /// Opening one component below the trusted home; test-only hook point
    /// for the deterministic path swap.
    Descend(usize),
    /// Syncing the parent directory after creating component `n`, so the
    /// new entry is durable.
    SyncParent(usize),
    CreateTemp,
    /// First half of the bytes.
    Write,
    /// Second half; a failure here leaves a half-written temp file.
    WriteRest,
    SyncFile,
    /// After the temp file is durable and before the store takes its
    /// exclusive guard. Not a system call; a pause point only.
    Staged,
    Rename,
    SyncDir,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn shim<T>(
    #[cfg_attr(not(test), allow(unused_variables))] step: Step,
    op: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    #[cfg(test)]
    seams::fire(step)?;
    op()
}

/// Test-only seams. Nothing here exists in a non-test build, so no public
/// API can reach a bypass. Every seam is thread-local, so parallel tests do
/// not see each other's settings, and [`seams::Reset`] clears them all.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) mod seams {
    use std::{
        cell::{Cell, RefCell},
        ffi::CStr,
    };

    use super::Step;

    // Guards that a negative control may bypass.
    pub(crate) const NOFOLLOW: u32 = 1 << 0;
    pub(crate) const OWNER: u32 = 1 << 1;
    pub(crate) const MODE: u32 = 1 << 2;
    pub(crate) const INTERMEDIATE: u32 = 1 << 3;
    pub(crate) const NLINK: u32 = 1 << 4;
    pub(crate) const LOCAL_FS: u32 = 1 << 5;
    pub(crate) const BYTE_CAP: u32 = 1 << 6;
    /// Skips the exact-mode `fchmod` on objects the agent creates.
    pub(crate) const SKIP_FCHMOD: u32 = 1 << 7;
    /// Skips clearing the extended ACL on objects the agent creates (macOS).
    #[cfg(target_os = "macos")]
    pub(crate) const SKIP_ACL_CLEAR: u32 = 1 << 8;
    /// Skips the "no extended ACL entry" check (macOS).
    #[cfg(target_os = "macos")]
    pub(crate) const ACL: u32 = 1 << 9;

    // Objects whose owner classification a test may force to "foreign".
    pub(crate) const HOME: u32 = 1 << 0;
    pub(crate) const INTERMEDIATE_DIR: u32 = 1 << 1;
    pub(crate) const ROOT: u32 = 1 << 2;
    pub(crate) const FILE: u32 = 1 << 3;

    pub(crate) type Hook = Box<dyn FnMut(Step) -> std::io::Result<()>>;

    thread_local! {
        static BYPASS: Cell<u32> = const { Cell::new(0) };
        static FOREIGN: Cell<u32> = const { Cell::new(0) };
        static NONLOCAL: Cell<bool> = const { Cell::new(false) };
        static LOCK_NAME: Cell<Option<&'static CStr>> = const { Cell::new(None) };
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn bypass(flags: u32) {
        BYPASS.with(|cell| cell.set(flags));
    }
    pub(crate) fn bypassed(flag: u32) -> bool {
        BYPASS.with(|cell| cell.get() & flag != 0)
    }
    pub(crate) fn force_foreign(objects: u32) {
        FOREIGN.with(|cell| cell.set(objects));
    }
    pub(crate) fn forced_foreign(object: u32) -> bool {
        FOREIGN.with(|cell| cell.get() & object != 0)
    }
    pub(crate) fn force_nonlocal(value: bool) {
        NONLOCAL.with(|cell| cell.set(value));
    }
    pub(crate) fn forced_nonlocal() -> bool {
        NONLOCAL.with(Cell::get)
    }
    /// Locks this file instead of the dedicated lock file.
    pub(crate) fn lock_name_override(name: Option<&'static CStr>) {
        LOCK_NAME.with(|cell| cell.set(name));
    }
    pub(crate) fn lock_name() -> Option<&'static CStr> {
        LOCK_NAME.with(Cell::get)
    }
    pub(crate) fn set_hook(hook: Option<Hook>) {
        HOOK.with(|cell| *cell.borrow_mut() = hook);
    }
    pub(crate) fn fire(step: Step) -> std::io::Result<()> {
        HOOK.with(|cell| match cell.borrow_mut().as_mut() {
            Some(hook) => hook(step),
            None => Ok(()),
        })
    }

    /// Clears every seam on this thread when dropped, including on panic.
    pub(crate) struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            bypass(0);
            force_foreign(0);
            force_nonlocal(false);
            lock_name_override(None);
            set_hook(None);
        }
    }
}

/// Temporary "home" directories for tests. Only directories this helper
/// created are removed.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) mod test_support {
    use std::{
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// No spaces: the frozen macOS suffix has one, so tests use this suffix,
    /// which exercises the same intermediate-directory and root rules.
    pub(crate) const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];

    pub(crate) struct TempHome {
        pub(crate) path: PathBuf,
    }

    impl TempHome {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        pub(crate) fn root(&self) -> PathBuf {
            SUFFIX
                .iter()
                .fold(self.path.clone(), |path, part| path.join(part))
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Reopen after this process dropped the previous owner. Tests in the
    /// same binary spawn child processes, and between fork and exec a child
    /// holds a copy of every descriptor; `O_CLOEXEC` closes it only at exec.
    /// `flock` belongs to the open file description, so a lock this process
    /// just released can stay held for that window and an immediate reopen
    /// sees `Busy` (measured: 1 in 60 full-binary runs on macOS). Only `Busy`
    /// is retried, for at most 2 s; tests that assert `Busy` must not use this.
    pub(crate) fn retry_busy<T>(
        mut attempt: impl FnMut() -> Result<T, super::StorageError>,
    ) -> Result<T, super::StorageError> {
        for _ in 0..200 {
            match attempt() {
                Err(super::StorageError::Busy) => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                other => return other,
            }
        }
        attempt()
    }
}
