//! Resident install and uninstall (`spec/install-v1.md`).
//!
//! Every path comes from the frozen [`install_objects`](crate::security::install_objects)
//! for the trusted home the caller passes. Nothing here reads the
//! environment, searches `PATH`, runs a shell, or loads or starts a service.
//! macOS and Linux only; every other platform returns
//! [`InstallError::Unsupported`].

use std::path::Path;

use crate::{secure_fs::StorageError, state_store::StateStore};

/// Stable install errors. They carry no path or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    /// Not macOS or Linux.
    Unsupported,
    /// The home is not an absolute UTF-8 path the frozen `install_objects`
    /// accepts, or the binary path holds a byte outside `[A-Za-z0-9/._-]`.
    Invalid,
    /// A directory or an existing target failed the type, owner, mode,
    /// link-count or ACL policy. Nothing was written.
    UnsafeState,
    /// A filesystem call failed.
    Io,
    /// The durable `StateStore::uninstall` failed; nothing was removed.
    Storage(StorageError),
}

/// What uninstall did with one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Removed (an object) or emptied (a cache).
    Removed,
    /// Not there.
    Absent,
    /// Left in place: unsafe, not the agent's, or the removal failed. The
    /// owner has to repair it by hand.
    ManualRepair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UninstallReport {
    pub autostart: Outcome,
    pub binary: Outcome,
    pub producer_cache: Outcome,
    pub receiver_cache: Outcome,
    /// `state.json` and `peers.json` were removed (`purge` only).
    pub purged: bool,
}

impl UninstallReport {
    pub fn manual_repair(&self) -> bool {
        [
            self.autostart,
            self.binary,
            self.producer_cache,
            self.receiver_cache,
        ]
        .contains(&Outcome::ManualRepair)
    }
}

/// launchd agent template; `@BINARY@` is the installed binary.
pub const MACOS_PLIST_TEMPLATE: &str =
    include_str!("../packaging/macos/com.nyanako.syrtis.agent.plist");
/// systemd user unit template; `@BINARY@` is the installed binary.
pub const LINUX_UNIT_TEMPLATE: &str = include_str!("../packaging/linux/syrtis-agent.service");

/// Copies `current_exe` to the frozen binary path and writes the autostart
/// object, each by temp file and `rename`. Never loads or starts a service.
pub fn install(trusted_home: &Path, current_exe: &Path) -> Result<(), InstallError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return unix::install(trusted_home, current_exe);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (trusted_home, current_exe);
        Err(InstallError::Unsupported)
    }
}

/// Durable uninstall first, then the exact agent-owned objects, then both
/// caches, then (`purge`, nothing marked) `state.json` and `peers.json`.
///
/// Takes the only handle to the store: after a purge no one may commit the
/// old state again. The listener and control must already be stopped.
pub fn uninstall(
    store: StateStore,
    trusted_home: &Path,
    purge: bool,
    terminal_at_ms: i64,
) -> Result<UninstallReport, InstallError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return unix::uninstall(store, trusted_home, purge, terminal_at_ms);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (store, trusted_home, purge, terminal_at_ms);
        Err(InstallError::Unsupported)
    }
}

/// The autostart object's bytes for `binary`. A byte outside
/// `[A-Za-z0-9/._-]` would need XML or systemd escaping (or quoting a
/// space), so it is refused rather than escaped.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn autostart_contents(binary: &str) -> Result<String, InstallError> {
    let plain = binary
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte));
    if !plain {
        return Err(InstallError::Invalid);
    }
    #[cfg(target_os = "macos")]
    let template = MACOS_PLIST_TEMPLATE;
    #[cfg(target_os = "linux")]
    let template = LINUX_UNIT_TEMPLATE;
    Ok(template.replacen("@BINARY@", binary, 1))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix {
    use std::{
        ffi::CString,
        fs::File,
        io::{self, Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
        sync::Arc,
    };

    use super::{InstallError, Outcome, UninstallReport, autostart_contents};
    use crate::{
        cache::CacheRole,
        cache_store::CacheStore,
        peer_store::PEERS_FILE,
        security::{MemoryLedger, Platform, install_objects},
        state_store::{STATE_FILE, StateStore},
    };

    #[cfg(target_os = "macos")]
    const PLATFORM: Platform = Platform::MacOs;
    #[cfg(target_os = "linux")]
    const PLATFORM: Platform = Platform::Linux;

    /// One object below a verified parent directory.
    struct Target {
        dir: File,
        name: CString,
    }

    pub(super) fn install(trusted_home: &Path, current_exe: &Path) -> Result<(), InstallError> {
        let home = trusted_home.to_str().ok_or(InstallError::Invalid)?;
        let objects = install_objects(PLATFORM, home).map_err(|_| InstallError::Invalid)?;
        let autostart = autostart_contents(&objects.binary)?;
        // Check-only pass: both chains as far as they exist, both existing
        // targets and the source, before any directory is created.
        for path in [&objects.binary, &objects.autostart_object] {
            if let Some(target) = descend(home, path, false)? {
                existing(&target)?;
            }
        }
        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(current_exe)
            .map_err(|_| InstallError::Io)?;
        if !source.metadata().map_err(|_| InstallError::Io)?.is_file() {
            return Err(InstallError::Io);
        }
        // Create-and-write pass; every directory is checked again.
        let binary = descend(home, &objects.binary, true)?.ok_or(InstallError::Io)?;
        let launcher = descend(home, &objects.autostart_object, true)?.ok_or(InstallError::Io)?;
        existing(&binary)?;
        existing(&launcher)?;
        let mut bytes = Vec::new();
        source
            .read_to_end(&mut bytes)
            .map_err(|_| InstallError::Io)?;
        replace(&binary, &bytes, 0o755)?;
        replace(&launcher, autostart.as_bytes(), 0o644)
    }

    pub(super) fn uninstall(
        store: StateStore,
        trusted_home: &Path,
        purge: bool,
        terminal_at_ms: i64,
    ) -> Result<UninstallReport, InstallError> {
        // Durable first: sharing off, every grant revoked, deny floor
        // raised. If this fails nothing is removed.
        store
            .uninstall(terminal_at_ms)
            .map_err(InstallError::Storage)?;
        // Each object on its own: a chain that fails its checks marks only
        // that object. Paths that cannot be derived mark both; the caches
        // and the report still follow.
        let remove = |found: Result<Found, InstallError>| match found {
            Ok(Found::Absent) => Outcome::Absent,
            Ok(Found::Safe(target)) => match unlink(&target) {
                Ok(()) => Outcome::Removed,
                Err(_) => Outcome::ManualRepair,
            },
            Ok(Found::Foreign) | Err(_) => Outcome::ManualRepair,
        };
        let paths = trusted_home
            .to_str()
            .and_then(|home| Some((home, install_objects(PLATFORM, home).ok()?)));
        let (autostart, binary) = match paths {
            Some((home, objects)) => {
                let expected = autostart_contents(&objects.binary).ok();
                let launcher = find(home, &objects.autostart_object).map(|found| match found {
                    Found::Safe(target) if !matches(&target, expected.as_deref()) => Found::Foreign,
                    other => other,
                });
                (remove(launcher), remove(find(home, &objects.binary)))
            }
            None => (Outcome::ManualRepair, Outcome::ManualRepair),
        };
        let root = store.root();
        let clear = |role| match CacheStore::open(Arc::clone(&root), role, MemoryLedger::default())
            .and_then(|cache| cache.clear())
        {
            Ok(_) => Outcome::Removed,
            Err(_) => Outcome::ManualRepair,
        };
        let mut report = UninstallReport {
            autostart,
            binary,
            producer_cache: clear(CacheRole::Producer),
            receiver_cache: clear(CacheRole::Receiver),
            purged: false,
        };
        // `owner.lock` is never removed: unlinking a held lock lets the next
        // process lock a different inode.
        report.purged = purge
            && !report.manual_repair()
            && root.remove_file(PEERS_FILE).is_ok()
            && root.remove_file(STATE_FILE).is_ok();
        Ok(report)
    }

    enum Found {
        Absent,
        /// Regular, owned by the effective UID, one link (and, for the
        /// autostart object, byte-equal to this version's template).
        Safe(Target),
        /// Present but not provably the agent's.
        Foreign,
    }

    /// `Err` only when a parent directory fails its checks.
    fn find(home: &str, path: &str) -> Result<Found, InstallError> {
        let Some(target) = descend(home, path, false)? else {
            return Ok(Found::Absent);
        };
        Ok(match existing(&target) {
            Ok(false) => Found::Absent,
            Ok(true) => Found::Safe(target),
            Err(_) => Found::Foreign,
        })
    }

    /// Whether the object is byte-equal to `expected`, read through a
    /// no-follow descriptor. `None` (no template could be rendered) never
    /// matches.
    fn matches(target: &Target, expected: Option<&str>) -> bool {
        expected.is_some_and(|expected| {
            read_exact_object(target, expected.len())
                .ok()
                .flatten()
                .is_some_and(|bytes| bytes == expected.as_bytes())
        })
    }

    /// Opens `home` by path, then each directory of `path` below it with
    /// `openat(O_DIRECTORY | O_NOFOLLOW)`, checking each one on its
    /// descriptor. With `create`, a missing directory is created `0755`;
    /// without it, a missing directory is `Ok(None)`.
    fn descend(home: &str, path: &str, create: bool) -> Result<Option<Target>, InstallError> {
        let rest = path
            .strip_prefix(home)
            .and_then(|rest| rest.strip_prefix('/'))
            .ok_or(InstallError::Invalid)?;
        let mut names = rest
            .split('/')
            .map(|name| {
                if name.is_empty() || name == "." || name == ".." {
                    return Err(InstallError::Invalid);
                }
                CString::new(name).map_err(|_| InstallError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let name = names.pop().ok_or(InstallError::Invalid)?;
        let home = CString::new(home).map_err(|_| InstallError::Invalid)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let mut dir = file(unsafe { libc::open(home.as_ptr(), flags) })
            .map_err(|_| InstallError::UnsafeState)?;
        check_dir(&dir)?;
        for component in &names {
            let next = match open_dir_at(&dir, component) {
                Ok(next) => next,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    if !create {
                        return Ok(None);
                    }
                    create_dir_at(&dir, component)?
                }
                Err(_) => return Err(InstallError::UnsafeState),
            };
            check_dir(&next)?;
            dir = next;
        }
        Ok(Some(Target { dir, name }))
    }

    /// A directory owned by the effective UID, not group- or
    /// other-writable, and on macOS with no ACL entry other than an explicit
    /// deny (an allow entry does not show in the mode bits).
    fn check_dir(dir: &File) -> Result<(), InstallError> {
        let meta = dir.metadata().map_err(|_| InstallError::UnsafeState)?;
        let ok =
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0;
        #[cfg(target_os = "macos")]
        let ok = ok && crate::secure_fs::acl::deny_only(dir);
        if ok {
            Ok(())
        } else {
            Err(InstallError::UnsafeState)
        }
    }

    fn open_dir_at(parent: &File, name: &CString) -> io::Result<File> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        file(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) })
    }

    /// `mkdirat` `0755` (exact, whatever the umask), then a sync of the
    /// parent so the new entry is durable.
    fn create_dir_at(parent: &File, name: &CString) -> Result<File, InstallError> {
        let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
        let created = rc == 0;
        if !created && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(InstallError::Io);
        }
        let dir = open_dir_at(parent, name).map_err(|_| InstallError::UnsafeState)?;
        if created {
            cvt(unsafe { libc::fchmod(dir.as_raw_fd(), 0o755) }).map_err(|_| InstallError::Io)?;
            full_sync(parent).map_err(|_| InstallError::Io)?;
        }
        Ok(dir)
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)`: `Ok(false)` when absent, `Ok(true)`
    /// for a regular file owned by the effective UID with one link, else
    /// `UnsafeState`.
    fn existing(target: &Target) -> Result<bool, InstallError> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                target.dir.as_raw_fd(),
                target.name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(false)
            } else {
                Err(InstallError::UnsafeState)
            };
        }
        let ok = stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == unsafe { libc::geteuid() }
            && stat.st_nlink == 1;
        if ok {
            Ok(true)
        } else {
            Err(InstallError::UnsafeState)
        }
    }

    /// The object's bytes if it is still a regular file of at most `len`
    /// bytes owned by the effective UID with one link, read through a
    /// no-follow descriptor; `None` when longer.
    fn read_exact_object(target: &Target, len: usize) -> io::Result<Option<Vec<u8>>> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        let object =
            file(unsafe { libc::openat(target.dir.as_raw_fd(), target.name.as_ptr(), flags) })?;
        let meta = object.metadata()?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        object.take(len as u64 + 1).read_to_end(&mut bytes)?;
        Ok((bytes.len() <= len).then_some(bytes))
    }

    /// Writes `bytes` to `.<name>.tmp` (`O_EXCL`, no-follow), sets `mode` on
    /// that descriptor, syncs it, renames it over the target and syncs the
    /// directory. A failure before the rename removes the temp file and
    /// leaves the old target as it was.
    fn replace(target: &Target, bytes: &[u8], mode: libc::mode_t) -> Result<(), InstallError> {
        let mut temp = b".".to_vec();
        temp.extend_from_slice(target.name.as_bytes());
        temp.extend_from_slice(b".tmp");
        let temp = CString::new(temp).map_err(|_| InstallError::Invalid)?;
        let dir = target.dir.as_raw_fd();
        // A temp left by a crash; `unlinkat` never follows a link.
        if unsafe { libc::unlinkat(dir, temp.as_ptr(), 0) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(InstallError::Io);
        }
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mode_bits: libc::c_uint = 0o600;
        let mut object = file(unsafe { libc::openat(dir, temp.as_ptr(), flags, mode_bits) })
            .map_err(|_| InstallError::Io)?;
        let staged = object
            .write_all(bytes)
            .and_then(|()| cvt(unsafe { libc::fchmod(object.as_raw_fd(), mode) }))
            .and_then(|()| full_sync(&object))
            .and_then(|()| {
                cvt(unsafe { libc::renameat(dir, temp.as_ptr(), dir, target.name.as_ptr()) })
            });
        if staged.is_err() {
            unsafe { libc::unlinkat(dir, temp.as_ptr(), 0) };
            return Err(InstallError::Io);
        }
        full_sync(&target.dir).map_err(|_| InstallError::Io)
    }

    fn unlink(target: &Target) -> io::Result<()> {
        cvt(unsafe { libc::unlinkat(target.dir.as_raw_fd(), target.name.as_ptr(), 0) })?;
        full_sync(&target.dir)
    }

    /// macOS `fsync` does not flush the drive cache; `F_FULLFSYNC` does.
    #[cfg(target_os = "macos")]
    fn full_sync(file: &File) -> io::Result<()> {
        cvt(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) })
    }

    #[cfg(target_os = "linux")]
    fn full_sync(file: &File) -> io::Result<()> {
        cvt(unsafe { libc::fsync(file.as_raw_fd()) })
    }

    fn cvt(rc: libc::c_int) -> io::Result<()> {
        if rc == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn file(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;

        use crate::{
            secure_fs::{
                SecureRoot, Step,
                seams::{self, Reset},
                test_support::{SUFFIX, TempHome, retry_busy},
            },
            security::install_objects,
            state_store::StateStore,
        };

        const NOW: i64 = 1_700_000_000;

        fn objects(home: &TempHome) -> (PathBuf, PathBuf) {
            let home = home.path.to_str().unwrap();
            let objects = install_objects(super::PLATFORM, home).unwrap();
            (objects.binary.into(), objects.autostart_object.into())
        }

        /// Acceptance 7: a failing durable uninstall removes nothing.
        #[test]
        fn a_failed_durable_uninstall_removes_nothing() {
            let home = TempHome::new();
            let source = home.path.join("source-binary");
            std::fs::write(&source, b"agent").unwrap();
            super::install(&home.path, &source).unwrap();
            let store = retry_busy(|| {
                SecureRoot::open_under(&home.path, SUFFIX)
                    .and_then(|root| StateStore::open(root, NOW))
            })
            .unwrap();
            let state = home.root().join("state.json");
            let before = std::fs::read(&state).unwrap();

            let _reset = Reset;
            seams::set_hook(Some(Box::new(|step| match step {
                Step::Rename => Err(std::io::Error::other("injected")),
                _ => Ok(()),
            })));
            let result = super::uninstall(store, &home.path, true, NOW * 1_000);
            seams::set_hook(None);

            assert!(matches!(result, Err(super::InstallError::Storage(_))));
            let (binary, autostart) = objects(&home);
            assert_eq!(std::fs::read(&binary).unwrap(), b"agent");
            assert!(autostart.is_file());
            assert_eq!(std::fs::read(&state).unwrap(), before);
        }
    }
}
