//! macOS and Linux secure root: descriptor-relative, no-follow, owner-only.

use std::{
    ffi::{CStr, CString, OsStr},
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

use super::{Step, StorageError, shim};

/// Frozen state-root suffix below the trusted home (`spec/security-v1.md`).
#[cfg(target_os = "macos")]
pub const STATE_SUFFIX: &[&str] = &["Library", "Application Support", "com.nyanako.syrtis.agent"];
/// Frozen state-root suffix below the trusted home (`spec/security-v1.md`).
#[cfg(target_os = "linux")]
pub const STATE_SUFFIX: &[&str] = &[".local", "state", "syrtis-agent"];

const LOCK_FILE: &CStr = c"owner.lock";

/// `com.apple.metadata:com_apple_backup_excludeItem` = binary plist string
/// `com.apple.backupd`, the value `tmutil addexclusion` writes.
#[cfg(target_os = "macos")]
pub const BACKUP_EXCLUDE_XATTR: &CStr = c"com.apple.metadata:com_apple_backup_excludeItem";
#[cfg(target_os = "macos")]
pub const BACKUP_EXCLUDE_VALUE: [u8; 61] = *b"bplist00_\x10\x11com.apple.backupd\x08\
\0\0\0\0\0\0\x01\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c";

#[cfg(test)]
use super::seams;

/// One verified agent root, held with its exclusive owner lock.
///
/// The only way to obtain one is [`SecureRoot::open_under`], which takes the
/// lock, so holding a `SecureRoot` is the type-level proof that commits run
/// under the lock. Dropping it closes both descriptors and releases the lock;
/// so does process exit.
pub struct SecureRoot {
    dir: File,
    _lock: File,
}

/// A temp file written and synced, not yet renamed over its target.
pub(crate) struct Staged<'a> {
    root: &'a SecureRoot,
    temp: CString,
    target: CString,
}

/// The home of the effective UID from the directory service
/// (`getpwuid_r(geteuid())`). `HOME`, `XDG_*` and every other environment
/// variable are ignored.
pub fn trusted_home() -> Result<PathBuf, StorageError> {
    let uid = unsafe { libc::geteuid() };
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || entry.pw_dir.is_null() {
            return Err(StorageError::UnsafeState);
        }
        let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
        if !absolute(home) {
            return Err(StorageError::UnsafeState);
        }
        return Ok(PathBuf::from(OsStr::from_bytes(home)));
    }
}

/// The production root path. Computes only: nothing is opened or created.
pub fn default_root_path() -> Result<PathBuf, StorageError> {
    Ok(STATE_SUFFIX
        .iter()
        .fold(trusted_home()?, |path, part| path.join(part)))
}

fn absolute(path: &[u8]) -> bool {
    path.starts_with(b"/") && !path.starts_with(b"//")
}

impl SecureRoot {
    /// Opens the production root below the directory-service home.
    pub fn open_default() -> Result<Self, StorageError> {
        Self::open_under(&trusted_home()?, STATE_SUFFIX)
    }

    /// Opens `home/suffix…` and takes its owner lock.
    ///
    /// `home` is opened by path and must be owned by the effective UID. Every
    /// component below it is opened relative to its parent's descriptor with
    /// `O_NOFOLLOW`, created `0700` when missing, and checked on the
    /// descriptor: intermediate directories must be owned by the effective UID
    /// and not group- or other-writable; the last one, the agent root, must be
    /// exactly `0700` on a local filesystem.
    pub fn open_under(home: &Path, suffix: &[&str]) -> Result<Self, StorageError> {
        let home = home.as_os_str().as_bytes();
        if !absolute(home) || suffix.is_empty() {
            return Err(StorageError::UnsafeState);
        }
        let home = CString::new(home).map_err(|_| StorageError::UnsafeState)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let mut dir = file_from(unsafe { libc::open(home.as_ptr(), flags) })?;
        check_owner(&metadata(&dir)?, Object::Home)?;
        for (index, component) in suffix.iter().enumerate() {
            let name = component_name(component)?;
            shim(Step::Descend(index), || Ok(())).map_err(|_| StorageError::UnsafeState)?;
            let last = index + 1 == suffix.len();
            let (next, created) = open_or_create_dir(&dir, &name)?;
            if created {
                // Only an object created in this call is ever chmod-ed or
                // stripped: an existing one is checked as found.
                set_exact_mode(&next, 0o700).map_err(|_| StorageError::UnsafeState)?;
                #[cfg(target_os = "macos")]
                if last {
                    clear_acl(&next).map_err(|_| StorageError::UnsafeState)?;
                }
                shim(Step::SyncParent(index), || full_sync(&dir))
                    .map_err(|_| StorageError::UnsafeState)?;
            }
            let meta = metadata(&next)?;
            guard(meta.is_dir(), 0, StorageError::UnsafeState)?;
            if last {
                check_owner(&meta, Object::Root)?;
                #[cfg(target_os = "macos")]
                guard(acl::none(&next), ACL, StorageError::UnsafeState)?;
                guard(
                    meta.mode() & 0o7777 == 0o700,
                    MODE,
                    StorageError::UnsafeState,
                )?;
                guard(local_filesystem(&next), LOCAL_FS, StorageError::UnsafeState)?;
            } else {
                check_owner(&meta, Object::Intermediate)?;
                guard(
                    meta.mode() & 0o022 == 0,
                    INTERMEDIATE,
                    StorageError::UnsafeState,
                )?;
            }
            dir = next;
        }
        #[cfg(target_os = "macos")]
        set_backup_exclude(&dir)?;
        let lock = acquire_lock(&dir)?;
        Ok(Self { dir, _lock: lock })
    }

    /// Reads an agent-owned file: no-follow, regular, owned by the effective
    /// UID, `0600`, one link, at most `max` bytes. `Ok(None)` when absent.
    pub(crate) fn read_file(
        &self,
        name: &str,
        max: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let name = file_name(name)?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | nofollow();
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        let file = file_from(fd)?;
        check_private_file(&file)?;
        let mut bytes = Vec::new();
        (&file)
            .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::UnsafeState)?;
        guard(bytes.len() <= max, BYTE_CAP, StorageError::Corrupt)?;
        Ok(Some(bytes))
    }

    /// Creates `.<name>.tmp` exclusively and no-follow, writes `bytes`, and
    /// syncs it. Any failure is [`StorageError::Unknown`].
    pub(crate) fn stage(&self, name: &str, bytes: &[u8]) -> Result<Staged<'_>, StorageError> {
        let target = file_name(name)?;
        let temp = temp_name(name)?;
        let unknown = |_| StorageError::Unknown;
        let file = shim(Step::CreateTemp, || {
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            let mode: libc::c_uint = 0o600;
            let fd = unsafe { libc::openat(self.dir.as_raw_fd(), temp.as_ptr(), flags, mode) };
            let file = cvt_file(fd)?;
            // The create mode is filtered by umask; fix it on the descriptor,
            // and drop any inherited ACL before a byte is written.
            set_exact_mode(&file, 0o600)?;
            #[cfg(target_os = "macos")]
            clear_acl(&file)?;
            Ok(file)
        })
        .map_err(unknown)?;
        let (first, rest) = bytes.split_at(bytes.len() / 2);
        shim(Step::Write, || (&file).write_all(first)).map_err(unknown)?;
        shim(Step::WriteRest, || (&file).write_all(rest)).map_err(unknown)?;
        shim(Step::SyncFile, || full_sync(&file)).map_err(unknown)?;
        shim(Step::Staged, || Ok(())).map_err(unknown)?;
        Ok(Staged {
            root: self,
            temp,
            target,
        })
    }

    /// Removes a temp file left by a crash: only the exact `.<name>.tmp`, and
    /// `unlinkat` never follows a link.
    pub(crate) fn remove_stale_temp(&self, name: &str) -> Result<(), StorageError> {
        let temp = temp_name(name)?;
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), temp.as_ptr(), 0) } == 0
            || io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
        {
            Ok(())
        } else {
            Err(StorageError::UnsafeState)
        }
    }

    #[cfg(test)]
    pub(crate) fn dir_metadata(&self) -> Metadata {
        self.dir.metadata().unwrap()
    }
}

impl Staged<'_> {
    /// `renameat` over the target, then syncs the directory. Any failure is
    /// [`StorageError::Unknown`]: the durable state is then old or new, and
    /// which one cannot be known without a restart.
    pub(crate) fn publish(self) -> Result<(), StorageError> {
        let dir = self.root.dir.as_raw_fd();
        shim(Step::Rename, || {
            cvt(unsafe { libc::renameat(dir, self.temp.as_ptr(), dir, self.target.as_ptr()) })
        })
        .map_err(|_| StorageError::Unknown)?;
        shim(Step::SyncDir, || full_sync(&self.root.dir)).map_err(|_| StorageError::Unknown)
    }
}

#[derive(Clone, Copy)]
enum Object {
    Home,
    Intermediate,
    Root,
    File,
}

// Bypass flags; real values only in test builds, where `guard` consults them.
#[cfg(all(test, target_os = "macos"))]
use seams::ACL;
#[cfg(test)]
use seams::{BYTE_CAP, INTERMEDIATE, LOCAL_FS, MODE, NLINK, OWNER};
#[cfg(all(not(test), target_os = "macos"))]
const ACL: u32 = 0;
#[cfg(not(test))]
const BYTE_CAP: u32 = 0;
#[cfg(not(test))]
const INTERMEDIATE: u32 = 0;
#[cfg(not(test))]
const LOCAL_FS: u32 = 0;
#[cfg(not(test))]
const MODE: u32 = 0;
#[cfg(not(test))]
const NLINK: u32 = 0;
#[cfg(not(test))]
const OWNER: u32 = 0;

/// Fails with `error` unless `ok`. Test builds let a negative control bypass
/// the guard named by `flag`; a non-test build has no such path.
fn guard(
    ok: bool,
    #[cfg_attr(not(test), allow(unused_variables))] flag: u32,
    error: StorageError,
) -> Result<(), StorageError> {
    #[cfg(test)]
    if seams::bypassed(flag) {
        return Ok(());
    }
    if ok { Ok(()) } else { Err(error) }
}

fn nofollow() -> libc::c_int {
    #[cfg(test)]
    if seams::bypassed(seams::NOFOLLOW) {
        return 0;
    }
    libc::O_NOFOLLOW
}

fn check_owner(
    meta: &Metadata,
    #[cfg_attr(not(test), allow(unused_variables))] object: Object,
) -> Result<(), StorageError> {
    #[cfg(test)]
    let forced = seams::forced_foreign(match object {
        Object::Home => seams::HOME,
        Object::Intermediate => seams::INTERMEDIATE_DIR,
        Object::Root => seams::ROOT,
        Object::File => seams::FILE,
    });
    #[cfg(not(test))]
    let forced = false;
    let owned = meta.uid() == unsafe { libc::geteuid() } && !forced;
    guard(owned, OWNER, StorageError::UnsafeState)
}

fn check_private_file(file: &File) -> Result<(), StorageError> {
    let meta = metadata(file)?;
    guard(meta.is_file(), 0, StorageError::UnsafeState)?;
    check_owner(&meta, Object::File)?;
    guard(
        meta.mode() & 0o7777 == 0o600,
        MODE,
        StorageError::UnsafeState,
    )?;
    guard(meta.nlink() == 1, NLINK, StorageError::UnsafeState)?;
    #[cfg(target_os = "macos")]
    guard(acl::none(file), ACL, StorageError::UnsafeState)?;
    Ok(())
}

/// Sets the exact mode on an object this call created; `mkdirat` and
/// `openat` modes are filtered by the process umask.
fn set_exact_mode(file: &File, mode: libc::mode_t) -> io::Result<()> {
    #[cfg(test)]
    if seams::bypassed(seams::SKIP_FCHMOD) {
        return Ok(());
    }
    cvt(unsafe { libc::fchmod(file.as_raw_fd(), mode) })
}

/// Removes every extended ACL entry from an object this call created, so an
/// inheritable ACL on a parent cannot grant other UIDs access.
#[cfg(target_os = "macos")]
fn clear_acl(file: &File) -> io::Result<()> {
    #[cfg(test)]
    if seams::bypassed(seams::SKIP_ACL_CLEAR) {
        return Ok(());
    }
    acl::clear(file)
}

/// macOS extended ACLs. `libc` 0.2.189 has no bindings; these are libSystem.
/// Constants from `<sys/acl.h>` (`acl_type_t` is a C enum, so `int`).
#[cfg(target_os = "macos")]
mod acl {
    use std::{
        ffi::{c_int, c_void},
        fs::File,
        io,
        os::fd::AsRawFd,
    };

    type Acl = *mut c_void;
    type AclEntry = *mut c_void;
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> Acl;
        fn acl_free(object: *mut c_void) -> c_int;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> Acl;
        fn acl_set_fd_np(fd: c_int, acl: Acl, kind: c_int) -> c_int;
    }

    /// Replaces the extended ACL with an empty one.
    pub(super) fn clear(file: &File) -> io::Result<()> {
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
        let error = io::Error::last_os_error();
        unsafe { acl_free(acl) };
        if rc == 0 { Ok(()) } else { Err(error) }
    }

    /// True only when the descriptor verifiably carries no extended ACL
    /// entry; any error reading it counts as "has one".
    pub(crate) fn none(file: &File) -> bool {
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            return io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
        }
        let mut entry: AclEntry = std::ptr::null_mut();
        let has_entry = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
        unsafe { acl_free(acl) };
        !has_entry
    }
}

#[cfg(target_os = "macos")]
fn local_filesystem(dir: &File) -> bool {
    #[cfg(test)]
    if seams::forced_nonlocal() {
        return false;
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) };
    rc == 0 && stat.f_flags & libc::MNT_LOCAL as u32 != 0
}

/// `statfs` `f_type` allowlist: ext2/3/4, XFS, Btrfs, tmpfs.
#[cfg(target_os = "linux")]
fn local_filesystem(dir: &File) -> bool {
    #[cfg(test)]
    if seams::forced_nonlocal() {
        return false;
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) };
    rc == 0
        && matches!(
            stat.f_type,
            libc::EXT4_SUPER_MAGIC
                | libc::XFS_SUPER_MAGIC
                | libc::BTRFS_SUPER_MAGIC
                | libc::TMPFS_MAGIC
        )
}

#[cfg(target_os = "macos")]
fn set_backup_exclude(dir: &File) -> Result<(), StorageError> {
    let rc = unsafe {
        libc::fsetxattr(
            dir.as_raw_fd(),
            BACKUP_EXCLUDE_XATTR.as_ptr(),
            BACKUP_EXCLUDE_VALUE.as_ptr().cast(),
            BACKUP_EXCLUDE_VALUE.len(),
            0,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(StorageError::UnsafeState)
    }
}

fn acquire_lock(dir: &File) -> Result<File, StorageError> {
    #[cfg(test)]
    let name = seams::lock_name().unwrap_or(LOCK_FILE);
    #[cfg(not(test))]
    let name = LOCK_FILE;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK | nofollow();
    let open = || cvt_file(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) });
    let file = match open() {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            let mode: libc::c_uint = 0o600;
            let create = flags | libc::O_CREAT | libc::O_EXCL;
            match cvt_file(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), create, mode) }) {
                Ok(file) => {
                    set_exact_mode(&file, 0o600).map_err(|_| StorageError::UnsafeState)?;
                    #[cfg(target_os = "macos")]
                    clear_acl(&file).map_err(|_| StorageError::UnsafeState)?;
                    file
                }
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                    open().map_err(|_| StorageError::UnsafeState)?
                }
                Err(_) => return Err(StorageError::UnsafeState),
            }
        }
        Err(_) => return Err(StorageError::UnsafeState),
    };
    check_private_file(&file)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(file)
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
        Err(StorageError::Busy)
    } else {
        Err(StorageError::UnsafeState)
    }
}

fn open_dir_at(parent: &File, name: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | nofollow();
    cvt_file(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) })
}

/// Opens `name` below `parent`, creating it when missing. The flag is true
/// only when this call's `mkdirat` created it.
fn open_or_create_dir(parent: &File, name: &CStr) -> Result<(File, bool), StorageError> {
    match open_dir_at(parent, name) {
        Ok(dir) => return Ok((dir, false)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(_) => return Err(StorageError::UnsafeState),
    }
    let mode: libc::mode_t = 0o700;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } == 0;
    if !created && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(StorageError::UnsafeState);
    }
    let dir = open_dir_at(parent, name).map_err(|_| StorageError::UnsafeState)?;
    Ok((dir, created))
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

fn metadata(file: &File) -> Result<Metadata, StorageError> {
    file.metadata().map_err(|_| StorageError::UnsafeState)
}

fn cvt(rc: libc::c_int) -> io::Result<()> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cvt_file(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn file_from(fd: libc::c_int) -> Result<File, StorageError> {
    cvt_file(fd).map_err(|_| StorageError::UnsafeState)
}

/// A path component of the suffix: not empty, `.` or `..`, no `/` or NUL.
fn component_name(component: &str) -> Result<CString, StorageError> {
    if component.is_empty() || component == "." || component == ".." || component.contains('/') {
        return Err(StorageError::UnsafeState);
    }
    CString::new(component).map_err(|_| StorageError::UnsafeState)
}

/// An agent-owned file name: `[a-z0-9._-]`, not starting with `.`.
fn file_name(name: &str) -> Result<CString, StorageError> {
    let valid = !name.is_empty()
        && !name.starts_with('.')
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
    if valid {
        CString::new(name).map_err(|_| StorageError::UnsafeState)
    } else {
        Err(StorageError::UnsafeState)
    }
}

fn temp_name(name: &str) -> Result<CString, StorageError> {
    file_name(name)?;
    CString::new(format!(".{name}.tmp")).map_err(|_| StorageError::UnsafeState)
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    use super::*;
    use crate::secure_fs::{
        seams::{self, Reset},
        test_support::{SUFFIX, TempHome, retry_busy},
    };

    fn open(home: &TempHome) -> Result<SecureRoot, StorageError> {
        retry_busy(|| open_once(home))
    }

    /// No retry: for the assertions that expect `Busy`.
    fn open_once(home: &TempHome) -> Result<SecureRoot, StorageError> {
        SecureRoot::open_under(&home.path, SUFFIX)
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn write_state(root: &SecureRoot, bytes: &[u8]) {
        root.stage("state.json", bytes).unwrap().publish().unwrap();
    }

    /// Runs `attack` once normally (it must fail closed with `expected`) and
    /// once with `bypass` set (it must succeed): the negative control proving
    /// that the named guard is what stops it.
    fn fails_closed_only_by<T>(
        bypass: u32,
        expected: StorageError,
        mut attack: impl FnMut() -> Result<T, StorageError>,
    ) -> T {
        let _reset = Reset;
        assert_eq!(attack().err(), Some(expected));
        seams::bypass(bypass);
        let bypassed = attack();
        seams::bypass(0);
        match bypassed {
            Ok(value) => value,
            Err(error) => panic!("bypass {bypass:#x} did not admit the attack: {error:?}"),
        }
    }

    #[test]
    fn missing_directories_are_created_0700_and_0755_intermediates_open() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        for depth in 1..=SUFFIX.len() {
            let path = SUFFIX[..depth]
                .iter()
                .fold(home.path.clone(), |p, c| p.join(c));
            let meta = std::fs::symlink_metadata(&path).unwrap();
            assert!(meta.is_dir());
            assert_eq!(meta.mode() & 0o7777, 0o700, "{depth}");
        }
        drop(root);
        // A real `~/Library` or `~/.local` is commonly 0755.
        chmod(&home.path.join("Library"), 0o755);
        chmod(&home.path.join("Library/AppSupport"), 0o755);
        open(&home).unwrap();
    }

    #[test]
    fn a_group_writable_intermediate_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        chmod(&home.path.join("Library/AppSupport"), 0o775);
        fails_closed_only_by(INTERMEDIATE, StorageError::UnsafeState, || open(&home));
        chmod(&home.path.join("Library/AppSupport"), 0o757);
        fails_closed_only_by(INTERMEDIATE, StorageError::UnsafeState, || open(&home));
    }

    #[test]
    fn a_root_that_is_not_exactly_0700_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        chmod(&home.root(), 0o750);
        fails_closed_only_by(MODE, StorageError::UnsafeState, || open(&home));
    }

    #[test]
    fn a_symlinked_root_fails_closed() {
        let home = TempHome::new();
        let decoy = home.path.join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        chmod(&decoy, 0o700);
        std::fs::create_dir_all(home.path.join("Library/AppSupport")).unwrap();
        symlink(&decoy, home.root()).unwrap();
        let root = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || open(&home));
        // With the guard bypassed the root really is the decoy.
        assert_eq!(
            root.dir_metadata().ino(),
            std::fs::metadata(&decoy).unwrap().ino()
        );
    }

    #[test]
    fn a_symlinked_state_file_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside.json");
        std::fs::write(&outside, b"outside").unwrap();
        chmod(&outside, 0o600);
        symlink(&outside, home.root().join("state.json")).unwrap();
        let bytes = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
        assert_eq!(bytes.unwrap(), b"outside");
    }

    #[test]
    fn a_path_swap_between_components_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let decoy = home.path.join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        chmod(&decoy, 0o700);
        let (root, moved, target) = (home.root(), home.path.join("moved"), decoy.clone());
        let swap = move |step: Step| {
            // Just before the agent root is opened, replace it with a link.
            if step == Step::Descend(SUFFIX.len() - 1)
                && std::fs::symlink_metadata(&root).unwrap().is_dir()
            {
                std::fs::rename(&root, &moved).unwrap();
                symlink(&target, &root).unwrap();
            }
            Ok(())
        };
        let _reset = Reset;
        seams::set_hook(Some(Box::new(swap)));
        assert_eq!(open(&home).err(), Some(StorageError::UnsafeState));
        seams::bypass(seams::NOFOLLOW);
        let root = open(&home).unwrap();
        assert_eq!(
            root.dir_metadata().ino(),
            std::fs::metadata(&decoy).unwrap().ino()
        );
    }

    #[test]
    fn a_hard_linked_state_file_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        std::fs::hard_link(
            home.root().join("state.json"),
            home.path.join("second-name"),
        )
        .unwrap();
        fails_closed_only_by(NLINK, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
    }

    #[test]
    fn a_state_file_that_is_not_0600_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        assert_eq!(root.read_file("state.json", 64).unwrap().unwrap(), b"{}");
        chmod(&home.root().join("state.json"), 0o644);
        fails_closed_only_by(MODE, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
    }

    #[test]
    fn a_foreign_owner_anywhere_on_the_path_fails_closed() {
        // Ownership classification is injected: CI cannot chown to another UID.
        for object in [seams::HOME, seams::INTERMEDIATE_DIR, seams::ROOT] {
            let home = TempHome::new();
            let _reset = Reset;
            seams::force_foreign(object);
            fails_closed_only_by(OWNER, StorageError::UnsafeState, || open(&home));
        }
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        let _reset = Reset;
        seams::force_foreign(seams::FILE);
        fails_closed_only_by(OWNER, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
    }

    #[test]
    fn a_non_local_filesystem_fails_closed() {
        // Filesystem classification is injected: CI cannot mount a network volume.
        let home = TempHome::new();
        let _reset = Reset;
        seams::force_nonlocal(true);
        fails_closed_only_by(LOCAL_FS, StorageError::UnsafeState, || open(&home));
    }

    #[test]
    fn an_oversize_file_is_rejected_before_decode() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, &[b'x'; 65]);
        assert_eq!(root.read_file("state.json", 65).unwrap().unwrap().len(), 65);
        let bytes = fails_closed_only_by(BYTE_CAP, StorageError::Corrupt, || {
            root.read_file("state.json", 64)
        });
        // The read itself stops at cap + 1.
        assert_eq!(bytes.unwrap().len(), 65);
    }

    #[test]
    fn a_second_opener_cannot_take_the_lock_after_a_replace() {
        let home = TempHome::new();
        let first = open(&home).unwrap();
        write_state(&first, b"{\"a\":1}");
        write_state(&first, b"{\"a\":2}");
        assert_eq!(open_once(&home).err(), Some(StorageError::Busy));
        drop(first);
        drop(open(&home).unwrap());

        // Negative control: locking the replaced file instead of the stable
        // lock file loses the lock at the first replace.
        let _reset = Reset;
        seams::lock_name_override(Some(c"state.json"));
        let first = open(&home).unwrap();
        assert_eq!(open_once(&home).err(), Some(StorageError::Busy));
        write_state(&first, b"{\"a\":3}");
        let second = open(&home);
        assert!(
            second.is_ok(),
            "the replaced inode should be lockable again"
        );
    }

    #[test]
    fn stale_temp_cleanup_removes_only_the_exact_name_and_never_follows() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        symlink(&outside, home.root().join(".state.json.tmp")).unwrap();
        std::fs::write(home.root().join(".other.tmp"), b"keep").unwrap();
        root.remove_stale_temp("state.json").unwrap();
        assert!(std::fs::symlink_metadata(home.root().join(".state.json.tmp")).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(home.root().join(".other.tmp").exists());
        root.remove_stale_temp("state.json").unwrap();
    }

    /// Creating a directory syncs its parent so the new entry is durable;
    /// reopening an existing root creates and syncs nothing.
    #[test]
    fn each_created_directory_is_followed_by_a_sync_of_its_parent() {
        let home = TempHome::new();
        let _reset = Reset;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = std::sync::Arc::clone(&seen);
        seams::set_hook(Some(Box::new(move |step| {
            if matches!(step, Step::Descend(_) | Step::SyncParent(_)) {
                record.lock().unwrap().push(step);
            }
            Ok(())
        })));
        drop(open(&home).unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Step::Descend(0),
                Step::SyncParent(0),
                Step::Descend(1),
                Step::SyncParent(1),
                Step::Descend(2),
                Step::SyncParent(2),
            ]
        );
        seen.lock().unwrap().clear();
        drop(open(&home).unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [Step::Descend(0), Step::Descend(1), Step::Descend(2)]
        );
    }

    /// The child side of `a_restrictive_umask…`. A no-op in a normal run.
    #[test]
    fn umask_child_entry() {
        let Ok(home) = std::env::var("SYRTIS_UMASK_HOME") else {
            return;
        };
        unsafe { libc::umask(0o277) };
        if std::env::var_os("SYRTIS_UMASK_SKIP_FCHMOD").is_some() {
            seams::bypass(seams::SKIP_FCHMOD);
        }
        let result = SecureRoot::open_under(Path::new(&home), SUFFIX).and_then(|root| {
            root.stage("state.json", b"{}")?.publish()?;
            root.read_file("state.json", 64).map(|_| ())
        });
        println!("UMASK:{result:?}");
    }

    /// umask is process-wide, so it is set in a child process. Under umask
    /// 0277 every object the agent creates still ends with its exact mode.
    /// Negative control: without the `fchmod`, the root cannot be created.
    #[test]
    fn a_restrictive_umask_still_yields_exact_modes() {
        for (skip, expected) in [(false, "Ok(())"), (true, "Err(UnsafeState)")] {
            let home = TempHome::new();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "secure_fs::unix::tests::umask_child_entry",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("SYRTIS_UMASK_HOME", &home.path)
                .envs(skip.then_some(("SYRTIS_UMASK_SKIP_FCHMOD", "1")))
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let line = stdout
                .lines()
                .find_map(|line| line.split_once("UMASK:").map(|(_, rest)| rest))
                .unwrap_or_else(|| panic!("{stdout}"));
            assert_eq!(line, expected, "skip fchmod: {skip}");
            if !skip {
                for depth in 1..=SUFFIX.len() {
                    let path = SUFFIX[..depth]
                        .iter()
                        .fold(home.path.clone(), |p, c| p.join(c));
                    let mode = std::fs::symlink_metadata(&path).unwrap().mode() & 0o7777;
                    assert_eq!(mode, 0o700, "{depth}");
                }
                for file in ["state.json", "owner.lock"] {
                    let meta = std::fs::symlink_metadata(home.root().join(file)).unwrap();
                    assert_eq!(meta.mode() & 0o7777, 0o600, "{file}");
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn add_acl(path: &Path, entry: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// `ls -le` lists extended ACL entries as ` 0: …` lines.
    #[cfg(target_os = "macos")]
    fn ls_shows_acl(path: &Path) -> bool {
        let output = std::process::Command::new("/bin/ls")
            .arg("-led")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().contains("\n 0: ")
    }

    #[cfg(target_os = "macos")]
    const INHERITED: &str = "everyone allow read,list,search,file_inherit,directory_inherit";

    /// A home whose `Library` passes an inheritable "everyone may read" ACL
    /// to everything created below it.
    #[cfg(target_os = "macos")]
    fn home_with_inheritable_acl() -> TempHome {
        let home = TempHome::new();
        let library = home.path.join("Library");
        std::fs::create_dir(&library).unwrap();
        chmod(&library, 0o700);
        add_acl(&library, INHERITED);
        assert!(ls_shows_acl(&library), "control: ls must show the ACL");
        home
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_inherited_acl_is_cleared_from_everything_the_agent_creates() {
        let home = home_with_inheritable_acl();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        // The intermediate the agent created did inherit it...
        assert!(ls_shows_acl(&home.path.join("Library/AppSupport")));
        // ...but nothing that holds secrets carries it.
        for path in [
            home.root(),
            home.root().join("state.json"),
            home.root().join("owner.lock"),
        ] {
            assert!(!ls_shows_acl(&path), "{}", path.display());
        }
        assert_eq!(root.read_file("state.json", 64).unwrap().unwrap(), b"{}");
        drop(root);

        // Negative control: without the clearing the root inherits the ACL,
        // and the check fails it closed.
        let home = home_with_inheritable_acl();
        let _reset = Reset;
        seams::bypass(seams::SKIP_ACL_CLEAR);
        assert_eq!(open(&home).err(), Some(StorageError::UnsafeState));
        assert!(ls_shows_acl(&home.root()));
    }

    /// An ACL on an object the agent did not just create fails closed and is
    /// left in place for manual repair.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_existing_acl_fails_closed_and_is_not_stripped() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        add_acl(&home.root().join("state.json"), "everyone allow read");
        fails_closed_only_by(seams::ACL, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
        drop(root);

        add_acl(&home.root().join("owner.lock"), "everyone allow read");
        fails_closed_only_by(seams::ACL, StorageError::UnsafeState, || open(&home));
        assert!(ls_shows_acl(&home.root().join("owner.lock")));

        let home = TempHome::new();
        drop(open(&home).unwrap());
        add_acl(&home.root(), "everyone allow read");
        fails_closed_only_by(seams::ACL, StorageError::UnsafeState, || open(&home));
        assert!(
            ls_shows_acl(&home.root()),
            "an existing ACL must not be stripped"
        );
    }

    /// Defense in depth behind the root guard: even under a root that
    /// carries an inheritable ACL (reachable here only by bypassing the ACL
    /// check), the lock file and the state file the agent creates are
    /// cleared before use.
    #[cfg(target_os = "macos")]
    #[test]
    fn created_files_clear_their_own_inherited_acl() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        std::fs::remove_file(home.root().join("owner.lock")).unwrap();
        add_acl(&home.root(), INHERITED);
        let _reset = Reset;
        seams::bypass(seams::ACL);
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        assert!(
            ls_shows_acl(&home.root()),
            "control: the root does carry it"
        );
        for file in ["owner.lock", "state.json"] {
            assert!(!ls_shows_acl(&home.root().join(file)), "{file}");
        }
    }

    #[test]
    fn agent_file_names_are_restricted() {
        for bad in ["", ".state.json", "../x", "a/b", "State.json", "a b"] {
            assert!(file_name(bad).is_err(), "{bad:?}");
        }
        assert!(file_name("state.json").is_ok());
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(component_name(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_root_carries_the_backup_exclusion() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let mut value = [0u8; 128];
        let len = unsafe {
            libc::fgetxattr(
                root.dir.as_raw_fd(),
                BACKUP_EXCLUDE_XATTR.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        assert_eq!(usize::try_from(len).ok(), Some(BACKUP_EXCLUDE_VALUE.len()));
        assert_eq!(value[..BACKUP_EXCLUDE_VALUE.len()], BACKUP_EXCLUDE_VALUE);
    }
}
