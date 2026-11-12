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
    /// `home/suffix…` as passed to [`SecureRoot::open_under`]. Recorded for
    /// one use only, the control socket (`spec/control-v1.md`); nothing in
    /// this module ever reopens anything by it.
    path: PathBuf,
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
        let path = suffix
            .iter()
            .fold(home.to_path_buf(), |path, part| path.join(part));
        let home = home.as_os_str().as_bytes();
        if !absolute(home) || suffix.is_empty() {
            return Err(StorageError::UnsafeState);
        }
        let home = CString::new(home).map_err(|_| StorageError::UnsafeState)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let mut dir = file_from(unsafe { libc::open(home.as_ptr(), flags) })?;
        let meta = metadata(&dir)?;
        check_owner(&meta, Object::Home)?;
        // sshd StrictModes: a home others can write lets them replace any
        // entry below it.
        guard(
            meta.mode() & 0o022 == 0,
            HOME_MODE,
            StorageError::UnsafeState,
        )?;
        #[cfg(target_os = "macos")]
        guard(
            acl::deny_only(&dir),
            INTERMEDIATE_ACL,
            StorageError::UnsafeState,
        )?;
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
                clear_acl(&next).map_err(|_| StorageError::UnsafeState)?;
            }
            // A created intermediate's entry is made durable in its parent.
            if created && !last {
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
                // The root's parent is synced on every open whose root
                // passes its own checks, found or created, so a root an
                // earlier run created but crashed before syncing is durable
                // before any commit lands in it. After the root's own checks
                // (a root that fails them, for example on a non-local
                // filesystem, never pays for or hangs on the sync) and
                // before the backup exclusion (macOS only), the `owner.lock`
                // checks and the lock, so an open that then fails there or
                // gets `Busy` has already synced. Failure is `UnsafeState`:
                // nothing was committed, so nothing is unknown.
                if created || sync_found_root_parent() {
                    shim(Step::SyncParent(index), || full_sync(&dir))
                        .map_err(|_| StorageError::UnsafeState)?;
                }
            } else {
                check_owner(&meta, Object::Intermediate)?;
                guard(
                    meta.mode() & 0o022 == 0,
                    INTERMEDIATE,
                    StorageError::UnsafeState,
                )?;
                #[cfg(target_os = "macos")]
                guard(
                    acl::deny_only(&next),
                    INTERMEDIATE_ACL,
                    StorageError::UnsafeState,
                )?;
            }
            dir = next;
        }
        #[cfg(target_os = "macos")]
        set_backup_exclude(&dir)?;
        let lock = acquire_lock(&dir)?;
        Ok(Self {
            dir,
            _lock: lock,
            path,
        })
    }

    /// The root's path as opened. Read-only; for the control socket, the
    /// one sanctioned pathname use after the checks (`spec/control-v1.md`).
    pub(crate) fn path(&self) -> &Path {
        &self.path
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

    /// Opens the directory `name` directly below the root, creating it `0700`
    /// when missing, and returns its path. Checked like the root itself:
    /// opened no-follow relative to the root's descriptor, a directory, owned
    /// by the effective UID, exactly `0700`, no extended ACL (macOS). An
    /// existing directory is checked as found, never chmod-ed. `name` follows
    /// the agent file-name rule. The returned path is for an API that takes a
    /// path (the engine's source cache and pricing roots); whoever opens it
    /// later resolves it again (`spec/source-v1.md`, non-claims).
    // ponytail: no parent sync after mkdir; the directories hold re-creatable caches.
    pub(crate) fn private_subdir(&self, name: &str) -> Result<PathBuf, StorageError> {
        let c_name = file_name(name)?;
        let (dir, created) = open_or_create_dir(&self.dir, &c_name)?;
        if created {
            set_exact_mode(&dir, 0o700).map_err(|_| StorageError::UnsafeState)?;
            #[cfg(target_os = "macos")]
            clear_acl(&dir).map_err(|_| StorageError::UnsafeState)?;
        }
        let meta = metadata(&dir)?;
        guard(meta.is_dir(), 0, StorageError::UnsafeState)?;
        check_owner(&meta, Object::Root)?;
        #[cfg(target_os = "macos")]
        guard(acl::none(&dir), ACL, StorageError::UnsafeState)?;
        guard(
            meta.mode() & 0o7777 == 0o700,
            MODE,
            StorageError::UnsafeState,
        )?;
        Ok(self.path.join(name))
    }

    /// Empties the directory `name` directly below the root, which is
    /// checked as [`Self::private_subdir`] checks it but never created or
    /// chmod-ed; absent is success. The directory itself stays. Every entry
    /// is classified with a no-follow `fstatat` on its parent's descriptor:
    /// a directory is opened `O_DIRECTORY|O_NOFOLLOW` relative to that
    /// descriptor, emptied the same way, then removed with `AT_REMOVEDIR`;
    /// anything else, a symlink included, is `unlinkat`-ed, which removes
    /// the link and never its target. Nesting deeper than
    /// [`CLEAR_DEPTH_MAX`] or any failed call is `UnsafeState`; what was
    /// removed before it stays removed.
    pub(crate) fn clear_private_subdir(&self, name: &str) -> Result<(), StorageError> {
        let c_name = file_name(name)?;
        let dir = match open_dir_at(&self.dir, &c_name) {
            Ok(dir) => dir,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(_) => return Err(StorageError::UnsafeState),
        };
        let meta = metadata(&dir)?;
        guard(meta.is_dir(), 0, StorageError::UnsafeState)?;
        check_owner(&meta, Object::Root)?;
        #[cfg(target_os = "macos")]
        guard(acl::none(&dir), ACL, StorageError::UnsafeState)?;
        guard(
            meta.mode() & 0o7777 == 0o700,
            MODE,
            StorageError::UnsafeState,
        )?;
        clear_dir(&dir, 0)
    }

    /// Reads an agent-owned file under the checks of [`Self::read_file`]
    /// into one buffer of exactly `size + 1` bytes, allocated before the
    /// first read and never grown, so the buffer's capacity is the
    /// `size + 1` the caller reserved. More than `size` bytes is `Corrupt`;
    /// a failed allocation is `Unavailable`. `Ok(None)` when absent.
    pub(crate) fn read_file_sized(
        &self,
        name: &str,
        size: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let name = file_name(name)?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | nofollow();
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        let file = file_from(fd)?;
        check_private_file(&file)?;
        let capacity = size.checked_add(1).ok_or(StorageError::Corrupt)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| StorageError::Unavailable)?;
        bytes.resize(capacity, 0);
        let mut filled = 0;
        while filled < capacity {
            match (&file).read(&mut bytes[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(StorageError::UnsafeState),
            }
        }
        bytes.truncate(filled);
        guard(filled <= size, BYTE_CAP, StorageError::Corrupt)?;
        Ok(Some(bytes))
    }

    /// The entries whose name starts with `prefix` (one of
    /// [`CACHE_PREFIXES`](super::CACHE_PREFIXES), else `Refused(Invalid)`),
    /// with their sizes, sorted by name. Every such entry is checked with a
    /// no-follow `fstatat` on the root descriptor: a regular file owned by
    /// the effective UID, mode `0600`, one link, and a valid agent file
    /// name. One that fails makes the whole call `UnsafeState`; nothing is
    /// opened, followed or removed. Other entries are only counted: more
    /// than [`LIST_ENTRIES_MAX`](super::LIST_ENTRIES_MAX) is `UnsafeState`.
    /// Temp files (`.<name>.tmp`) never carry the prefix, so never appear.
    pub(crate) fn list(&self, prefix: &str) -> Result<Vec<(String, u64)>, StorageError> {
        super::cache_prefix(prefix)?;
        let mut listed = Vec::new();
        for name in self.entries()? {
            if !name.starts_with(prefix.as_bytes()) {
                continue;
            }
            let path = CString::new(name.clone()).map_err(|_| StorageError::UnsafeState)?;
            let stat = stat_at(&self.dir, &path)?;
            guard(
                (stat.st_mode & libc::S_IFMT) == libc::S_IFREG,
                0,
                StorageError::UnsafeState,
            )?;
            #[cfg(test)]
            let forced = seams::forced_foreign(seams::FILE);
            #[cfg(not(test))]
            let forced = false;
            guard(
                stat.st_uid == unsafe { libc::geteuid() } && !forced,
                OWNER,
                StorageError::UnsafeState,
            )?;
            guard(
                (stat.st_mode & 0o7777) == 0o600,
                MODE,
                StorageError::UnsafeState,
            )?;
            guard(stat.st_nlink == 1, NLINK, StorageError::UnsafeState)?;
            let text = String::from_utf8(name).map_err(|_| StorageError::UnsafeState)?;
            file_name(&text)?;
            let size = u64::try_from(stat.st_size).map_err(|_| StorageError::UnsafeState)?;
            listed.push((text, size));
        }
        listed.sort();
        Ok(listed)
    }

    /// `unlinkat` of one agent file (never follows a link), then a sync of
    /// the root directory. An absent file is success. Either step failing
    /// is `Unknown`. Both run through `shim` (`Step::Unlink`,
    /// `Step::SyncDir`).
    pub(crate) fn remove_file(&self, name: &str) -> Result<(), StorageError> {
        let name = file_name(name)?;
        let dir = self.dir.as_raw_fd();
        shim(Step::Unlink, || {
            cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) }).or_else(|error| {
                if error.raw_os_error() == Some(libc::ENOENT) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
        })
        .map_err(|_| StorageError::Unknown)?;
        shim(Step::SyncDir, || full_sync(&self.dir)).map_err(|_| StorageError::Unknown)
    }

    /// Removes every temp file `.<prefix>….tmp` left by a crash, `prefix`
    /// one of [`CACHE_PREFIXES`](super::CACHE_PREFIXES) (else
    /// `Refused(Invalid)`). `unlinkat` only, which never follows a link; a
    /// removal failing for any reason other than `ENOENT` is `UnsafeState`.
    pub(crate) fn remove_stale_temps(&self, prefix: &str) -> Result<(), StorageError> {
        super::cache_prefix(prefix)?;
        let lead = format!(".{prefix}");
        for name in self.entries()? {
            if !(name.starts_with(lead.as_bytes()) && name.ends_with(b".tmp")) {
                continue;
            }
            let temp = CString::new(name).map_err(|_| StorageError::UnsafeState)?;
            if unsafe { libc::unlinkat(self.dir.as_raw_fd(), temp.as_ptr(), 0) } != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
            {
                return Err(StorageError::UnsafeState);
            }
        }
        Ok(())
    }

    /// Every entry name of the root except `.` and `..`, read through a
    /// fresh descriptor of the root (`openat(dir, ".")`), so concurrent
    /// listings never share a directory offset. More than
    /// [`LIST_ENTRIES_MAX`](super::LIST_ENTRIES_MAX) is `UnsafeState`.
    fn entries(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), c".".as_ptr(), flags) };
        let fd = file_from(fd)?;
        let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
        if stream.is_null() {
            return Err(StorageError::UnsafeState);
        }
        // `closedir` now owns the descriptor.
        std::mem::forget(fd);
        let mut names = Vec::new();
        let result = loop {
            unsafe { *errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break if io::Error::last_os_error().raw_os_error() == Some(0) {
                    Ok(names)
                } else {
                    Err(StorageError::UnsafeState)
                };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() == super::LIST_ENTRIES_MAX {
                break Err(StorageError::UnsafeState);
            }
            names.push(name.to_vec());
        };
        unsafe { libc::closedir(stream) };
        result
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

/// An agent root opened by [`SecureRoot::open_read_only`]: no owner lock,
/// and the only operation is [`ReadOnlyRoot::read_file`].
pub struct ReadOnlyRoot {
    dir: File,
}

impl SecureRoot {
    /// Opens `home/suffix…` for reading only (`SA-2C2b`), for a second
    /// process of the owner while the resident agent holds the lock. The
    /// checks of [`SecureRoot::open_under`], on the same descriptors: the
    /// home opened by path and owned by the effective UID, not group- or
    /// other-writable, deny-only ACL (macOS); every component opened
    /// relative to its parent with `O_NOFOLLOW`; intermediates owned and not
    /// group- or other-writable (deny-only ACL on macOS); the root owned,
    /// exactly `0700`, no ACL (macOS), on a local filesystem. Unlike
    /// `open_under` it creates, chmods, syncs, tags and locks nothing.
    /// `Ok(None)` when a component does not exist.
    ///
    /// No lock is taken, so the resident agent may replace a file while it
    /// is read; replacement is a `rename`, so a read sees the old or the new
    /// file whole.
    pub fn open_read_only(
        home: &Path,
        suffix: &[&str],
    ) -> Result<Option<ReadOnlyRoot>, StorageError> {
        let home = home.as_os_str().as_bytes();
        if !absolute(home) || suffix.is_empty() {
            return Err(StorageError::UnsafeState);
        }
        let home = CString::new(home).map_err(|_| StorageError::UnsafeState)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let mut dir = file_from(unsafe { libc::open(home.as_ptr(), flags) })?;
        let meta = metadata(&dir)?;
        check_owner(&meta, Object::Home)?;
        guard(
            meta.mode() & 0o022 == 0,
            HOME_MODE,
            StorageError::UnsafeState,
        )?;
        #[cfg(target_os = "macos")]
        guard(
            acl::deny_only(&dir),
            INTERMEDIATE_ACL,
            StorageError::UnsafeState,
        )?;
        for (index, component) in suffix.iter().enumerate() {
            let name = component_name(component)?;
            let next = match open_dir_at(&dir, &name) {
                Ok(next) => next,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
                Err(_) => return Err(StorageError::UnsafeState),
            };
            let meta = metadata(&next)?;
            guard(meta.is_dir(), 0, StorageError::UnsafeState)?;
            if index + 1 == suffix.len() {
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
                #[cfg(target_os = "macos")]
                guard(
                    acl::deny_only(&next),
                    INTERMEDIATE_ACL,
                    StorageError::UnsafeState,
                )?;
            }
            dir = next;
        }
        Ok(Some(ReadOnlyRoot { dir }))
    }
}

impl ReadOnlyRoot {
    /// [`SecureRoot::read_file`] on this root: no-follow, regular, owned by
    /// the effective UID, `0600`, no ACL (macOS), at most `max` bytes.
    /// `Ok(None)` when absent. One difference: a link count of 0 is
    /// accepted as well as 1. Without the lock the resident may `rename` a
    /// new file over this one between the open and the check; the opened
    /// inode is then unlinked (0 links), still whole and still owner-only.
    /// Two or more links are refused.
    pub fn read_file(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>, StorageError> {
        match self.open_file(name)? {
            Some(file) => read_opened(&file, max).map(Some),
            None => Ok(None),
        }
    }

    fn open_file(&self, name: &str) -> Result<Option<File>, StorageError> {
        let name = file_name(name)?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | nofollow();
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        file_from(fd).map(Some)
    }
}

/// The checks and the bounded read of [`ReadOnlyRoot::read_file`] on an
/// already opened file.
// ponytail: repeats `check_private_file` except the link count, because
// SA-2C2b may only add to secure_fs; fold them when the file is next open.
fn read_opened(file: &File, max: usize) -> Result<Vec<u8>, StorageError> {
    let meta = metadata(file)?;
    guard(meta.is_file(), 0, StorageError::UnsafeState)?;
    check_owner(&meta, Object::File)?;
    guard(
        meta.mode() & 0o7777 == 0o600,
        MODE,
        StorageError::UnsafeState,
    )?;
    guard(meta.nlink() <= 1, NLINK, StorageError::UnsafeState)?;
    #[cfg(target_os = "macos")]
    guard(acl::none(file), ACL, StorageError::UnsafeState)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| StorageError::UnsafeState)?;
    guard(bytes.len() <= max, BYTE_CAP, StorageError::Corrupt)?;
    Ok(bytes)
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
use seams::{ACL, INTERMEDIATE_ACL};
#[cfg(test)]
use seams::{BYTE_CAP, HOME_MODE, INTERMEDIATE, LOCAL_FS, MODE, NLINK, OWNER};
#[cfg(all(not(test), target_os = "macos"))]
const ACL: u32 = 0;
#[cfg(all(not(test), target_os = "macos"))]
const INTERMEDIATE_ACL: u32 = 0;
#[cfg(not(test))]
const HOME_MODE: u32 = 0;
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

/// Whether an agent root that already existed, and passed its own checks,
/// has its parent synced on open. Always in a non-test build.
fn sync_found_root_parent() -> bool {
    #[cfg(test)]
    if seams::bypassed(seams::SKIP_PARENT_SYNC) {
        return false;
    }
    true
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
/// Constants from `<sys/acl.h>` (`acl_type_t`, `acl_tag_t` and
/// `acl_entry_id_t` are C enums, so `int`).
#[cfg(target_os = "macos")]
pub(crate) mod acl {
    use std::{
        ffi::{c_int, c_void},
        fs::File,
        io,
        os::fd::AsRawFd,
    };

    pub(super) type Acl = *mut c_void;
    pub(super) type AclEntry = *mut c_void;
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    pub(super) const ACL_UNDEFINED_TAG: c_int = 0;
    #[cfg(test)]
    pub(super) const ACL_EXTENDED_ALLOW: c_int = 1;
    pub(super) const ACL_EXTENDED_DENY: c_int = 2;
    /// `ACL_MAX_ENTRIES`: an extended ACL holds at most this many entries.
    const ACL_MAX_ENTRIES: usize = 128;

    unsafe extern "C" {
        pub(super) fn acl_init(count: c_int) -> Acl;
        fn acl_free(object: *mut c_void) -> c_int;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
        pub(super) fn acl_get_tag_type(entry: AclEntry, tag: *mut c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> Acl;
        fn acl_set_fd_np(fd: c_int, acl: Acl, kind: c_int) -> c_int;
        #[cfg(test)]
        pub(super) fn acl_create_entry(acl: *mut Acl, entry: *mut AclEntry) -> c_int;
        #[cfg(test)]
        pub(super) fn acl_set_tag_type(entry: AclEntry, tag: c_int) -> c_int;
    }

    /// `acl_get_entry`, the only call site for both `none` and the
    /// deny-only walk. errno is cleared first, so the `EINVAL` read after a
    /// −1 can only come from this call, never from an earlier one. Test
    /// seams can make it fail with a chosen errno, or fail without setting
    /// errno.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid ACL handle that has not been freed, and it must
    /// stay valid for the call: `acl_get_entry` reads through it.
    unsafe fn get_entry(acl: Acl, entry_id: c_int, entry: &mut AclEntry) -> c_int {
        unsafe { *libc::__error() = 0 };
        #[cfg(test)]
        if let Some(errno) = super::seams::acl_get_entry_failure() {
            unsafe { *libc::__error() = errno };
            return -1;
        }
        #[cfg(test)]
        if super::seams::acl_get_entry_fails_silently() {
            return -1;
        }
        unsafe { acl_get_entry(acl, entry_id, entry) }
    }

    /// `acl_free`. When a test sets the seam, errno is then overwritten with
    /// `EINVAL`, so code that reads errno after the free, instead of before
    /// it, reads the "no more entries" value and is caught.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid ACL handle that the caller owns (from
    /// `acl_get_fd_np` or `acl_init`) and does not use or free afterwards:
    /// `acl_free` releases it.
    unsafe fn free(acl: Acl) {
        unsafe { acl_free(acl) };
        #[cfg(test)]
        if super::seams::clobbers_errno_after_acl_free() {
            unsafe { *libc::__error() = libc::EINVAL };
        }
    }

    fn errno() -> Option<i32> {
        io::Error::last_os_error().raw_os_error()
    }

    /// Replaces the extended ACL with an empty one.
    pub(super) fn clear(file: &File) -> io::Result<()> {
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
        let error = io::Error::last_os_error();
        // SAFETY: `acl` is the non-null handle `acl_init` returned above,
        // owned here and not used after this call.
        unsafe { free(acl) };
        if rc == 0 { Ok(()) } else { Err(error) }
    }

    /// The descriptor's extended ACL: `Ok(None)` when it has none, `Err`
    /// when it cannot be read.
    fn read(file: &File) -> Result<Option<Acl>, ()> {
        // Cleared first, so an `ENOENT` left by an earlier call can never
        // read as "no ACL".
        unsafe { *libc::__error() = 0 };
        // A test seam can make the call return NULL without setting errno.
        #[cfg(test)]
        let silent_null = super::seams::acl_get_fd_returns_null_silently();
        #[cfg(not(test))]
        let silent_null = false;
        let acl = if silent_null {
            std::ptr::null_mut()
        } else {
            unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) }
        };
        if !acl.is_null() {
            Ok(Some(acl))
        } else if errno() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(())
        }
    }

    /// True only when the descriptor verifiably carries no extended ACL
    /// entry; any error reading it counts as "has one".
    pub(crate) fn none(file: &File) -> bool {
        match read(file) {
            Ok(None) => true,
            Err(()) => false,
            // SAFETY: `acl` is the handle `acl_get_fd_np` just returned,
            // owned here and passed on exactly once.
            Ok(Some(acl)) => unsafe { empty_then_free(acl) },
        }
    }

    /// Whether `acl` has no entry, then frees it.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid ACL handle that the caller owns (from
    /// `acl_get_fd_np` or `acl_init`) and does not use or free afterwards:
    /// this function frees it exactly once.
    pub(super) unsafe fn empty_then_free(acl: Acl) -> bool {
        let mut entry: AclEntry = std::ptr::null_mut();
        // SAFETY: the caller guarantees `acl` is a valid handle; it is not
        // freed until below.
        let rc = unsafe { get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
        // errno is read before `acl_free`, which may change it. Only
        // `EINVAL` means "no entry"; any other failure counts as one.
        let empty = rc == -1 && errno() == Some(libc::EINVAL);
        // SAFETY: the caller hands over ownership of `acl`; this is its only
        // free and nothing uses it afterwards.
        unsafe { free(acl) };
        empty
    }

    /// True only when the descriptor has no extended ACL or every entry is
    /// an explicit deny (a stock `~/Library` carries `everyone deny
    /// delete`). An allow, undefined or unknown tag, a tag that cannot be
    /// read, more than `ACL_MAX_ENTRIES` entries, or an unreadable ACL all
    /// count as "may grant another UID access".
    pub(crate) fn deny_only(file: &File) -> bool {
        match read(file) {
            Ok(None) => true,
            Err(()) => false,
            // SAFETY: `acl` is the handle `acl_get_fd_np` just returned,
            // owned here and passed on exactly once.
            Ok(Some(acl)) => unsafe { all_deny_then_free(acl) },
        }
    }

    /// Walks every entry of `acl`, then frees it.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid ACL handle that the caller owns (from
    /// `acl_get_fd_np` or `acl_init`) and does not use or free afterwards:
    /// this function frees it exactly once.
    pub(super) unsafe fn all_deny_then_free(acl: Acl) -> bool {
        let mut verdict = false;
        let mut entry_id = ACL_FIRST_ENTRY;
        // One more iteration than the cap, to see the end of a full ACL.
        for _ in 0..=ACL_MAX_ENTRIES {
            let mut entry: AclEntry = std::ptr::null_mut();
            // SAFETY: the caller guarantees `acl` is a valid handle; it is
            // not freed until after the loop.
            if unsafe { get_entry(acl, entry_id, &mut entry) } != 0 {
                // Before `acl_free`. Only `EINVAL` is "no more entries".
                verdict = errno() == Some(libc::EINVAL);
                break;
            }
            let mut tag = ACL_UNDEFINED_TAG;
            // SAFETY: `entry` is a live entry that `get_entry` just returned
            // from `acl`, which is not freed until after the loop.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != ACL_EXTENDED_DENY {
                break;
            }
            entry_id = ACL_NEXT_ENTRY;
        }
        // SAFETY: the caller hands over ownership of `acl`; this is its only
        // free and nothing uses it afterwards.
        unsafe { free(acl) };
        verdict
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

/// How many directory levels below the cleared directory
/// [`SecureRoot::clear_private_subdir`] descends before it gives up.
const CLEAR_DEPTH_MAX: usize = 32;

/// Removes every entry of `dir` (see [`SecureRoot::clear_private_subdir`]).
fn clear_dir(dir: &File, depth: usize) -> Result<(), StorageError> {
    for name in entry_names(dir)? {
        let stat = stat_at(dir, &name)?;
        let flag = if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            guard(depth < CLEAR_DEPTH_MAX, 0, StorageError::UnsafeState)?;
            let child = open_dir_at(dir, &name).map_err(|_| StorageError::UnsafeState)?;
            clear_dir(&child, depth + 1)?;
            libc::AT_REMOVEDIR
        } else {
            0
        };
        cvt(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flag) })
            .map_err(|_| StorageError::UnsafeState)?;
    }
    Ok(())
}

/// Every entry name of `dir` except `.` and `..`, read through a fresh
/// descriptor (`openat(dir, ".")`). Uncapped: the only caller empties a
/// `0700` directory of the agent's own.
// ponytail: a same-UID process can make this list as large as it likes;
// that UID can already delete the whole root (same-UID non-claim).
fn entry_names(dir: &File) -> Result<Vec<CString>, StorageError> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let fd = file_from(unsafe { libc::openat(dir.as_raw_fd(), c".".as_ptr(), flags) })?;
    let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    if stream.is_null() {
        return Err(StorageError::UnsafeState);
    }
    // `closedir` now owns the descriptor.
    std::mem::forget(fd);
    let mut names = Vec::new();
    let result = loop {
        unsafe { *errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break if io::Error::last_os_error().raw_os_error() == Some(0) {
                Ok(names)
            } else {
                Err(StorageError::UnsafeState)
            };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    };
    unsafe { libc::closedir(stream) };
    result
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

/// `fstatat(dir, name)` without following a final link (unless a test
/// bypasses `NOFOLLOW`).
fn stat_at(dir: &File, name: &CStr) -> Result<libc::stat, StorageError> {
    let follow = if nofollow() == 0 {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut stat, follow) })
        .map_err(|_| StorageError::UnsafeState)?;
    Ok(stat)
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
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
    fn a_private_subdir_is_created_0700_and_reopened_as_found() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let path = root.private_subdir("source-cache").unwrap();
        assert_eq!(path, home.root().join("source-cache"));
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert_eq!(root.private_subdir("source-cache").unwrap(), path);
        for name in ["", ".hidden", "a/b", "Upper"] {
            assert_eq!(
                root.private_subdir(name),
                Err(StorageError::UnsafeState),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_symlinked_private_subdir_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let decoy = home.path.join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        chmod(&decoy, 0o700);
        symlink(&decoy, home.root().join("pricing")).unwrap();
        fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            root.private_subdir("pricing")
        });
        // The link was not followed into, replaced or removed.
        assert!(
            std::fs::symlink_metadata(home.root().join("pricing"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_private_subdir_that_is_not_exactly_0700_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let path = root.private_subdir("pricing").unwrap();
        chmod(&path, 0o755);
        fails_closed_only_by(MODE, StorageError::UnsafeState, || {
            root.private_subdir("pricing")
        });
        // Checked as found: the mode was not repaired.
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().mode() & 0o7777,
            0o755
        );
    }

    /// A decoy directory outside the root holding one file.
    fn decoy(home: &TempHome) -> std::path::PathBuf {
        let decoy = home.path.join("decoy");
        std::fs::create_dir_all(decoy.join("inner")).unwrap();
        std::fs::write(decoy.join("keep"), b"decoy").unwrap();
        std::fs::write(decoy.join("inner/keep"), b"decoy").unwrap();
        decoy
    }

    fn decoy_intact(decoy: &Path) -> bool {
        std::fs::read(decoy.join("keep")).ok().as_deref() == Some(b"decoy".as_slice())
            && std::fs::read(decoy.join("inner/keep")).ok().as_deref() == Some(b"decoy".as_slice())
    }

    /// SA-2C2a acceptance (8b): nested directories are emptied, a symlink
    /// inside is removed as a link while its target (a decoy directory
    /// outside the root) keeps every file; the cleared directory itself
    /// stays, `0700`. Absent is success.
    #[test]
    fn clear_private_subdir_empties_nested_dirs_and_unlinks_symlinks_only() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        assert_eq!(root.clear_private_subdir("source-cache"), Ok(()));
        let path = root.private_subdir("source-cache").unwrap();
        let decoy = decoy(&home);
        std::fs::create_dir_all(path.join("a/b/c")).unwrap();
        std::fs::write(path.join("a/b/c/session"), b"id").unwrap();
        std::fs::write(path.join("top"), b"id").unwrap();
        symlink(&decoy, path.join("link-dir")).unwrap();
        symlink(decoy.join("keep"), path.join("a/link-file")).unwrap();

        root.clear_private_subdir("source-cache").unwrap();
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert!(decoy_intact(&decoy));
    }

    /// SA-2C2a acceptance (8b), negative control: with the no-follow
    /// guard bypassed the same layout follows the link into the decoy, so
    /// that guard is what keeps the decoy intact.
    #[test]
    fn clear_private_subdir_follows_a_symlink_only_without_nofollow() {
        let _reset = Reset;
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let path = root.private_subdir("source-cache").unwrap();
        let decoy = decoy(&home);
        symlink(&decoy, path.join("link-dir")).unwrap();
        seams::bypass(seams::NOFOLLOW);
        let _ = root.clear_private_subdir("source-cache");
        seams::bypass(0);
        assert!(!decoy_intact(&decoy));
    }

    /// SA-2C2a acceptance (8b): `source-cache` itself a symlink to a decoy
    /// is refused, the link and the decoy untouched; so is one that is not
    /// exactly `0700`.
    #[test]
    fn clear_private_subdir_refuses_a_symlinked_or_loose_directory() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let decoy = decoy(&home);
        let link = home.root().join("source-cache");
        symlink(&decoy, &link).unwrap();
        assert_eq!(
            root.clear_private_subdir("source-cache"),
            Err(StorageError::UnsafeState)
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(decoy_intact(&decoy));

        let path = root.private_subdir("pricing").unwrap();
        std::fs::write(path.join("keep"), b"x").unwrap();
        chmod(&path, 0o755);
        fails_closed_only_by(MODE, StorageError::UnsafeState, || {
            root.clear_private_subdir("pricing")
        });
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

    /// Creating a directory syncs its parent so the new entry is durable,
    /// and every open whose root passes its own checks syncs the root's
    /// parent, also when the root already exists. Creating the root records
    /// that sync once, not twice; reopening creates nothing, so it syncs
    /// only the root's parent.
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
        // A `Busy` retry would descend again: record only the last attempt.
        let open_recorded = || {
            retry_busy(|| {
                seen.lock().unwrap().clear();
                open_once(&home)
            })
        };
        drop(open_recorded().unwrap());
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
        drop(open_recorded().unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Step::Descend(0),
                Step::Descend(1),
                Step::Descend(2),
                Step::SyncParent(2),
            ]
        );
        // Negative control: without the per-open sync, reopening an
        // existing root syncs nothing.
        seams::bypass(seams::SKIP_PARENT_SYNC);
        drop(open_recorded().unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [Step::Descend(0), Step::Descend(1), Step::Descend(2)]
        );
    }

    /// A failed sync of the root's parent on open is `UnsafeState`, not the
    /// store's sticky `Unknown`: nothing was committed. A later open works.
    #[test]
    fn a_failed_root_parent_sync_on_open_is_unsafe_state() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let _reset = Reset;
        seams::set_hook(Some(Box::new(|step| {
            if step == Step::SyncParent(SUFFIX.len() - 1) {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        })));
        assert_eq!(open(&home).err(), Some(StorageError::UnsafeState));
        seams::set_hook(None);
        drop(open(&home).unwrap());
    }

    /// sshd StrictModes: a home that group or other can write fails closed;
    /// a `0755` home opens.
    #[test]
    fn a_group_or_other_writable_home_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        chmod(&home.path, 0o775);
        fails_closed_only_by(HOME_MODE, StorageError::UnsafeState, || open(&home));
        chmod(&home.path, 0o757);
        fails_closed_only_by(HOME_MODE, StorageError::UnsafeState, || open(&home));
        chmod(&home.path, 0o755);
        drop(open(&home).unwrap());
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
            root.private_subdir("pricing")?;
            root.read_file("state.json", 64).map(|_| ())
        });
        println!("UMASK:{result:?}");
    }

    /// Whether a skipped permission-bypass control must fail the test instead
    /// of printing `SKIPPED`: true whenever `GITHUB_ACTIONS` is set (any
    /// value), with no exception, so CI can never pass by skipping the
    /// control. A CI job that bypasses directory permissions (root or
    /// `CAP_DAC_OVERRIDE`) therefore fails; this repository's workflow uses
    /// only GitHub-hosted runners.
    fn skip_must_fail_here() -> bool {
        std::env::var_os("GITHUB_ACTIONS").is_some()
    }

    /// Whether this process is refused a `mkdir` inside a `0500` directory it
    /// owns. False for root and for a process with `CAP_DAC_OVERRIDE`, which
    /// bypass directory permissions. Probed by behaviour, not by UID. Only
    /// `PermissionDenied` counts as enforced; any other `mkdir` error fails
    /// the test. `TempHome` drop removes the probe (an empty `0500`
    /// directory, or one holding `inner` when permissions are bypassed).
    fn directory_permissions_enforced() -> bool {
        let scratch = TempHome::new();
        let probe = scratch.path.join("probe");
        std::fs::create_dir(&probe).unwrap();
        chmod(&probe, 0o500);
        match std::fs::create_dir(probe.join("inner")) {
            Ok(()) => false,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => true,
            Err(error) => panic!("directory permission probe: {error}"),
        }
    }

    /// umask is process-wide, so it is set in a child process. Under umask
    /// 0277 every object the agent creates still ends with its exact mode.
    /// Negative control: without the `fchmod` the open fails closed. When
    /// directory permissions are enforced (not root or `CAP_DAC_OVERRIDE`)
    /// the root cannot be created: hosted CI (macOS and Linux) is measured
    /// to take that branch, since it passes with the bypass panic in place.
    /// Otherwise the root is inferred, not measured, to be created `0500`
    /// and refused by the exact-`0700` check; that branch has never run.
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
                let pricing = std::fs::symlink_metadata(home.root().join("pricing")).unwrap();
                assert_eq!(pricing.mode() & 0o7777, 0o700, "private_subdir");
            } else {
                // Where it failed: `Library` was created but left at the
                // umask-filtered `0500`. When directory permissions are
                // enforced, creating `AppSupport` in it fails with `EACCES`
                // and the root is never created; the `NotFound` assertions
                // check that. Root or `CAP_DAC_OVERRIDE` bypasses the
                // `EACCES` (found by the probe, not by UID); there the
                // inferred failure point is asserted instead: the root is
                // created `0500` and refused by the exact-`0700` check. That
                // branch has never run: hosted CI (macOS and Linux) is
                // measured to take the `NotFound` branch, and so is the
                // maintainer's Mac. Under `GITHUB_ACTIONS` the bypassed
                // branch fails the test (`skip_must_fail_here`), because CI
                // must run the `NotFound` branch; elsewhere it prints
                // `SKIPPED`. The `Err(UnsafeState)` assertion above and the
                // `Library` `0500` assertion run either way.
                let library = home.path.join(SUFFIX[0]);
                let mode = std::fs::symlink_metadata(&library).unwrap().mode() & 0o7777;
                assert_eq!(mode, 0o500);
                if directory_permissions_enforced() {
                    for path in [library.join(SUFFIX[1]), home.root()] {
                        let error = std::fs::symlink_metadata(&path).unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{path:?}");
                    }
                } else {
                    let root = std::fs::symlink_metadata(home.root()).unwrap_or_else(|e| {
                        panic!("permissions bypassed (root/CAP_DAC_OVERRIDE) but root missing: {e}")
                    });
                    assert_eq!(root.mode() & 0o7777, 0o500);
                    if skip_must_fail_here() {
                        panic!(
                            "directory permissions bypassed (root/CAP_DAC_OVERRIDE) under GITHUB_ACTIONS"
                        );
                    }
                    eprintln!("SKIPPED: a_restrictive_umask_still_yields_exact_modes");
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
        acl_listing(path).contains("\n 0: ")
    }

    #[cfg(target_os = "macos")]
    const INHERITED: &str = "everyone allow read,list,search,file_inherit,directory_inherit";

    /// A deny-only inheritable entry: the shape of a stock `~/Library`
    /// (`everyone deny delete`), made inheritable.
    #[cfg(target_os = "macos")]
    const INHERITED_DENY: &str = "everyone deny delete,file_inherit,directory_inherit";

    /// A home whose `Library` passes an inheritable deny-only ACL to
    /// everything created below it. Deny-only, so `Library` itself passes the
    /// intermediate ACL check.
    #[cfg(target_os = "macos")]
    fn home_with_inheritable_acl() -> TempHome {
        let home = TempHome::new();
        let library = home.path.join("Library");
        std::fs::create_dir(&library).unwrap();
        chmod(&library, 0o700);
        add_acl(&library, INHERITED_DENY);
        assert!(ls_shows_acl(&library), "control: ls must show the ACL");
        home
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_inherited_acl_is_cleared_from_everything_the_agent_creates() {
        let home = home_with_inheritable_acl();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        // Every directory the agent created, intermediate and root, and
        // every file it holds carries no ACL. No ACL check is bypassed.
        for path in [
            home.path.join("Library/AppSupport"),
            home.root(),
            home.root().join("state.json"),
            home.root().join("owner.lock"),
        ] {
            assert!(!ls_shows_acl(&path), "{}", path.display());
        }
        assert_eq!(root.read_file("state.json", 64).unwrap().unwrap(), b"{}");
        drop(root);

        // Negative control: without the clearing the created intermediate
        // and the root inherit the ACL, and the root check fails it closed.
        let home = home_with_inheritable_acl();
        let _reset = Reset;
        seams::bypass(seams::SKIP_ACL_CLEAR);
        assert_eq!(open(&home).err(), Some(StorageError::UnsafeState));
        assert!(ls_shows_acl(&home.path.join("Library/AppSupport")));
        assert!(ls_shows_acl(&home.root()));
    }

    /// `ls -led` output, for asserting entry order.
    #[cfg(target_os = "macos")]
    fn acl_listing(path: &Path) -> String {
        let output = std::process::Command::new("/bin/ls")
            .arg("-led")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    #[cfg(target_os = "macos")]
    const ALLOW_WRITE: &str = "everyone allow add_subdirectory,delete_child";

    /// c2: an ACL on the home or an intermediate directory passes only when
    /// every entry is a deny. Each case fails closed, and bypassing only the
    /// deny-only check admits it.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_allow_entry_on_the_home_or_an_intermediate_fails_closed() {
        // One allow entry on an intermediate.
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let support = home.path.join("Library/AppSupport");
        add_acl(&support, ALLOW_WRITE);
        fails_closed_only_by(INTERMEDIATE_ACL, StorageError::UnsafeState, || open(&home));

        // Deny first, allow second: the walk must read past the first entry.
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let support = home.path.join("Library/AppSupport");
        add_acl(&support, "everyone deny delete");
        add_acl(&support, ALLOW_WRITE);
        let listing = acl_listing(&support);
        assert!(
            listing.contains("\n 0: group:everyone deny delete\n")
                && listing.contains("\n 1: group:everyone allow add_subdirectory,delete_child\n"),
            "control: deny is entry 0 and allow entry 1: {listing}"
        );
        fails_closed_only_by(INTERMEDIATE_ACL, StorageError::UnsafeState, || open(&home));

        // An allow entry on the home itself.
        let home = TempHome::new();
        drop(open(&home).unwrap());
        add_acl(&home.path, ALLOW_WRITE);
        fails_closed_only_by(INTERMEDIATE_ACL, StorageError::UnsafeState, || open(&home));
    }

    /// c2: deny-only ACLs on the home and every intermediate, as on a stock
    /// macOS account, open.
    #[cfg(target_os = "macos")]
    #[test]
    fn deny_only_acls_on_the_home_and_intermediates_open() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        for path in [
            home.path.clone(),
            home.path.join("Library"),
            home.path.join("Library/AppSupport"),
        ] {
            add_acl(&path, "everyone deny delete");
            assert!(ls_shows_acl(&path), "control: {}", path.display());
        }
        // A second principal, so `chmod +a` adds an entry instead of merging.
        add_acl(
            &home.path.join("Library"),
            "group:wheel deny add_subdirectory",
        );
        assert!(acl_listing(&home.path.join("Library")).contains("\n 1: "));
        drop(open(&home).unwrap());
    }

    /// An in-memory ACL with one entry per tag; `None` leaves a fresh
    /// entry's tag as created. A control asserts each tag reads back.
    #[cfg(target_os = "macos")]
    fn in_memory_acl(tags: &[Option<libc::c_int>]) -> acl::Acl {
        let mut list = unsafe { acl::acl_init(4) };
        assert!(!list.is_null());
        for tag in tags {
            let mut entry: acl::AclEntry = std::ptr::null_mut();
            assert_eq!(unsafe { acl::acl_create_entry(&mut list, &mut entry) }, 0);
            if let Some(tag) = tag {
                assert_eq!(unsafe { acl::acl_set_tag_type(entry, *tag) }, 0);
            }
            let mut read = -1;
            assert_eq!(unsafe { acl::acl_get_tag_type(entry, &mut read) }, 0);
            assert_eq!(read, tag.unwrap_or(acl::ACL_UNDEFINED_TAG), "control: tag");
        }
        list
    }

    /// c2 at the tag level, on in-memory ACLs: only `ACL_EXTENDED_DENY`
    /// passes. `ACL_UNDEFINED_TAG` cannot be written to a file, so this is
    /// where an "every tag except allow" rule is caught.
    #[cfg(target_os = "macos")]
    #[test]
    fn only_explicit_deny_tags_pass_the_intermediate_acl_check() {
        use acl::{ACL_EXTENDED_ALLOW, ACL_EXTENDED_DENY};
        // SAFETY: each handle is freshly built and freed once by the walk.
        let verdict =
            |tags: &[Option<libc::c_int>]| unsafe { acl::all_deny_then_free(in_memory_acl(tags)) };
        let (deny, allow) = (Some(ACL_EXTENDED_DENY), Some(ACL_EXTENDED_ALLOW));
        assert!(verdict(&[]));
        assert!(verdict(&[deny]));
        assert!(verdict(&[deny, deny]));
        assert!(!verdict(&[allow]));
        assert!(!verdict(&[deny, allow]));
        assert!(!verdict(&[None]));
        assert!(!verdict(&[deny, None]));
    }

    /// c5: when `acl_get_entry` fails, only `EINVAL` ("no more entries")
    /// counts as the end; any other errno counts as an ACL. This test makes
    /// `acl_free` overwrite errno with `EINVAL`, so errno read after the free
    /// instead of before it admits the failure and turns this red.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_failed_acl_entry_read_counts_as_an_acl() {
        // `acl::none`, through the state file. A deny entry that does not
        // stop the owner reading makes `acl_get_fd_np` return an ACL.
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        add_acl(&home.root().join("state.json"), "everyone deny delete");
        let _reset = Reset;
        seams::clobber_errno_after_acl_free(true);
        seams::fail_acl_get_entry(Some(libc::EIO));
        assert_eq!(
            root.read_file("state.json", 64).err(),
            Some(StorageError::UnsafeState)
        );
        // Control: the same failure with `EINVAL` reads as "no entry", so
        // errno alone decided.
        seams::fail_acl_get_entry(Some(libc::EINVAL));
        assert_eq!(root.read_file("state.json", 64).unwrap().unwrap(), b"{}");
        seams::fail_acl_get_entry(None);
        drop(root);

        // The deny-only walk, through an intermediate that otherwise opens.
        let home = TempHome::new();
        drop(open(&home).unwrap());
        add_acl(&home.path.join("Library"), "everyone deny delete");
        drop(open(&home).unwrap());
        seams::fail_acl_get_entry(Some(libc::EIO));
        assert_eq!(open(&home).err(), Some(StorageError::UnsafeState));
        seams::fail_acl_get_entry(Some(libc::EINVAL));
        drop(open(&home).unwrap());
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

    /// B7: errno is cleared before every `acl_get_entry`, so an `EINVAL`
    /// left by an earlier call can never read as "end of list". Each ACL is
    /// built first; errno is set to `EINVAL` right before the call, so
    /// nothing in between can change it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_stale_einval_never_ends_the_acl_walk() {
        use acl::{ACL_EXTENDED_ALLOW, ACL_EXTENDED_DENY};
        let (deny, allow) = (Some(ACL_EXTENDED_DENY), Some(ACL_EXTENDED_ALLOW));
        // SAFETY: each handle is freshly built and freed once by the call.
        let walk = |tags: &[Option<libc::c_int>]| {
            let list = in_memory_acl(tags);
            unsafe { *libc::__error() = libc::EINVAL };
            unsafe { acl::all_deny_then_free(list) }
        };
        let empty = |tags: &[Option<libc::c_int>]| {
            let list = in_memory_acl(tags);
            unsafe { *libc::__error() = libc::EINVAL };
            unsafe { acl::empty_then_free(list) }
        };
        let _reset = Reset;
        // Control: with a stale `EINVAL` in errno the walk still evaluates
        // every real entry.
        assert!(walk(&[deny, deny]));
        assert!(!walk(&[deny, allow]));
        assert!(!empty(&[deny]));
        // A failure that sets no errno, after a stale `EINVAL`, is not the
        // end of the list: the walk (second call) and `none` (first call)
        // both refuse.
        seams::fail_acl_get_entry_silently_at(Some(1));
        assert!(!walk(&[deny, deny]));
        seams::fail_acl_get_entry_silently_at(Some(0));
        assert!(!empty(&[deny]));
    }

    /// E11: errno is cleared before `acl_get_fd_np`, so a NULL return that
    /// sets no errno, after a stale `ENOENT`, never reads as "no ACL".
    #[cfg(target_os = "macos")]
    #[test]
    fn a_stale_enoent_never_reads_as_no_acl() {
        let home = TempHome::new();
        let file = std::fs::File::create(home.path.join("probe")).unwrap();
        let _reset = Reset;
        // Control: the real call on a file with no ACL reads as none, even
        // with a stale `ENOENT` set right before it.
        unsafe { *libc::__error() = libc::ENOENT };
        assert!(acl::none(&file));
        unsafe { *libc::__error() = libc::ENOENT };
        assert!(acl::deny_only(&file));
        seams::acl_get_fd_null_silently(true);
        unsafe { *libc::__error() = libc::ENOENT };
        assert!(!acl::none(&file));
        unsafe { *libc::__error() = libc::ENOENT };
        assert!(!acl::deny_only(&file));
    }

    /// B4: the root's parent is synced only after the root passed its own
    /// checks, so an open whose root is refused (here: injected non-local
    /// filesystem) syncs no root parent, whether the root was just created
    /// or found.
    #[test]
    fn a_refused_root_syncs_no_parent() {
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
        seams::force_nonlocal(true);
        assert_eq!(open_once(&home).err(), Some(StorageError::UnsafeState));
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Step::Descend(0),
                Step::SyncParent(0),
                Step::Descend(1),
                Step::SyncParent(1),
                Step::Descend(2),
            ]
        );
        seen.lock().unwrap().clear();
        assert_eq!(open_once(&home).err(), Some(StorageError::UnsafeState));
        assert_eq!(
            *seen.lock().unwrap(),
            [Step::Descend(0), Step::Descend(1), Step::Descend(2)]
        );
        // Control: the same root, classified local, opens and syncs its
        // parent.
        seams::force_nonlocal(false);
        drop(
            retry_busy(|| {
                seen.lock().unwrap().clear();
                open_once(&home)
            })
            .unwrap(),
        );
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Step::Descend(0),
                Step::Descend(1),
                Step::Descend(2),
                Step::SyncParent(2),
            ]
        );
    }

    // SA-2B3a acceptance (9): the cache primitives.

    const CACHED: &str = "pcache-00";

    fn write_cached(root: &SecureRoot, name: &str, bytes: &[u8]) {
        root.stage(name, bytes).unwrap().publish().unwrap();
    }

    /// A file just over a power of two: `read_to_end` growth would double
    /// the capacity to 8,192; the sized read allocates `size + 1` once.
    #[test]
    fn read_file_sized_allocates_size_plus_one_and_never_grows() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let bytes = vec![b'x'; 4_097];
        write_cached(&root, CACHED, &bytes);
        let read = root.read_file_sized(CACHED, 4_097).unwrap().unwrap();
        assert_eq!(read, bytes);
        assert!(read.capacity() <= 4_098, "{}", read.capacity());
        // Control: the growing read of the same file does exceed it.
        let grown = root.read_file(CACHED, 4_097).unwrap().unwrap();
        assert!(grown.capacity() > 4_098, "{}", grown.capacity());
        // A file larger than `size` is `Corrupt`, and the read stopped at
        // `size + 1`.
        let over = fails_closed_only_by(BYTE_CAP, StorageError::Corrupt, || {
            root.read_file_sized(CACHED, 4_000)
        });
        assert_eq!(over.unwrap().len(), 4_001);
        assert_eq!(root.read_file_sized("pcache-01", 10), Ok(None));
    }

    #[test]
    fn list_and_remove_stale_temps_accept_only_the_cache_prefixes() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let refused = Some(StorageError::Refused(
            crate::security::SecurityError::Invalid,
        ));
        for prefix in ["", "state", "peers.json", "pcache", "xcache-", "."] {
            assert_eq!(root.list(prefix).err(), refused, "{prefix:?}");
            assert_eq!(root.remove_stale_temps(prefix).err(), refused, "{prefix:?}");
        }
        write_cached(&root, CACHED, b"p");
        write_cached(&root, "rcache-00", b"rr");
        write_state(&root, b"{}");
        assert_eq!(root.list("pcache-").unwrap(), [(CACHED.to_owned(), 1)]);
        assert_eq!(root.list("rcache-").unwrap(), [("rcache-00".to_owned(), 2)]);
    }

    /// Each attack on a prefixed entry makes the whole `list` fail closed
    /// with the target untouched; bypassing only the named guard admits it.
    #[test]
    fn list_fails_closed_on_a_symlink_hard_link_wrong_mode_or_foreign_entry() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        chmod(&outside, 0o600);
        let entry = home.root().join(CACHED);
        let untouched = |entry: &Path| {
            assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
            assert!(std::fs::symlink_metadata(entry).is_ok());
        };

        symlink(&outside, &entry).unwrap();
        let listed = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            root.list("pcache-")
        });
        assert_eq!(listed, [(CACHED.to_owned(), 4)]);
        untouched(&entry);
        std::fs::remove_file(&entry).unwrap();

        std::fs::hard_link(&outside, &entry).unwrap();
        fails_closed_only_by(NLINK, StorageError::UnsafeState, || root.list("pcache-"));
        untouched(&entry);
        std::fs::remove_file(&entry).unwrap();

        write_cached(&root, CACHED, b"p");
        chmod(&entry, 0o644);
        fails_closed_only_by(MODE, StorageError::UnsafeState, || root.list("pcache-"));
        untouched(&entry);
        chmod(&entry, 0o600);

        let _reset = Reset;
        seams::force_foreign(seams::FILE);
        fails_closed_only_by(OWNER, StorageError::UnsafeState, || root.list("pcache-"));
        seams::force_foreign(0);
        untouched(&entry);
        std::fs::remove_file(&entry).unwrap();

        // A FIFO with the right owner, mode and link count: only the
        // regular-file check refuses it (that guard has no bypass).
        let fifo = CString::new(entry.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        chmod(&entry, 0o600);
        assert_eq!(root.list("pcache-"), Err(StorageError::UnsafeState));
        untouched(&entry);
        std::fs::remove_file(&entry).unwrap();

        // Entries without the prefix are not checked.
        symlink(&outside, home.root().join("rcache-00")).unwrap();
        assert_eq!(root.list("pcache-").unwrap(), []);
    }

    #[test]
    fn list_fails_closed_past_4096_entries() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        // `owner.lock` is one entry; fill to exactly the cap.
        for n in 0..crate::secure_fs::LIST_ENTRIES_MAX - 1 {
            std::fs::write(home.root().join(format!("junk-{n}")), b"").unwrap();
        }
        assert_eq!(root.list("pcache-").unwrap(), []);
        std::fs::write(home.root().join("junk-last"), b"").unwrap();
        assert_eq!(root.list("pcache-"), Err(StorageError::UnsafeState));
    }

    #[test]
    fn remove_file_never_follows_and_absent_is_success() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        let entry = home.root().join(CACHED);
        symlink(&outside, &entry).unwrap();
        root.remove_file(CACHED).unwrap();
        assert!(std::fs::symlink_metadata(&entry).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        root.remove_file(CACHED).unwrap();
        assert_eq!(
            root.remove_file("../outside"),
            Err(StorageError::UnsafeState)
        );
    }

    #[test]
    fn remove_file_failures_are_unknown() {
        for step in [Step::Unlink, Step::SyncDir] {
            let home = TempHome::new();
            let root = open(&home).unwrap();
            write_cached(&root, CACHED, b"p");
            let _reset = Reset;
            seams::set_hook(Some(Box::new(move |at| {
                if at == step {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            })));
            assert_eq!(
                root.remove_file(CACHED),
                Err(StorageError::Unknown),
                "{step:?}"
            );
        }
    }

    #[test]
    fn remove_stale_temps_removes_only_the_prefixed_temps_and_never_follows() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        let dir = home.root();
        symlink(&outside, dir.join(".pcache-00.tmp")).unwrap();
        std::fs::write(dir.join(".pcache-01.tmp"), b"x").unwrap();
        for keep in [".rcache-00.tmp", ".state.json.tmp", ".pcache-00.tmpx"] {
            std::fs::write(dir.join(keep), b"x").unwrap();
        }
        // Not `CACHED`: its own temp name is planted above.
        write_cached(&root, "pcache-02", b"p");
        root.remove_stale_temps("pcache-").unwrap();
        for gone in [".pcache-00.tmp", ".pcache-01.tmp"] {
            assert!(std::fs::symlink_metadata(dir.join(gone)).is_err(), "{gone}");
        }
        for keep in [
            ".rcache-00.tmp",
            ".state.json.tmp",
            ".pcache-00.tmpx",
            "pcache-02",
        ] {
            assert!(dir.join(keep).exists(), "{keep}");
        }
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
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

    /// SA-2C2b review: the resident replaces `state.json` by `rename`
    /// between the menu's open and its check. The opened, now unlinked
    /// file (0 links) is read whole with the old bytes; the locked
    /// `read_file` still refuses it. A file with 2 links is refused.
    #[test]
    fn a_read_only_read_accepts_a_file_replaced_after_its_open() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"old");
        let read_only = SecureRoot::open_read_only(&home.path, SUFFIX)
            .unwrap()
            .unwrap();
        let opened = read_only.open_file("state.json").unwrap().unwrap();
        write_state(&root, b"new");
        assert_eq!(opened.metadata().unwrap().nlink(), 0);
        assert_eq!(read_opened(&opened, 16).unwrap(), b"old");
        assert_eq!(
            check_private_file(&opened).err(),
            Some(StorageError::UnsafeState),
            "control: the locked check refuses 0 links"
        );
        assert_eq!(
            read_only.read_file("state.json", 16).unwrap().unwrap(),
            b"new"
        );

        std::fs::hard_link(home.root().join("state.json"), home.root().join("second")).unwrap();
        assert_eq!(
            read_only.read_file("state.json", 16).err(),
            Some(StorageError::UnsafeState)
        );
    }
}
