//! Windows secure root: handle-relative, no-follow, owner-only.
//!
//! Every object below the trusted base (the LocalAppData known folder, or the
//! `home` a caller passes) is opened with `NtCreateFile` relative to its
//! verified parent's handle (`OBJECT_ATTRIBUTES.RootDirectory`), with
//! `FILE_OPEN_REPARSE_POINT`, and checked on the handle: attributes, owner,
//! DACL, link count, volume. Objects the agent creates get an explicit
//! security descriptor at creation (owner = the current user, a protected DACL
//! granting only the current user), so they never inherit a parent's ACEs.
//! A replace is `NtSetInformationFile(FileRenameInformationEx)` with
//! `REPLACE_IF_EXISTS | POSIX_SEMANTICS` on the temp file's own handle; the
//! owner lock is `LockFileEx` on a dedicated `owner.lock`. No path-based
//! `CreateFileW`, `MoveFileExW` or `ReplaceFileW` is used. See
//! `spec/state-store-v1.md`, section "Windows".

use std::{
    ffi::{OsString, c_void},
    fs::File,
    io::{self, Read},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};

use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION, FILE_DISPOSITION_DELETE,
            FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION_EX,
            FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
            FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileBasicInformation,
            FileDirectoryInformation, FileDispositionInformationEx, FileFsAttributeInformation,
            FileFsDeviceInformation, FileRenameInformationEx, FileStandardInformation,
            NtCreateFile, NtQueryDirectoryFile, NtQueryInformationFile, NtQuerySecurityObject,
            NtQueryVolumeInformationFile, NtSetInformationFile,
        },
        System::SystemServices::{
            FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
        },
    },
    Win32::{
        Foundation::{
            ERROR_LOCK_VIOLATION, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, NTSTATUS,
            OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, S_OK, STATUS_BUFFER_OVERFLOW,
            STATUS_BUFFER_TOO_SMALL, STATUS_NO_MORE_FILES, STATUS_OBJECT_NAME_NOT_FOUND,
            STATUS_SHARING_VIOLATION, UNICODE_STRING,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
            GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, INHERIT_ONLY_ACE, InitializeAcl, InitializeSecurityDescriptor,
            IsWellKnownSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
            SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_DUPLICATE,
            TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
            WinLocalSystemSid,
        },
        Storage::FileSystem::{
            DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_DELETE_CHILD, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, LOCKFILE_EXCLUSIVE_LOCK,
            LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, READ_CONTROL, SYNCHRONIZE, UnlockFileEx,
            WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Com::CoTaskMemFree,
            IO::{IO_STATUS_BLOCK, OVERLAPPED},
            Ioctl::FILE_DEVICE_NETWORK_FILE_SYSTEM,
            SystemServices::{
                ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
                SECURITY_DESCRIPTOR_REVISION,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    },
};

use super::{Step, StorageError, shim};

#[cfg(test)]
use super::seams;

/// Frozen state-root suffix below the LocalAppData known folder
/// (`spec/security-v1.md`).
pub const STATE_SUFFIX: &[&str] = &["Nyanako", "Syrtis Agent"];

const LOCK_FILE: &str = "owner.lock";

/// One verified agent root, held with its exclusive owner lock.
///
/// The only way to obtain one is [`SecureRoot::open_under`], which takes the
/// lock, so holding a `SecureRoot` is the type-level proof that commits run
/// under the lock. Dropping it unlocks and closes the lock file; so does
/// process exit.
pub struct SecureRoot {
    dir: File,
    _lock: Lock,
    /// `home/suffix…` as passed to [`SecureRoot::open_under`]. Nothing in this
    /// module ever reopens anything by it.
    path: PathBuf,
    user: Sid,
}

/// A temp file written and flushed, not yet renamed over its target. It keeps
/// the temp file's handle: the rename and the flush after it run on that
/// handle, never on a name.
pub(crate) struct Staged<'a> {
    root: &'a SecureRoot,
    file: File,
    target: Vec<u16>,
}

/// The current token's LocalAppData known folder
/// (`SHGetKnownFolderPath(FOLDERID_LocalAppData)` with the process token).
/// `LOCALAPPDATA` is not read. It must be a plain drive path (`X:\…`); UNC,
/// verbatim and device paths fail closed.
pub fn trusted_home() -> Result<PathBuf, StorageError> {
    let token = process_token(TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE)?;
    let mut raw: *mut u16 = ptr::null_mut();
    // SAFETY: the GUID is a static; `token` is a live token handle owned by
    // this function; `raw` is an out pointer the call fills.
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            0,
            token.as_raw_handle() as HANDLE,
            &mut raw,
        )
    };
    let path = if result == S_OK && !raw.is_null() {
        // SAFETY: on success `raw` is a NUL-terminated wide string allocated
        // by the call; it is read up to its NUL (bounded) before the free.
        let length = (0..32_768)
            .take_while(|&i| unsafe { *raw.add(i) } != 0)
            .count();
        // SAFETY: `length` units starting at `raw` were just read above.
        let units = unsafe { std::slice::from_raw_parts(raw, length) };
        Some(PathBuf::from(OsString::from_wide(units)))
    } else {
        None
    };
    // SAFETY: the documentation requires freeing the buffer whether or not
    // the call succeeded; NULL is accepted. Nothing reads `raw` afterwards.
    unsafe { CoTaskMemFree(raw as *const c_void) };
    let Some(path) = path else {
        return Err(fail("SHGetKnownFolderPath", result));
    };
    nt_path(&path)?;
    // The frozen root rule (`security::resolve_secure_root`) takes `X:\…`
    // only, not the verbatim `\\?\X:\…` that `open_under` also accepts.
    let plain_drive = matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    );
    if !plain_drive {
        return Err(StorageError::UnsafeState);
    }
    Ok(path)
}

/// The production root path. Computes only: nothing is opened or created.
pub fn default_root_path() -> Result<PathBuf, StorageError> {
    Ok(STATE_SUFFIX
        .iter()
        .fold(trusted_home()?, |path, part| path.join(part)))
}

impl SecureRoot {
    /// Opens the production root below the LocalAppData known folder.
    pub fn open_default() -> Result<Self, StorageError> {
        Self::open_under(&trusted_home()?, STATE_SUFFIX)
    }

    /// Opens `home\suffix…` and takes its owner lock.
    ///
    /// `home` must be an absolute drive path; it is opened by its NT path
    /// (`\??\X:\…`), following a junction or symlink at any level, and
    /// checked on the handle: a directory owned by the current user, SYSTEM
    /// or Administrators, a DACL that grants no other SID a write-type right,
    /// a volume with persistent ACLs that is not a network volume. Every
    /// component below it is opened relative to its parent's handle with
    /// `FILE_OPEN_REPARSE_POINT`, created with the owner-only descriptor when
    /// missing, and must not be a reparse point. Intermediate directories
    /// follow the base's owner and DACL rule; the last one, the agent root,
    /// must be owned by the current user with a protected DACL whose every
    /// ACE names only the current user.
    pub fn open_under(home: &Path, suffix: &[&str]) -> Result<Self, StorageError> {
        let path = suffix
            .iter()
            .fold(home.to_path_buf(), |path, part| path.join(part));
        if suffix.is_empty() {
            return Err(StorageError::UnsafeState);
        }
        let base = nt_path(home)?;
        let user = Sid::current()?;
        let mut dir = nt_create(None, &base, BASE_OPEN, None).map_err(|s| fail("open home", s))?;
        check_dir(&dir, Object::Home, &user)?;
        check_volume(&dir)?;
        let descriptor = Descriptor::owner_only(&user, true)?;
        for (index, component) in suffix.iter().enumerate() {
            let name = component_name(component)?;
            shim(Step::Descend(index), || Ok(())).map_err(|_| StorageError::UnsafeState)?;
            let open = Open {
                disposition: FILE_OPEN_IF,
                options: DIR_OPTIONS | nofollow(),
                ..DIR_OPEN
            };
            let next = nt_create(Some(&dir), &name, open, explicit(&descriptor))
                .map_err(|s| fail("open component", s))?;
            if index + 1 == suffix.len() {
                check_dir(&next, Object::Root, &user)?;
                check_volume(&next)?;
            } else {
                check_dir(&next, Object::Intermediate, &user)?;
            }
            dir = next;
        }
        drop(descriptor);
        let lock = acquire_lock(&dir, &user)?;
        Ok(Self {
            dir,
            _lock: lock,
            path,
            user,
        })
    }

    /// The root's path as opened. Read-only; nothing here reopens by it.
    // ponytail: only control.rs (macOS/Linux) reads it until W3.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Reads an agent-owned file: opened with `FILE_OPEN_REPARSE_POINT`, not
    /// a directory or reparse point, owned by the current user, a protected
    /// current-user-only DACL, one link, at most `max` bytes. `Ok(None)` when
    /// absent.
    pub(crate) fn read_file(
        &self,
        name: &str,
        max: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(file) = open_agent_file(&self.dir, name)? else {
            return Ok(None);
        };
        check_private_file(&file, &self.user, Links::One)?;
        read_bounded(&file, max).map(Some)
    }

    /// Creates `.<name>.tmp` with `FILE_CREATE` (fails if any entry of that
    /// name exists, a reparse point included) and the owner-only descriptor,
    /// writes `bytes`, and flushes it. Any failure is
    /// [`StorageError::Unknown`].
    pub(crate) fn stage(&self, name: &str, bytes: &[u8]) -> Result<Staged<'_>, StorageError> {
        let target = file_name(name)?;
        let temp = temp_name(name)?;
        let unknown = |_| StorageError::Unknown;
        let descriptor = Descriptor::owner_only(&self.user, false).map_err(unknown)?;
        let file = shim(Step::CreateTemp, || {
            let open = Open {
                // DELETE: the rename runs on this handle.
                access: GENERIC_WRITE | DELETE,
                share: 0,
                disposition: FILE_CREATE,
                options: FILE_OPTIONS | FILE_OPEN_REPARSE_POINT,
            };
            nt_create(Some(&self.dir), &temp, open, explicit(&descriptor)).map_err(nt_error)
        })
        .map_err(|_| StorageError::Unknown)?;
        let (first, rest) = bytes.split_at(bytes.len() / 2);
        shim(Step::Write, || io::Write::write_all(&mut &file, first))
            .map_err(|_| StorageError::Unknown)?;
        shim(Step::WriteRest, || io::Write::write_all(&mut &file, rest))
            .map_err(|_| StorageError::Unknown)?;
        // `sync_all` is `FlushFileBuffers` on this handle.
        shim(Step::SyncFile, || file.sync_all()).map_err(|_| StorageError::Unknown)?;
        shim(Step::Staged, || Ok(())).map_err(|_| StorageError::Unknown)?;
        Ok(Staged {
            root: self,
            file,
            target,
        })
    }

    /// Removes a temp file left by a crash: only the exact `.<name>.tmp`,
    /// opened with `FILE_OPEN_REPARSE_POINT` (a reparse point is removed
    /// itself, never followed) and deleted through that handle.
    pub(crate) fn remove_stale_temp(&self, name: &str) -> Result<(), StorageError> {
        let temp = temp_name(name)?;
        match delete_at(&self.dir, &temp) {
            Ok(()) | Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(()),
            Err(status) => Err(fail("remove stale temp", status)),
        }
    }

    /// Opens the directory `name` directly below the root, creating it with
    /// the owner-only descriptor when missing, and returns its path. Checked
    /// like the root itself on the handle: opened with
    /// `FILE_OPEN_REPARSE_POINT` relative to the root's handle, a directory
    /// and not a reparse point, owned by the current user, a protected DACL
    /// naming only the current user. An existing directory is checked as
    /// found, never changed. Its ACE is inheritable, so files that a
    /// path-based consumer creates inside inherit owner-only access. `name`
    /// follows the agent file-name rule. Whoever opens the returned path
    /// later resolves it again (`spec/source-v1.md`, non-claims).
    // ponytail: the only callers (source.rs, agent.rs) are cfg(unix) until W3.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn private_subdir(&self, name: &str) -> Result<PathBuf, StorageError> {
        let wide_name = file_name(name)?;
        let descriptor = Descriptor::owner_only(&self.user, true)?;
        let open = Open {
            disposition: FILE_OPEN_IF,
            options: DIR_OPTIONS | nofollow(),
            ..DIR_OPEN
        };
        let dir = nt_create(Some(&self.dir), &wide_name, open, explicit(&descriptor))
            .map_err(|s| fail("open private subdir", s))?;
        check_dir(&dir, Object::Root, &self.user)?;
        Ok(self.path.join(name))
    }

    /// Empties the directory `name` directly below the root, which is
    /// checked as [`Self::private_subdir`] checks it but never created;
    /// absent is success. The directory itself stays. Every entry is opened
    /// with `FILE_OPEN_REPARSE_POINT` relative to its parent's handle and
    /// classified on that handle: a reparse point (a junction, a symlink, or
    /// any other) is deleted itself and never entered; a directory is
    /// emptied the same way, then deleted; anything else is deleted. Every
    /// delete is a POSIX-semantics delete through the entry's own handle.
    /// Nesting deeper than [`CLEAR_DEPTH_MAX`] or any failed call is
    /// `UnsafeState`; what was removed before it stays removed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn clear_private_subdir(&self, name: &str) -> Result<(), StorageError> {
        let wide_name = file_name(name)?;
        let open = Open {
            options: DIR_OPTIONS | nofollow(),
            ..DIR_OPEN
        };
        let dir = match nt_create(Some(&self.dir), &wide_name, open, None) {
            Ok(dir) => dir,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(()),
            Err(status) => return Err(fail("open private subdir to clear", status)),
        };
        check_dir(&dir, Object::Root, &self.user)?;
        clear_dir(&dir, 0)
    }

    /// Reads an agent-owned file under the checks of [`Self::read_file`]
    /// into one buffer of exactly `size + 1` bytes, allocated before the
    /// first read and never grown. More than `size` bytes is `Corrupt`; a
    /// failed allocation is `Unavailable`. `Ok(None)` when absent.
    pub(crate) fn read_file_sized(
        &self,
        name: &str,
        size: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(file) = open_agent_file(&self.dir, name)? else {
            return Ok(None);
        };
        check_private_file(&file, &self.user, Links::One)?;
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
        guard(filled <= size, BYTE_CAP, "byte cap", StorageError::Corrupt)?;
        Ok(Some(bytes))
    }

    /// The entries whose name starts with `prefix` (one of
    /// [`CACHE_PREFIXES`](super::CACHE_PREFIXES), else `Refused(Invalid)`),
    /// with their sizes, sorted by name. Every such entry is opened with
    /// `FILE_OPEN_REPARSE_POINT` for attributes and security only (no data
    /// access) and must pass the agent-file checks: not a directory or
    /// reparse point, owned by the current user, protected current-user-only
    /// DACL, one link, a valid agent file name. One that fails makes the
    /// whole call `UnsafeState`; nothing is followed or removed. Other
    /// entries are only counted: more than
    /// [`LIST_ENTRIES_MAX`](super::LIST_ENTRIES_MAX) is `UnsafeState`.
    pub(crate) fn list(&self, prefix: &str) -> Result<Vec<(String, u64)>, StorageError> {
        super::cache_prefix(prefix)?;
        let lead = wide(prefix);
        let mut listed = Vec::new();
        for name in entry_names(&self.dir, super::LIST_ENTRIES_MAX)? {
            if !name.starts_with(&lead) {
                continue;
            }
            let text = String::from_utf16(&name).map_err(|_| StorageError::UnsafeState)?;
            let wide_name = file_name(&text)?;
            let open = Open {
                access: FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                share: SHARE_ALL,
                disposition: FILE_OPEN,
                options: FILE_SYNCHRONOUS_IO_NONALERT | nofollow(),
            };
            let file = nt_create(Some(&self.dir), &wide_name, open, None)
                .map_err(|s| fail("open listed entry", s))?;
            check_private_file(&file, &self.user, Links::One)?;
            let size = u64::try_from(standard(&file)?.end_of_file)
                .map_err(|_| StorageError::UnsafeState)?;
            listed.push((text, size));
        }
        listed.sort();
        Ok(listed)
    }

    /// Deletes one agent file through a handle opened with
    /// `FILE_OPEN_REPARSE_POINT` (a reparse point is removed itself, never
    /// followed). An absent file is success. Either step failing is
    /// `Unknown`. Both run through `shim` (`Step::Unlink`, `Step::SyncDir`);
    /// Windows has no directory sync, so `SyncDir` does nothing here.
    pub(crate) fn remove_file(&self, name: &str) -> Result<(), StorageError> {
        let name = file_name(name)?;
        shim(Step::Unlink, || match delete_at(&self.dir, &name) {
            Ok(()) | Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(()),
            Err(status) => Err(nt_error(status)),
        })
        .map_err(|_| StorageError::Unknown)?;
        // ponytail: no directory sync on Windows; the delete's durability is
        // the filesystem's (spec non-claim).
        shim(Step::SyncDir, || Ok(())).map_err(|_| StorageError::Unknown)
    }

    /// Removes every temp file `.<prefix>….tmp` left by a crash, `prefix`
    /// one of [`CACHE_PREFIXES`](super::CACHE_PREFIXES) (else
    /// `Refused(Invalid)`). Each is deleted through a handle opened with
    /// `FILE_OPEN_REPARSE_POINT`; a failure other than "not found" is
    /// `UnsafeState`.
    pub(crate) fn remove_stale_temps(&self, prefix: &str) -> Result<(), StorageError> {
        super::cache_prefix(prefix)?;
        let lead = wide(&format!(".{prefix}"));
        let tail = wide(".tmp");
        for name in entry_names(&self.dir, super::LIST_ENTRIES_MAX)? {
            if !(name.starts_with(&lead) && name.ends_with(&tail)) {
                continue;
            }
            match delete_at(&self.dir, &name) {
                Ok(()) | Err(STATUS_OBJECT_NAME_NOT_FOUND) => {}
                Err(status) => return Err(fail("remove stale cache temp", status)),
            }
        }
        Ok(())
    }
}

impl Staged<'_> {
    /// Renames the temp file over its target through its own handle
    /// (`NtSetInformationFile(FileRenameInformationEx)`, `REPLACE_IF_EXISTS |
    /// POSIX_SEMANTICS`, `RootDirectory` = the root's handle), then flushes
    /// that still-open handle. Any failure is [`StorageError::Unknown`]: the
    /// durable state is then old or new, and which one cannot be known
    /// without a restart.
    pub(crate) fn publish(self) -> Result<(), StorageError> {
        shim(Step::Rename, || {
            rename_over(&self.file, &self.root.dir, &self.target).map_err(nt_error)
        })
        .map_err(|_| StorageError::Unknown)?;
        shim(Step::SyncDir, || self.file.sync_all()).map_err(|_| StorageError::Unknown)
    }
}

/// An agent root opened by [`SecureRoot::open_read_only`]: no owner lock,
/// and the only operation is [`ReadOnlyRoot::read_file`].
pub struct ReadOnlyRoot {
    dir: File,
    user: Sid,
}

impl SecureRoot {
    /// Opens `home\suffix…` for reading only, for a second process of the
    /// owner while the resident agent holds the lock. The checks of
    /// [`SecureRoot::open_under`] on the same handles, but nothing is
    /// created or locked. `Ok(None)` when a component does not exist.
    ///
    /// Replacement is a POSIX rename, and the read opens with
    /// `FILE_SHARE_DELETE`, so a read sees the old or the new file whole.
    pub fn open_read_only(
        home: &Path,
        suffix: &[&str],
    ) -> Result<Option<ReadOnlyRoot>, StorageError> {
        if suffix.is_empty() {
            return Err(StorageError::UnsafeState);
        }
        let base = nt_path(home)?;
        let user = Sid::current()?;
        let mut dir = nt_create(None, &base, BASE_OPEN, None).map_err(|s| fail("open home", s))?;
        check_dir(&dir, Object::Home, &user)?;
        check_volume(&dir)?;
        for (index, component) in suffix.iter().enumerate() {
            let name = component_name(component)?;
            let open = Open {
                options: DIR_OPTIONS | nofollow(),
                ..DIR_OPEN
            };
            let next = match nt_create(Some(&dir), &name, open, None) {
                Ok(next) => next,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
                Err(status) => return Err(fail("open component read-only", status)),
            };
            if index + 1 == suffix.len() {
                check_dir(&next, Object::Root, &user)?;
                check_volume(&next)?;
            } else {
                check_dir(&next, Object::Intermediate, &user)?;
            }
            dir = next;
        }
        Ok(Some(ReadOnlyRoot { dir, user }))
    }
}

impl ReadOnlyRoot {
    /// [`SecureRoot::read_file`] on this root, with one difference: a link
    /// count of 0 is accepted as well as 1, because without the lock the
    /// resident may rename a new file over this one between the open and
    /// the check; the opened file is then deleted but still whole and still
    /// owner-only. Two or more links are refused.
    pub fn read_file(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>, StorageError> {
        match self.open_file(name)? {
            Some(file) => read_opened(&file, max, &self.user).map(Some),
            None => Ok(None),
        }
    }

    fn open_file(&self, name: &str) -> Result<Option<File>, StorageError> {
        open_agent_file(&self.dir, name)
    }
}

/// The checks and the bounded read of [`ReadOnlyRoot::read_file`] on an
/// already opened file.
fn read_opened(file: &File, max: usize, user: &Sid) -> Result<Vec<u8>, StorageError> {
    check_private_file(file, user, Links::AtMostOne)?;
    read_bounded(file, max)
}

fn read_bounded(file: &File, max: usize) -> Result<Vec<u8>, StorageError> {
    let mut bytes = Vec::new();
    file.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| StorageError::UnsafeState)?;
    guard(
        bytes.len() <= max,
        BYTE_CAP,
        "byte cap",
        StorageError::Corrupt,
    )?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug)]
enum Object {
    /// The base: the known folder, or the `home` a caller passed.
    Home,
    Intermediate,
    /// The agent root, and a private subdirectory below it.
    Root,
    File,
}

#[derive(Clone, Copy)]
enum Links {
    One,
    AtMostOne,
}

// Bypass flags; real values only in test builds, where `guard` consults them.
#[cfg(test)]
use seams::{BYTE_CAP, DACL, DACL_PRESENT, INTERMEDIATE, LOCAL_FS, NLINK, OWNER, PERSISTENT_ACLS};
#[cfg(not(test))]
const BYTE_CAP: u32 = 0;
#[cfg(not(test))]
const DACL: u32 = 0;
#[cfg(not(test))]
const DACL_PRESENT: u32 = 0;
#[cfg(not(test))]
const INTERMEDIATE: u32 = 0;
#[cfg(not(test))]
const LOCAL_FS: u32 = 0;
#[cfg(not(test))]
const NLINK: u32 = 0;
#[cfg(not(test))]
const OWNER: u32 = 0;
#[cfg(not(test))]
const PERSISTENT_ACLS: u32 = 0;

/// Fails with `error` unless `ok`. Test builds let a negative control bypass
/// the guard named by `flag`, and print which guard refused (`what`) so a CI
/// log names it; a non-test build has no bypass and prints nothing.
fn guard(
    ok: bool,
    #[cfg_attr(not(test), allow(unused_variables))] flag: u32,
    #[cfg_attr(not(test), allow(unused_variables))] what: &str,
    error: StorageError,
) -> Result<(), StorageError> {
    #[cfg(test)]
    if seams::bypassed(flag) {
        return Ok(());
    }
    if ok {
        Ok(())
    } else {
        #[cfg(test)]
        eprintln!("secure_fs::windows: guard refused: {what}");
        Err(error)
    }
}

/// `UnsafeState` for a failed system call. Test builds print the step and
/// the NTSTATUS, HRESULT or Win32 error so a CI log is diagnosable; a
/// non-test build prints nothing.
fn fail(
    #[cfg_attr(not(test), allow(unused_variables))] step: &str,
    #[cfg_attr(not(test), allow(unused_variables))] code: i32,
) -> StorageError {
    #[cfg(test)]
    eprintln!("secure_fs::windows: {step} failed: {:#010x}", code as u32);
    StorageError::UnsafeState
}

/// The last Win32 error as an `i32` code for [`fail`].
fn last_error() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn nt_error(status: NTSTATUS) -> io::Error {
    // SAFETY: a pure status-code translation.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn nofollow() -> u32 {
    #[cfg(test)]
    if seams::bypassed(seams::NOFOLLOW) {
        return 0;
    }
    FILE_OPEN_REPARSE_POINT
}

/// The descriptor to create an object with: always `Some`, except when a
/// test bypasses `EXPLICIT_SD` (the object then inherits its parent's ACEs).
fn explicit<'d, 'u>(descriptor: &'d Descriptor<'u>) -> Option<&'d Descriptor<'u>> {
    #[cfg(test)]
    if seams::bypassed(seams::EXPLICIT_SD) {
        return None;
    }
    Some(descriptor)
}

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
/// Every handle is synchronous (so `std::fs::File` I/O works on it), and
/// none is ever created inheritable (`OBJ_INHERIT` is never set).
const DIR_OPTIONS: u32 = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
const FILE_OPTIONS: u32 = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
/// Directory handles: list, traverse, read attributes and security. Shared
/// for read, write and delete, so the I/O manager can open the parent during
/// a rename below it (inferred from the rename documentation).
const DIR_OPEN: Open = Open {
    access: FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    share: SHARE_ALL,
    disposition: FILE_OPEN,
    options: DIR_OPTIONS,
};
/// The base is opened by path and follows reparse points (no
/// `FILE_OPEN_REPARSE_POINT`), like the Unix home.
const BASE_OPEN: Open = DIR_OPEN;

/// Right bits that let a holder add, delete, replace or re-permission an
/// entry below a directory. An allow ACE granting any of them to a SID
/// other than the current user, SYSTEM or Administrators makes the base or
/// an intermediate directory unsafe.
const WRITE_RIGHTS: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

#[derive(Clone, Copy)]
struct Open {
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
}

/// `NtCreateFile` of `name`: relative to `parent`'s handle, or an absolute NT
/// path when `parent` is `None`. `OBJ_CASE_INSENSITIVE` as Win32 opens do;
/// never `OBJ_INHERIT`. `descriptor` applies only if the call creates the
/// object.
fn nt_create(
    parent: Option<&File>,
    name: &[u16],
    open: Open,
    descriptor: Option<&Descriptor<'_>>,
) -> Result<File, NTSTATUS> {
    // A name longer than a UNICODE_STRING can carry is an invalid name.
    const STATUS_OBJECT_NAME_INVALID: NTSTATUS = 0xC000_0033_u32 as NTSTATUS;
    let bytes = name
        .len()
        .checked_mul(2)
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or(STATUS_OBJECT_NAME_INVALID)?;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(ptr::null_mut(), |p| p.as_raw_handle() as HANDLE),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.map_or(ptr::null(), Descriptor::as_ptr),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a live local: `object_name` borrows
    // `name` (which outlives the call), `attributes` and `status_block` are
    // locals, the root handle is borrowed from a live `File`, and the
    // descriptor (when given) is a valid absolute descriptor kept alive by
    // the borrow. No EA buffer.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            open.access,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            open.share,
            open.disposition,
            open.options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }
    // SAFETY: on success the call returned a new handle that nothing else
    // owns; the `File` takes ownership and closes it once.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

/// `\??\X:\a\b` for an absolute drive path `X:\a\b` (or `\\?\X:\a\b`). UNC,
/// `\\?\UNC`, device, relative and drive-relative paths, `..`, and
/// components holding `/`, `:` or NUL fail closed. The base is trusted as
/// a path, as the Unix home is.
fn nt_path(home: &Path) -> Result<Vec<u16>, StorageError> {
    let mut components = home.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) if drive.is_ascii_alphabetic() => {
                drive
            }
            _ => return Err(StorageError::UnsafeState),
        },
        _ => return Err(StorageError::UnsafeState),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(StorageError::UnsafeState);
    }
    let mut path = wide("\\??\\");
    path.extend([u16::from(drive), u16::from(b':')]);
    let mut any = false;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(StorageError::UnsafeState);
        };
        let units: Vec<u16> = name.encode_wide().collect();
        if units.is_empty() || units.iter().any(|&u| u == 0 || u == 0x2f || u == 0x3a) {
            return Err(StorageError::UnsafeState);
        }
        path.push(u16::from(b'\\'));
        path.extend(units);
        any = true;
    }
    if !any {
        // `\??\X:` alone names the volume, not its root directory.
        path.push(u16::from(b'\\'));
    }
    Ok(path)
}

/// The current user's SID, from the process token's `TokenUser`. The SID
/// lives inside the `TOKEN_USER` buffer, which this owns.
struct Sid(Vec<u64>);

impl Sid {
    fn current() -> Result<Self, StorageError> {
        let token = process_token(TOKEN_QUERY)?;
        let mut needed = 0u32;
        // SAFETY: a size query: no buffer, `needed` is an out parameter.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed == 0 || needed > 4_096 {
            return Err(fail("GetTokenInformation size", last_error()));
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buffer` is writable for `needed` bytes and 8-aligned,
        // enough for TOKEN_USER; `token` is live.
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(fail("GetTokenInformation", last_error()));
        }
        Ok(Self(buffer))
    }

    fn as_ptr(&self) -> PSID {
        // SAFETY: the buffer holds the TOKEN_USER the token query wrote; its
        // SID pointer points into the same buffer, which lives as long as
        // `self` (moving the Vec does not move its heap allocation).
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn process_token(access: u32) -> Result<OwnedHandle, StorageError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    // close; `token` is an out parameter.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(fail("OpenProcessToken", last_error()));
    }
    // SAFETY: the call succeeded and returned a new handle owned here.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as _) })
}

/// An absolute security descriptor: owner = the current user, a protected
/// DACL with one allow ACE (`FILE_ALL_ACCESS`) for the current user, made
/// inheritable for directories. It borrows the SID it names.
struct Descriptor<'a> {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _acl: Vec<u64>,
    _user: &'a Sid,
}

impl<'a> Descriptor<'a> {
    fn owner_only(user: &'a Sid, directory: bool) -> Result<Self, StorageError> {
        // SAFETY: `user` holds a valid SID from the token.
        let sid_len = unsafe { GetLengthSid(user.as_ptr()) } as usize;
        // The ACL header, one ACCESS_ALLOWED_ACE without its `SidStart`
        // placeholder, the SID; rounded up to a DWORD.
        let acl_len = (size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
            + sid_len)
            .next_multiple_of(4);
        let mut acl = vec![0u64; acl_len.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let sd: PSECURITY_DESCRIPTOR = ptr::addr_of_mut!(*descriptor).cast();
        // SAFETY: `acl_ptr` is writable for `acl_len` bytes and 8-aligned;
        // `sd` points to a writable SECURITY_DESCRIPTOR in a Box; the SID is
        // valid. The descriptor stores pointers to the ACL and the SID, whose
        // heap storage this struct keeps alive (the ACL Vec) or borrows (the
        // SID) for its whole life.
        let ok = unsafe {
            InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) != 0
                && AddAccessAllowedAceEx(
                    acl_ptr,
                    ACL_REVISION,
                    flags,
                    FILE_ALL_ACCESS,
                    user.as_ptr(),
                ) != 0
                && InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) != 0
                && SetSecurityDescriptorOwner(sd, user.as_ptr(), 0) != 0
                && SetSecurityDescriptorDacl(sd, 1, acl_ptr, 0) != 0
                && SetSecurityDescriptorControl(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
        };
        if !ok {
            return Err(fail("build security descriptor", last_error()));
        }
        Ok(Self {
            descriptor,
            _acl: acl,
            _user: user,
        })
    }

    fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        &*self.descriptor
    }
}

/// A directory handle's checks: a directory; below the base, not a reparse
/// point; then the owner and DACL rule of `object`.
fn check_dir(dir: &File, object: Object, user: &Sid) -> Result<(), StorageError> {
    let attributes = basic_attributes(dir)?;
    guard(
        attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        0,
        "a directory",
        StorageError::UnsafeState,
    )?;
    if !matches!(object, Object::Home) {
        // Defence in depth: `FILE_OPEN_REPARSE_POINT` opened the reparse
        // point itself, so a junction or symlink is refused here.
        guard(
            attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            0,
            "not a reparse point",
            StorageError::UnsafeState,
        )?;
    }
    check_security(dir, object, user)
}

/// An agent file's checks on its handle: not a directory or reparse point,
/// owned by the current user, protected current-user-only DACL, and the
/// link count.
fn check_private_file(file: &File, user: &Sid, links: Links) -> Result<(), StorageError> {
    let attributes = basic_attributes(file)?;
    guard(
        attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0,
        0,
        "a regular file",
        StorageError::UnsafeState,
    )?;
    check_security(file, Object::File, user)?;
    let count = standard(file)?.links;
    let ok = match links {
        Links::One => count == 1,
        Links::AtMostOne => count <= 1,
    };
    guard(ok, NLINK, "link count", StorageError::UnsafeState)
}

/// The owner and DACL of an open handle (`NtQuerySecurityObject`, which
/// needs `READ_CONTROL`), checked by [`check_descriptor`].
fn check_security(handle: &File, object: Object, user: &Sid) -> Result<(), StorageError> {
    let mut buffer = vec![0u64; 128];
    loop {
        let length = (buffer.len() * 8) as u32;
        let mut needed = 0u32;
        // SAFETY: `buffer` is writable for `length` bytes and 8-aligned;
        // the handle is live.
        let status = unsafe {
            NtQuerySecurityObject(
                handle.as_raw_handle() as HANDLE,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                buffer.as_mut_ptr().cast(),
                length,
                &mut needed,
            )
        };
        if status == STATUS_BUFFER_TOO_SMALL && needed > length && needed <= 65_536 {
            buffer = vec![0u64; (needed as usize).div_ceil(8)];
            continue;
        }
        if status < 0 {
            return Err(fail("NtQuerySecurityObject", status));
        }
        return check_descriptor(buffer.as_mut_ptr().cast(), object, user);
    }
}

/// The owner and DACL rules (`spec/state-store-v1.md`, "Windows"):
///
/// - Base and intermediate: owner is the current user, SYSTEM or
///   Administrators; every ACE is an allow or deny ACE; no allow ACE that is
///   not inherit-only grants a [`WRITE_RIGHTS`] bit to any other SID.
/// - Agent root, private subdirectory, agent file: owner is the current user;
///   the DACL is protected; every ACE is an allow or deny ACE naming the
///   current user.
/// - Every object: a DACL is present and not NULL.
fn check_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    object: Object,
    user: &Sid,
) -> Result<(), StorageError> {
    let mut owner: PSID = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: `descriptor` is a valid self-relative or absolute descriptor
    // (from `NtQuerySecurityObject` or built here); out parameters are locals.
    let read = unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) };
    let owned = read != 0
        && !owner.is_null()
        && !forced_foreign(object)
        && match object {
            Object::Home | Object::Intermediate => trusted_sid(owner, user),
            Object::Root | Object::File => same_sid(owner, user.as_ptr()),
        };
    guard(owned, OWNER, "owner", StorageError::UnsafeState)?;

    let (mut control, mut revision) = (0u16, 0u32);
    let (mut present, mut dacl, mut dacl_defaulted) = (0, ptr::null_mut::<ACL>(), 0);
    // SAFETY: as above; out parameters are locals.
    let read = unsafe {
        GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
            && GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut dacl_defaulted)
                != 0
    };
    if !read {
        return Err(fail("read security descriptor", last_error()));
    }
    // A NULL DACL grants everyone everything; a missing one is unverifiable.
    guard(
        present != 0 && !dacl.is_null(),
        DACL_PRESENT,
        "a DACL present and not NULL",
        StorageError::UnsafeState,
    )?;
    let aces = if dacl.is_null() {
        Vec::new()
    } else {
        // SAFETY: `dacl` points into `descriptor`, which is valid.
        unsafe { read_aces(dacl) }?
    };
    match object {
        Object::Root | Object::File => guard(
            control & SE_DACL_PROTECTED != 0
                && aces
                    .iter()
                    .all(|ace| ace.known && same_sid(ace.sid, user.as_ptr())),
            DACL,
            "a protected current-user-only DACL",
            StorageError::UnsafeState,
        ),
        Object::Home | Object::Intermediate => guard(
            aces.iter().all(|ace| {
                ace.known
                    && (ace.kind != ACCESS_ALLOWED_ACE_TYPE as u8
                        || ace.flags & INHERIT_ONLY_ACE as u8 != 0
                        || ace.mask & WRITE_RIGHTS == 0
                        || trusted_sid(ace.sid, user))
            }),
            INTERMEDIATE,
            "no write-type right for another SID",
            StorageError::UnsafeState,
        ),
    }
}

struct Ace {
    /// An allow or deny ACE; every other type (callback, object, audit,
    /// unknown) is not, and fails the DACL rules.
    known: bool,
    kind: u8,
    flags: u8,
    mask: u32,
    sid: PSID,
}

/// Every ACE of `dacl`, in order.
///
/// # Safety
///
/// `dacl` must point to a valid ACL that stays alive while the returned
/// SID pointers are used.
unsafe fn read_aces(dacl: *mut ACL) -> Result<Vec<Ace>, StorageError> {
    // SAFETY: the caller guarantees a valid ACL.
    let count = unsafe { (*dacl).AceCount };
    let mut aces = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `index` is below the ACL's own count; `ace` is an out
        // parameter that points into the ACL on success.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(fail("GetAce", last_error()));
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        let known = matches!(
            u32::from(header.AceType),
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) && usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>();
        let (mask, sid) = if known {
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: allow and deny ACEs share the ACCESS_ALLOWED_ACE
            // layout, and `AceSize` covers it (checked above).
            unsafe {
                (
                    ptr::addr_of!((*allowed).Mask).read_unaligned(),
                    ptr::addr_of_mut!((*allowed).SidStart).cast::<c_void>(),
                )
            }
        } else {
            (0, ptr::null_mut())
        };
        aces.push(Ace {
            known,
            kind: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
    }
    Ok(aces)
}

fn same_sid(a: PSID, b: PSID) -> bool {
    // SAFETY: both point to SIDs inside live buffers.
    !a.is_null() && !b.is_null() && unsafe { EqualSid(a, b) } != 0
}

/// The current user, SYSTEM (S-1-5-18) or Administrators (S-1-5-32-544).
fn trusted_sid(sid: PSID, user: &Sid) -> bool {
    // SAFETY: `sid` points to a SID inside a live descriptor buffer.
    same_sid(sid, user.as_ptr())
        || unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
}

#[cfg(test)]
fn forced_foreign(object: Object) -> bool {
    seams::forced_foreign(match object {
        Object::Home => seams::HOME,
        Object::Intermediate => seams::INTERMEDIATE_DIR,
        Object::Root => seams::ROOT,
        Object::File => seams::FILE,
    })
}

#[cfg(not(test))]
fn forced_foreign(_: Object) -> bool {
    false
}

/// The volume holding `dir` must keep ACLs (`FILE_PERSISTENT_ACLS`) and be
/// local: not `FILE_REMOTE_DEVICE`, `FILE_REMOTE_DEVICE_VSMB` or
/// `FILE_DEVICE_NETWORK_FILE_SYSTEM` (`FileFsDeviceInformation`).
fn check_volume(dir: &File) -> Result<(), StorageError> {
    let mut buffer = [0u64; 64];
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buffer` is writable for its size and 8-aligned; the handle is
    // live. The fixed part of FILE_FS_ATTRIBUTE_INFORMATION fits; a long
    // file system name only truncates (`STATUS_BUFFER_OVERFLOW`).
    let status = unsafe {
        NtQueryVolumeInformationFile(
            dir.as_raw_handle() as HANDLE,
            &mut status_block,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            FileFsAttributeInformation,
        )
    };
    if status < 0 && status != STATUS_BUFFER_OVERFLOW {
        return Err(fail("FileFsAttributeInformation", status));
    }
    // `FileSystemAttributes` is the first field.
    let attributes = buffer[0] as u32;
    #[cfg(test)]
    let forced = seams::forced_no_persistent_acls();
    #[cfg(not(test))]
    let forced = false;
    guard(
        attributes & FILE_PERSISTENT_ACLS != 0 && !forced,
        PERSISTENT_ACLS,
        "a volume with persistent ACLs",
        StorageError::UnsafeState,
    )?;

    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    // SAFETY: `device` is a writable FILE_FS_DEVICE_INFORMATION.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            dir.as_raw_handle() as HANDLE,
            &mut status_block,
            ptr::addr_of_mut!(device).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        return Err(fail("FileFsDeviceInformation", status));
    }
    let network = device.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB) != 0
        || device.DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM;
    #[cfg(test)]
    let network = network || seams::forced_nonlocal();
    guard(
        !network,
        LOCAL_FS,
        "a local volume",
        StorageError::UnsafeState,
    )
}

/// `FileBasicInformation.FileAttributes` of an open handle.
fn basic_attributes(handle: &File) -> Result<u32, StorageError> {
    // CreationTime, LastAccessTime, LastWriteTime, ChangeTime (i64 each),
    // then FileAttributes (u32), padded to 40 bytes.
    let mut buffer = [0u64; 5];
    query_information(handle, &mut buffer, FileBasicInformation)?;
    Ok(buffer[4] as u32)
}

struct Standard {
    end_of_file: i64,
    links: u32,
}

/// `FileStandardInformation` of an open handle: end of file and link count.
fn standard(handle: &File) -> Result<Standard, StorageError> {
    // AllocationSize, EndOfFile (i64 each), NumberOfLinks (u32),
    // DeletePending and Directory (one byte each), padded to 24 bytes.
    let mut buffer = [0u64; 3];
    query_information(handle, &mut buffer, FileStandardInformation)?;
    Ok(Standard {
        end_of_file: buffer[1] as i64,
        links: buffer[2] as u32,
    })
}

fn query_information(handle: &File, buffer: &mut [u64], class: i32) -> Result<(), StorageError> {
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buffer` is writable for its size and 8-aligned; the handle is
    // live and was opened with FILE_READ_ATTRIBUTES.
    let status = unsafe {
        NtQueryInformationFile(
            handle.as_raw_handle() as HANDLE,
            &mut status_block,
            buffer.as_mut_ptr().cast(),
            size_of_val(buffer) as u32,
            class,
        )
    };
    if status < 0 {
        return Err(fail("NtQueryInformationFile", status));
    }
    Ok(())
}

/// Opens an agent file for reading: `FILE_OPEN_REPARSE_POINT` (unless a test
/// bypasses it), not a directory, shared for delete so the resident's POSIX
/// rename can replace it while it is read. `Ok(None)` when absent.
fn open_agent_file(dir: &File, name: &str) -> Result<Option<File>, StorageError> {
    let name = file_name(name)?;
    let open = Open {
        access: GENERIC_READ,
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: FILE_OPTIONS | nofollow(),
    };
    match nt_create(Some(dir), &name, open, None) {
        Ok(file) => Ok(Some(file)),
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(None),
        Err(status) => Err(fail("open agent file", status)),
    }
}

fn acquire_lock(dir: &File, user: &Sid) -> Result<Lock, StorageError> {
    #[cfg(test)]
    let name = seams::lock_name()
        .map(|name| name.to_str().unwrap())
        .unwrap_or(LOCK_FILE);
    #[cfg(not(test))]
    let name = LOCK_FILE;
    let descriptor = Descriptor::owner_only(user, false)?;
    // Shared for read and write, so a second opener reaches `LockFileEx`
    // (and gets `Busy` there) instead of a sharing violation.
    let open = Open {
        access: GENERIC_READ | GENERIC_WRITE,
        share: FILE_SHARE_READ | FILE_SHARE_WRITE,
        disposition: FILE_OPEN_IF,
        options: FILE_OPTIONS | nofollow(),
    };
    let file = match nt_create(Some(dir), &wide(name), open, explicit(&descriptor)) {
        Ok(file) => file,
        Err(STATUS_SHARING_VIOLATION) => return Err(StorageError::Busy),
        Err(status) => return Err(fail("open owner.lock", status)),
    };
    check_private_file(&file, user, Links::One)?;
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the handle is live and synchronous; `overlapped` (offset 0)
    // outlives the call, which returns at once (`FAIL_IMMEDIATELY`).
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if locked != 0 {
        Ok(Lock(file))
    } else {
        let error = last_error();
        if error == ERROR_LOCK_VIOLATION as i32 {
            Err(StorageError::Busy)
        } else {
            Err(fail("LockFileEx", error))
        }
    }
}

/// The locked `owner.lock`. Dropping it unlocks, then closes the handle.
struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        let mut overlapped = OVERLAPPED::default();
        // SAFETY: the handle is live until the `File` field drops after
        // this; it holds the byte-0 lock this unlocks.
        unsafe { UnlockFileEx(self.0.as_raw_handle() as HANDLE, 0, 1, 0, &mut overlapped) };
    }
}

/// `FileRenameInformationEx` on `file`'s handle: `target` in `dir`,
/// replacing an existing file with POSIX semantics (the replaced file may
/// still be open elsewhere if it was opened with `FILE_SHARE_DELETE`).
fn rename_over(file: &File, dir: &File, target: &[u16]) -> Result<(), NTSTATUS> {
    let name_bytes = target.len() * 2;
    let total = (offset_of!(FILE_RENAME_INFORMATION, FileName) + name_bytes)
        .max(size_of::<FILE_RENAME_INFORMATION>());
    let mut buffer = vec![0u64; total.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buffer` is zeroed, 8-aligned and `total` bytes long, which
    // covers the header and `name_bytes` of name; the root handle is live.
    let status = unsafe {
        (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
        (*info).RootDirectory = dir.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            target.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            target.len(),
        );
        let mut status_block = IO_STATUS_BLOCK::default();
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut status_block,
            info.cast(),
            total as u32,
            FileRenameInformationEx,
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// Opens `name` below `dir` with `FILE_OPEN_REPARSE_POINT` (never followed)
/// as a non-directory and deletes it through that handle.
fn delete_at(dir: &File, name: &[u16]) -> Result<(), NTSTATUS> {
    let open = Open {
        access: DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: FILE_OPTIONS | FILE_OPEN_REPARSE_POINT,
    };
    dispose(&nt_create(Some(dir), name, open, None)?)
}

/// A POSIX-semantics delete through an open handle: the name disappears at
/// once, even while other handles (opened with `FILE_SHARE_DELETE`) are
/// open. A read-only attribute does not stop it, as it does not stop
/// `unlinkat`.
fn dispose(handle: &File) -> Result<(), NTSTATUS> {
    let info = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a valid local; the handle is live and has DELETE.
    let status = unsafe {
        NtSetInformationFile(
            handle.as_raw_handle() as HANDLE,
            &mut status_block,
            ptr::addr_of!(info).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// How many directory levels below the cleared directory
/// [`SecureRoot::clear_private_subdir`] descends before it gives up.
const CLEAR_DEPTH_MAX: usize = 32;

/// Removes every entry of `dir` (see [`SecureRoot::clear_private_subdir`]).
fn clear_dir(dir: &File, depth: usize) -> Result<(), StorageError> {
    for name in entry_names(dir, usize::MAX)? {
        let open = Open {
            access: DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: FILE_SYNCHRONOUS_IO_NONALERT | nofollow(),
        };
        let child =
            nt_create(Some(dir), &name, open, None).map_err(|s| fail("open entry to clear", s))?;
        let attributes = basic_attributes(&child)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            guard(
                depth < CLEAR_DEPTH_MAX,
                0,
                "clear depth",
                StorageError::UnsafeState,
            )?;
            clear_dir(&child, depth + 1)?;
        }
        dispose(&child).map_err(|s| fail("delete entry", s))?;
    }
    Ok(())
}

/// Every entry name of `dir` except `.` and `..`, read through a fresh
/// handle (`NtCreateFile` with an empty name relative to `dir`), so
/// concurrent listings never share an enumeration position. More than `cap`
/// names is `UnsafeState`.
// ponytail: clear_dir passes no cap; a same-UID process can make the list as
// large as it likes, and that UID can already delete the whole root.
fn entry_names(dir: &File, cap: usize) -> Result<Vec<Vec<u16>>, StorageError> {
    let open = Open {
        access: FILE_LIST_DIRECTORY | SYNCHRONIZE,
        share: SHARE_ALL,
        disposition: FILE_OPEN,
        options: DIR_OPTIONS,
    };
    let listing = nt_create(Some(dir), &[], open, None).map_err(|s| fail("reopen directory", s))?;
    let mut buffer = vec![0u64; 8_192];
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buffer` is writable for its size and 8-aligned; the handle
        // is live and synchronous, so the call completes before it returns.
        let status = unsafe {
            NtQueryDirectoryFile(
                listing.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut status_block,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                FileDirectoryInformation,
                false,
                ptr::null(),
                restart,
            )
        };
        restart = false;
        if status == STATUS_NO_MORE_FILES {
            return Ok(names);
        }
        if status < 0 {
            return Err(fail("NtQueryDirectoryFile", status));
        }
        let filled = status_block.Information.min(buffer.len() * 8);
        let base = buffer.as_ptr().cast::<u8>();
        let name_offset = offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
        let mut offset = 0usize;
        loop {
            if offset + name_offset > filled {
                return Err(fail("directory entry bounds", 0));
            }
            // SAFETY: `offset + name_offset <= filled`, inside the buffer;
            // fields are read unaligned.
            let entry = unsafe { base.add(offset) }.cast::<FILE_DIRECTORY_INFORMATION>();
            let (next, name_bytes) = unsafe {
                (
                    ptr::addr_of!((*entry).NextEntryOffset).read_unaligned() as usize,
                    ptr::addr_of!((*entry).FileNameLength).read_unaligned() as usize,
                )
            };
            if offset + name_offset + name_bytes > filled {
                return Err(fail("directory entry name bounds", 0));
            }
            // SAFETY: the name lies inside the filled part (checked above).
            let name: Vec<u16> = (0..name_bytes / 2)
                .map(|i| unsafe {
                    base.add(offset + name_offset + 2 * i)
                        .cast::<u16>()
                        .read_unaligned()
                })
                .collect();
            if name != [0x2e] && name != [0x2e, 0x2e] {
                if names.len() == cap {
                    return Err(fail("too many entries", 0));
                }
                names.push(name);
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// A path component of the suffix: not empty, `.` or `..`, no `\`, `/`, `:`
/// or NUL.
fn component_name(component: &str) -> Result<Vec<u16>, StorageError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains(['\\', '/', ':', '\0'])
    {
        return Err(StorageError::UnsafeState);
    }
    Ok(wide(component))
}

/// An agent-owned file name: `[a-z0-9._-]`, not starting with `.`.
fn file_name(name: &str) -> Result<Vec<u16>, StorageError> {
    let valid = !name.is_empty()
        && !name.starts_with('.')
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
    if valid {
        Ok(wide(name))
    } else {
        Err(StorageError::UnsafeState)
    }
}

fn temp_name(name: &str) -> Result<Vec<u16>, StorageError> {
    file_name(name)?;
    Ok(wide(&format!(".{name}.tmp")))
}

/// Windows guards with their negative controls (acceptance (6) of
/// `SA-2B1b` and W1 r1 (a)). A failing test prints the refusing guard or the
/// failing call with its status code (`guard`, `fail`), so a CI log names it.
#[cfg(test)]
mod tests {
    use std::{os::windows::fs::OpenOptionsExt, process::Command};

    use windows_sys::Win32::{
        Security::{AddAccessDeniedAceEx, CreateWellKnownSid, WinBuiltinUsersSid, WinWorldSid},
        Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
    };

    use super::*;
    use crate::secure_fs::{
        seams::{self, Reset},
        test_support::{SUFFIX, TempHome, retry_busy},
    };

    /// `S-1-5-32-545`, BUILTIN\Users: a SID other than the user, SYSTEM and
    /// Administrators, for `icacls` grants.
    const USERS: &str = "*S-1-5-32-545";

    fn open(home: &TempHome) -> Result<SecureRoot, StorageError> {
        retry_busy(|| open_once(home))
    }

    /// No retry: for the assertions that expect `Busy`.
    fn open_once(home: &TempHome) -> Result<SecureRoot, StorageError> {
        SecureRoot::open_under(&home.path, SUFFIX)
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

    /// Runs a fixture tool and fails the test with its output if it fails.
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

    /// A directory junction at `link` pointing at `target` (`mklink /J`).
    fn junction(link: &Path, target: &Path) {
        run(
            "cmd",
            &[
                "/c".as_ref(),
                "mklink".as_ref(),
                "/J".as_ref(),
                link.as_os_str(),
                target.as_os_str(),
            ],
        );
    }

    /// `icacls <path> <args…>`.
    fn icacls(path: &Path, args: &[&str]) {
        let mut all = vec![path.as_os_str()];
        all.extend(args.iter().map(std::ffi::OsStr::new));
        run("icacls", &all);
    }

    /// A file symlink (needs `SeCreateSymbolicLinkPrivilege`, which the
    /// elevated CI runner holds).
    fn file_symlink(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(target, link)
            .unwrap_or_else(|e| panic!("symlink_file {link:?} -> {target:?}: {e}"));
    }

    /// A second home whose agent root the agent itself created, holding a
    /// `state.json` of `decoy`: it passes every root and file check, so a
    /// bypassed guard admits an attack by landing there, not by a check
    /// failing.
    fn decoy_home() -> TempHome {
        let decoy = TempHome::new();
        write_state(&open(&decoy).unwrap(), b"decoy");
        decoy
    }

    fn is_link(path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }

    struct Summary {
        protected: bool,
        owner_is_user: bool,
        /// (ACE flags, names the user) per ACE.
        aces: Vec<(u8, bool)>,
    }

    /// The owner and DACL of `path`, read through a path-based test-only
    /// open (never following a reparse point).
    fn summary(path: &Path) -> Summary {
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let user = Sid::current().unwrap();
        let mut buffer = vec![0u64; 1_024];
        let mut needed = 0;
        let status = unsafe {
            NtQuerySecurityObject(
                file.as_raw_handle() as HANDLE,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                buffer.as_mut_ptr().cast(),
                8_192,
                &mut needed,
            )
        };
        assert!(status >= 0, "NtQuerySecurityObject {status:#x}");
        let sd: PSECURITY_DESCRIPTOR = buffer.as_mut_ptr().cast();
        let (mut owner, mut d) = (ptr::null_mut(), 0);
        let (mut control, mut revision) = (0u16, 0u32);
        let (mut present, mut dacl) = (0, ptr::null_mut::<ACL>());
        unsafe {
            assert_ne!(GetSecurityDescriptorOwner(sd, &mut owner, &mut d), 0);
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            assert_ne!(
                GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut d),
                0
            );
        }
        assert!(present != 0 && !dacl.is_null(), "{path:?}: no DACL");
        let aces = unsafe { read_aces(dacl) }.unwrap();
        Summary {
            protected: control & SE_DACL_PROTECTED != 0,
            owner_is_user: same_sid(owner, user.as_ptr()),
            aces: aces
                .iter()
                .map(|ace| (ace.flags, ace.known && same_sid(ace.sid, user.as_ptr())))
                .collect(),
        }
    }

    fn assert_owner_only(path: &Path, inheritable: bool) {
        let s = summary(path);
        assert!(s.protected, "{path:?}: DACL not protected");
        assert!(s.owner_is_user, "{path:?}: owner is not the user");
        let flags = if inheritable {
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
        } else {
            0
        };
        assert_eq!(s.aces, [(flags, true)], "{path:?}");
    }

    /// Every directory the agent creates, `state.json` and `owner.lock` carry
    /// the explicit descriptor from creation: owner the user, a protected
    /// DACL with one ACE for the user. Negative control: created without it
    /// (`EXPLICIT_SD`), the root inherits its parent's ACEs, is not
    /// protected, and the open fails closed.
    #[test]
    fn created_objects_carry_a_protected_owner_only_dacl() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        for depth in 1..=SUFFIX.len() {
            let path = SUFFIX[..depth]
                .iter()
                .fold(home.path.clone(), |p, c| p.join(c));
            assert_owner_only(&path, true);
        }
        for file in ["state.json", "owner.lock"] {
            assert_owner_only(&home.root().join(file), false);
        }
        assert_eq!(root.path(), home.root());

        let fresh = TempHome::new();
        let _reset = Reset;
        seams::bypass(seams::EXPLICIT_SD);
        assert_eq!(open(&fresh).err(), Some(StorageError::UnsafeState));
        seams::bypass(0);
        assert!(!summary(&fresh.root()).protected, "control: inherited");
    }

    /// An allow ACE giving BUILTIN\Users a write-type right on an
    /// intermediate directory fails closed; the same right inherit-only, or
    /// a read-only grant, does not.
    #[test]
    fn an_intermediate_granting_users_write_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let library = home.path.join(SUFFIX[0]);
        icacls(&library, &["/grant", &format!("{USERS}:(W)")]);
        fails_closed_only_by(INTERMEDIATE, StorageError::UnsafeState, || open(&home));

        let home = TempHome::new();
        drop(open(&home).unwrap());
        let library = home.path.join(SUFFIX[0]);
        icacls(&library, &["/grant", &format!("{USERS}:(OI)(CI)(IO)(W)")]);
        icacls(&library, &["/grant", &format!("{USERS}:(RX)")]);
        drop(open(&home).unwrap());
    }

    /// A NULL DACL (everyone, everything) on an intermediate directory fails
    /// closed. The fixture is real: `Library` is created with a descriptor
    /// whose DACL is present and NULL.
    #[test]
    fn a_null_dacl_fails_closed() {
        let home = TempHome::new();
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let sd: PSECURITY_DESCRIPTOR = ptr::addr_of_mut!(*descriptor).cast();
        unsafe {
            assert_ne!(
                InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION),
                0
            );
            assert_ne!(SetSecurityDescriptorDacl(sd, 1, ptr::null(), 0), 0);
        }
        let null_dacl = Descriptor {
            descriptor,
            _acl: Vec::new(),
            _user: &Sid::current().unwrap(),
        };
        let base = nt_create(None, &nt_path(&home.path).unwrap(), BASE_OPEN, None).unwrap();
        let open_if = Open {
            disposition: FILE_OPEN_IF,
            ..DIR_OPEN
        };
        drop(nt_create(Some(&base), &wide(SUFFIX[0]), open_if, Some(&null_dacl)).unwrap());
        fails_closed_only_by(DACL_PRESENT, StorageError::UnsafeState, || open(&home));
    }

    /// A root whose DACL inherits again (`icacls /inheritance:e`) is no
    /// longer protected (here it inherits only its parent's ACE for the
    /// user, so the protection check alone refuses it; extra SIDs are
    /// covered by the file and in-memory tests).
    #[test]
    fn an_unprotected_root_with_inherited_aces_fails_closed() {
        let home = TempHome::new();
        drop(open(&home).unwrap());
        icacls(&home.root(), &["/inheritance:e"]);
        assert!(!summary(&home.root()).protected);
        fails_closed_only_by(DACL, StorageError::UnsafeState, || open(&home));
    }

    #[test]
    fn a_state_file_with_another_sids_ace_fails_closed() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        write_state(&root, b"{}");
        assert_eq!(root.read_file("state.json", 64).unwrap().unwrap(), b"{}");
        icacls(
            &home.root().join("state.json"),
            &["/grant", &format!("{USERS}:(R)")],
        );
        fails_closed_only_by(DACL, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
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

    /// Ownership classification is injected: CI cannot create an object
    /// owned by another account. Covers the base, the intermediate (R-3),
    /// the root and a file.
    #[test]
    fn a_foreign_owner_anywhere_on_the_path_fails_closed() {
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

    /// Volume classification is injected: CI cannot mount a network volume
    /// or a volume without persistent ACLs.
    #[test]
    fn a_network_volume_fails_closed() {
        let home = TempHome::new();
        let _reset = Reset;
        seams::force_nonlocal(true);
        fails_closed_only_by(LOCAL_FS, StorageError::UnsafeState, || open(&home));
    }

    #[test]
    fn a_volume_without_persistent_acls_fails_closed() {
        let home = TempHome::new();
        let _reset = Reset;
        seams::force_no_persistent_acls(true);
        fails_closed_only_by(PERSISTENT_ACLS, StorageError::UnsafeState, || open(&home));
    }

    /// The agent root is a junction to another, valid agent root. Opened
    /// with `FILE_OPEN_REPARSE_POINT` it is refused; without (`NOFOLLOW`)
    /// the open lands in the decoy, proven by a write that appears there.
    #[test]
    fn a_junctioned_root_fails_closed() {
        let decoy = decoy_home();
        let home = TempHome::new();
        drop(open(&home).unwrap());
        std::fs::rename(home.root(), home.path.join("moved")).unwrap();
        junction(&home.root(), &decoy.root());
        let root = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || open(&home));
        write_state(&root, b"landed");
        assert_eq!(
            std::fs::read(decoy.root().join("state.json")).unwrap(),
            b"landed"
        );
    }

    /// A deterministic hook replaces the agent root with a junction to a
    /// valid decoy root just before the root is opened.
    #[test]
    fn a_junction_swap_between_components_fails_closed() {
        let decoy = decoy_home();
        let home = TempHome::new();
        drop(open(&home).unwrap());
        let (root, moved, target) = (home.root(), home.path.join("moved"), decoy.root());
        let _reset = Reset;
        seams::set_hook(Some(Box::new(move |step| {
            if step == Step::Descend(SUFFIX.len() - 1) && !is_link(&root) {
                std::fs::rename(&root, &moved).unwrap();
                junction(&root, &target);
            }
            Ok(())
        })));
        let opened = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            open_once(&home)
        });
        write_state(&opened, b"landed");
        assert_eq!(
            std::fs::read(decoy.root().join("state.json")).unwrap(),
            b"landed"
        );
    }

    /// A `state.json` that is a file symlink to a valid agent file elsewhere.
    #[test]
    fn a_symlinked_state_file_fails_closed() {
        let decoy = decoy_home();
        let home = TempHome::new();
        let root = open(&home).unwrap();
        file_symlink(
            &decoy.root().join("state.json"),
            &home.root().join("state.json"),
        );
        let bytes = fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            root.read_file("state.json", 64)
        });
        assert_eq!(bytes.unwrap(), b"decoy");
    }

    #[test]
    fn a_private_subdir_is_created_protected_and_reopened_as_found() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let path = root.private_subdir("source-cache").unwrap();
        assert_eq!(path, home.root().join("source-cache"));
        assert_owner_only(&path, true);
        assert_eq!(root.private_subdir("source-cache").unwrap(), path);
        // A path-based consumer's file inside inherits owner-only access.
        std::fs::write(path.join("engine-file"), b"x").unwrap();
        let inner = summary(&path.join("engine-file"));
        assert!(inner.aces.iter().all(|(_, user)| *user), "inherited ACEs");
        for name in ["", ".hidden", "a/b", "a\\b", "Upper", "a:b"] {
            assert_eq!(
                root.private_subdir(name),
                Err(StorageError::UnsafeState),
                "{name:?}"
            );
        }
        // Negative control: created without the explicit descriptor it
        // inherits the root's ACE unprotected, and is refused.
        let _reset = Reset;
        seams::bypass(seams::EXPLICIT_SD);
        assert_eq!(
            root.private_subdir("pricing"),
            Err(StorageError::UnsafeState)
        );
        seams::bypass(0);
        // Found as created there: checked as found, not repaired.
        assert_eq!(
            root.private_subdir("pricing"),
            Err(StorageError::UnsafeState)
        );
        icacls(
            &home.root().join("source-cache"),
            &["/grant", &format!("{USERS}:(R)")],
        );
        fails_closed_only_by(DACL, StorageError::UnsafeState, || {
            root.private_subdir("source-cache")
        });
    }

    #[test]
    fn a_junctioned_private_subdir_fails_closed() {
        let decoy = decoy_home();
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let link = home.root().join("pricing");
        junction(&link, &decoy.root());
        fails_closed_only_by(seams::NOFOLLOW, StorageError::UnsafeState, || {
            root.private_subdir("pricing")
        });
        assert!(is_link(&link), "the junction was not replaced or removed");
    }

    /// A decoy directory outside the root holding one file and one nested
    /// file.
    fn decoy_dir(home: &TempHome) -> PathBuf {
        let decoy = home.path.join("decoy");
        std::fs::create_dir_all(decoy.join("inner")).unwrap();
        std::fs::write(decoy.join("keep"), b"decoy").unwrap();
        std::fs::write(decoy.join("inner").join("keep"), b"decoy").unwrap();
        decoy
    }

    fn decoy_intact(decoy: &Path) -> bool {
        std::fs::read(decoy.join("keep")).ok().as_deref() == Some(b"decoy".as_slice())
            && std::fs::read(decoy.join("inner").join("keep"))
                .ok()
                .as_deref()
                == Some(b"decoy".as_slice())
    }

    /// W1 r1 (a): nested directories are emptied; a junction inside to a
    /// decoy outside the root is removed itself and never entered, so the
    /// decoy keeps every file. The cleared directory stays, protected.
    /// Absent is success.
    #[test]
    fn clear_private_subdir_removes_a_junction_and_never_enters_it() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        assert_eq!(root.clear_private_subdir("source-cache"), Ok(()));
        let path = root.private_subdir("source-cache").unwrap();
        let decoy = decoy_dir(&home);
        std::fs::create_dir_all(path.join("a").join("b").join("c")).unwrap();
        std::fs::write(path.join("a").join("b").join("c").join("session"), b"id").unwrap();
        std::fs::write(path.join("top"), b"id").unwrap();
        junction(&path.join("link-dir"), &decoy);
        junction(&path.join("a").join("link-deep"), &decoy);

        root.clear_private_subdir("source-cache").unwrap();
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        assert_owner_only(&path, true);
        assert!(decoy_intact(&decoy));
    }

    /// Negative control of the test above: with `NOFOLLOW` bypassed the
    /// clear enters the junction and empties the decoy.
    #[test]
    fn clear_private_subdir_enters_a_junction_only_without_nofollow() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let path = root.private_subdir("source-cache").unwrap();
        let decoy = decoy_dir(&home);
        junction(&path.join("link-dir"), &decoy);
        let _reset = Reset;
        seams::bypass(seams::NOFOLLOW);
        let _ = root.clear_private_subdir("source-cache");
        seams::bypass(0);
        assert!(!decoy_intact(&decoy));
    }

    /// `source-cache` itself a junction to a decoy is refused, the junction
    /// and the decoy untouched; so is one whose DACL names another SID.
    #[test]
    fn clear_private_subdir_refuses_a_junctioned_or_loose_directory() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let decoy = decoy_dir(&home);
        let link = home.root().join("source-cache");
        junction(&link, &decoy);
        assert_eq!(
            root.clear_private_subdir("source-cache"),
            Err(StorageError::UnsafeState)
        );
        assert!(is_link(&link));
        assert!(decoy_intact(&decoy));

        let path = root.private_subdir("pricing").unwrap();
        std::fs::write(path.join("keep"), b"x").unwrap();
        icacls(&path, &["/grant", &format!("{USERS}:(R)")]);
        fails_closed_only_by(DACL, StorageError::UnsafeState, || {
            root.clear_private_subdir("pricing")
        });
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
        assert_eq!(bytes.unwrap().len(), 65);
    }

    /// A second opener, in this process, gets `Busy` from `LockFileEx` even
    /// after replaces. Negative control: locking the replaced file instead of
    /// the stable lock file breaks the replace itself (the lock handle does
    /// not share delete, so the POSIX rename over it fails, `Unknown`).
    #[test]
    fn a_second_opener_cannot_take_the_lock_after_a_replace() {
        let home = TempHome::new();
        let first = open(&home).unwrap();
        write_state(&first, b"{\"a\":1}");
        write_state(&first, b"{\"a\":2}");
        assert_eq!(open_once(&home).err(), Some(StorageError::Busy));
        drop(first);
        drop(open(&home).unwrap());

        let _reset = Reset;
        seams::lock_name_override(Some(c"state.json"));
        let first = open(&home).unwrap();
        assert_eq!(open_once(&home).err(), Some(StorageError::Busy));
        assert_eq!(
            first.stage("state.json", b"{\"a\":3}").unwrap().publish(),
            Err(StorageError::Unknown)
        );
    }

    /// Only the exact `.state.json.tmp` is removed; a file symlink of that
    /// name is removed itself and its target kept.
    #[test]
    fn stale_temp_cleanup_removes_only_the_exact_name_and_never_follows() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let outside = home.path.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        file_symlink(&outside, &home.root().join(".state.json.tmp"));
        std::fs::write(home.root().join(".other.tmp"), b"keep").unwrap();
        root.remove_stale_temp("state.json").unwrap();
        assert!(std::fs::symlink_metadata(home.root().join(".state.json.tmp")).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(home.root().join(".other.tmp").exists());
        root.remove_stale_temp("state.json").unwrap();
    }

    const CACHED: &str = "pcache-00";

    fn write_cached(root: &SecureRoot, name: &str, bytes: &[u8]) {
        root.stage(name, bytes).unwrap().publish().unwrap();
    }

    #[test]
    fn read_file_sized_allocates_size_plus_one_and_never_grows() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let bytes = vec![b'x'; 4_097];
        write_cached(&root, CACHED, &bytes);
        let read = root.read_file_sized(CACHED, 4_097).unwrap().unwrap();
        assert_eq!(read, bytes);
        assert!(read.capacity() <= 4_098, "{}", read.capacity());
        let grown = root.read_file(CACHED, 4_097).unwrap().unwrap();
        assert!(grown.capacity() > 4_098, "{}", grown.capacity());
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
    /// with the entry untouched; bypassing only the named guard admits it.
    #[test]
    fn list_fails_closed_on_a_junction_hard_link_loose_dacl_or_foreign_entry() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
        let entry = home.root().join(CACHED);

        // A junction (a directory reparse point): refused, never followed.
        let decoy = decoy_dir(&home);
        junction(&entry, &decoy);
        assert_eq!(root.list("pcache-"), Err(StorageError::UnsafeState));
        assert!(is_link(&entry) && decoy_intact(&decoy));
        std::fs::remove_dir(&entry).unwrap();

        // A second name of a valid agent file.
        write_state(&root, b"{}");
        std::fs::hard_link(home.root().join("state.json"), &entry).unwrap();
        let listed =
            fails_closed_only_by(NLINK, StorageError::UnsafeState, || root.list("pcache-"));
        assert_eq!(listed, [(CACHED.to_owned(), 2)]);
        std::fs::remove_file(&entry).unwrap();

        write_cached(&root, CACHED, b"p");
        icacls(&entry, &["/grant", &format!("{USERS}:(R)")]);
        fails_closed_only_by(DACL, StorageError::UnsafeState, || root.list("pcache-"));
        root.remove_file(CACHED).unwrap();

        write_cached(&root, CACHED, b"p");
        let _reset = Reset;
        seams::force_foreign(seams::FILE);
        fails_closed_only_by(OWNER, StorageError::UnsafeState, || root.list("pcache-"));
        seams::force_foreign(0);

        // Entries without the prefix are not checked.
        junction(&home.root().join("rcache-00"), &decoy);
        assert_eq!(root.list("pcache-").unwrap(), [(CACHED.to_owned(), 1)]);
    }

    #[test]
    fn list_fails_closed_past_4096_entries() {
        let home = TempHome::new();
        let root = open(&home).unwrap();
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
        file_symlink(&outside, &entry);
        root.remove_file(CACHED).unwrap();
        assert!(std::fs::symlink_metadata(&entry).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        root.remove_file(CACHED).unwrap();
        assert_eq!(
            root.remove_file("..\\outside"),
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
        file_symlink(&outside, &dir.join(".pcache-00.tmp"));
        std::fs::write(dir.join(".pcache-01.tmp"), b"x").unwrap();
        for keep in [".rcache-00.tmp", ".state.json.tmp", ".pcache-00.tmpx"] {
            std::fs::write(dir.join(keep), b"x").unwrap();
        }
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

    /// The read-only open applies the open checks without creating or
    /// locking anything: absent is `None`, a junctioned root is refused, and
    /// a read works while the resident holds the lock.
    #[test]
    fn open_read_only_checks_without_creating_or_locking() {
        let home = TempHome::new();
        assert!(
            SecureRoot::open_read_only(&home.path, SUFFIX)
                .unwrap()
                .is_none()
        );
        assert!(!home.path.join(SUFFIX[0]).exists(), "created nothing");
        let root = open(&home).unwrap();
        write_state(&root, b"held");
        let read_only = SecureRoot::open_read_only(&home.path, SUFFIX)
            .unwrap()
            .unwrap();
        assert_eq!(
            read_only.read_file("state.json", 16).unwrap().unwrap(),
            b"held"
        );
        drop(read_only);
        drop(root);

        let decoy = decoy_home();
        std::fs::rename(home.root(), home.path.join("moved")).unwrap();
        junction(&home.root(), &decoy.root());
        let _reset = Reset;
        let attack = || SecureRoot::open_read_only(&home.path, SUFFIX).map(|r| r.is_some());
        assert_eq!(attack().err(), Some(StorageError::UnsafeState));
        seams::bypass(seams::NOFOLLOW);
        assert_eq!(attack(), Ok(true));
    }

    /// The resident replaces `state.json` by a POSIX rename between the
    /// read-only open and its check. The opened, now deleted file is read
    /// whole with the old bytes; a file with 2 links is refused.
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
        let links = standard(&opened).unwrap().links;
        eprintln!("links of the replaced, still open file: {links}");
        assert_eq!(read_opened(&opened, 16, &read_only.user).unwrap(), b"old");
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

    #[test]
    fn agent_file_names_and_components_are_restricted() {
        for bad in [
            "",
            ".state.json",
            "../x",
            "a/b",
            "a\\b",
            "State.json",
            "a b",
            "a:b",
        ] {
            assert!(file_name(bad).is_err(), "{bad:?}");
        }
        assert!(file_name("state.json").is_ok());
        for bad in ["", ".", "..", "a/b", "a\\b", "a:b", "a\0b"] {
            assert!(component_name(bad).is_err(), "{bad:?}");
        }
        assert!(component_name("Syrtis Agent").is_ok());
    }

    /// Only absolute drive paths become NT paths; UNC, `\\?\UNC`, device,
    /// relative, drive-relative and `..` paths fail closed.
    #[test]
    fn only_absolute_drive_paths_become_nt_paths() {
        let nt = |p: &str| nt_path(Path::new(p)).map(|w| String::from_utf16(&w).unwrap());
        assert_eq!(
            nt(r"C:\Users\a\AppData\Local").unwrap(),
            r"\??\C:\Users\a\AppData\Local"
        );
        assert_eq!(nt(r"\\?\D:\x").unwrap(), r"\??\D:\x");
        assert_eq!(nt(r"C:\").unwrap(), r"\??\C:\");
        for bad in [
            r"\\server\share\x",
            r"\\?\UNC\server\share\x",
            r"\\.\C:\x",
            r"relative\x",
            r"C:relative",
            r"\rooted",
            r"C:\a\..\b",
            r"\\?\C:\a/b",
            r"C:\a\b:stream",
        ] {
            assert_eq!(nt(bad).err(), Some(StorageError::UnsafeState), "{bad}");
        }
    }

    #[test]
    fn the_trusted_home_is_a_drive_path_and_the_root_its_frozen_suffix() {
        let home = trusted_home().unwrap();
        assert!(nt_path(&home).is_ok(), "{home:?}");
        assert_eq!(
            default_root_path().unwrap(),
            home.join("Nyanako").join("Syrtis Agent")
        );
    }

    /// A SID buffer for a well-known SID.
    fn well_known(kind: i32) -> Vec<u64> {
        let mut sid = vec![0u64; 9];
        let mut size = 72u32;
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size)
        };
        assert_ne!(ok, 0);
        sid
    }

    /// An in-memory absolute descriptor: `owner`, and `aces` as
    /// (deny?, flags, mask, sid) in order; `protected` sets
    /// `SE_DACL_PROTECTED`. `retype` overwrites the type byte of one ACE.
    fn in_memory(
        owner: PSID,
        aces: &[(bool, u32, u32, PSID)],
        protected: bool,
        retype: Option<(u32, u8)>,
    ) -> (Box<SECURITY_DESCRIPTOR>, Vec<u64>) {
        let mut acl = vec![0u64; 256];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let sd: PSECURITY_DESCRIPTOR = ptr::addr_of_mut!(*descriptor).cast();
        unsafe {
            assert_ne!(InitializeAcl(acl_ptr, 2_048, ACL_REVISION), 0);
            for &(deny, flags, mask, sid) in aces {
                let ok = if deny {
                    AddAccessDeniedAceEx(acl_ptr, ACL_REVISION, flags, mask, sid)
                } else {
                    AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, mask, sid)
                };
                assert_ne!(ok, 0);
            }
            if let Some((index, kind)) = retype {
                let mut ace = ptr::null_mut();
                assert_ne!(GetAce(acl_ptr, index, &mut ace), 0);
                (*ace.cast::<ACE_HEADER>()).AceType = kind;
            }
            assert_ne!(
                InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION),
                0
            );
            assert_ne!(SetSecurityDescriptorOwner(sd, owner, 0), 0);
            assert_ne!(SetSecurityDescriptorDacl(sd, 1, acl_ptr, 0), 0);
            if protected {
                assert_ne!(
                    SetSecurityDescriptorControl(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED),
                    0
                );
            }
        }
        (descriptor, acl)
    }

    /// The owner and DACL rules on in-memory descriptors, each refusal
    /// next to the closest accepted shape: ACE types (contract (c)), the
    /// write-type rule and inherit-only exemption (d), the protected
    /// user-only rule (e), owner sets, a NULL DACL (b).
    #[test]
    fn in_memory_descriptors_follow_the_owner_and_dacl_rules() {
        let user = Sid::current().unwrap();
        let u = user.as_ptr();
        let system = well_known(WinLocalSystemSid);
        let admins = well_known(WinBuiltinAdministratorsSid);
        let users = well_known(WinBuiltinUsersSid);
        let world = well_known(WinWorldSid);
        let (system, admins, users, world): (PSID, PSID, PSID, PSID) = (
            system.as_ptr().cast_mut().cast(),
            admins.as_ptr().cast_mut().cast(),
            users.as_ptr().cast_mut().cast(),
            world.as_ptr().cast_mut().cast(),
        );
        let all = FILE_ALL_ACCESS;
        let check = |owner, aces: &[(bool, u32, u32, PSID)], protected, retype, object| {
            let (mut sd, _acl) = in_memory(owner, aces, protected, retype);
            check_descriptor(ptr::addr_of_mut!(*sd).cast(), object, &user)
        };
        let ok = Ok(());
        let unsafe_state = Err(StorageError::UnsafeState);
        // Root and file: protected, user-only, user-owned.
        for object in [Object::Root, Object::File] {
            assert_eq!(check(u, &[(false, 0, all, u)], true, None, object), ok);
            assert_eq!(
                check(u, &[(false, 0, all, u)], false, None, object),
                unsafe_state
            );
            let extra = [(false, 0, all, u), (false, 0, 1, users)];
            assert_eq!(check(u, &extra, true, None, object), unsafe_state);
            let deny = [(true, 0, all, world), (false, 0, all, u)];
            assert_eq!(check(u, &deny, true, None, object), unsafe_state);
            assert_eq!(
                check(admins, &[(false, 0, all, u)], true, None, object),
                unsafe_state
            );
            let callback = Some((0, 9));
            assert_eq!(
                check(u, &[(false, 0, all, u)], true, callback, object),
                unsafe_state
            );
        }
        // Base and intermediate.
        for object in [Object::Home, Object::Intermediate] {
            let stock = [
                (false, 0, all, system),
                (false, 0, all, admins),
                (false, 0, all, u),
            ];
            for owner in [u, system, admins] {
                assert_eq!(check(owner, &stock, false, None, object), ok);
            }
            assert_eq!(check(users, &stock, false, None, object), unsafe_state);
            let read = [(false, 0, 0x0012_00a9, users)];
            assert_eq!(check(u, &read, false, None, object), ok);
            for right in [
                FILE_ADD_FILE,
                FILE_ADD_SUBDIRECTORY,
                FILE_DELETE_CHILD,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
                GENERIC_WRITE,
                GENERIC_ALL,
            ] {
                let write = [(false, 0, right, users)];
                assert_eq!(
                    check(u, &write, false, None, object),
                    unsafe_state,
                    "{right:#x}"
                );
                let inherit_only = [(false, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, right, users)];
                assert_eq!(
                    check(u, &inherit_only, false, None, object),
                    ok,
                    "{right:#x}"
                );
                let denied = [(true, 0, right, users)];
                assert_eq!(check(u, &denied, false, None, object), ok, "{right:#x}");
            }
            for kind in [2u8, 5, 9, 0x11] {
                assert_eq!(
                    check(u, &[(false, 0, all, u)], false, Some((0, kind)), object),
                    unsafe_state,
                    "type {kind}"
                );
            }
        }
        // A NULL DACL fails every object.
        for object in [
            Object::Home,
            Object::Intermediate,
            Object::Root,
            Object::File,
        ] {
            let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
            let sd: PSECURITY_DESCRIPTOR = ptr::addr_of_mut!(*descriptor).cast();
            unsafe {
                assert_ne!(
                    InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION),
                    0
                );
                assert_ne!(SetSecurityDescriptorOwner(sd, u, 0), 0);
                assert_ne!(SetSecurityDescriptorDacl(sd, 1, ptr::null(), 0), 0);
            }
            assert_eq!(
                check_descriptor(sd, object, &user),
                unsafe_state,
                "{object:?}"
            );
        }
    }
}
