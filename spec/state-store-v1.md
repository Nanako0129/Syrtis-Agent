# Syrtis Agent State Store v1

## Purpose and boundary

This document fixes how the agent's durable state is stored: where, in what bytes, how it is validated on load, and how it is replaced. It does not define keys. The state key set is frozen by `spec/v1.md` (rows "State top level" through "Terminal state record") and this store adds none. Implementation: `src/state_store.rs` and `src/secure_fs/`.

> v1 makes no confidentiality claim against the same UID, root, or Administrator. Owner-only modes, no-follow opens, an exclusive lock and atomic replace protect against other local UIDs and against partial writes, not against the owner.

## Root

| Platform | Trusted home | Root below the home |
|---|---|---|
| macOS | `getpwuid_r(geteuid())` `pw_dir` (directory service) | `Library/Application Support/com.nyanako.syrtis.agent` |
| Linux | `getpwuid_r(geteuid())` `pw_dir` | `.local/state/syrtis-agent` |
| Windows | Current-token LocalAppData known folder (`SHGetKnownFolderPath(FOLDERID_LocalAppData)` with the process token) | `Nyanako\Syrtis Agent` |
| Every other platform | none | none: fails closed with `unsafeState` (below) |

macOS and Linux: `HOME`, `XDG_*` and every other environment variable are ignored, and a home that is not absolute (`/`, not `//`) fails closed. Windows: see "Windows" below; `LOCALAPPDATA` is ignored, but no claim is made for every environment variable.

The paragraphs and the object table below, up to "Files in the root", describe macOS and Linux. Windows has its own section.

The home is opened by path and checked on the descriptor. Every component below it is opened with `openat(parent, name, O_DIRECTORY | O_NOFOLLOW)`; a missing component is created with `mkdirat(…, 0700)`, reopened the same way, set to exactly `0700` with `fchmod` on the new descriptor (the `mkdirat` mode is filtered by the process umask), has its extended ACL cleared on macOS, and then its parent directory is synced (`F_FULLFSYNC` on macOS, `fsync` on Linux) so the new entry is durable. Nothing is ever reopened by pathname after a check.

**Root parent sync.** Every open whose agent root passes the root's own checks (the "Agent root" row of the table below: owner, mode, no extended ACL, local filesystem) syncs the root's parent directory, whether the root was created in this call or found, so a root that an earlier run created but crashed before syncing is durable before any commit lands in it. The sync runs after those checks and before the backup-exclusion attribute (set on macOS only; Linux has no such step), the `owner.lock` checks and the lock: a root that fails its own checks (for example one on a non-local filesystem) never triggers the sync, while an open that then fails on `owner.lock` or gets `busy` has already synced. Creating the root syncs its parent once, not twice. A failure of this sync is `unsafeState` (nothing was committed, so the store does not become sticky unknown). Only the root's parent is synced on every open: an intermediate directory the agent created is synced once, right after its `mkdirat`, so a crash between that `mkdirat` and its sync, followed by a later open that finds the directory and a power loss, can lose it on ext4. That affects availability only (the root is then missing and is created again), not confidentiality.

**Created versus found.** Whether an object is `fchmod`-ed and has its ACL cleared is decided by name: a directory whose `mkdirat` succeeded in this call, `owner.lock` whose `O_CREAT|O_EXCL` open succeeded, and the commit temp file. Only a directory is reopened by name afterwards (`mkdirat` returns no descriptor), so another process of the same UID can substitute a directory in between; a substitute owned by another UID is stopped because `fchmod` on it fails with `EPERM`, which fails closed (inferred from `fchmod(2)`; a second UID cannot be created in a test). `owner.lock` and the temp file keep the descriptor their `O_EXCL` open returned, so nothing can be substituted for them. An object that already existed is checked exactly as found, and if it fails a rule it fails closed and is left in place for manual repair. A restrictive umask (for example `0277`) therefore cannot make the root unopenable.

**Interrupted creation.** Objects are created with mode `0700` (directories) or `0600` (files), filtered by the umask. A crash between creating an object and its `fchmod` or ACL clearing, or a lost first-start race against a process that has not done them yet, leaves an object that the next open checks as found:

- With a umask that clears no owner bit (for example `022` or `077`) and no inherited ACL, the object already has its exact mode and no ACL, so the next open accepts it (inferred from the create modes; not reproduced by a test).
- It may fail closed in these cases, the ones found by reading the code (not proven exhaustive):
  - a umask that clears owner bits. Measured only in the test's temp-home layout (`Library`/`AppSupport`/`agent` below an empty temp home, the same on macOS and Linux): under umask `0277`, an open that skips `fchmod` fails closed. When directory permissions are enforced (that is, not root or `CAP_DAC_OVERRIDE`), it fails at the first directory created below the un-`fchmod`-ed intermediate: `Library` is left `0500`, so creating the next component fails, and the root is never created (asserted by the negative-control branch of `a_restrictive_umask_still_yields_exact_modes`). For root or `CAP_DAC_OVERRIDE` the root is inferred, not measured, to be created `0500` and then refused at the exact-`0700` check. The test's permission-bypassed branch asserts exactly that (the root exists with mode `0500`), but that branch has never run: GitHub-hosted CI (macOS and Linux) is measured to take the enforced branch: under GitHub Actions the bypassed branch fails the test, and the test passed there (CI runs 43009041944 at `1c32ef8` and 43016382735 at `fe1af3b`, the latter's macOS and Linux logs showing the test `ok` and no `SKIPPED`). The maintainer's Mac also takes the enforced branch: the full suite passes there with `GITHUB_ACTIONS=true`, where taking the bypassed branch would fail the test. If the bypassed branch is taken under `GITHUB_ACTIONS` (any value, no exception), the test fails; outside GitHub Actions it prints `SKIPPED` and passes. Real homes differ and neither real layout was measured: on Linux `.local` usually already exists, so the first component the agent creates comes later in the path, and the real macOS suffix (`Library/Application Support/com.nyanako.syrtis.agent`) is not the test suffix either. Separately, a found root whose mode is not exactly `0700` is refused (measured with `0750`). A found `owner.lock` whose mode lacks owner read or write (for example the `0400` that umask `0277` leaves) is refused earlier, at its `O_RDWR` `openat`, which fails with `EACCES` for a non-root process (inferred from `open(2)`; not reproduced by a test). For root or a process with `CAP_DAC_OVERRIDE` that open succeeds, and the file check refuses the mode instead (inferred). A found `owner.lock` that the owner can read and write but whose mode is not exactly `0600` (for example `0644`) is refused by the same file check as `state.json` (measured for `state.json` with `0644`);
  - an inherited ACL that the object's own check refuses: any entry on the root or `owner.lock` (measured for the root: a root whose inherited ACL is not cleared is refused), or an entry that is not a deny on an agent-created intermediate directory (refused by the intermediate ACL rule; inferred, no crash-between-steps test).

  After a crash such an object needs manual repair, because the agent never fixes an object it did not just create. In a first-start race the loser's `unsafeState` is transient: once the winner has finished, a retry succeeds (inferred).

| Object | Required on the open descriptor |
|---|---|
| Home | Owner is the effective UID, not group- or other-writable (`0755` is accepted; the same rule as sshd `StrictModes`), and on macOS any extended ACL is deny-only (below) |
| Intermediate directory | Directory, owner is the effective UID, not group- or other-writable (`0755` is accepted), and on macOS any extended ACL is deny-only (below) |
| Agent root | Directory, owner is the effective UID, mode exactly `0700`, local filesystem, no extended ACL entry (macOS) |
| Agent file (`state.json`, `owner.lock`) | Regular file, owner is the effective UID, mode exactly `0600`, link count 1, opened `O_NOFOLLOW`, no extended ACL entry (macOS) |

**macOS ACLs.** An extended ACL grants or denies access whatever the mode says, and an inheritable entry on a parent is copied onto every new directory or file below it. The agent therefore replaces the extended ACL with an empty one (`acl_init(0)` + `acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED)`) on every directory it creates (each intermediate and the root), on `owner.lock` and on the commit temp file, right after creating each and before any secret byte is written.

- The root, `state.json` and `owner.lock` must carry no extended ACL entry at all (`acl_get_fd_np` + `acl_get_entry(ACL_FIRST_ENTRY)`).
- The home and every intermediate directory pass only if they carry no extended ACL, or if every entry's tag is `ACL_EXTENDED_DENY`. A stock account's `~`, `~/Library` and `~/Library/Application Support` carry only `everyone deny delete`, which passes. Every entry is read, `acl_get_entry(ACL_FIRST_ENTRY)` and then `ACL_NEXT_ENTRY`, up to `ACL_MAX_ENTRIES` (128); an `ACL_EXTENDED_ALLOW` entry (for example `everyone allow add_subdirectory,delete_child`, which would let another UID replace the next component), an `ACL_UNDEFINED_TAG` or unknown tag, a tag `acl_get_tag_type` cannot read, or more than 128 entries fails closed. A deny entry followed by an allow entry fails closed: the walk does not stop at the first entry.
- When `acl_get_entry` returns −1, errno is read immediately, before `acl_free`. Only `EINVAL` means "no more entries"; any other errno counts as an entry that may grant access, and fails closed. An ACL that `acl_get_fd_np` cannot read (any errno except `ENOENT`) also counts as present. errno is cleared before both `acl_get_fd_np` and every `acl_get_entry`, so an `ENOENT` or `EINVAL` left by an earlier call can never read as "no ACL" or "no more entries".
- An ACL on an object the agent did not just create fails closed and is not stripped.

**Linux** needs no ACL handling: with the mode exactly `0700`/`0600`, the POSIX ACL mask is zero, so no named entry can grant group or other access (per `acl(5)`; not tested).

Local filesystem: macOS requires `MNT_LOCAL` in `fstatfs` `f_flags`. Linux requires `fstatfs` `f_type` to be one of ext2/3/4 (`0xEF53`), XFS (`0x58465342`), Btrfs (`0x9123683E`) or tmpfs (`0x01021994`).

**Not observable in CI:** a foreign owner and a network filesystem cannot be created on a CI runner. Both classifications pass through a test-only seam that forces the result; the tests prove the guard refuses the forced result, not that the OS classifies a real foreign or network object the same way.

On macOS every open sets the extended attribute `com.apple.metadata:com_apple_backup_excludeItem` on the root to the binary plist string `com.apple.backupd` (the 61 bytes `tmutil addexclusion` writes); failure to set it fails closed. Tests prove the attribute is present; whether Time Machine honours it is not observable in CI.

Any failure of a rule above leaves listener, control endpoint and report serving off. Only bounded repair diagnostics are allowed.

## Files in the root

| Name | Purpose |
|---|---|
| `owner.lock` | Owner lock. Stable; never replaced; `flock(LOCK_EX \| LOCK_NB)` (Windows: `LockFileEx`, see "Windows"). |
| `state.json` | The durable state. |
| `.state.json.tmp` | Commit temp file. Present only during a commit or after a crash. |
| `pcache-<64 hex>`, `rcache-<64 hex>` and their `.…tmp` | Producer and receiver cache entries (`spec/cache-store-v1.md`). |

The lock is taken on `owner.lock`, never on `state.json`: a lock on a file that is replaced is lost at the first replace. It is held for the life of the open root and released when the descriptor closes, including on process exit. A second opener gets `busy`. All commit APIs are reachable only through an open root, so a commit without the lock cannot be expressed.

### Cache primitives

Four more root operations serve the cache store (`spec/cache-store-v1.md`). Each runs on the root descriptor, never by pathname, and takes names through the same agent-file name rule as `state.json` (`[a-z0-9._-]`, not starting with `.`; no path separator).

| Operation | Rule |
|---|---|
| `read_file_sized(name, size)` | The checks of the "Agent file" row above, on the descriptor of a no-follow `openat`. Then one buffer of exactly `size + 1` bytes is allocated (`try_reserve_exact`; failure is `unavailable`) and filled until end of file or `size + 1` bytes; it never grows, so its capacity is the `size + 1` the caller reserved (measured: a 4,097-byte file reads into a capacity of at most 4,098, where the growing `read_file` reaches more). More than `size` bytes is `corrupt`. Absent is `None`. The existing `read_file` is unchanged |
| `list(prefix)` | `prefix` must be `pcache-` or `rcache-`; anything else, the empty string included, is `refused(invalid)`. Reads the root's entries through a fresh descriptor (`openat(root, ".")` and `fdopendir`), so two listings never share a directory offset. Every entry whose name starts with `prefix` is checked with `fstatat(…, AT_SYMLINK_NOFOLLOW)`: a regular file, owner the effective UID, mode exactly `0600`, link count 1, and a valid agent-file name. One entry failing any of them makes the whole call `unsafeState`; nothing is opened, followed or removed. Entries without the prefix are not checked, only counted: more than 4,096 entries (not counting `.` and `..`) is `unsafeState`. Temp files start with `.`, so they never carry the prefix. Returns names and sizes, sorted by name. No ACL check here: the read that follows (`read_file_sized`) checks it on macOS |
| `remove_file(name)` | `unlinkat(root, name, 0)`, which removes a link and never follows it, then a directory sync. An absent file is success. Either step failing is `unknown`. Both run through the commit shim (`Unlink`, then `SyncDir`), so tests can fail each |
| `remove_stale_temps(prefix)` | `prefix` as for `list`. Removes every entry named `.<prefix>….tmp` with `unlinkat` (never follows); `ENOENT` is ignored and any other failure is `unsafeState`. Only crash leftovers of that role's writes match |

## Windows

Implementation: `src/secure_fs/windows.rs` (`windows-sys` 0.61.2, below). Every rule here is enforced on an open handle; no Windows code path opens anything below the base by name, and none uses path-based `CreateFileW`, `MoveFileExW` or `ReplaceFileW`.

### Base and descent

| Step | Rule |
|---|---|
| Base | `trusted_home()` is the LocalAppData known folder of the process token. `open_under(home, suffix)` accepts only an absolute drive path (`X:\…` or `\\?\X:\…`); UNC, `\\?\UNC\…`, device, relative and drive-relative paths, `..`, and components holding `/`, `:` or NUL fail closed before anything is opened. The base is opened by its NT path (`\??\X:\…`) with `NtCreateFile` and **follows** reparse points (a user who moved AppData with a junction keeps working), the same as the Unix home opened by path. Path components above the base are trusted as a path, as on Unix |
| Below the base | Every component is opened with `NtCreateFile` relative to its parent's handle (`OBJECT_ATTRIBUTES.RootDirectory`), one constant name per call, `OBJ_CASE_INSENSITIVE`, never `OBJ_INHERIT`, with `FILE_OPEN_REPARSE_POINT`, so a junction or symlink is opened itself; its handle must then not carry `FILE_ATTRIBUTE_REPARSE_POINT`. The agent root and private subdirectories are opened with `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE` (the I/O manager opens the parent during a rename below it; inferred); intermediate directories without `FILE_SHARE_DELETE`, and held (W4, below). A missing component is created by the same call (`FILE_OPEN_IF`) with the explicit descriptor below |
| Suffix components | Not empty, `.` or `..`; no `\`, `/`, `:` or NUL |
| Agent file names | The rule above (`[a-z0-9._-]`, not starting with `.`) |

### Owner and DACL

Every object the agent creates (each directory of the suffix, a private subdirectory, `owner.lock`, every temp file) gets an explicit security descriptor in the creating `NtCreateFile` call (`OBJECT_ATTRIBUTES.SecurityDescriptor`): owner = the current user's SID (from `TokenUser`), a DACL with `SE_DACL_PROTECTED` and one allow ACE, `FILE_ALL_ACCESS` for the current user (on directories with `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, so a file a path-based consumer creates inside a private subdirectory inherits owner-only access). Nothing is changed after creation; an object that already exists is checked as found and, if it fails, left in place for manual repair.

| Object | Required on the handle (`NtQuerySecurityObject`, `FileBasicInformation`, `FileStandardInformation`) |
|---|---|
| Every object | A DACL is present and not NULL (`SE_DACL_PRESENT`; a NULL DACL grants everyone everything). Every ACE is `ACCESS_ALLOWED_ACE_TYPE` or `ACCESS_DENIED_ACE_TYPE`; a callback, object, audit or unknown ACE type fails closed |
| Base | Directory. Owner is the current user, SYSTEM (`S-1-5-18`) or Administrators (`S-1-5-32-544`). Other SIDs **may** hold write-type rights (W4, below). Not checked for being a reparse point (the base may be reached through a junction). On the base the owner, ACE-type and NULL-DACL checks are sanity checks, not security properties: with another account allowed to write there they protect nothing; they are kept only so W4 changes no more behaviour than it needs |
| Intermediate (`Nyanako`) | Directory, not a reparse point. Owner is the current user, SYSTEM (`S-1-5-18`) or Administrators (`S-1-5-32-544`). No allow ACE that is not `INHERIT_ONLY_ACE` grants any of `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL` to any other SID (inherit-only ACEs do not count: the agent's children carry explicit descriptors). Deny ACEs are allowed |
| Agent root, private subdirectory | Directory, not a reparse point. Owner is the current user. `SE_DACL_PROTECTED` is set and every ACE names the current user |
| Agent file (`state.json`, `owner.lock`, cache entries) | Not a directory and not a reparse point. Owner, protection and ACEs as for the root. `NumberOfLinks == 1` |

The base and the agent root must also be on a volume whose `FileFsAttributeInformation` has `FILE_PERSISTENT_ACLS` (a file system that keeps no security descriptors fails closed), and that `FileFsDeviceInformation` does not classify as network: `Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB)` or `DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM` fails closed.

The CI runner is elevated, so the default owner of objects it creates is Administrators; the explicit descriptor is what makes the agent's own objects owned by the user.

### Commit, delete and lock

```text
NtCreateFile(root, ".<name>.tmp", GENERIC_WRITE|DELETE, share 0, FILE_CREATE,
             FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_REPARSE_POINT,
             explicit descriptor)
write (all bytes)
FlushFileBuffers(temp handle)
                   -- store takes its exclusive guard --
NtSetInformationFile(temp handle, FileRenameInformationEx,
                     REPLACE_IF_EXISTS|POSIX_SEMANTICS, RootDirectory = root, "<name>")
FlushFileBuffers(the same, now renamed, handle)    -- shim step SyncDir
                   -- in-memory state replaced, guard released --
```

- The rename runs on the temp file's own handle; nothing is reopened by name. `FILE_CREATE` fails if any entry of the temp name exists, a reparse point included.
- **There is no directory sync on Windows.** The flush after the rename runs through the same shim step as the Unix directory sync (`SyncDir`), and its failure makes the store sticky unknown like any commit failure. Whether the rename itself survives power loss is the file system's (not observable in CI, as on Unix).
- Deletes (`remove_file`, `remove_stale_temp`, `remove_stale_temps`, and every entry of `clear_private_subdir`) open the entry with `FILE_OPEN_REPARSE_POINT` relative to its parent's handle and delete through that handle (`FileDispositionInformationEx`, `DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE`): a reparse point is removed itself, never followed. `remove_file` runs the delete as shim step `Unlink`; its `SyncDir` step does nothing on Windows. `clear_private_subdir` classifies each entry on its own handle: a reparse point (junction, symlink or other) is deleted and never entered, a directory is emptied (at most 32 levels) and deleted, anything else is deleted.
- `list` and the cache primitives keep the rules of "Cache primitives" above, with the Windows agent-file checks in place of mode and owner; `list` opens each prefixed entry for attributes and security only (no data access). Every listing reads the directory through a fresh handle (`NtCreateFile` with an empty name relative to the directory), so two listings never share an enumeration position.
- Lock: `owner.lock` is opened `GENERIC_READ | GENERIC_WRITE` with `FILE_SHARE_READ | FILE_SHARE_WRITE` (no delete sharing), so a second opener reaches `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)` on byte 0; `ERROR_LOCK_VIOLATION` (the Win32 form of `STATUS_LOCK_NOT_GRANTED`) and `STATUS_SHARING_VIOLATION` are `busy`, any other failure `unsafeState`. Dropping the root calls `UnlockFileEx` and then closes the handle; process exit releases it too.
- Every handle that becomes a `std::fs::File` is opened with `SYNCHRONIZE` and `FILE_SYNCHRONOUS_IO_NONALERT`.
- `open_read_only` applies the same checks and creates and locks nothing. Its reads open with `FILE_SHARE_DELETE`, so the resident's POSIX rename can replace the file while it is read; a link count of 0 or 1 is accepted there, 2 or more refused.

### Base writable by other accounts (W4)

Measured on a real Windows machine (2026-11-21): OpenAI's Codex Windows sandbox puts inheritable Modify plus delete-child ACEs (`(OI)(CI)(M,DC)`) for its sandbox principals (the `CodexSandboxUsers` group, and capability SIDs of its unelevated mode) on the user's profile folder, and `AppData\Local` inherits them. Under the earlier rule (no write-type right for another SID on the base) `SecureRoot::open_default()` returned `unsafeState` and the agent could not start on such a machine. The owner decided (2026-11-21) to drop that rule for the base only. Every rule for the intermediate directory, the agent root, private subdirectories and agent files is unchanged, and nothing the agent creates inherits the base's ACEs: every object gets the explicit protected owner-only descriptor in the creating call (test `secure_fs::windows::tests::a_base_others_may_modify_still_yields_owner_only_objects`, whose negative control shows the grant inherited when that descriptor is left out).

An existing `Nyanako` that is not owner-only by the intermediate rule is refused (`unsafeState`) and left as found. That includes one that inherited the base's ACEs because something other than the agent created it (`mkdir`, Explorer), and one another account created first. The remedy is to rename that `Nyanako` away (or delete it) and let the agent create a new one; the agent never repairs it. No installer of this project creates `LocalAppData\Nyanako` (the Windows app installs below `Nyanako.Syrtis`).

Two hardenings come with the relaxed rule:

- **Held intermediates.** For the life of a `SecureRoot`, every intermediate directory between the base and the root (today `Nyanako`) stays open on the handle the descent opened it with, whose share mode is `FILE_SHARE_READ | FILE_SHARE_WRITE` without `FILE_SHARE_DELETE`. While it is open, any open of that directory asking for `DELETE`, which renaming or deleting it needs, fails with a sharing violation (`ERROR_SHARING_VIOLATION`), so it cannot be renamed or deleted while the agent runs. A second `open_under` in the same or another process, `open_read_only`, and every operation below the root ask for no `DELETE` on the intermediate and are unaffected. A process that already holds `Nyanako` open with `DELETE` access when the agent starts makes the open fail with `unsafeState` (availability only). The base and the folders above it are not held; what Windows did when renaming them on the CI runner is measured below, not claimed.
- **The path leads to the held root.** Before `open_under` returns (before the lock), the root is opened again by its path: the base by its NT path as before, then each suffix component relative to its parent's handle with `FILE_OPEN` and `FILE_OPEN_REPARSE_POINT`, nothing created. Its `FileIdInformation` (volume serial number and 128-bit file ID) must equal the held root handle's, or the open is `unsafeState`. The engine and the app open `source-cache` and `pricing` by path; this makes that path lead to the directory whose handle the agent holds at start, and the held intermediate keeps it so for the agent's life (the base and above excepted, as said).

Measured on the windows-latest CI runner (run 44905015471) by `secure_fs::windows::tests::a_held_root_keeps_its_intermediates_from_being_renamed`, which prints `MEASURED W4: …` lines. Asserted there: with a root held, a `DELETE` open of each intermediate fails with `ERROR_SHARING_VIOLATION` and `std::fs::rename` (`MoveFileExW`) of the intermediate fails; after the root is dropped both succeed. The three printed results of that run, each a rename by the same user that owns the tree while a root was held:

| Rename while a root is held | Result on that runner |
|---|---|
| The intermediate, held handle in place | Failed, Win32 error 32 (`ERROR_SHARING_VIOLATION`) |
| The base (never held) | Failed, Win32 error 5 (`ERROR_ACCESS_DENIED`) |
| The intermediate, held handle bypassed (`HOLD`; the root and `owner.lock` handles still open) | Failed, Win32 error 5 (`ERROR_ACCESS_DENIED`) |

What follows: on that runner, while the agent ran, neither the intermediate nor the base could be renamed, with or without the held handle. The held handle was therefore not what stopped the rename there (third row): Windows refused it anyway because handles below it were open. The held handle is kept as an explicit guarantee that does not depend on that behaviour. What does not follow: these are measurements on one CI runner, not guarantees for every Windows version or file system. Nothing was measured for an account other than the user, for the folders above the base (beyond the base itself), or while the agent is stopped. While the agent is stopped nothing is held or open, and the residual risks (i)–(iii) below apply unchanged.

### Environment

`LOCALAPPDATA` is ignored: a child process with `LOCALAPPDATA` set elsewhere resolves the same root (`localappdata_does_not_change_the_root`, `tests/runtime_storage_windows_v1.rs`). The known folder is asked with the process token; `userprofile_does_not_change_the_root` asserts that a child with `USERPROFILE` set elsewhere also resolves the same root; measured on windows-latest (run 44863236471: `userprofile_does_not_change_the_root … ok`). Other environment variables are not measured, so on Windows no claim is made that every environment variable is ignored: a process that can set this agent's environment runs as the same user, which is a same-user non-claim.

### Windows non-claims

- A holder of `SeBackupPrivilege` or `SeRestorePrivilege` who is not an administrator is treated as an administrator: those privileges bypass DACLs.
- A low-integrity process of the same user is a same-user non-claim; mandatory integrity labels are not checked or set.
- An antivirus or indexer that holds a handle on `state.json` (or another target) without `FILE_SHARE_DELETE` makes the POSIX replace fail; the store becomes sticky unknown. This affects availability only and fails closed.
- Durability across power loss, as on Unix, is not observable in CI; there is no directory sync.
- **Another writer of the base (W4).** (i) A program that runs as the user under a write-restricted token and has write access to the base (the trace measured: the capability SID of Codex's unelevated sandbox mode) can build a whole fake `Nyanako\Syrtis Agent` tree owned by the user with a DACL that passes every rule, and the agent loads it: an identity key that program knows, grants and peers of its choosing, a scope record it can compute. Such a program can already read the state (the same-user non-claim). (ii) Another account with delete-child on the base can, while the agent is not running, rename `Nyanako` away (it cannot delete the non-empty directory, whose contents grant it nothing) and later put it back. If the tree was moved away before the owner revoked device D, the revocation happens in a new state that does not contain D; once the old tree is back, D's grant is valid again for the data present. Turning sharing off, a narrowed scope and an uninstall are undone the same way. `lastAcceptedWall`, `nextAuthEpoch`, `denyFloor` and `sourceScopeGeneration` are all inside the swapped tree, so the agent's own counters do not protect against this; the only outside limits are the OS clock and the grant's `expiresAt` (100 years, in effect none). (iii) See "Residual risks": the restore is not only the owner's. Syrtis's own caches and settings in the user's folders (`%APPDATA%`, `%LOCALAPPDATA%`) were already writable by these accounts on such a machine. No registry or other anchor outside the tree is kept (owner decision, 2026-11-21).
- **Not observable in CI:** an object owned by another account, a network volume and a volume without persistent ACLs cannot be made on a CI runner. Those three classifications go through test-only seams that force the result; the tests prove that the guard refuses the forced result, not that Windows classifies a real such object the same way. A NULL DACL, a junction, a hard link, a file symlink, an extra ACE and a re-enabled inheritance are real fixtures (`NtCreateFile` with a NULL-DACL descriptor in the test, `mklink /J`, `std::fs::hard_link`, `symlink_file`, `icacls`).

### Other platforms

Every target other than macOS, Linux and Windows compiles `src/secure_fs/unsupported.rs`: `SecureRoot` and `ReadOnlyRoot` wrap an uninhabited type, so every open returns `unsafeState` and no state can be read, written or served. No CI job builds such a target; it fails closed because its types are empty, not because a test shows it.

## Encoding

`state.json` is one CanonicalJsonV1 object (`src/canonical.rs`) with exactly the keys of `spec/v1.md`. No trailing newline.

### Value encodings

| Value | Encoding |
|---|---|
| `schema` | Integer `1` (`STATE_SCHEMA_VERSION`) |
| Byte arrays (`controlToken`, `identityPrivate`, `offerId`, `pendingId`, `grantId`, `recordId`, `secretHash`, `initiatorStatic`, `responderStatic`) | Lowercase hex, exact length |
| Offer `state` | `active`, `consumed`, `cancelled`, `expired` |
| Pending `state` | `awaitingApproval`, `approved`, `rejected`, `expired` |
| Grant `state` | `active`, `revoked`, `expired` |
| Terminal `kind` | `offer`, `pending`, `grant`, `reset`, `uninstall` |
| `createdAt`, `expiresAt`, `terminalAt` | Unix milliseconds, signed integer |
| `lastAcceptedWallUnixSeconds` | Unix seconds, signed integer, strictly positive |
| Grant `scope` | `usage.aggregate.read.v1` only |
| Grant `endpoints` | `[1,2,3,4]` only |
| `bindHost`, `nodeLabel` | String or `null` |
| `bindPort` | Integer 0–65535 |

Enum values are camelCase variant names, matching the existing `GrantState` serializer; byte arrays match the existing `Grant` serializer. Golden: `tests/fixtures/v1/runtime/storage/state-golden.json` (synthetic keys only).

### Initial state

| Field | Initial value |
|---|---|
| `config.sharingEnabled` | `false` |
| `config.bindHost` | `null`: no listener can start before the owner chooses one |
| `config.bindPort` | CSPRNG, uniform in 49152–65535, persisted |
| `config.nodeLabel` | `null` |
| `counters` | `nextAuthEpoch` 1, `denyFloor` 0, `sourceScopeGeneration` 1, `lastAcceptedWallUnixSeconds` = OS time at install, strictly positive |
| `identityPrivate`, `controlToken` | 32 CSPRNG bytes each (snow's OS RNG, `getrandom`) |
| Records | Empty |

`config.sharingEnabled` is `ReferenceState.sharing_enabled`, one to one. `identityPrivate` and `controlToken` are held by the store, never by `ReferenceState`, and every type that holds them redacts them in `Debug`.

## Load validation

1. Read at most 4 MiB + 1 byte from the verified descriptor; more than 4 MiB is `corrupt`. This bounds a damaged same-UID file; it is not a security boundary.
2. The top level must be an object with an integer `schema`; a missing or non-integer `schema`, or a top level that is not an object, is `corrupt`. An integer `schema` other than 1 (older, newer, zero or negative) is `incompatible`.
3. Strict CanonicalJsonV1 typed decode; a missing, extra or non-canonical key or value is `corrupt`.
4. The invariants below; any violation is `corrupt`.

| Invariant | Rule |
|---|---|
| Grant epochs | Every `grant.authEpoch < nextAuthEpoch` |
| Deny floor | `denyFloor < nextAuthEpoch` |
| Wall | `lastAcceptedWallUnixSeconds > 0` |
| Scope and endpoints | Frozen values above |
| Sharing | Sharing off implies no active grant |
| Active grants | At most 16 |
| Record IDs | Offer, pending and grant IDs unique across all three |
| Terminal IDs | `recordId` unique within `terminal`; a terminal may share the ID of the record it ended |
| Listen host | When `bindHost` is not `null`: `{bindHost,bindPort}` passes the frozen `listenConfigure` validator (`verify_control_command`, command 8: canonical host, port 1024–65535), and, if it parses as an IP address, `to_canonical()` of it is not unspecified (refuses `0.0.0.0`, `::`, `::ffff:0.0.0.0`). Hostnames are not resolved; a hostname that resolves to the wildcard is refused at bind time (SA-2B2) |
| Node label | When not `null`: at most 128 bytes of UTF-8 (and NFC, as every string). Load checks only this: a stored label that fails the node-label rule of `spec/report-cache-v1.md` still loads (the producer sends it as `null`) |

There is no record-count check: revoke, disable, reset, uninstall and reject never fail on record count (`spec/security-v1.md`), so a valid state may hold more than 256 records.

The store never writes a state it could not load. Before staging, a commit whose new state fails any invariant above, cannot be encoded canonically, or encodes to more than 4 MiB is refused with `refused(invalid)`. The file on disk is fine, so nothing is written, the in-memory state is unchanged, and the store does not become sticky unknown.

Errors are a stable enum with no path, OS error text or file content.

The listen-host rule recognises unspecified addresses only in the IP-literal spellings Rust's `IpAddr` parser accepts. Other spellings a resolver may accept for the wildcard, such as `0x0`, are treated as hostnames here and are not refused at load; refusing them belongs to the bind-time check of SA-2B2, which must bind only a resolved address that is not unspecified.

## Commit

Every change is a full replace of one agent-owned file in the root:

```text
openat(root, ".<name>.tmp", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600); fchmod 0600
write (all bytes)
file sync          macOS fcntl(F_FULLFSYNC); Linux fsync
                   -- store takes its exclusive guard --
renameat(root, ".<name>.tmp", root, "<name>")
directory sync     macOS fcntl(F_FULLFSYNC) on the root; Linux fsync on the root
                   -- in-memory state replaced, guard released --
```

- Before anything is staged, `nextAuthEpoch`, `denyFloor` and `sourceScopeGeneration` must each be at least the currently persisted value, and so must `lastAcceptedWallUnixSeconds` except in the reset commit (below), the only commit allowed to lower the wall. A violation is a caller bug, not an I/O failure: the commit is refused with `refused(conflict)`, nothing is written, the in-memory state is unchanged, and the store does not become sticky unknown, because the durable state is known.
- In-memory state advances only after the directory sync succeeds.
- The store's exclusive guard is held from before the rename until the in-memory state is replaced. Authorization takes the shared guard and reads only that in-memory state, which is always the last durable commit. After the rename no authorization can read the pre-commit state; before it, none can read the new one.
- Any failure during the commit (create, write, sync, rename, directory sync, including `ENOSPC`) makes the store **sticky unknown** until the process restarts: no state reads, no authorization (always false), no further commits, and a sync is never retried and then trusted. The durable result is then the old or the new state.
- On open, a leftover `.state.json.tmp` from a crash is removed with `unlinkat`, which never follows a link; only that exact name is touched.
- A panic inside the staging step (between creating the temp file and the rename) unwinds without making the store sticky, but leaves `.state.json.tmp` behind; the next commit's `O_EXCL` create then fails and the store becomes sticky unknown until the process restarts, whose open removes the temp file.
- **Not observable in CI:** durability across power loss. Tests prove the order of the calls and the old-or-new outcome after an injected error or a process abort at every step, not what a disk does with its cache.

## Listen config

`set_listen_config(bindHost, bindPort, nodeLabel)` replaces `config` except `sharingEnabled` through the same commit path, so the load rules above apply: a non-null host must pass the frozen validator (port 1024–65535) and must not be an unspecified address; with a null host any `u16` port is stored. The label is normalized to NFC first; a label that differs from the stored one must then pass the node-label rule of `spec/report-cache-v1.md` (`security::valid_node_label`), and an unchanged stored label is written back without that check, so a label stored before the rule never blocks a listen change (`DR-2b`). Counters, records and secrets are unchanged. A refused value returns `refused(invalid)` with nothing written.

A panic inside a caller's transition closure does not poison the store: the commit mutex guards no data, so its poison is ignored and the next commit (for example a revoke) proceeds. The state lock is only written after a successful durable commit, and a poisoned state lock still reads as sticky unknown (authorization false).

## Reset and clock

Install wall: OS time in whole seconds, strictly positive. The wall advances only through the checked transitions of `spec/security-v1.md`; the store's checkpoint is `compact_terminals(osNow)`.

Owner-confirmed reset is the only recovery from a clock anomaly. It is two commits: first `disable_commit` (sharing off, active grants revoked, deny floor raised), then a new state with

| Field | After reset |
|---|---|
| `lastAcceptedWallUnixSeconds` | The current OS time; the only counter that may go down |
| `nextAuthEpoch` | Unchanged |
| `denyFloor` | `max(old, nextAuthEpoch - 1)` |
| `sourceScopeGeneration` | Old value + 1 |
| `offers`, `pending`, `grants` | Empty |
| `terminal` | Kept, including the record the disable just wrote |
| `identityPrivate`, `controlToken` | New CSPRNG values |
| `config` | Kept; `sharingEnabled` is `false` |

A crash between the two commits leaves the disabled state, which grants nothing. Transitions that take a caller-supplied new `record_id` (disable, uninstall) get 16 fresh CSPRNG bytes from the store; an ID is never reused.

Accepted trade-off (F-07): a checkpoint taken while the OS clock is temporarily fast writes that fast time into the durable wall. After the clock is corrected every clock-bound transition refuses until a reset. This fails closed and affects availability only.

## Dependency provenance

`tests/dependency_provenance_v1.rs` checks `Cargo.lock` against the frozen baseline and `Cargo.toml` against an allowlist of tables and keys, with every version an exact three-part pin (`=` and three numeric parts). A lock package outside the baseline is accepted only by its full (name, version, source, checksum) tuple on an allowlist, never by name, never without a source, and the allowlist must equal what the lock adds. The Windows dependency is `windows-sys = "=0.61.2"` under `[target.'cfg(windows)'.dependencies]`: that version, and the `windows-link 0.2.1` it uses, were already in the baseline, so the lock gained no package and the allowlist is empty. It replaces the `0.59.x` that the SA-2B1b contract first named (chosen then to avoid `windows-link`): 0.61.2 needs Rust 1.71 (the toolchain is 1.85), has every `Wdk` and `Win32` item used, and adds nothing to the lock (W1 r1 (d)). The one exception is `tokscale-core`, a git dependency pinned by a full 40-hex `rev` that the lock must repeat (`spec/source-v1.md`). Cargo source replacement (`.cargo/config.toml`) is outside both checks. The test checks only the package (manifest) directory, `CARGO_MANIFEST_DIR`, which is the repository root today: it asserts that this directory has no `.cargo` entry. That is a tripwire against adding one there by accident, not a defence against a malicious source replacement. On Windows no test reaches the branch of the check (`no_cargo_config_in`) for a `.cargo` lookup that fails with an error other than `NotFound`: its only control, a directory without search permission, is Unix-only. The check's not-a-directory error is reached on every OS. Cargo takes configuration from many other places; per the Cargo book's configuration-discovery documentation (not measured here), examples include a `.cargo/config.toml` in the working directory and each of its parents (so cargo run from inside `tests/` would read a `tests/.cargo/`, which this test does not check), `$CARGO_HOME/config.toml`, `--config` on the command line, and `CARGO_*` environment variables.

## Residual risks

Restoring an older `state.json` from a backup can revive a revoked grant and lower `denyFloor` (SEC-2B1-12). The macOS backup exclusion above mitigates Time Machine only; no other backup tool is covered. On Windows the restore need not be the owner's from a backup: another account with write access to the state base (W4: delete-child, as the Codex sandbox principals have) can rename the current `Nyanako` away while the agent is not running and put an older one back, with the same effect (Windows non-claims, (ii)). This is disclosed here and must be disclosed in Settings.
