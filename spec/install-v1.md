# Install and uninstall v1

`src/install.rs` puts the running executable and its autostart object at the frozen paths, and removes them again on uninstall. macOS and Linux only; on every other platform `install` and `uninstall` return `Unsupported` and touch nothing. Neither function loads, starts or stops a service: `launchctl` and `systemctl` are the owner's step.

## Paths

Both paths come only from the frozen `security::install_objects(platform, trusted_home)`; `trusted_home` is the caller's (the product is to pass `secure_fs::trusted_home()` once `SA-2C2` wires the CLI; tests pass a temp home). The module reads no environment variable, searches no `PATH` and runs no shell.

| Platform | Binary | Autostart object |
|---|---|---|
| macOS | `<home>/.local/bin/syrtis-agent` | `<home>/Library/LaunchAgents/com.nyanako.syrtis.agent.plist` |
| Linux | `<home>/.local/bin/syrtis-agent` | `<home>/.config/systemd/user/syrtis-agent.service` |

A home that is not valid UTF-8, or that `install_objects` refuses, is `Invalid`. Each path is split below the home into components; an empty, `.` or `..` component is `Invalid`.

## Directory walk

The home is opened by path (`O_DIRECTORY`); links above and at the home are trusted, as for the state root. Every directory below it is opened relative to its parent's descriptor with `openat(O_DIRECTORY | O_NOFOLLOW)`, and every directory, the home included, is checked on its descriptor: a directory, owned by the effective UID, not group- or other-writable, and on macOS `acl::deny_only` (no ACL entry other than an explicit deny; an allow entry does not show in the mode bits). Any failure is `UnsafeState`. Install creates a missing directory with `mkdirat`, sets exactly `0755` with `fchmod`, and syncs its parent. Uninstall creates nothing; a missing directory makes that object `Absent`.

## Install

`install(trusted_home, current_exe)`:

1. Walk both parent chains and check both existing targets with `fstatat(AT_SYMLINK_NOFOLLOW)`: an existing target must be a regular file owned by the effective UID with one link, else `UnsafeState`. All checks finish before anything is written.
2. Read `current_exe` (it must be a regular file).
3. Binary, then autostart object, each: remove a leftover `.<name>.tmp` (`unlinkat`, never follows), create it with `O_CREAT | O_EXCL | O_NOFOLLOW`, write, `fchmod` the descriptor (`0755` binary, `0644` autostart), sync it, `renameat` over the target, sync the directory. A failure before the rename removes the temp file and leaves the old target as it was; after the rename the target is the new object.

The same source installed twice gives the same bytes and modes. The binary path must be bytes from `[A-Za-z0-9/._-]` only; anything else (a space, `&`, `%`, non-ASCII) would need XML or systemd escaping and is `Invalid` rather than escaped.

### Autostart templates

`packaging/macos/com.nyanako.syrtis.agent.plist` and `packaging/linux/syrtis-agent.service`, compiled in with `include_str!`. The single `@BINARY@` is replaced by the binary path. The plist sets `Label`, `ProgramArguments = [binary, "run"]` and `RunAtLoad`; the unit sets `ExecStart=<binary> run` and `WantedBy=default.target`.

## Uninstall

`uninstall(store, trusted_home, purge, terminal_at_ms) -> UninstallReport` takes the only `StateStore` handle by value; the caller has stopped the listener and control first. The store, and with it `owner.lock`, is released when the call returns.

1. `StateStore::uninstall(terminal_at_ms)`: sharing off, every active grant revoked, deny floor raised. On failure the call returns `Storage(_)` and removes nothing.
2. Walk both parent chains (no creation). If either chain fails its checks, neither object is removed and each present one is `ManualRepair`.
3. Autostart object: removed (`unlinkat`, then a directory sync) only when `fstatat` shows a regular file owned by the effective UID with one link, and its bytes, read through an `O_NOFOLLOW | O_NONBLOCK` descriptor that passes the same checks, equal this version's rendered template. Otherwise `ManualRepair`.
4. Binary: removed when it is a regular file owned by the effective UID with one link. Otherwise `ManualRepair`.
5. Producer and receiver caches: `CacheStore::open` + `clear` on the store's root. Failure is `ManualRepair`.
6. Only with `purge` and no `ManualRepair` anywhere: `SecureRoot::remove_file` of `peers.json`, then `state.json`. `owner.lock` is never removed: unlinking a held lock would let the next process lock a different inode.

Nothing follows a link, nothing removes a directory, and nothing removes an object whose name or bytes do not match. A path error after step 1 (an invalid home) returns `Invalid` with the durable uninstall already committed.

## Non-claims

- The checks and the `unlinkat` or `renameat` that follows them are separate calls. Between them, only a process of the same UID can change an entry, because every directory on the path is checked not to be group- or other-writable; that process is not defended against.
- `current_exe` is opened by path, following links; it is the caller's verified executable.
- No test loads the plist or unit into `launchd` or `systemd`; that is a manual acceptance step.
- Windows is `Unsupported`.

## Acceptance map

All in `tests/install_v1.rs` unless noted; every test works under a temp home it creates.

| Item | Test |
|---|---|
| 1 | `install_writes_both_frozen_objects_with_exact_modes_and_golden_contents` |
| 2 | `reinstall_is_idempotent_and_an_upgrade_replaces_the_binary` |
| 3 | `install_refuses_a_symlinked_target_and_leaves_the_decoy`, `install_refuses_a_hard_linked_target_and_leaves_the_decoy`, `install_refuses_a_symlinked_parent_and_leaves_the_decoy`, `install_refuses_an_other_writable_parent` |
| 4 | `uninstall_revokes_removes_both_objects_clears_caches_and_keeps_state` |
| 5 | `uninstall_keeps_a_modified_autostart_object`, `uninstall_keeps_a_symlinked_binary_and_its_target`, `uninstall_never_follows_a_symlinked_parent`, `uninstall_keeps_objects_under_a_group_writable_parent`, `install_refuses_an_allow_acl_on_the_bin_directory` (macOS) |
| 6 | `purge_removes_state_and_peers_but_keeps_the_owner_lock`, `purge_keeps_state_when_anything_needs_manual_repair` |
| 7 | `install::unix::tests::a_failed_durable_uninstall_removes_nothing` (unit test, `src/install.rs`) |
| 8 | `only_the_two_frozen_objects_ever_appear` |
