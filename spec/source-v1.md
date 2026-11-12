# Syrtis Agent Report Source v1

## Purpose and boundary

This document fixes the product `ReportSource` (`report_peer::ReportSource`): where report bodies come from, what the owner's consent binds to, and what the agent claims about the scan. Implementation: `src/source.rs` (`EngineSource`, `cfg(unix)`); the secure-root primitive `SecureRoot::private_subdir` in `src/secure_fs/unix.rs`; acceptance: `tests/runtime_source_v1.rs`, the engine and provenance checks in `tests/dependency_provenance_v1.rs`, and the `private_subdir` unit tests in `src/secure_fs/unix.rs`.

Every scan, parse, dedup, price and fold happens in the engine, `tokscale-core` (`aggregate_remote_usage_from_source_v1`). `EngineSource` builds the engine's context from owner inputs, checks the approved-scope record, copies the requested endpoint's records field by field into the frozen `report.rs` types, and encodes them with `ReportResponse::from_request` and `encode_response`. It never filters, re-aggregates or edits a value the engine returns.

Not in this slice: wiring the source into `Runtime` (the assembler injects it, `SA-2C`); the `status` scan fields (`SA-2C`); the producer cache (not wired, see the plan); install; Windows (no `EngineSource` exists there; a runtime without one answers `internal` through `NoSource`).

## Engine pin

`Cargo.toml` declares, under `[target.'cfg(unix)'.dependencies]`:

`tokscale-core = { git = "https://github.com/Nanako0129/tokscale-core", rev = "e156d67caa9708458fd2030f379d3c2a77ff05bf" }`

The SHA is the `vendor/tokscale-core` commit recorded on `Nanako0129/TokenBar-Native` `origin/main` on 2026-11-12 (`git ls-tree origin/main vendor/tokscale-core`), the engine the Syrtis macOS app builds. A pin change is a reviewed change: SEC-R4 (the engine's remote tests at the new SHA, and a security review of the engine's `src/` diff) and the D1 list below are redone for it.

Provenance (`tests/dependency_provenance_v1.rs`): `tokscale-core` is the only dependency that may come from git, and only as exactly `{ git = "https://github.com/Nanako0129/tokscale-core", rev = "<40 lowercase hex>" }` (no `version`, `branch`, `tag` or other key). Every other dependency is still refused a `git` or `rev` key and needs an exact `=x.y.z` registry pin. The lock must hold exactly one `tokscale-core`, with source `git+https://github.com/Nanako0129/tokscale-core?rev=<SHA>#<SHA>` and the manifest's SHA in both places. Every package the engine brings is in `tests/fixtures/v1/runtime/storage/cargo-lock-baseline.json` with name, version, source and checksum; `NEW_PACKAGE_ALLOWLIST` stays empty, so a later `rev` change fails as a changed baseline package. (`spec/state-store-v1.md`, in its provenance paragraph, names this `tokscale-core` exception to the exact-pin rule and points here.)

The engine's `reqwest`, `tokio`, `rusqlite` (bundled SQLite) and `zstd` are not optional in the engine and so are in the agent's dependency graph. The remote seam does not use the network by the engine's contract; this crate makes no claim about it beyond the engine's own tests (SEC-R4). Removing the HTTP client from the agent binary needs a feature gate in the fork, a follow-up.

## Secure-root layout

| Name | Kind | Purpose |
|---|---|---|
| `source-scope.json` | File | The approved-scope record (below) |
| `.source-scope.json.tmp` | File | Commit temp file; removed by `EngineSource::new` |
| `source-cache/` | Directory, `0700` | The engine's source (message) cache (`source_cache_dir`) |
| `pricing/` | Directory, `0700` | The engine's pricing root (`RemotePricingSnapshot::from_cache_root`) |

`SecureRoot::private_subdir(name)` opens `name` directly below the root, no-follow and relative to the root's descriptor, creating it `0700` (exact mode set on the descriptor, ACL cleared on macOS) when missing; it must be a directory owned by the effective UID, exactly `0700`, with no extended ACL on macOS. An existing directory is checked as found and never repaired: a symlink or a mode other than `0700` is `UnsafeState`. It returns the directory's path, because the engine takes paths. The stub on other platforms is uncallable (no root can exist there).

`SecureRoot::clear_private_subdir(name)` (`SA-2C2a`; called only by `Agent::uninstall` with `source-cache`) opens `name` the same way and with the same checks, but never creates or chmods it; absent is success. It empties the directory and keeps it: each entry is classified by a no-follow `fstatat` on its parent's descriptor; a directory is opened `O_DIRECTORY|O_NOFOLLOW` relative to that descriptor, emptied the same way and removed with `unlinkat(AT_REMOVEDIR)`; every other entry, a symlink included, is removed with `unlinkat`, which removes the link, never its target. More than 32 nested levels, or any failed call, is `UnsafeState`, and what was removed before it stays removed. The entry list is not capped (a same-UID process can grow it; same-UID non-claim). The stub on other platforms is uncallable.

Nothing writes pricing files yet. With `pricing/` empty the engine prices every record at zero cost (the engine's fail-soft rule, its test `pricing_snapshot_absence_zeroes_cost_and_changes_nothing_else`, which passed at the pin; this crate's tests observe zero cost only for a model missing from a non-empty pricing root); filling it is out of this slice. One `EngineSource` per root.

## Owner inputs and the approved scope

The owner inputs are: `home`, `config_dir`, `data_dir` (absolute paths the assembler supplies), the source cache directory (`<root>/source-cache`), and the complete `ScannerSettings`. Custom roots are the absolute paths in `ScannerSettings.extraScanPaths` and `ScannerSettings.opencodeDbPaths`; there is no separate custom-root input. `ownerInputsSha256` (`source::owner_inputs_sha256`) is SHA-256, lowercase hex, over the CanonicalJsonV1 encoding of an object whose keys and encoding this crate fixes: `{configDir, dataDir, excludedScanPaths, extraScanPaths, home, opencodeDbPaths, sourceCacheDir}`. Paths are UTF-8 strings; each path list is sorted (bytewise) and deduplicated; the two maps are keyed by client id in key order. The engine's serde form of `ScannerSettings` is not hashed: an engine pin that adds or renames a settings field would otherwise change the digest of unchanged owner inputs, deny every report and force a re-consent, which D1 rules out. The settings are read by an exhaustive destructuring with no `..`, so a pin that adds a `ScannerSettings` field does not compile until the field is either added to the hashed object (a consent change: every owner re-approves after a `source_change_commit`) or stated here as not an owner input. `ScannerSettings` at the pin is not `#[non_exhaustive]`. A golden test (`engine::the_owner_inputs_digest_is_fixed_by_this_crate`) fixes the digest of one input set as a literal, so any change to the encoding shows in review. A path that is not UTF-8 or not NFC, or any input the engine's `preview_fingerprint` refuses (a relative root or setting path), makes `EngineSource::new` return `Refused(Invalid)`.

`source-scope.json` is one CanonicalJsonV1 object, no trailing newline: `{generation, ownerInputsSha256, schema}`, `schema` the integer `1`; `spec/v1.md` registers these fields as the "Source scope record" surface (`localOnlyFields`, `SA-0G`). The control command `scopeApprove` carries the `ownerInputsSha256` the owner was shown (`spec/v1.md`, "Control bodies and results"). It is written only by `EngineSource::approve(&StateStore)`, with `stage` then `publish`, under a per-source mutex:

1. The store must be over the same root (`Arc` identity), else `Refused(Invalid)`.
2. `generation` is the store's current `sourceScopeGeneration`.
3. If a record exists for different inputs, `generation` must be strictly greater than the record's, else `Refused(Conflict)` and nothing is written. So an owner who changes an input first runs the frozen `source_change_commit` (the generation advances and every grant bound to the old one stops authorizing), then `approve`. A crash between the two leaves a record with a smaller generation than the state, which denies.
4. A record that cannot be read or decoded is returned as that error (`UnsafeState`, `Corrupt`, `Incompatible`); nothing is written.

The same inputs may be approved again at any generation (after a reset, for example).

D1: consent binds `ownerInputsSha256`, not the engine's fingerprint. The engine's fingerprint also hashes its client table and resolver version, so it changes with every pin; binding it would make every app update re-ask. An engine pin change therefore keeps the existing consent, including clients the new engine supports; an owner change to a setting or custom root needs a new approval.

## `report(request, deadline)`

0. If `Instant::now()` is already past `deadline`, `SourceError` before anything is read (`SA-2C2a`). Such a call is not a scan (below).
1. The endpoint must be one of the four; else `SourceError`.
2. Deny (`SourceError`) unless `source-scope.json` exists, decodes, has `schema` 1, its `generation` equals `request.sourceScopeGeneration` (which the producer's admission already checked against the durable counter), and its `ownerInputsSha256` equals this source's.
3. Build `RemoteSourceScopeTokenV1` from the engine's `preview_fingerprint` of the same inputs and the request's generation, then `RemoteSourceContextV1::new`.
4. Call `aggregate_remote_usage_from_source_v1` with the request's clients, dates, timezone and tzdb revision, and the pricing snapshot of `pricing/`.
5. Take the requested endpoint's records and the bundle's `saturated`, copy each record field by field, encode. The other three endpoints are dropped: each endpoint request is one engine scan. The engine's source cache is meant to make repeat scans cheaper; that is not measured here.
6. If `Instant::now()` is past `deadline` when the body is ready, `SourceError`.

Every failure is `SourceError`; no path, engine message or file content leaves this module.

### Scan record and scope read (`SA-2C2a`)

A scan is a `report` call that reached the engine, step 3. A call refused before it (step 0, an unknown endpoint, or a scope denial at step 2) is not a scan and leaves the record unchanged, so pulls before the owner approves do not read as a broken engine. `EngineSource::scan_status()` returns what control `status` shows (`spec/control-v1.md`): `scanStatus` is `ok` when the last scan returned a body and `error` when it failed at any of steps 3–6 (an engine or encoding failure, or a late body); `never` until the first scan of this process. `lastScanAt` is the OS wall clock (`SystemTime`, whole seconds) when the last successful scan finished; `sourceFamilies` is the set of `client` values in all four endpoints of that scan's engine bundle, sorted, at most 128. A failed scan changes only `scanStatus`. The record is in memory only; a restart starts at `never`.

`EngineSource::scope_record()` reads `source-scope.json` without writing: `None` when absent, otherwise its `generation` and whether its digest equals this source's inputs; a record that cannot be read or decoded is that error.

## D1 containment (per pin)

`tests/fixtures/v1/source/default-roots.json` is the frozen list of default scan locations at the pinned SHA: every `CLIENTS` entry (id, root kind, env var and fallback, relative path) and every hard-coded extra root of the engine's remote scan (`scan_all_clients_resolved_inner` and its helpers), each with its engine `file:line`. Tests: every relative path is non-empty, not absolute, has no `~`, `\`, `:` or `..` component; the client part equals the live `tokscale_core::clients::CLIENTS` table; and the list's `engineSha` equals the `tokscale-core` rev in `Cargo.lock`, so a pin change fails until the list is derived again. The extra-root part is compared with nothing live (the engine exposes no list of it); it is kept current by the per-pin review.

The escape test is a smoke test, not a detector: a cc-mirror variant below the temp home whose `configDir` points at session data outside every approved root yields nothing on any endpoint, and the same pointer aimed inside the home yields the data. Lanes that do not pass through the engine's `admits_scan_root` (the OpenCode, Kilo, Hermes, Goose, Zed, Kiro CLI, ZCode, Copilot desktop and synthetic databases, the Grok unified log, the Copilot exporter path) rely on the per-pin review only; the list marks them (from reading the engine at the pin, not from a test).

`tests/fixtures/v1/source/environment-keys.json` lists every environment key the engine names at the pin (with `file:line`), plus `XDG_STATE_HOME` and `TMPDIR`; a test checks it covers every client env root of the live table. The environment test sets every key to a decoy tree holding session data and moves the working directory into it, in a child process, and requires the four bodies to be byte-identical to those produced before.

## Non-claims

- Symlink TOCTOU (SEC-SPLIT-03): a process running as the same UID that replaces an approved source root, or a directory above one, with a symlink after approval is outside this design; the engine resolves paths as it finds them. Approved roots, or directories above them, writable by another UID are outside the guarantee as well.
- The engine has no cancellation hook: a scan runs to completion, and a body ready after the deadline is dropped, not interrupted.
- The engine's memory use during a scan is not charged to the agent's `MemoryLedger`.
- The paths `private_subdir` returns are resolved again by the engine when it opens them.
- The source cache and pricing directories are not removed on revoke or uninstall in this slice.

## Added packages at the pin

Licenses as `cargo metadata` reports them. "Lock only" packages are recorded in `Cargo.lock` but are not built for any target with the enabled features (optional dependencies of the engine's dependencies).

| Package | Version | License |
|---|---|---|
| `ahash` | 0.8.12 | MIT OR Apache-2.0 |
| `allocator-api2` | 0.2.21 | MIT OR Apache-2.0 |
| `android_system_properties` | 0.1.6 | MIT OR Apache-2.0 |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT |
| `aws-lc-rs` | 1.19.0 | ISC AND (Apache-2.0 OR ISC) |
| `aws-lc-sys` | 0.47.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) |
| `base64` | 0.23.1 | MIT OR Apache-2.0 |
| `bincode` | 1.3.3 | MIT |
| `bitflags` | 1.3.2 | MIT/Apache-2.0 (lock only: not built for any target) |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 |
| `bumpalo` | 3.20.3 | MIT OR Apache-2.0 |
| `bytes` | 1.12.1 | MIT |
| `cc` | 1.11.1 | MIT OR Apache-2.0 |
| `cfg_aliases` | 0.2.2 | MIT (lock only: not built for any target) |
| `chacha20` | 0.10.2 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 |
| `combine` | 4.6.9 | MIT |
| `core-foundation` | 0.10.1 | MIT OR Apache-2.0 |
| `core-foundation-sys` | 0.8.7 | MIT OR Apache-2.0 |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `crossbeam-deque` | 0.8.8 | MIT OR Apache-2.0 |
| `crossbeam-epoch` | 0.9.21 | MIT OR Apache-2.0 |
| `crossbeam-utils` | 0.8.23 | MIT OR Apache-2.0 |
| `defmt` | 1.2.0 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `defmt-macros` | 1.2.0 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `defmt-parser` | 1.1.0 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `dirs` | 5.0.1 | MIT OR Apache-2.0 |
| `dirs-sys` | 0.4.1 | MIT OR Apache-2.0 |
| `displaydoc` | 0.2.7 | MIT OR Apache-2.0 |
| `dunce` | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| `either` | 1.19.0 | MIT OR Apache-2.0 |
| `fallible-iterator` | 0.3.0 | MIT/Apache-2.0 |
| `fallible-streaming-iterator` | 0.1.9 | MIT/Apache-2.0 |
| `find-msvc-tools` | 0.1.15 | MIT OR Apache-2.0 |
| `float-cmp` | 0.10.0 | MIT |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 |
| `fs2` | 0.4.3 | MIT/Apache-2.0 |
| `fs_extra` | 1.3.0 | MIT |
| `futures-channel` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-core` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-task` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-util` | 0.3.34 | MIT OR Apache-2.0 |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |
| `halfbrown` | 0.2.5 | Apache-2.0/MIT |
| `hashbrown` | 0.14.5 | MIT OR Apache-2.0 |
| `hashlink` | 0.9.1 | MIT OR Apache-2.0 |
| `http` | 1.5.0 | MIT OR Apache-2.0 |
| `http-body` | 1.1.0 | MIT |
| `http-body-util` | 0.1.5 | MIT |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 |
| `hyper` | 1.12.0 | MIT |
| `hyper-rustls` | 0.27.10 | Apache-2.0 OR ISC OR MIT |
| `hyper-util` | 0.1.21 | MIT |
| `iana-time-zone` | 0.1.65 | MIT OR Apache-2.0 |
| `iana-time-zone-haiku` | 0.1.2 | MIT OR Apache-2.0 |
| `icu_collections` | 2.1.1 | Unicode-3.0 |
| `icu_locale_core` | 2.1.1 | Unicode-3.0 |
| `icu_normalizer` | 2.1.1 | Unicode-3.0 |
| `icu_normalizer_data` | 2.1.1 | Unicode-3.0 |
| `icu_properties` | 2.1.2 | Unicode-3.0 |
| `icu_properties_data` | 2.1.2 | Unicode-3.0 |
| `icu_provider` | 2.1.1 | Unicode-3.0 |
| `idna` | 1.1.0 | MIT OR Apache-2.0 |
| `idna_adapter` | 1.2.1 | Apache-2.0 OR MIT |
| `ipnet` | 2.12.2 | MIT OR Apache-2.0 |
| `jiff` | 0.2.32 | Unlicense OR MIT |
| `jiff-static` | 0.2.32 | Unlicense OR MIT |
| `jiff-tzdb` | 0.1.8 | Unlicense OR MIT |
| `jni` | 0.22.4 | MIT OR Apache-2.0 |
| `jni-macros` | 0.22.4 | MIT OR Apache-2.0 |
| `jni-sys` | 0.4.1 | MIT OR Apache-2.0 |
| `jni-sys-macros` | 0.4.1 | MIT OR Apache-2.0 |
| `jobserver` | 0.1.35 | MIT OR Apache-2.0 |
| `js-sys` | 0.3.107 | MIT OR Apache-2.0 |
| `libredox` | 0.1.25 | MIT |
| `libsqlite3-sys` | 0.30.1 | MIT |
| `litemap` | 0.8.3 | Unicode-3.0 |
| `log` | 0.4.35 | MIT OR Apache-2.0 |
| `lru-slab` | 0.1.3 | MIT OR Apache-2.0 OR Zlib (lock only: not built for any target) |
| `mio` | 1.2.4 | MIT |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 |
| `openssl-probe` | 0.2.2 | MIT OR Apache-2.0 |
| `option-ext` | 0.2.0 | MPL-2.0 |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT |
| `pkg-config` | 0.3.34 | MIT OR Apache-2.0 |
| `portable-atomic` | 1.15.0 | Apache-2.0 OR MIT |
| `portable-atomic-util` | 0.2.8 | Apache-2.0 OR MIT |
| `potential_utf` | 0.1.6 | Unicode-3.0 |
| `quinn` | 0.11.12 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `quinn-proto` | 0.11.19 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `quinn-udp` | 0.5.16 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| `rand` | 0.10.3 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `rand_core` | 0.10.1 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `rand_pcg` | 0.10.2 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `rayon` | 1.12.0 | MIT OR Apache-2.0 |
| `rayon-core` | 1.13.0 | MIT OR Apache-2.0 |
| `redox_users` | 0.4.6 | MIT |
| `ref-cast` | 1.0.27 | MIT OR Apache-2.0 |
| `ref-cast-impl` | 1.0.27 | MIT OR Apache-2.0 |
| `reqwest` | 0.13.5 | MIT OR Apache-2.0 |
| `ring` | 0.17.14 | Apache-2.0 AND ISC (lock only: not built for any target) |
| `rusqlite` | 0.32.1 | MIT |
| `rustc-hash` | 2.1.3 | Apache-2.0 OR MIT (lock only: not built for any target) |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| `rustls-native-certs` | 0.8.5 | Apache-2.0 OR ISC OR MIT |
| `rustls-pki-types` | 1.16.0 | MIT OR Apache-2.0 |
| `rustls-platform-verifier` | 0.7.1 | MIT OR Apache-2.0 |
| `rustls-platform-verifier-android` | 0.2.0 | MIT OR Apache-2.0 |
| `rustls-webpki` | 0.103.16 | ISC |
| `rustversion` | 1.0.23 | MIT OR Apache-2.0 |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| `same-file` | 1.0.6 | Unlicense/MIT |
| `schannel` | 0.1.30 | MIT |
| `security-framework` | 3.7.0 | MIT OR Apache-2.0 |
| `security-framework-sys` | 2.17.0 | MIT OR Apache-2.0 |
| `sha2-asm` | 0.6.4 | MIT |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 |
| `simd-json` | 0.14.3 | Apache-2.0 OR MIT |
| `simd_cesu8` | 1.2.0 | Apache-2.0 OR MIT |
| `simdutf8` | 0.1.5 | MIT OR Apache-2.0 |
| `slab` | 0.4.12 | MIT |
| `smallvec` | 1.16.5 | MIT OR Apache-2.0 |
| `socket2` | 0.6.5 | MIT OR Apache-2.0 |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 |
| `sync_wrapper` | 1.0.2 | Apache-2.0 |
| `synstructure` | 0.14.0 | MIT |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 |
| `thiserror-impl` | 1.0.69 | MIT OR Apache-2.0 |
| `thiserror-impl` | 2.0.21 | MIT OR Apache-2.0 |
| `tinystr` | 0.8.5 | Unicode-3.0 |
| `tokio` | 1.54.1 | MIT |
| `tokio-macros` | 2.7.2 | MIT |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 |
| `tokscale-core` | 3.0.0 | MIT |
| `tower` | 0.5.3 | MIT |
| `tower-http` | 0.6.11 | MIT |
| `tower-layer` | 0.3.3 | MIT |
| `tower-service` | 0.3.3 | MIT |
| `tracing` | 0.1.44 | MIT |
| `tracing-attributes` | 0.1.31 | MIT |
| `tracing-core` | 0.1.36 | MIT |
| `try-lock` | 0.2.5 | MIT |
| `untrusted` | 0.9.0 | ISC |
| `url` | 2.5.8 | MIT OR Apache-2.0 |
| `utf8_iter` | 1.1.0 | Apache-2.0 OR MIT |
| `utf_types` | 1.0.0 | Apache-2.0 OR MIT |
| `value-trait` | 0.10.1 | Apache-2.0/MIT |
| `vcpkg` | 0.2.15 | MIT/Apache-2.0 |
| `walkdir` | 2.5.0 | Unlicense/MIT |
| `want` | 0.3.2 | MIT |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `wasm-bindgen` | 0.2.130 | MIT OR Apache-2.0 |
| `wasm-bindgen-futures` | 0.4.80 | MIT OR Apache-2.0 |
| `wasm-bindgen-macro` | 0.2.130 | MIT OR Apache-2.0 |
| `wasm-bindgen-macro-support` | 0.2.130 | MIT OR Apache-2.0 |
| `wasm-bindgen-shared` | 0.2.130 | MIT OR Apache-2.0 |
| `web-sys` | 0.3.107 | MIT OR Apache-2.0 |
| `web-time` | 1.1.0 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `webpki-root-certs` | 1.0.12 | CDLA-Permissive-2.0 |
| `winapi` | 0.3.9 | MIT/Apache-2.0 |
| `winapi-i686-pc-windows-gnu` | 0.4.0 | MIT/Apache-2.0 |
| `winapi-util` | 0.1.11 | Unlicense OR MIT |
| `winapi-x86_64-pc-windows-gnu` | 0.4.0 | MIT/Apache-2.0 |
| `windows-core` | 0.62.2 | MIT OR Apache-2.0 |
| `windows-implement` | 0.60.2 | MIT OR Apache-2.0 |
| `windows-interface` | 0.59.3 | MIT OR Apache-2.0 |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 |
| `windows-result` | 0.4.1 | MIT OR Apache-2.0 |
| `windows-strings` | 0.5.1 | MIT OR Apache-2.0 |
| `windows-sys` | 0.48.0 | MIT OR Apache-2.0 |
| `windows-sys` | 0.52.0 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 |
| `windows-targets` | 0.48.5 | MIT OR Apache-2.0 |
| `windows-targets` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_aarch64_gnullvm` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_aarch64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_aarch64_msvc` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_aarch64_msvc` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_i686_gnu` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_i686_gnu` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_i686_gnullvm` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_i686_msvc` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_i686_msvc` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_x86_64_gnu` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_x86_64_gnu` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_x86_64_gnullvm` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_x86_64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `windows_x86_64_msvc` | 0.48.5 | MIT OR Apache-2.0 |
| `windows_x86_64_msvc` | 0.52.6 | MIT OR Apache-2.0 (lock only: not built for any target) |
| `writeable` | 0.6.4 | Unicode-3.0 |
| `yoke` | 0.8.4 | Unicode-3.0 |
| `yoke-derive` | 0.8.4 | Unicode-3.0 |
| `zerocopy` | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zerocopy-derive` | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zerofrom` | 0.1.8 | Unicode-3.0 |
| `zerofrom-derive` | 0.1.8 | Unicode-3.0 |
| `zerotrie` | 0.2.5 | Unicode-3.0 |
| `zerovec` | 0.11.9 | Unicode-3.0 |
| `zerovec-derive` | 0.11.7 | Unicode-3.0 |
| `zstd` | 0.13.4 | BSD-3-Clause |
| `zstd-safe` | 7.4.0 | BSD-3-Clause |
| `zstd-sys` | 2.1.2+zstd.1.5.7 | BSD-3-Clause |
