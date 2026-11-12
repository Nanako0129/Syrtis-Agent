//! SA-2C1 acceptance: install and uninstall through the public API
//! (`spec/install-v1.md`).
//!
//! Every test works below a temp home it creates; nothing derives a path
//! from the real `trusted_home()`, and nothing calls `launchctl` or
//! `systemctl`. The failing-durable-uninstall case needs a test-only seam
//! and lives in the unit tests of `src/install.rs`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    collections::BTreeSet,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use syrtis_agent::{
    cache::{CacheKey, CacheRole},
    cache_store::CacheStore,
    install::{InstallError, Outcome, UninstallReport, install, uninstall},
    peer_store::encode_peers,
    report::{GraphRecord, GraphResponse, ReportRequest, encode_response},
    secure_fs::{SecureRoot, StorageError},
    security::{
        AGGREGATION_REVISION, GrantState, MemoryLedger, Offer, OfferClaim, OfferState,
        PendingApproval, Platform, REPORT_SCHEMA_VERSION, ReferenceState, TZDB_REVISION,
        TerminalKind, install_objects, offer_secret_hash,
    },
    state_store::{AuthorizationQuery, StateStore},
};

#[cfg(target_os = "macos")]
const PLATFORM: Platform = Platform::MacOs;
#[cfg(target_os = "linux")]
const PLATFORM: Platform = Platform::Linux;

/// No spaces: the frozen macOS suffix has one, so tests use this suffix.
const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
const NOW: i64 = 1_700_000_000;
const NOW_MS: i64 = NOW * 1_000;
const DAY_MS: i64 = 86_400_000;
const RESPONDER: [u8; 32] = [0xc1; 32];
const SOURCE: &str = "source-binary";

/// A temporary home. Only the directory this helper created is removed.
struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "syrtis-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn root(&self) -> PathBuf {
        SUFFIX
            .iter()
            .fold(self.path.clone(), |path, part| path.join(part))
    }

    fn binary(&self) -> PathBuf {
        self.objects().0
    }

    fn autostart(&self) -> PathBuf {
        self.objects().1
    }

    /// The frozen paths for this home.
    fn objects(&self) -> (PathBuf, PathBuf) {
        let objects = install_objects(PLATFORM, self.path.to_str().unwrap()).unwrap();
        (objects.binary.into(), objects.autostart_object.into())
    }

    /// Writes the stand-in for the running executable.
    fn source(&self, bytes: &[u8]) -> PathBuf {
        let path = self.path.join(SOURCE);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn store(&self) -> StateStore {
        retry_busy(|| {
            SecureRoot::open_under(&self.path, SUFFIX).and_then(|root| StateStore::open(root, NOW))
        })
        .unwrap()
    }

    /// Every non-directory below the home, relative, except the state root
    /// and the source file. Never follows a link.
    fn objects_on_disk(&self) -> BTreeSet<PathBuf> {
        fn walk(dir: &Path, base: &Path, skip: &Path, out: &mut BTreeSet<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path == skip {
                    continue;
                }
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    walk(&path, base, skip, out);
                } else {
                    out.insert(path.strip_prefix(base).unwrap().to_path_buf());
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&self.path, &self.path, &self.root(), &mut out);
        out.remove(Path::new(SOURCE));
        out
    }

    fn frozen_objects(&self) -> BTreeSet<PathBuf> {
        [self.binary(), self.autostart()]
            .iter()
            .map(|path| path.strip_prefix(&self.path).unwrap().to_path_buf())
            .collect()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Retries only `Busy`, for about 2 s: a fork-to-exec child of this binary
/// (the ACL test runs `/bin/chmod`) can still hold a lock this process just
/// released.
fn retry_busy<T>(mut f: impl FnMut() -> Result<T, StorageError>) -> Result<T, StorageError> {
    for _ in 0..200 {
        match f() {
            Err(StorageError::Busy) => std::thread::sleep(std::time::Duration::from_millis(10)),
            other => return other,
        }
    }
    f()
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn mkdirs(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
}

/// The golden autostart object for `binary`.
#[cfg(target_os = "macos")]
fn golden(binary: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>Label</key>\n\
\t<string>com.nyanako.syrtis.agent</string>\n\
\t<key>ProgramArguments</key>\n\
\t<array>\n\
\t\t<string>{}</string>\n\
\t\t<string>run</string>\n\
\t</array>\n\
\t<key>RunAtLoad</key>\n\
\t<true/>\n\
</dict>\n\
</plist>\n",
        binary.display()
    )
}

#[cfg(target_os = "linux")]
fn golden(binary: &Path) -> String {
    format!(
        "[Unit]\nDescription=Syrtis Agent\n\n[Service]\nExecStart={} run\n\n\
[Install]\nWantedBy=default.target\n",
        binary.display()
    )
}

// Pairing, as in tests/runtime_storage_v1.rs.

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// Offer 1 → pending 11 → active grant 21, with sharing on.
fn paired(state: &ReferenceState) -> Result<ReferenceState, syrtis_agent::security::SecurityError> {
    let offer = Offer {
        offer_id: id(1),
        secret_hash: offer_secret_hash(&id(1), &[1; 32], &RESPONDER),
        created_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 600_000,
        state: OfferState::Active,
    };
    let claim = OfferClaim {
        offer_id: id(1),
        secret: [1; 32],
        responder_static: RESPONDER,
        pending_id: id(11),
        initiator_static: [11 ^ 0xb0; 32],
        sas_code: "0A1B-2C3D".into(),
        sas_generation: 1,
    };
    let approval = PendingApproval {
        pending_id: id(11),
        sas_generation: 1,
        grant_id: id(21),
        responder_static: RESPONDER,
        grant_expires_at_ms: NOW_MS + 30 * DAY_MS,
        disclosure_exact: true,
    };
    let state = state.enable_sharing()?.create_offer(offer, NOW)?;
    let (state, _, _) = state.claim_offer(claim, NOW)?;
    state.approve_pending(approval, NOW)
}

fn grant_query() -> AuthorizationQuery {
    AuthorizationQuery {
        grant_id: id(21),
        auth_epoch: 1,
        source_scope_generation: 1,
        endpoint: 1,
        os_now_unix_seconds: NOW,
    }
}

// Cache entries, as in tests/cache_store_v1.rs.

fn cache_key(role: CacheRole) -> CacheKey {
    CacheKey {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: 1,
        clients: vec![],
        end_date_exclusive: "2025-02-01".into(),
        endpoint: 1,
        grant_id: "22".repeat(16),
        peer_static: "33".repeat(32),
        report_schema: REPORT_SCHEMA_VERSION,
        role,
        source_scope_generation: 1,
        start_date: "2025-01-01".into(),
        timezone: "UTC".into(),
        tzdb_revision: TZDB_REVISION.into(),
    }
}

fn cache_body(key: &CacheKey) -> Vec<u8> {
    let request = ReportRequest {
        aggregation_revision: key.aggregation_revision,
        auth_epoch: key.auth_epoch,
        clients: key.clients.clone(),
        end_date_exclusive: key.end_date_exclusive.clone(),
        endpoint: key.endpoint,
        grant_id: key.grant_id.clone(),
        protocol: 1,
        report_schema: key.report_schema,
        request_id: "11".repeat(16),
        source_scope_generation: key.source_scope_generation,
        start_date: key.start_date.clone(),
        timezone: key.timezone.clone(),
        tzdb_revision: key.tzdb_revision.clone(),
    };
    let row = GraphRecord {
        date: "2025-01-02".into(),
        client: "claude".into(),
        model: Some("model".into()),
        provider: None,
        input_tokens: 1,
        output_tokens: 1,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 2,
        message_count: 1,
        turn_count: 1,
        cost_nano_usd: 7,
    };
    encode_response(&GraphResponse::from_request(&request, vec![row], false)).unwrap()
}

fn put_cache(root: &Arc<SecureRoot>, role: CacheRole) {
    let cache = CacheStore::open(Arc::clone(root), role, MemoryLedger::default()).unwrap();
    let key = cache_key(role);
    cache
        .put(&key, &cache_body(&key), NOW_MS, NOW_MS + DAY_MS)
        .unwrap();
    assert_eq!(cache.len().unwrap(), 1);
}

fn cache_files(home: &TempHome) -> Vec<String> {
    std::fs::read_dir(home.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.contains("cache-"))
        .collect()
}

const CLEAN: UninstallReport = UninstallReport {
    autostart: Outcome::Removed,
    binary: Outcome::Removed,
    producer_cache: Outcome::Removed,
    receiver_cache: Outcome::Removed,
    purged: false,
};

/// Acceptance 1.
#[test]
fn install_writes_both_frozen_objects_with_exact_modes_and_golden_contents() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent v1")).unwrap();
    let (binary, autostart) = home.objects();
    assert_eq!(std::fs::read(&binary).unwrap(), b"agent v1");
    assert_eq!(mode(&binary), 0o755);
    assert_eq!(
        std::fs::read_to_string(&autostart).unwrap(),
        golden(&binary)
    );
    assert_eq!(mode(&autostart), 0o644);
    // Missing directories are created 0755.
    assert_eq!(mode(binary.parent().unwrap()), 0o755);
    assert_eq!(mode(autostart.parent().unwrap()), 0o755);
}

/// Acceptance 2.
#[test]
fn reinstall_is_idempotent_and_an_upgrade_replaces_the_binary() {
    let home = TempHome::new();
    let source = home.source(b"agent v1");
    install(&home.path, &source).unwrap();
    let snapshot = |home: &TempHome| {
        (
            std::fs::read(home.binary()).unwrap(),
            std::fs::read(home.autostart()).unwrap(),
            mode(&home.binary()),
            mode(&home.autostart()),
        )
    };
    let first = snapshot(&home);
    install(&home.path, &source).unwrap();
    assert_eq!(snapshot(&home), first);
    assert_eq!(home.objects_on_disk(), home.frozen_objects());

    install(&home.path, &home.source(b"agent v2, longer")).unwrap();
    let upgraded = snapshot(&home);
    assert_eq!(upgraded.0, b"agent v2, longer");
    assert_eq!(
        (upgraded.1, upgraded.2, upgraded.3),
        (first.1, first.2, first.3)
    );
}

/// Acceptance 3: the existing binary is a symlink to a decoy.
#[test]
fn install_refuses_a_symlinked_target_and_leaves_the_decoy() {
    let home = TempHome::new();
    let decoy = home.path.join("decoy");
    std::fs::write(&decoy, b"decoy").unwrap();
    mkdirs(home.binary().parent().unwrap());
    symlink(&decoy, home.binary()).unwrap();

    let result = install(&home.path, &home.source(b"agent"));

    assert_eq!(result, Err(InstallError::UnsafeState));
    assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy");
    assert_eq!(std::fs::read_link(home.binary()).unwrap(), decoy);
    assert!(!home.autostart().exists());
}

/// Acceptance 3: the existing binary has a second hard link.
#[test]
fn install_refuses_a_hard_linked_target_and_leaves_the_decoy() {
    let home = TempHome::new();
    let decoy = home.path.join("decoy");
    std::fs::write(&decoy, b"decoy").unwrap();
    mkdirs(home.binary().parent().unwrap());
    std::fs::hard_link(&decoy, home.binary()).unwrap();

    let result = install(&home.path, &home.source(b"agent"));

    assert_eq!(result, Err(InstallError::UnsafeState));
    assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy");
    assert_eq!(std::fs::read(home.binary()).unwrap(), b"decoy");
    assert_eq!(std::fs::metadata(&decoy).unwrap().nlink(), 2);
    assert!(!home.autostart().exists());
}

/// Acceptance 3: the binary's parent directory is a symlink to a decoy
/// directory.
#[test]
fn install_refuses_a_symlinked_parent_and_leaves_the_decoy() {
    let home = TempHome::new();
    let decoy = home.path.join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    std::fs::write(decoy.join("syrtis-agent"), b"decoy").unwrap();
    let parent = home.binary().parent().unwrap().to_path_buf();
    mkdirs(parent.parent().unwrap());
    symlink(&decoy, &parent).unwrap();

    let result = install(&home.path, &home.source(b"agent"));

    assert_eq!(result, Err(InstallError::UnsafeState));
    assert_eq!(std::fs::read(decoy.join("syrtis-agent")).unwrap(), b"decoy");
    assert_eq!(std::fs::read_dir(&decoy).unwrap().count(), 1);
    assert!(!home.autostart().exists());
}

/// Acceptance 3: the binary's parent directory is other-writable.
#[test]
fn install_refuses_an_other_writable_parent() {
    let home = TempHome::new();
    let parent = home.binary().parent().unwrap().to_path_buf();
    mkdirs(&parent);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o757)).unwrap();

    let result = install(&home.path, &home.source(b"agent"));

    assert_eq!(result, Err(InstallError::UnsafeState));
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    assert!(!home.autostart().exists());
}

/// Acceptance 5 (macOS): an allow ACL entry, which the mode bits do not
/// show, on the temp `.local/bin`.
#[cfg(target_os = "macos")]
#[test]
fn install_refuses_an_allow_acl_on_the_bin_directory() {
    let home = TempHome::new();
    let parent = home.binary().parent().unwrap().to_path_buf();
    mkdirs(&parent);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow add_file"])
        .arg(&parent)
        .status()
        .unwrap();
    assert!(status.success());
    // Control: the mode bits alone would pass.
    assert_eq!(mode(&parent) & 0o022, 0);

    let result = install(&home.path, &home.source(b"agent"));

    assert_eq!(result, Err(InstallError::UnsafeState));
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
}

/// Acceptance 4.
#[test]
fn uninstall_revokes_removes_both_objects_clears_caches_and_keeps_state() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let store = home.store();
    store.transition(paired).unwrap();
    // Control: the grant authorizes before the uninstall.
    assert!(store.authorize(&grant_query()));
    let before = store.state().unwrap().reference;
    put_cache(&store.root(), CacheRole::Producer);
    put_cache(&store.root(), CacheRole::Receiver);
    assert_eq!(cache_files(&home).len(), 2);

    let report = uninstall(store, &home.path, false, NOW_MS + 1).unwrap();

    assert_eq!(report, CLEAN);
    assert!(!home.binary().exists() && !home.autostart().exists());
    assert!(home.objects_on_disk().is_empty());
    assert!(cache_files(&home).is_empty());
    assert!(home.root().join("state.json").is_file());
    let store = home.store();
    let after = store.state().unwrap().reference;
    assert!(!after.sharing_enabled);
    assert!(after.grants.iter().all(|g| g.state != GrantState::Active));
    assert!(after.deny_floor > before.deny_floor);
    assert!(after.deny_floor >= 1);
    assert_eq!(after.terminal.last().unwrap().kind, TerminalKind::Uninstall);
    assert!(!store.authorize(&grant_query()));
    drop(store);

    // Reinstall, reopen: still no active grant.
    install(&home.path, &home.source(b"agent")).unwrap();
    let store = home.store();
    let state = store.state().unwrap().reference;
    assert!(!state.sharing_enabled);
    assert!(state.grants.iter().all(|g| g.state != GrantState::Active));
    store.transition(|r| r.enable_sharing()).unwrap();
    assert!(!store.authorize(&grant_query()));
}

/// Acceptance 5: an autostart object whose bytes differ from the template.
#[test]
fn uninstall_keeps_a_modified_autostart_object() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let mut changed = std::fs::read(home.autostart()).unwrap();
    changed.push(b'\n');
    std::fs::write(home.autostart(), &changed).unwrap();

    let report = uninstall(home.store(), &home.path, false, NOW_MS).unwrap();

    assert_eq!(report.autostart, Outcome::ManualRepair);
    assert_eq!(std::fs::read(home.autostart()).unwrap(), changed);
    assert_eq!(report.binary, Outcome::Removed);
}

/// Acceptance 5: the binary was replaced by a symlink to a decoy.
#[test]
fn uninstall_keeps_a_symlinked_binary_and_its_target() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let decoy = home.path.join("decoy");
    std::fs::write(&decoy, b"decoy").unwrap();
    std::fs::remove_file(home.binary()).unwrap();
    symlink(&decoy, home.binary()).unwrap();

    let report = uninstall(home.store(), &home.path, false, NOW_MS).unwrap();

    assert_eq!(report.binary, Outcome::ManualRepair);
    assert_eq!(std::fs::read_link(home.binary()).unwrap(), decoy);
    assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy");
}

/// Acceptance 5: the binary's parent directory was replaced by a symlink
/// to a decoy directory holding a same-name file of the same owner.
#[test]
fn uninstall_never_follows_a_symlinked_parent() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let decoy = home.path.join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(decoy.join("syrtis-agent"), b"decoy").unwrap();
    let parent = home.binary().parent().unwrap().to_path_buf();
    std::fs::remove_file(home.binary()).unwrap();
    std::fs::remove_dir(&parent).unwrap();
    symlink(&decoy, &parent).unwrap();

    let report = uninstall(home.store(), &home.path, true, NOW_MS).unwrap();

    assert_eq!(report.binary, Outcome::ManualRepair);
    assert_eq!(std::fs::read(decoy.join("syrtis-agent")).unwrap(), b"decoy");
    // A failed parent removes nothing at all, and blocks the purge.
    assert_eq!(report.autostart, Outcome::ManualRepair);
    assert!(home.autostart().is_file());
    assert!(!report.purged);
    assert!(home.root().join("state.json").is_file());
}

/// Acceptance 5: the binary's parent directory became group-writable.
#[test]
fn uninstall_keeps_objects_under_a_group_writable_parent() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let parent = home.binary().parent().unwrap().to_path_buf();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();

    let report = uninstall(home.store(), &home.path, false, NOW_MS).unwrap();

    assert_eq!(report.binary, Outcome::ManualRepair);
    assert_eq!(std::fs::read(home.binary()).unwrap(), b"agent");
    assert_eq!(report.autostart, Outcome::ManualRepair);
    assert!(home.autostart().is_file());
}

/// Acceptance 6: everything safe.
#[test]
fn purge_removes_state_and_peers_but_keeps_the_owner_lock() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    let store = home.store();
    let identity = store.state().unwrap().identity_public().unwrap();
    let peers = home.root().join("peers.json");
    std::fs::write(&peers, encode_peers(&[]).unwrap()).unwrap();
    std::fs::set_permissions(&peers, std::fs::Permissions::from_mode(0o600)).unwrap();

    let report = uninstall(store, &home.path, true, NOW_MS).unwrap();

    assert_eq!(
        report,
        UninstallReport {
            purged: true,
            ..CLEAN
        }
    );
    assert!(!home.root().join("state.json").exists());
    assert!(!peers.exists());
    assert!(home.root().join("owner.lock").is_file());
    let fresh = home.store().state().unwrap();
    assert_ne!(fresh.identity_public().unwrap(), identity);
}

/// Acceptance 6: one object needs manual repair, so the state stays.
#[test]
fn purge_keeps_state_when_anything_needs_manual_repair() {
    let home = TempHome::new();
    install(&home.path, &home.source(b"agent")).unwrap();
    std::fs::write(home.autostart(), b"edited by hand").unwrap();
    let store = home.store();
    let identity = store.state().unwrap().identity_public().unwrap();

    let report = uninstall(store, &home.path, true, NOW_MS).unwrap();

    assert!(report.manual_repair());
    assert!(!report.purged);
    assert!(home.root().join("state.json").is_file());
    assert_eq!(
        home.store().state().unwrap().identity_public().unwrap(),
        identity
    );
}

/// Acceptance 8: install, upgrade, uninstall, reinstall; only the two
/// frozen objects ever appear, and no temp file is left behind.
#[test]
fn only_the_two_frozen_objects_ever_appear() {
    let home = TempHome::new();
    let frozen = home.frozen_objects();
    assert_eq!(frozen.len(), 2);

    install(&home.path, &home.source(b"agent v1")).unwrap();
    assert_eq!(home.objects_on_disk(), frozen);
    install(&home.path, &home.source(b"agent v2")).unwrap();
    assert_eq!(home.objects_on_disk(), frozen);
    let report = uninstall(home.store(), &home.path, false, NOW_MS).unwrap();
    assert_eq!(report, CLEAN);
    assert!(home.objects_on_disk().is_empty());
    install(&home.path, &home.source(b"agent v2")).unwrap();
    assert_eq!(home.objects_on_disk(), frozen);
}

/// A relative home is refused before anything is touched.
#[test]
fn a_relative_home_is_invalid() {
    let home = TempHome::new();
    assert_eq!(
        install(Path::new("relative/home"), &home.source(b"agent")),
        Err(InstallError::Invalid)
    );
}
