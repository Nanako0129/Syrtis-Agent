//! SA-2B1a storage acceptance through the public API only.
//!
//! Guard-bypass negative controls need test-only seams, so they live in the
//! unit tests of `src/state_store.rs` and `src/secure_fs/unix.rs`.

use std::collections::BTreeSet;

use serde_json::Value;
use syrtis_agent::{
    canonical::CanonicalJsonV1,
    security::{
        CONSENT_SCOPE, Grant, GrantState, Offer, OfferState, Pending, PendingState, ReferenceState,
        Terminal, TerminalKind,
    },
    state_store::{ListenConfig, Secret32, StoredState, decode_state, encode_state},
};

const NOW: i64 = 1_700_000_000;
const NOW_MS: i64 = NOW * 1_000;
const GOLDEN: &str = include_str!("fixtures/v1/runtime/storage/state-golden.json");
const SPEC_V1: &str = include_str!("../spec/v1.md");

/// Synthetic keys only. Every record kind and every enum value appears.
fn golden_state() -> StoredState {
    let mut reference = ReferenceState::new(NOW + 500).unwrap();
    reference.sharing_enabled = true;
    reference.next_auth_epoch = 3;
    reference.deny_floor = 1;
    reference.source_scope_generation = 2;
    let offer = |id: u8, state| Offer {
        offer_id: [id; 16],
        secret_hash: [id ^ 0xa0; 32],
        created_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 600_000,
        state,
    };
    reference.offers = vec![
        offer(0x01, OfferState::Consumed),
        offer(0x02, OfferState::Active),
        offer(0x03, OfferState::Cancelled),
        offer(0x04, OfferState::Expired),
        offer(0x05, OfferState::Consumed),
        offer(0x06, OfferState::Consumed),
        offer(0x07, OfferState::Consumed),
    ];
    let pending = |id: u8, offer: u8, sas: &str, state| Pending {
        pending_id: [id; 16],
        offer_id: [offer; 16],
        initiator_static: [id ^ 0xb0; 32],
        sas_code: sas.into(),
        sas_generation: u64::from(id),
        created_at_ms: NOW_MS + 1_000,
        expires_at_ms: NOW_MS + 600_000,
        state,
    };
    reference.pending = vec![
        pending(0x11, 0x01, "0A1B-2C3D", PendingState::Approved),
        pending(0x12, 0x05, "4E5F-6071", PendingState::Rejected),
        pending(0x13, 0x06, "8293-A4B5", PendingState::AwaitingApproval),
        pending(0x14, 0x07, "C6D7-E8F9", PendingState::Expired),
    ];
    let grant = |id: u8, epoch, generation, state| Grant {
        grant_id: [id; 16],
        initiator_static: [id ^ 0xb0; 32],
        responder_static: [0xc1; 32],
        scope: CONSENT_SCOPE,
        endpoints: [1, 2, 3, 4],
        auth_epoch: epoch,
        source_scope_generation: generation,
        created_at_ms: NOW_MS + 2_000,
        expires_at_ms: NOW_MS + 2_592_000_000,
        state,
    };
    reference.grants = vec![
        grant(0x21, 2, 2, GrantState::Active),
        grant(0x22, 1, 1, GrantState::Revoked),
        grant(0x23, 1, 1, GrantState::Expired),
    ];
    let terminal = |id: u8, kind, epoch, done| Terminal {
        record_id: [id; 16],
        kind,
        auth_epoch: epoch,
        terminal_at_ms: NOW_MS + 3_000,
        cleanup_complete: done,
    };
    reference.terminal = vec![
        terminal(0x03, TerminalKind::Offer, 0, true),
        terminal(0x04, TerminalKind::Offer, 0, false),
        terminal(0x12, TerminalKind::Pending, 0, false),
        terminal(0x14, TerminalKind::Pending, 0, false),
        terminal(0x22, TerminalKind::Grant, 1, false),
        terminal(0x23, TerminalKind::Grant, 1, false),
        terminal(0x31, TerminalKind::Reset, 1, false),
        terminal(0x32, TerminalKind::Uninstall, 1, false),
    ];
    StoredState {
        reference,
        config: ListenConfig {
            bind_host: Some("192.168.1.20".into()),
            bind_port: 49_200,
            node_label: Some("studio-mac".into()),
        },
        identity_private: Secret32::new([0x5a; 32]),
        control_token: Secret32::new([0x6b; 32]),
    }
}

fn spec_fields(surface: &str) -> BTreeSet<&'static str> {
    let prefix = format!("| {surface} |");
    let row = SPEC_V1
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("spec/v1.md has no row {surface}"));
    row.split('|')
        .nth(2)
        .unwrap()
        .trim()
        .trim_matches('`')
        .split(',')
        .collect()
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

/// The serialized key set equals the frozen `spec/v1.md` rows, at every level.
fn assert_frozen_keys(bytes: &[u8]) -> Value {
    let value = CanonicalJsonV1::decode_value(bytes).unwrap();
    assert_eq!(keys(&value), spec_fields("State top level"));
    assert_eq!(keys(&value["config"]), spec_fields("State config"));
    assert_eq!(keys(&value["counters"]), spec_fields("State counters"));
    for (array, surface) in [
        ("offers", "Offer state record"),
        ("pending", "Pending state record"),
        ("grants", "Grant state record"),
        ("terminal", "Terminal state record"),
    ] {
        for record in value[array].as_array().unwrap() {
            assert_eq!(keys(record), spec_fields(surface), "{array}");
        }
    }
    value
}

#[test]
fn the_golden_fixture_is_the_canonical_encoding_of_the_golden_state() {
    let encoded = encode_state(&golden_state()).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert_eq!(GOLDEN.strip_suffix('\n'), Some(text.as_str()));
    assert_eq!(decode_state(&encoded).unwrap(), golden_state());
}

#[test]
fn golden_keys_and_value_encodings_match_the_specs() {
    let value = assert_frozen_keys(GOLDEN.trim_end().as_bytes());
    for array in ["offers", "pending", "grants", "terminal"] {
        assert!(!value[array].as_array().unwrap().is_empty(), "{array}");
    }
    let names = |array: &str, field: &str| -> BTreeSet<String> {
        value[array]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record[field].as_str().unwrap().to_owned())
            .collect()
    };
    let set =
        |items: &[&str]| -> BTreeSet<String> { items.iter().map(|s| s.to_string()).collect() };
    // spec/state-store-v1.md "Value encodings".
    assert_eq!(
        names("offers", "state"),
        set(&["active", "cancelled", "consumed", "expired"])
    );
    assert_eq!(
        names("pending", "state"),
        set(&["approved", "awaitingApproval", "expired", "rejected"])
    );
    assert_eq!(
        names("grants", "state"),
        set(&["active", "expired", "revoked"])
    );
    assert_eq!(
        names("terminal", "kind"),
        set(&["grant", "offer", "pending", "reset", "uninstall"])
    );
    assert_eq!(value["schema"], 1);
    assert_eq!(value["identityPrivate"], "5a".repeat(32));
    assert_eq!(value["offers"][0]["offerId"], "01".repeat(16));
}

#[test]
fn the_grant_codec_matches_the_frozen_grant_serializer() {
    let state = golden_state();
    let value = CanonicalJsonV1::decode_value(GOLDEN.trim_end().as_bytes()).unwrap();
    for (index, grant) in state.reference.grants.iter().enumerate() {
        assert_eq!(
            CanonicalJsonV1::encode(&value["grants"][index]).unwrap(),
            CanonicalJsonV1::encode(grant).unwrap()
        );
    }
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let shown = format!("{:?}", golden_state());
    assert!(shown.contains("Secret32(redacted)"));
    for secret in ["90, 90, 90", "107, 107, 107", "5a5a", "6b6b"] {
        assert!(!shown.contains(secret), "{secret}");
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn platforms_without_a_secure_implementation_fail_closed() {
    use syrtis_agent::secure_fs::{SecureRoot, StorageError, default_root_path, trusted_home};
    assert_eq!(
        SecureRoot::open_under(&std::env::temp_dir(), &["syrtis-agent-never-created"]).err(),
        Some(StorageError::UnsafeState)
    );
    assert_eq!(
        SecureRoot::open_default().err(),
        Some(StorageError::UnsafeState)
    );
    assert_eq!(default_root_path().err(), Some(StorageError::UnsafeState));
    assert_eq!(trusted_home().err(), Some(StorageError::UnsafeState));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use syrtis_agent::{
        secure_fs::{SecureRoot, StorageError, default_root_path, trusted_home},
        security::{
            OfferClaim, PendingApproval, Platform, RootMetadata, hex_encode, offer_secret_hash,
            resolve_secure_root,
        },
        state_store::{AuthorizationQuery, STATE_FILE_MAX_BYTES, StateStore},
    };

    use super::*;

    /// No spaces: the frozen macOS suffix has one, so tests use this suffix,
    /// which exercises the same intermediate-directory and root rules.
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const RESPONDER: [u8; 32] = [0xc1; 32];
    const DAY_MS: i64 = 86_400_000;

    /// A temporary home. Only directories this helper created are removed.
    struct TempHome {
        path: PathBuf,
    }

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-it-{}-{}",
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

        fn state_file(&self) -> PathBuf {
            self.root().join("state.json")
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn try_open(home: &Path, install_wall: i64) -> Result<StateStore, StorageError> {
        StateStore::open(SecureRoot::open_under(home, SUFFIX)?, install_wall)
    }

    fn open(home: &TempHome) -> StateStore {
        try_open(&home.path, NOW).unwrap()
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn offer(n: u8, lifetime_ms: i64) -> Offer {
        Offer {
            offer_id: id(n),
            secret_hash: offer_secret_hash(&id(n), &[n; 32], &RESPONDER),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + lifetime_ms,
            state: OfferState::Active,
        }
    }

    fn claim(offer: u8, pending: u8) -> OfferClaim {
        OfferClaim {
            offer_id: id(offer),
            secret: [offer; 32],
            responder_static: RESPONDER,
            pending_id: id(pending),
            initiator_static: [pending ^ 0xb0; 32],
            sas_code: "0A1B-2C3D".into(),
            sas_generation: 1,
        }
    }

    fn approval(pending: u8, grant: u8, expires_at_ms: i64) -> PendingApproval {
        PendingApproval {
            pending_id: id(pending),
            sas_generation: 1,
            grant_id: id(grant),
            responder_static: RESPONDER,
            grant_expires_at_ms: expires_at_ms,
            disclosure_exact: true,
        }
    }

    /// Offer `n` → pending `n + 10` → grant `n + 20`, at `NOW`.
    fn pair(state: &ReferenceState, n: u8, expires_at_ms: i64) -> ReferenceState {
        let state = state.create_offer(offer(n, 600_000), NOW).unwrap();
        let (state, _, _) = state.claim_offer(claim(n, n + 10), NOW).unwrap();
        state
            .approve_pending(approval(n + 10, n + 20, expires_at_ms), NOW)
            .unwrap()
    }

    fn query(grant: u8, auth_epoch: u64, generation: u64, os_now: i64) -> AuthorizationQuery {
        AuthorizationQuery {
            grant_id: id(grant),
            auth_epoch,
            source_scope_generation: generation,
            endpoint: 1,
            os_now_unix_seconds: os_now,
        }
    }

    /// Re-runs this test binary as a separate process in `mode` and returns
    /// the value it printed after `<tag>:`.
    fn child(mode: &str, home: &Path, env: &[(&str, &str)], tag: &str) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "disk::child_process_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SYRTIS_STORAGE_CHILD", mode)
            .env("SYRTIS_STORAGE_HOME", home)
            .envs(env.iter().copied())
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success(), "{stdout}");
        let marker = format!("{tag}:");
        let start = stdout.find(&marker).unwrap_or_else(|| panic!("{stdout}")) + marker.len();
        stdout[start..].lines().next().unwrap_or("").to_owned()
    }

    /// The child side of `child`. A no-op in a normal test run.
    #[test]
    fn child_process_entry() {
        let Ok(mode) = std::env::var("SYRTIS_STORAGE_CHILD") else {
            return;
        };
        let home = PathBuf::from(std::env::var("SYRTIS_STORAGE_HOME").unwrap());
        match mode.as_str() {
            "reopen" => {
                let state = try_open(&home, NOW).unwrap().state().unwrap();
                println!("STATE:{}", hex_encode(&encode_state(&state).unwrap()));
            }
            "lock" => {
                let result = SecureRoot::open_under(&home, SUFFIX).map(|_| ());
                println!("LOCK:{result:?}");
            }
            "home" => println!("HOME:{}", default_root_path().unwrap().display()),
            other => panic!("unknown child mode {other}"),
        }
    }

    type Step = (&'static str, fn(&StateStore) -> Result<(), StorageError>);

    /// Every `ReferenceState` transition, plus the store's reset.
    const EVERY_TRANSITION: &[Step] = &[
        ("enable", |s| s.transition(|r| r.enable_sharing())),
        ("create offer", |s| {
            s.transition(|r| r.create_offer(offer(1, 600_000), NOW))
        }),
        ("claim", |s| {
            s.transition(|r| r.claim_offer(claim(1, 11), NOW).map(|(next, _, _)| next))
        }),
        ("approve", |s| {
            s.transition(|r| r.approve_pending(approval(11, 21, NOW_MS + 30 * DAY_MS), NOW))
        }),
        ("create offer 2", |s| {
            s.transition(|r| r.create_offer(offer(2, 600_000), NOW))
        }),
        ("cancel", |s| {
            s.transition(|r| r.cancel_offer(id(2), NOW_MS + 1))
        }),
        ("create offer 3", |s| {
            s.transition(|r| r.create_offer(offer(3, 600_000), NOW))
        }),
        ("claim 3", |s| {
            s.transition(|r| r.claim_offer(claim(3, 13), NOW).map(|(next, _, _)| next))
        }),
        ("reject", |s| {
            s.transition(|r| r.reject_pending(id(13), 1, NOW_MS + 2))
        }),
        ("create offer 4", |s| {
            s.transition(|r| r.create_offer(offer(4, 1_000), NOW))
        }),
        ("expire", |s| {
            s.transition(|r| r.expire_one(id(4), NOW_MS + 1_000))
        }),
        ("pair 5", |s| {
            s.transition(|r| Ok(pair(r, 5, NOW_MS + 30 * DAY_MS)))
        }),
        ("revoke", |s| {
            s.transition(|r| r.revoke_commit(id(21), NOW_MS + 3))
        }),
        ("source change", |s| {
            s.transition(|r| r.source_change_commit())
        }),
        ("cleanup complete", |s| {
            s.transition(|r| r.mark_cleanup_complete(id(2), NOW))
        }),
        ("compaction checkpoint", |s| s.checkpoint(NOW + 60)),
        ("disable", |s| s.disable(NOW_MS + 4)),
        ("enable again", |s| s.transition(|r| r.enable_sharing())),
        ("uninstall", |s| s.uninstall(NOW_MS + 5)),
        ("reset", |s| s.reset(NOW + 120, NOW_MS + 6)),
    ];

    #[test]
    fn every_transition_survives_a_new_process_bit_for_bit() {
        let home = TempHome::new();
        drop(open(&home));
        for (name, step) in EVERY_TRANSITION {
            let store = open(&home);
            step(&store).unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let expected = encode_state(&store.state().unwrap()).unwrap();
            let on_disk = std::fs::read(home.state_file()).unwrap();
            assert_eq!(on_disk, expected, "{name}");
            assert_frozen_keys(&on_disk);
            drop(store);
            let reread = child("reopen", &home.path, &[], "STATE");
            assert_eq!(reread, hex_encode(&expected), "{name}");
        }
        let last = open(&home).state().unwrap().reference;
        assert!(
            last.terminal
                .iter()
                .any(|t| t.kind == TerminalKind::Uninstall)
        );
        assert!(
            last.terminal
                .iter()
                .any(|t| t.kind == TerminalKind::Pending)
        );
    }

    #[test]
    fn a_new_state_has_the_specified_initial_values() {
        let home = TempHome::new();
        let store = open(&home);
        let value = assert_frozen_keys(&std::fs::read(home.state_file()).unwrap());
        let port = value["config"]["bindPort"].as_u64().unwrap();
        assert!((49_152..=65_535).contains(&port), "{port}");
        assert_eq!(
            value["config"],
            serde_json::json!({"bindHost": null, "bindPort": port, "nodeLabel": null, "sharingEnabled": false})
        );
        assert_eq!(
            value["counters"],
            serde_json::json!({"denyFloor": 0, "lastAcceptedWallUnixSeconds": NOW, "nextAuthEpoch": 1, "sourceScopeGeneration": 1})
        );
        assert_eq!(value["schema"], 1);
        for array in ["offers", "pending", "grants", "terminal"] {
            assert_eq!(value[array], serde_json::json!([]), "{array}");
        }
        let state = store.state().unwrap();
        assert_ne!(state.identity_private, state.control_token);
        let other = TempHome::new();
        assert_ne!(
            open(&other).state().unwrap().identity_private,
            state.identity_private
        );
    }

    #[test]
    fn a_state_past_256_records_still_revokes_disables_and_reloads() {
        let home = TempHome::new();
        let store = open(&home);
        store
            .transition(|r| {
                let mut state = pair(&r.enable_sharing()?, 1, NOW_MS + 30 * DAY_MS);
                for k in 0..126u8 {
                    let mut offer = offer(0, 600_000);
                    offer.offer_id = [0xee, k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                    state = state.create_offer(offer, NOW)?;
                    state = state.cancel_offer(
                        [0xee, k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        NOW_MS,
                    )?;
                }
                Ok(state)
            })
            .unwrap();
        let count = |r: &ReferenceState| {
            r.offers.len() + r.pending.len() + r.grants.len() + r.terminal.len()
        };
        assert_eq!(count(&store.state().unwrap().reference), 255);
        store
            .transition(|r| r.revoke_commit(id(21), NOW_MS + 1))
            .unwrap();
        store.disable(NOW_MS + 2).unwrap();
        let expected = encode_state(&store.state().unwrap()).unwrap();
        assert_eq!(count(&store.state().unwrap().reference), 257);
        drop(store);
        assert_eq!(
            child("reopen", &home.path, &[], "STATE"),
            hex_encode(&expected)
        );
    }

    #[test]
    fn the_durable_wall_survives_restart_and_a_rolled_back_clock() {
        let home = TempHome::new();
        let store = open(&home);
        store
            .transition(|r| Ok(pair(&r.enable_sharing()?, 1, NOW_MS + 120_000)))
            .unwrap();
        let before_expiry = query(21, 1, 1, NOW);
        // Control: the query itself is valid while the grant is live.
        assert!(store.authorize(&before_expiry));
        store.checkpoint(NOW + 300).unwrap();
        drop(store);

        // Restart with the OS clock rolled back to before the expiry.
        let store = try_open(&home.path, NOW - 1_000).unwrap();
        let wall = store
            .state()
            .unwrap()
            .reference
            .last_accepted_wall_unix_seconds();
        assert_eq!(wall, NOW + 300, "the wall went backwards across a restart");
        assert!(!store.authorize(&before_expiry));
        drop(store);

        // Negative control: had the wall not been carried across the restart,
        // the same rolled-back query would revive the expired grant.
        let mut value =
            CanonicalJsonV1::decode_value(&std::fs::read(home.state_file()).unwrap()).unwrap();
        value["counters"]["lastAcceptedWallUnixSeconds"] = NOW.into();
        std::fs::write(home.state_file(), CanonicalJsonV1::encode(&value).unwrap()).unwrap();
        assert!(open(&home).authorize(&before_expiry));
    }

    #[test]
    fn a_second_process_cannot_take_the_lock_after_a_replace_and_read() {
        let home = TempHome::new();
        let store = open(&home);
        store.transition(|r| r.enable_sharing()).unwrap();
        assert!(store.state().unwrap().reference.sharing_enabled);
        assert_eq!(child("lock", &home.path, &[], "LOCK"), "Err(Busy)");
        drop(store);
        // The child takes the lock and exits; exit releases it.
        assert_eq!(child("lock", &home.path, &[], "LOCK"), "Ok(())");
        open(&home);
    }

    #[test]
    fn the_root_layout_is_owner_only() {
        let home = TempHome::new();
        let store = open(&home);
        for depth in 1..=SUFFIX.len() {
            let path = SUFFIX[..depth]
                .iter()
                .fold(home.path.clone(), |p, c| p.join(c));
            assert_eq!(
                std::fs::symlink_metadata(&path).unwrap().mode() & 0o7777,
                0o700
            );
        }
        for file in ["state.json", "owner.lock"] {
            let meta = std::fs::symlink_metadata(home.root().join(file)).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.mode() & 0o7777, 0o600, "{file}");
            assert_eq!(meta.nlink(), 1);
        }
        drop(store);
        // A symlinked root fails closed through the public API too.
        let other = TempHome::new();
        std::fs::create_dir_all(other.path.join("Library/AppSupport")).unwrap();
        std::os::unix::fs::symlink(home.root(), other.root()).unwrap();
        assert_eq!(
            try_open(&other.path, NOW).err(),
            Some(StorageError::UnsafeState)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_root_is_excluded_from_backups() {
        // Proves only that the exclusion is set; whether Time Machine honours
        // it is not observable in CI.
        let home = TempHome::new();
        drop(open(&home));
        let path =
            std::ffi::CString::new(home.root().into_os_string().into_encoded_bytes()).unwrap();
        let mut value = [0u8; 128];
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"com.apple.metadata:com_apple_backup_excludeItem".as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        let len = usize::try_from(len).unwrap();
        let plist = &value[..len];
        assert!(plist.starts_with(b"bplist00"));
        assert!(plist.windows(17).any(|w| w == b"com.apple.backupd"));
        assert_eq!(plist, syrtis_agent::secure_fs::BACKUP_EXCLUDE_VALUE);
    }

    #[test]
    fn unreadable_states_fail_closed_with_path_free_errors() {
        let home = TempHome::new();
        drop(open(&home));
        let golden = GOLDEN.trim_end();
        let cases: [(Vec<u8>, StorageError); 4] = [
            (
                golden.replace("\"schema\":1", "\"schema\":2").into_bytes(),
                StorageError::Incompatible,
            ),
            (
                golden.replace("\"schema\":1", "\"schema\":0").into_bytes(),
                StorageError::Incompatible,
            ),
            (b"{\"schema\":1}".to_vec(), StorageError::Corrupt),
            (vec![b' '; STATE_FILE_MAX_BYTES + 1], StorageError::Corrupt),
        ];
        for (bytes, expected) in cases {
            std::fs::write(home.state_file(), &bytes).unwrap();
            let error = try_open(&home.path, NOW).err().unwrap();
            assert_eq!(error, expected);
            let shown = format!("{error:?}");
            assert!(
                !shown.contains('/') && !shown.contains("syrtis-agent-it"),
                "{shown}"
            );
        }
        // Control: the golden state itself loads from the same file.
        std::fs::write(home.state_file(), golden).unwrap();
        assert_eq!(
            try_open(&home.path, NOW).unwrap().state().unwrap(),
            golden_state()
        );
    }

    #[test]
    fn reset_continues_counters_clears_records_and_rotates_secrets() {
        let home = TempHome::new();
        let store = open(&home);
        store
            .transition(|r| {
                let state = pair(&r.enable_sharing()?, 1, NOW_MS + 30 * DAY_MS);
                let state = state.create_offer(offer(2, 600_000), NOW)?;
                let state = state.cancel_offer(id(2), NOW_MS)?;
                let state = state.create_offer(offer(3, 600_000), NOW)?;
                let (state, _, _) = state.claim_offer(claim(3, 13), NOW)?;
                state.create_offer(offer(4, 600_000), NOW)
            })
            .unwrap();
        let old_grant = query(21, 1, 1, NOW);
        // Control: the old grant authorizes before the reset.
        assert!(store.authorize(&old_grant));
        let before = store.state().unwrap();
        let old = &before.reference;
        assert!(!old.offers.is_empty() && !old.pending.is_empty() && !old.grants.is_empty());
        assert!(!old.terminal.is_empty());

        // A rolled-back clock is what a reset recovers from: the wall may drop.
        store.reset(NOW - 7_200, NOW_MS + 10).unwrap();
        let after = store.state().unwrap();
        let new = &after.reference;
        assert_eq!(new.next_auth_epoch, old.next_auth_epoch);
        assert_eq!(new.deny_floor, old.next_auth_epoch - 1);
        assert_eq!(new.source_scope_generation, old.source_scope_generation + 1);
        assert_eq!(new.last_accepted_wall_unix_seconds(), NOW - 7_200);
        assert!(new.offers.is_empty() && new.pending.is_empty() && new.grants.is_empty());
        assert!(!new.sharing_enabled);
        assert_eq!(new.terminal[..old.terminal.len()], old.terminal[..]);
        assert_eq!(new.terminal.len(), old.terminal.len() + 1);
        assert_eq!(new.terminal.last().unwrap().kind, TerminalKind::Reset);
        assert_ne!(after.identity_private, before.identity_private);
        assert_ne!(after.control_token, before.control_token);
        assert_eq!(after.config, before.config);

        store.transition(|r| r.enable_sharing()).unwrap();
        for epoch in 0..=new.next_auth_epoch {
            for generation in [1, 2] {
                assert!(!store.authorize(&query(21, epoch, generation, NOW - 7_200)));
            }
        }
        drop(store);
        assert_eq!(
            open(&home).state().unwrap(),
            StoredState {
                reference: {
                    let mut enabled = after.reference.clone();
                    enabled.sharing_enabled = true;
                    enabled
                },
                ..after
            }
        );
    }

    #[test]
    fn the_production_root_path_is_only_computed_and_ignores_the_environment() {
        let path = default_root_path().unwrap();
        let home = trusted_home().unwrap();
        let platform = if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        };
        let all_verified = RootMetadata {
            absolute: true,
            local_filesystem: true,
            owner_matches: true,
            no_symlink_or_reparse: true,
            private_permissions: true,
        };
        let frozen = resolve_secure_root(platform, home.to_str(), None, all_verified).unwrap();
        assert_eq!(format!("{}/", path.display()), frozen);
        let from_child = child(
            "home",
            Path::new("/"),
            &[
                ("HOME", "/tmp/syrtis-attacker-home"),
                ("XDG_STATE_HOME", "/tmp/syrtis-attacker-state"),
            ],
            "HOME",
        );
        assert_eq!(from_child, path.display().to_string());
    }
}
