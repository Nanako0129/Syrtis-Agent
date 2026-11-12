//! SA-2B3cd acceptance: the engine-backed report source (`spec/source-v1.md`).
//!
//! Every test uses a temp home and a temp secure root below it, with session
//! files it writes itself; nothing reads the real home or the network. The
//! two tests that change the process environment or working directory run
//! their work in a child process of this binary (`child_process_entry`).
//! `EngineSource` and the engine dependency are `cfg(unix)`, so is this file.
#![cfg(unix)]

use std::collections::BTreeSet;

use serde_json::Value;

const DEFAULT_ROOTS: &str = include_str!("fixtures/v1/source/default-roots.json");
const ENVIRONMENT_KEYS: &str = include_str!("fixtures/v1/source/environment-keys.json");
const LOCK: &str = include_str!("../Cargo.lock");

/// The engine SHA the lock resolves `tokscale-core` to.
fn locked_engine_sha() -> String {
    let marker = "source = \"git+https://github.com/Nanako0129/tokscale-core?rev=";
    let start = LOCK.find(marker).expect("tokscale-core in Cargo.lock") + marker.len();
    LOCK[start..start + 40].to_owned()
}

/// D1: the frozen list carries no absolute path and no `..`, and it was
/// derived at the SHA the lock pins. A pin change turns this red until the
/// list is derived again.
#[test]
fn default_roots_are_relative_and_pinned_to_the_locked_engine() {
    for fixture in [DEFAULT_ROOTS, ENVIRONMENT_KEYS] {
        let doc: Value = serde_json::from_str(fixture).unwrap();
        assert_eq!(doc["engineSha"], locked_engine_sha().as_str());
    }
    let doc: Value = serde_json::from_str(DEFAULT_ROOTS).unwrap();
    let mut checked = 0;
    for entry in doc["clients"]
        .as_array()
        .unwrap()
        .iter()
        .chain(doc["extraRoots"].as_array().unwrap())
    {
        for key in ["relative", "fallbackRelative"] {
            let Some(path) = entry[key].as_str() else {
                continue;
            };
            assert!(!path.is_empty(), "{entry}");
            assert!(!path.starts_with('/') && !path.starts_with('~'), "{entry}");
            assert!(!path.contains('\\') && !path.contains(':'), "{entry}");
            assert!(path.split('/').all(|part| part != ".."), "{entry}");
            checked += 1;
        }
        assert!(entry["source"].as_str().unwrap().starts_with("src/"));
    }
    assert!(checked > 80, "{checked}");
    // Control: the checks above reject the shapes they name.
    for bad in ["/etc", "~/.x", "a/../b", ".."] {
        let ok = !bad.starts_with('/')
            && !bad.starts_with('~')
            && bad.split('/').all(|part| part != "..");
        assert!(!ok, "{bad}");
    }
}

/// D1: the client part of the frozen list equals the pinned engine's
/// `CLIENTS` table, entry for entry.
#[test]
fn default_client_roots_match_the_pinned_engine_table() {
    use tokscale_core::{PathRoot, clients::CLIENTS};
    let doc: Value = serde_json::from_str(DEFAULT_ROOTS).unwrap();
    let frozen: Vec<(String, String, Value, Value, String)> = doc["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().unwrap().to_owned(),
                entry["root"].as_str().unwrap().to_owned(),
                entry["var"].clone(),
                entry["fallbackRelative"].clone(),
                entry["relative"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let live: Vec<(String, String, Value, Value, String)> = CLIENTS
        .iter()
        .map(|client| {
            let (root, var, fallback) = match client.root {
                PathRoot::Home => ("Home", Value::Null, Value::Null),
                PathRoot::XdgData => ("XdgData", Value::Null, Value::Null),
                PathRoot::Config => ("Config", Value::Null, Value::Null),
                PathRoot::EnvVar {
                    var,
                    fallback_relative,
                } => ("EnvVar", var.into(), fallback_relative.into()),
                PathRoot::ReasonixHome => ("ReasonixHome", Value::Null, Value::Null),
            };
            (
                client.id.to_owned(),
                root.to_owned(),
                var,
                fallback,
                client.relative_path.to_owned(),
            )
        })
        .collect();
    assert_eq!(frozen, live);
}

/// Every client env root of the pinned engine is in the environment-key
/// list the env/cwd test sets.
#[test]
fn the_environment_key_list_covers_every_client_env_root() {
    use tokscale_core::{PathRoot, clients::CLIENTS};
    let doc: Value = serde_json::from_str(ENVIRONMENT_KEYS).unwrap();
    let keys: BTreeSet<&str> = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["key"].as_str().unwrap())
        .collect();
    for client in CLIENTS.iter() {
        match client.root {
            PathRoot::EnvVar { var, .. } => assert!(keys.contains(var), "{var}"),
            PathRoot::ReasonixHome => {
                assert!(keys.contains("REASONIX_HOME") && keys.contains("REASONIX_STATE_HOME"))
            }
            _ => {}
        }
    }
    for key in [
        "HOME",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "TOKSCALE_CONFIG_DIR",
        "TOKSCALE_EXTRA_DIRS",
        "TOKSCALE_HEADLESS_DIR",
        "TMPDIR",
    ] {
        assert!(keys.contains(key), "{key}");
    }
}

mod engine {
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };

    use syrtis_agent::{
        report::{
            AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
            ReportRequest, decode_response,
        },
        report_peer::{ReportSource, SourceError},
        secure_fs::{SecureRoot, StorageError},
        security::{
            AGGREGATION_REVISION, PEER_PROTOCOL_VERSION, REPORT_SCHEMA_VERSION, SecurityError,
            TZDB_REVISION,
        },
        source::{EngineSource, PRICING_DIR, SCOPE_FILE, SOURCE_CACHE_DIR},
        state_store::StateStore,
    };
    use tokscale_core::{
        RemotePricingSnapshot, RemoteSourceContextV1, RemoteSourceScopeTokenV1,
        RemoteUsageBundleV1, RemoteUsageQueryV1, ScannerSettings,
        aggregate_remote_usage_from_source_v1,
    };

    use super::*;

    /// No spaces: the frozen macOS suffix has one; this exercises the same
    /// rules (`tests/runtime_storage_v1.rs` does the same).
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const NOW: i64 = 1_700_000_000;

    /// A temporary directory, `0700`. Only directories this helper created
    /// are removed, by their exact path.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-src-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn root(&self) -> PathBuf {
            SUFFIX.iter().fold(self.path.clone(), |p, c| p.join(c))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn retry_busy<T>(mut f: impl FnMut() -> Result<T, StorageError>) -> Result<T, StorageError> {
        for _ in 0..200 {
            match f() {
                Err(StorageError::Busy) => std::thread::sleep(Duration::from_millis(10)),
                other => return other,
            }
        }
        f()
    }

    fn open_store(home: &Path) -> StateStore {
        retry_busy(|| {
            SecureRoot::open_under(home, SUFFIX).and_then(|root| StateStore::open(root, NOW))
        })
        .unwrap()
    }

    fn config_dir(home: &Path) -> PathBuf {
        home.join(".config")
    }

    fn data_dir(home: &Path) -> PathBuf {
        home.join(".local/share")
    }

    fn source(store: &StateStore, home: &Path, settings: ScannerSettings) -> EngineSource {
        EngineSource::new(
            store.root(),
            home.to_path_buf(),
            config_dir(home),
            data_dir(home),
            settings,
        )
        .unwrap()
    }

    fn request(endpoint: Endpoint, generation: u64) -> ReportRequest {
        ReportRequest {
            aggregation_revision: AGGREGATION_REVISION,
            auth_epoch: 1,
            clients: Vec::new(),
            end_date_exclusive: "2040-01-02".into(),
            endpoint: endpoint.into(),
            grant_id: "11".repeat(16),
            protocol: PEER_PROTOCOL_VERSION,
            report_schema: REPORT_SCHEMA_VERSION,
            request_id: "22".repeat(16),
            source_scope_generation: generation,
            start_date: "2040-01-01".into(),
            timezone: "UTC".into(),
            tzdb_revision: TZDB_REVISION.into(),
        }
    }

    const ENDPOINTS: [Endpoint; 4] = [
        Endpoint::Graph,
        Endpoint::Models,
        Endpoint::Hourly,
        Endpoint::Agents,
    ];

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(600)
    }

    fn report(source: &EngineSource, endpoint: Endpoint, generation: u64) -> Vec<u8> {
        source
            .report(&request(endpoint, generation), far())
            .unwrap_or_else(|error| panic!("{endpoint:?}: {error:?}"))
    }

    fn denied(source: &EngineSource, generation: u64) -> bool {
        ENDPOINTS.iter().all(|endpoint| {
            source.report(&request(*endpoint, generation), far()) == Err(SourceError)
        })
    }

    fn generation(store: &StateStore) -> u64 {
        store.state().unwrap().reference.source_scope_generation
    }

    /// One Claude session line. Every numerator differs, so a swapped field
    /// in the conversion shows up as a changed value.
    fn claude_line(
        stamp: &str,
        request_id: &str,
        model: &str,
        usage: (u64, u64, u64, u64),
    ) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{stamp}","requestId":"{request_id}","message":{{"id":"msg_{request_id}","model":"{model}","usage":{{"input_tokens":{},"output_tokens":{},"cache_read_input_tokens":{},"cache_creation_input_tokens":{}}}}}}}"#,
            usage.0, usage.1, usage.2, usage.3
        )
    }

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    /// The session fixture: two models, two hours, one day.
    fn write_sessions(home: &Path) {
        let lines = [
            claude_line(
                "2040-01-01T11:00:00.000Z",
                "req_a",
                "claude-3-5-sonnet",
                (300, 70, 11, 13),
            ),
            claude_line(
                "2040-01-01T13:30:00.000Z",
                "req_b",
                "claude-3-5-haiku",
                (50, 20, 7, 5),
            ),
        ];
        write(
            &home.join(".claude/projects/fixture/session.jsonl"),
            &(lines.join("\n") + "\n"),
        );
        // The engine's own Codex timing fixture (copied from its tests at
        // the pin): reasoning tokens and the duration, timed-token and
        // sample counters, which the Claude lines leave at zero.
        write(&home.join(".codex/sessions/remote.jsonl"), CODEX_TIMING);
    }

    const CODEX_TIMING: &str = include_str!("fixtures/v1/source/codex-duration-timing.jsonl");

    /// Pricing for the sonnet model only, so one model has a cost and the
    /// other does not.
    fn write_pricing(dir: &Path) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = serde_json::json!({
            "timestamp": stamp,
            "data": {"claude-3-5-sonnet": {
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000004,
            }},
        });
        for name in ["pricing-litellm.json", "pricing-openrouter.json"] {
            std::fs::write(dir.join(name), body.to_string()).unwrap();
        }
    }

    /// The engine's own bundle for the same inputs: the oracle the converted
    /// records are compared with.
    fn engine_bundle(
        home: &Path,
        source: &EngineSource,
        settings: ScannerSettings,
    ) -> RemoteUsageBundleV1 {
        let cache = source.source_cache_dir();
        let fingerprint = RemoteSourceContextV1::preview_fingerprint(
            home,
            &config_dir(home),
            &data_dir(home),
            cache,
            &settings,
        )
        .unwrap();
        let context = RemoteSourceContextV1::new(
            home,
            config_dir(home),
            data_dir(home),
            cache,
            settings,
            RemoteSourceScopeTokenV1::new(fingerprint, 1),
        )
        .unwrap();
        let query = RemoteUsageQueryV1 {
            clients: Vec::new(),
            start_date: "2040-01-01".into(),
            end_date_exclusive: "2040-01-02".into(),
            timezone: "UTC".into(),
            tzdb_revision: TZDB_REVISION.into(),
        };
        let pricing = RemotePricingSnapshot::from_cache_root(source.pricing_dir());
        aggregate_remote_usage_from_source_v1(&context, &query, &pricing).unwrap()
    }

    fn records<R: ReportRecord>(body: &[u8], endpoint: Endpoint, generation: u64) -> Vec<R> {
        decode_response::<R>(body, Some(&request(endpoint, generation)))
            .unwrap()
            .records
    }

    fn json<T: serde::Serialize>(value: &T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    /// Acceptance (1): each endpoint's body decodes with the frozen decoder,
    /// equals the engine's own records field for field, and carries the
    /// fixture's numbers.
    #[test]
    fn four_endpoints_decode_and_match_the_engine_bundle_and_the_fixture() {
        let home = TempDir::new("e2e");
        write_sessions(&home.path);
        let store = open_store(&home.path);
        let source = source(&store, &home.path, ScannerSettings::default());
        write_pricing(source.pricing_dir());
        source.approve(&store).unwrap();
        let generation = generation(&store);

        let graph: Vec<GraphRecord> = records(
            &report(&source, Endpoint::Graph, generation),
            Endpoint::Graph,
            generation,
        );
        let models: Vec<ModelsRecord> = records(
            &report(&source, Endpoint::Models, generation),
            Endpoint::Models,
            generation,
        );
        let hourly: Vec<HourlyRecord> = records(
            &report(&source, Endpoint::Hourly, generation),
            Endpoint::Hourly,
            generation,
        );
        let agents: Vec<AgentsRecord> = records(
            &report(&source, Endpoint::Agents, generation),
            Endpoint::Agents,
            generation,
        );

        let bundle = engine_bundle(&home.path, &source, ScannerSettings::default());
        assert_eq!(json(&graph), json(&bundle.graph));
        assert_eq!(json(&models), json(&bundle.models));
        assert_eq!(json(&hourly), json(&bundle.hourly));
        assert_eq!(json(&agents), json(&bundle.agents));

        // The fixture's numbers, so the oracle is not trivially empty.
        let sonnet = |model: &Option<String>| model.as_deref() == Some("claude-3-5-sonnet");
        let row = graph.iter().find(|r| sonnet(&r.model)).unwrap();
        assert_eq!(row.date, "2040-01-01");
        assert_eq!(row.client, "claude");
        assert_eq!(
            (
                row.input_tokens,
                row.output_tokens,
                row.cache_read_tokens,
                row.cache_write_tokens,
                row.message_count,
            ),
            (300, 70, 11, 13, 1)
        );
        assert!(row.cost_nano_usd > 0, "{row:?}");
        let haiku = graph.iter().find(|r| !sonnet(&r.model)).unwrap();
        assert_eq!(
            (haiku.input_tokens, haiku.output_tokens, haiku.cost_nano_usd),
            (50, 20, 0)
        );
        let claude = |client: &str| client == "claude";
        assert_eq!(graph.iter().filter(|r| claude(&r.client)).count(), 2);
        assert_eq!(models.iter().filter(|r| claude(&r.client)).count(), 2);
        let buckets: BTreeSet<i64> = hourly
            .iter()
            .filter(|r| claude(&r.client))
            .map(|r| r.bucket_start_unix_ms)
            .collect();
        // 2040-01-01T11:00Z and 13:00Z.
        assert_eq!(
            buckets,
            BTreeSet::from([2_209_028_400_000, 2_209_035_600_000])
        );
        let total: u64 = agents
            .iter()
            .filter(|r| claude(&r.client))
            .map(|r| r.input_tokens)
            .sum();
        assert_eq!(total, 350);
        // The Codex lane reaches the counters the Claude lines leave at zero.
        let codex = models.iter().find(|r| r.client == "codex").unwrap();
        assert!(
            codex.reasoning_tokens > 0
                && codex.duration_millis > 0
                && codex.timed_tokens > 0
                && codex.sample_count > 0,
            "{codex:?}"
        );
    }

    /// Acceptance (2): no record → deny; `approve` → served.
    #[test]
    fn no_approval_denies_and_approve_admits() {
        let home = TempDir::new("approve");
        write_sessions(&home.path);
        let store = open_store(&home.path);
        // A temp file left by a crashed approve is removed when the source
        // is built, or the exclusive create in `approve` would fail.
        let stale = home.root().join(format!(".{SCOPE_FILE}.tmp"));
        std::fs::write(&stale, b"{}").unwrap();
        let source = source(&store, &home.path, ScannerSettings::default());
        assert!(!stale.exists());
        let generation = generation(&store);
        assert!(!home.root().join(SCOPE_FILE).exists());
        assert!(denied(&source, generation));
        source.approve(&store).unwrap();
        assert!(home.root().join(SCOPE_FILE).exists());
        for endpoint in ENDPOINTS {
            report(&source, endpoint, generation);
        }
    }

    /// Acceptance (2): a changed `ScannerSettings` field or custom root is a
    /// different source; it is denied until it is approved after a
    /// `source_change_commit`, and then the old inputs are denied.
    #[test]
    fn changed_settings_or_custom_root_deny_until_reapproved() {
        let home = TempDir::new("change");
        write_sessions(&home.path);
        let store = open_store(&home.path);
        let original = source(&store, &home.path, ScannerSettings::default());
        original.approve(&store).unwrap();
        let first = generation(&store);
        report(&original, Endpoint::Graph, first);

        let custom_root = home.path.join("custom");
        let mut with_root = ScannerSettings::default();
        with_root
            .extra_scan_paths
            .insert("claude".into(), vec![custom_root]);
        let mut with_exclusion = ScannerSettings::default();
        with_exclusion
            .excluded_scan_paths
            .insert("claude".into(), vec![home.path.join("excluded")]);
        for settings in [with_root, with_exclusion] {
            let changed = source(&store, &home.path, settings);
            assert!(denied(&changed, generation(&store)));
            store
                .transition(|state| state.source_change_commit())
                .unwrap();
            changed.approve(&store).unwrap();
            let now = generation(&store);
            report(&changed, Endpoint::Graph, now);
            assert!(denied(&original, now));
        }
        assert_eq!(generation(&store), first + 2);
    }

    /// Acceptance (2): approving changed inputs without the generation
    /// advancing is refused and writes nothing; so is a store over another
    /// root.
    #[test]
    fn approve_after_an_input_change_needs_an_advanced_generation() {
        let home = TempDir::new("gen");
        let store = open_store(&home.path);
        source(&store, &home.path, ScannerSettings::default())
            .approve(&store)
            .unwrap();
        let before = std::fs::read(home.root().join(SCOPE_FILE)).unwrap();
        let mut settings = ScannerSettings::default();
        settings
            .extra_scan_paths
            .insert("claude".into(), vec![home.path.join("custom")]);
        let changed = source(&store, &home.path, settings);
        assert_eq!(
            changed.approve(&store),
            Err(StorageError::Refused(SecurityError::Conflict))
        );
        assert_eq!(std::fs::read(home.root().join(SCOPE_FILE)).unwrap(), before);
        // Re-approving the same inputs at the same generation is allowed.
        source(&store, &home.path, ScannerSettings::default())
            .approve(&store)
            .unwrap();

        let other = TempDir::new("other");
        let other_store = open_store(&other.path);
        assert_eq!(
            changed.approve(&other_store),
            Err(StorageError::Refused(SecurityError::Invalid))
        );
        assert_eq!(std::fs::read(home.root().join(SCOPE_FILE)).unwrap(), before);
    }

    /// Acceptance (2): the state's generation moving past the record denies,
    /// even with the inputs unchanged.
    #[test]
    fn an_advanced_state_generation_denies() {
        let home = TempDir::new("adv");
        write_sessions(&home.path);
        let store = open_store(&home.path);
        let source = source(&store, &home.path, ScannerSettings::default());
        source.approve(&store).unwrap();
        let first = generation(&store);
        report(&source, Endpoint::Graph, first);
        store
            .transition(|state| state.source_change_commit())
            .unwrap();
        assert!(denied(&source, first + 1));
        source.approve(&store).unwrap();
        report(&source, Endpoint::Graph, first + 1);
    }

    /// A body ready after the deadline is not returned.
    #[test]
    fn a_report_past_its_deadline_is_a_source_error() {
        let home = TempDir::new("deadline");
        write_sessions(&home.path);
        let store = open_store(&home.path);
        let source = source(&store, &home.path, ScannerSettings::default());
        source.approve(&store).unwrap();
        let generation = generation(&store);
        assert_eq!(
            source.report(&request(Endpoint::Graph, generation), Instant::now()),
            Err(SourceError)
        );
        report(&source, Endpoint::Graph, generation);
    }

    /// A cc-mirror variant whose `configDir` (file content) names `config`.
    fn write_variant(home: &Path, config: &Path) {
        write(
            &home.join(".cc-mirror/probe/variant.json"),
            &serde_json::json!({"name": "probe", "provider": "kimi", "configDir": config})
                .to_string(),
        );
        write(
            &config.join("projects/proj/session.jsonl"),
            &claude_line(
                "2040-01-01T12:00:00.000Z",
                "req_probe",
                "claude-3-5-sonnet",
                (900, 90, 9, 9),
            ),
        );
    }

    fn all_bodies(source: &EngineSource, generation: u64) -> Vec<Vec<u8>> {
        ENDPOINTS
            .iter()
            .map(|endpoint| report(source, *endpoint, generation))
            .collect()
    }

    /// Acceptance (3), escape smoke test: a pointer in a file below the home
    /// to data outside every approved root yields nothing on any endpoint;
    /// the same pointer aimed inside the home yields the data (control).
    #[test]
    fn a_cc_mirror_pointer_outside_the_approved_roots_yields_no_data() {
        let home = TempDir::new("escape");
        let outside = TempDir::new("decoy");
        let store = open_store(&home.path);
        let source = source(&store, &home.path, ScannerSettings::default());
        source.approve(&store).unwrap();
        let generation = generation(&store);

        write_variant(&home.path, &outside.path.join("config"));
        for body in all_bodies(&source, generation) {
            let text = String::from_utf8(body).unwrap();
            assert!(!text.contains("probe"), "{text}");
            assert!(!text.contains("\"inputTokens\":900"), "{text}");
        }

        write_variant(&home.path, &home.path.join("inside-config"));
        let graph: Vec<GraphRecord> = records(
            &report(&source, Endpoint::Graph, generation),
            Endpoint::Graph,
            generation,
        );
        let probe = graph
            .iter()
            .find(|row| row.client == "cc-mirror/probe")
            .unwrap_or_else(|| panic!("{graph:?}"));
        assert_eq!(probe.input_tokens, 900);
    }

    /// Runs `mode` in a child of this test binary with `env` and `cwd`, and
    /// returns its marker line. The child must print the marker, so a child
    /// that skipped its work (filtered out, early return) fails here.
    fn child(mode: &str, home: &Path, env: &[(String, PathBuf)], cwd: &Path) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine::child_process_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SYRTIS_SOURCE_CHILD", mode)
            .env("SYRTIS_SOURCE_HOME", home)
            .envs(env.iter().map(|(key, value)| (key, value)))
            .current_dir(cwd)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(output.status.success(), "{stdout}\n{stderr}");
        let marker = format!("{mode}-OK:");
        let start = stdout
            .find(&marker)
            .unwrap_or_else(|| panic!("{stdout}\n{stderr}"))
            + marker.len();
        stdout[start..].lines().next().unwrap_or("").to_owned()
    }

    fn env_keys() -> Vec<String> {
        let doc: Value = serde_json::from_str(ENVIRONMENT_KEYS).unwrap();
        doc["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["key"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Every entry below `dir`, recursively; empty when `dir` is empty.
    fn entries(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                found.extend(entries(&path));
            }
            found.push(path);
        }
        found
    }

    /// Acceptance (4): with every environment key the engine names (and
    /// `HOME`, `XDG_*`, `TOKSCALE_*`, `TMPDIR`) pointing at a decoy tree
    /// that holds session data, and the working directory inside it, the
    /// four bodies are byte for byte the ones produced before. Runs in a
    /// child process; the child starts with every key pointing at an empty
    /// directory, so neither run can reach the real home.
    #[test]
    fn environment_and_cwd_do_not_change_the_output() {
        let home = TempDir::new("env");
        let empty = TempDir::new("empty");
        let decoy = TempDir::new("envdecoy");
        let mut env: Vec<(String, PathBuf)> = env_keys()
            .into_iter()
            .map(|key| (key, empty.path.clone()))
            .collect();
        env.push(("SYRTIS_SOURCE_DECOY".into(), decoy.path.clone()));
        let line = child("ENV", &home.path, &env, &empty.path);
        let bodies: usize = line.trim().parse().unwrap();
        assert_eq!(bodies, 4);
        assert!(
            entries(&empty.path).is_empty(),
            "{:?}",
            entries(&empty.path)
        );
    }

    /// Acceptance (5): the engine's source cache lands below the secure
    /// root, and nothing lands in `$TMPDIR`, `$XDG_RUNTIME_DIR` or the
    /// environment's home and config roots (the engine's message-cache
    /// fallback would use `$TMPDIR/tokscale-uid-*`).
    #[test]
    fn engine_caches_stay_below_the_secure_root() {
        let home = TempDir::new("tmp");
        let tmp = TempDir::new("tmpdir");
        let runtime = TempDir::new("runtime");
        let env_home = TempDir::new("envhome");
        let env = [
            ("TMPDIR", tmp.path.clone()),
            ("XDG_RUNTIME_DIR", runtime.path.clone()),
            ("HOME", env_home.path.clone()),
            ("XDG_CACHE_HOME", env_home.path.join(".cache")),
            ("XDG_CONFIG_HOME", env_home.path.join(".config")),
            ("XDG_DATA_HOME", env_home.path.join(".local/share")),
            ("XDG_STATE_HOME", env_home.path.join(".local/state")),
            ("TOKSCALE_CONFIG_DIR", env_home.path.join("tokscale")),
        ]
        .map(|(key, value)| (key.to_owned(), value));
        child("TMP", &home.path, &env, &env_home.path);
        for dir in [&tmp.path, &runtime.path, &env_home.path] {
            assert!(entries(dir).is_empty(), "{dir:?}: {:?}", entries(dir));
        }
        let cache = home.root().join(SOURCE_CACHE_DIR);
        assert!(
            !entries(&cache).is_empty(),
            "the engine wrote no source cache"
        );
        // The pricing root holds only what the child wrote there.
        let pricing: BTreeSet<PathBuf> = entries(&home.root().join(PRICING_DIR))
            .into_iter()
            .map(|path| PathBuf::from(path.file_name().unwrap()))
            .collect();
        assert_eq!(
            pricing,
            BTreeSet::from([
                PathBuf::from("pricing-litellm.json"),
                PathBuf::from("pricing-openrouter.json"),
            ])
        );
    }

    /// The child side of `child`. A no-op in a normal test run.
    #[test]
    fn child_process_entry() {
        let Ok(mode) = std::env::var("SYRTIS_SOURCE_CHILD") else {
            return;
        };
        let home = PathBuf::from(std::env::var("SYRTIS_SOURCE_HOME").unwrap());
        write_sessions(&home);
        let store = open_store(&home);
        let source = source(&store, &home, ScannerSettings::default());
        write_pricing(source.pricing_dir());
        source.approve(&store).unwrap();
        let generation = generation(&store);
        match mode.as_str() {
            "ENV" => {
                let before = all_bodies(&source, generation);
                let decoy = PathBuf::from(std::env::var_os("SYRTIS_SOURCE_DECOY").unwrap());
                // Session data where a lane reading HOME, XDG_*, CODEX_HOME,
                // CLAUDE-style projects or the cwd would find it.
                for relative in [
                    ".claude/projects/decoy/s.jsonl",
                    "projects/decoy/s.jsonl",
                    "sessions/decoy.jsonl",
                    ".local/share/opencode/storage/message/p/m.jsonl",
                ] {
                    write(
                        &decoy.join(relative),
                        &claude_line(
                            "2040-01-01T10:00:00.000Z",
                            "req_decoy",
                            "decoy-model",
                            (777, 77, 7, 7),
                        ),
                    );
                }
                for key in env_keys() {
                    // SAFETY: this child runs only this test, on one thread
                    // (`--test-threads=1`, `--exact`), so nothing reads the
                    // environment concurrently.
                    unsafe { std::env::set_var(&key, &decoy) };
                }
                std::env::set_current_dir(&decoy).unwrap();
                let after = all_bodies(&source, generation);
                assert_eq!(before, after);
                for body in &after {
                    assert!(!String::from_utf8_lossy(body).contains("decoy"));
                }
                println!("ENV-OK:{}", after.len());
            }
            "TMP" => {
                all_bodies(&source, generation);
                println!("TMP-OK:4");
            }
            other => panic!("unknown mode {other}"),
        }
    }
}
