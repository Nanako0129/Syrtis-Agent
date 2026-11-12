//! SA-2C2a acceptance: the library entry point `Agent` and `merge::combine`
//! (`spec/agent-v1.md`).
//!
//! The `combine` tests are portable. Everything else runs two agents in
//! temp homes (below `/tmp`, so the control socket path fits) with session
//! files the test writes itself, paired over loopback; nothing reads the
//! real home, starts a service, or leaves loopback. Acceptance (8b) is a
//! unit test in `src/secure_fs/unix.rs`.

use syrtis_agent::{
    merge::{FailureClass, PartStatus, PeerData, PeerPart, Report, classify, combine},
    noise::NoiseError,
    report::{Endpoint, GraphRecord},
    report_peer::{FetchError, Records},
    runtime::PullError,
};

/// Review fix 2: the classification table of `spec/agent-v1.md`, entry
/// for entry. Only `NoAnswer` falls back to the cached body.
#[test]
fn classify_matches_the_spec_table() {
    use FailureClass::{InvalidReply, NoAnswer, Refused};
    let table = [
        (PullError::NoPeer, Refused),
        (PullError::Fetch(FetchError::InvalidQuery), NoAnswer),
        (PullError::Fetch(FetchError::Unusable), Refused),
        (PullError::Fetch(FetchError::TooMany), NoAnswer),
        (PullError::Fetch(FetchError::Expired), Refused),
        (PullError::Fetch(FetchError::Revoked), Refused),
        (PullError::Fetch(FetchError::CheckGrantStatus), Refused),
        (PullError::Fetch(FetchError::Busy), NoAnswer),
        (PullError::Fetch(FetchError::Internal), Refused),
        (PullError::Fetch(FetchError::Rejected), Refused),
        (
            PullError::Fetch(FetchError::Transport(NoiseError::Io)),
            NoAnswer,
        ),
        (
            PullError::Fetch(FetchError::Transport(NoiseError::Crypto)),
            NoAnswer,
        ),
        (PullError::Fetch(FetchError::Timeout), NoAnswer),
        (PullError::Fetch(FetchError::Protocol), InvalidReply),
        (PullError::Fetch(FetchError::Invalid), InvalidReply),
        (PullError::Fetch(FetchError::Memory), NoAnswer),
        (PullError::Fetch(FetchError::TooLarge), NoAnswer),
    ];
    for (error, class) in table {
        assert_eq!(classify(error), class, "{error:?}");
    }
}

fn graph(date: &str, client: &str, input: u64) -> GraphRecord {
    GraphRecord {
        date: date.into(),
        client: client.into(),
        model: Some("m".into()),
        provider: None,
        input_tokens: input,
        output_tokens: 1,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: input.saturating_add(1),
        message_count: 1,
        turn_count: 1,
        cost_nano_usd: 0,
    }
}

fn report(records: Vec<GraphRecord>, saturated: bool) -> Report {
    Report {
        records: Records::Graph(records),
        saturated,
    }
}

fn part(producer: u8, grant: u8, data: PeerData) -> PeerPart {
    PeerPart {
        producer_static: [producer; 32],
        grant_id: [grant; 16],
        data,
        error: None,
    }
}

fn inputs(records: &Option<Records>) -> Vec<(String, u64)> {
    match records {
        Some(Records::Graph(records)) => records
            .iter()
            .map(|r| (r.client.clone(), r.input_tokens))
            .collect(),
        other => panic!("{other:?}"),
    }
}

/// Acceptance (5): a peer whose records fail the frozen validation (a bad
/// date) and one of another endpoint are left out alone; the local part
/// and the good peer are summed.
#[test]
fn combine_leaves_out_only_the_invalid_peers() {
    let combined = combine(
        Endpoint::Graph,
        Some(report(vec![graph("2040-01-01", "claude", 5)], false)),
        vec![
            part(
                1,
                1,
                PeerData::Fresh(report(vec![graph("2040-01-01", "claude", 7)], false)),
            ),
            part(
                2,
                1,
                PeerData::Fresh(report(vec![graph("2040-13-45", "claude", 100)], false)),
            ),
            part(
                3,
                1,
                PeerData::LastGood(Report {
                    records: Records::Agents(Vec::new()),
                    saturated: false,
                }),
            ),
        ],
    );
    assert_eq!(inputs(&combined.records), [("claude".into(), 12)]);
    assert_eq!(combined.local, Some(PartStatus::Fresh));
    let statuses: Vec<_> = combined.peers.iter().map(|p| p.status).collect();
    assert_eq!(
        statuses,
        [PartStatus::Fresh, PartStatus::Invalid, PartStatus::Invalid]
    );
}

/// Acceptance (5): two parts of one producer keep one (`Fresh` before
/// `LastGood`), the other is `Duplicate`; every order of the input gives
/// the same result.
#[test]
fn combine_keeps_one_part_per_producer_whatever_the_order() {
    let parts = vec![
        part(
            9,
            1,
            PeerData::LastGood(report(vec![graph("2040-01-01", "codex", 1000)], false)),
        ),
        part(
            9,
            2,
            PeerData::Fresh(report(vec![graph("2040-01-01", "codex", 3)], false)),
        ),
        part(
            4,
            1,
            PeerData::Fresh(report(vec![graph("2040-01-01", "claude", 2)], false)),
        ),
        part(4, 3, PeerData::None),
    ];
    let expected = combine(Endpoint::Graph, None, parts.clone());
    assert_eq!(
        inputs(&expected.records),
        [("claude".into(), 2), ("codex".into(), 3)]
    );
    let statuses: Vec<_> = expected
        .peers
        .iter()
        .map(|p| (p.producer_static[0], p.grant_id[0], p.status))
        .collect();
    assert_eq!(
        statuses,
        [
            (4, 1, PartStatus::Fresh),
            (4, 3, PartStatus::Duplicate),
            (9, 2, PartStatus::Fresh),
            (9, 1, PartStatus::Duplicate),
        ]
    );
    for order in [[3, 2, 1, 0], [1, 0, 3, 2], [2, 3, 0, 1], [0, 2, 1, 3]] {
        let shuffled = order.iter().map(|&i| parts[i].clone()).collect();
        assert_eq!(
            combine(Endpoint::Graph, None, shuffled),
            expected,
            "{order:?}"
        );
    }
}

/// Acceptance (5): `saturated` from a kept part, and from a sum the frozen
/// merge saturated, reaches the result; a left-out part's flag does not.
#[test]
fn combine_carries_saturation() {
    let plain = |input| report(vec![graph("2040-01-01", "claude", input)], false);
    let none = combine(Endpoint::Graph, Some(plain(1)), vec![]);
    assert!(!none.saturated);
    let flagged = combine(
        Endpoint::Graph,
        Some(plain(1)),
        vec![part(
            1,
            1,
            PeerData::LastGood(report(vec![graph("2040-01-02", "codex", 1)], true)),
        )],
    );
    assert!(flagged.saturated);
    let summed = combine(
        Endpoint::Graph,
        Some(plain(u64::MAX - 1)),
        vec![part(1, 1, PeerData::Fresh(plain(5)))],
    );
    assert!(summed.saturated);
    assert_eq!(inputs(&summed.records), [("claude".into(), u64::MAX)]);
    let dropped = combine(
        Endpoint::Graph,
        Some(plain(1)),
        vec![part(
            1,
            1,
            PeerData::Fresh(report(vec![graph("bad", "x", 1)], true)),
        )],
    );
    assert!(!dropped.saturated);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod live {
    use std::{
        collections::BTreeMap,
        fs,
        net::TcpListener,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use serde_json::{Value, json};
    use syrtis_agent::{
        agent::{Agent, AgentConfig, AgentError, ScannerSettings},
        control::{Client, Command, LISTEN_CONFIGURE, OFFER_CREATE, OK, REVOKE, STATUS},
        install::{self, Outcome},
        merge::{Combined, PartStatus},
        noise::StaticKey,
        pairing::{ClaimAttempts, Clock, PairingClient, approve},
        peer_store::PeerRecord,
        report::{
            AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
            ReportRequest, ReportResponse, decode_response, encode_response,
        },
        report_peer::{FetchError, ReportQuery, ReportSource, SourceError},
        runtime::{Options, PullError, Runtime, RuntimeError},
        secure_fs::{SecureRoot, StorageError},
        security::{
            AGGREGATION_REVISION, GrantState, MemoryLedger, PEER_PROTOCOL_VERSION,
            REPORT_SCHEMA_VERSION, TZDB_REVISION, hex_encode,
        },
        source::{SCOPE_FILE, SOURCE_CACHE_DIR},
        state_store::Secret32,
    };

    use super::Records;

    const SUFFIX: &[&str] = &["r"];
    const LOOPBACK: &str = "127.0.0.1";
    const ENDPOINTS: [Endpoint; 4] = [
        Endpoint::Graph,
        Endpoint::Models,
        Endpoint::Hourly,
        Endpoint::Agents,
    ];

    /// Injected time starting at the real wall clock; `advance` moves both
    /// clocks, so a grant's rate tokens refill without waiting.
    struct TestClock {
        os: AtomicI64,
        mono: Mutex<Duration>,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Arc::new(Self {
                os: AtomicI64::new(now as i64),
                mono: Mutex::new(Duration::ZERO),
            })
        }

        fn advance(&self, seconds: u64) {
            *self.mono.lock().unwrap() += Duration::from_secs(seconds);
            self.os.fetch_add(seconds as i64, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn monotonic(&self) -> Duration {
            *self.mono.lock().unwrap()
        }

        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            Ok(self.os.load(Ordering::SeqCst))
        }

        fn sleep(&self, duration: Duration) {
            self.advance(duration.as_secs());
        }
    }

    /// A short temp home below the real `/tmp` (canonical, so no path
    /// component is a symlink). Only this directory is removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = fs::canonicalize("/tmp").unwrap().join(format!(
                "sag-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join(SUFFIX[0])
        }

        fn source_cache(&self) -> PathBuf {
            self.root().join(SOURCE_CACHE_DIR)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn claude_line(stamp: &str, id: &str, model: &str, usage: (u64, u64, u64, u64)) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{stamp}","requestId":"{id}","message":{{"id":"msg_{id}","model":"{model}","usage":{{"input_tokens":{},"output_tokens":{},"cache_read_input_tokens":{},"cache_creation_input_tokens":{}}}}}}}"#,
            usage.0, usage.1, usage.2, usage.3
        )
    }

    /// The fixture of `tests/runtime_source_v1.rs`: two Claude models on
    /// one day, plus the engine's own Codex timing fixture.
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
        write(
            &home.join(".codex/sessions/remote.jsonl"),
            include_str!("fixtures/v1/source/codex-duration-timing.jsonl"),
        );
    }

    fn config(home: &Path, clock: &Arc<TestClock>, settings: ScannerSettings) -> AgentConfig {
        let mut config = AgentConfig::new(
            home.to_path_buf(),
            home.join(".config"),
            home.join(".local/share"),
            settings,
        );
        config.state_suffix = SUFFIX;
        config.options = Options {
            clock: Arc::clone(clock) as Arc<dyn Clock>,
            housekeeping_period: Duration::from_secs(60),
        };
        config
    }

    /// Starts an agent, retrying while a reopen still sees the owner lock.
    fn start(home: &TempHome, clock: &Arc<TestClock>, settings: ScannerSettings) -> Agent {
        for _ in 0..200 {
            match Agent::start(config(&home.0, clock, settings.clone())) {
                Err(AgentError::Storage(StorageError::Busy))
                | Err(AgentError::Runtime(RuntimeError::Store(StorageError::Busy))) => {
                    thread::sleep(Duration::from_millis(10))
                }
                other => return other.unwrap(),
            }
        }
        panic!("the agent did not start");
    }

    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn call(runtime: &Runtime, id: u16, body: Value) -> Value {
        let token = *runtime.store().state().unwrap().control_token.expose();
        let reply = Client::new(Secret32::new(token), runtime.socket_path().to_path_buf())
            .call(&Command { id, body })
            .unwrap();
        assert_eq!(reply.code, OK);
        reply.data
    }

    /// A producer with the session fixture, listening on loopback.
    fn producer(home: &TempHome, clock: &Arc<TestClock>) -> Agent {
        write_sessions(&home.0);
        let agent = start(home, clock, ScannerSettings::default());
        call(
            agent.runtime(),
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": free_port()}),
        );
        agent
    }

    /// Pairs `receiver` with `producer` (sharing turned on first if off);
    /// returns the producer's static key.
    fn pair(producer: &Runtime, receiver: &Agent, clock: &TestClock) -> [u8; 32] {
        let _ = producer.enable_sharing();
        let url = call(producer, OFFER_CREATE, json!({"ttlSeconds": 600}))["pairUrl"]
            .as_str()
            .unwrap()
            .to_owned();
        let identity = StaticKey::from_state(&receiver.runtime().store().state().unwrap()).unwrap();
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &identity,
            ledger: &ledger,
            clock,
        };
        let now = clock.os_now_seconds().unwrap();
        let claimed = client
            .claim(&url, now * 1_000, &mut ClaimAttempts::default())
            .unwrap();
        approve(producer.store(), claimed.pending_id, 1, true, now).unwrap();
        let confirmed = client.poll(&claimed).unwrap();
        receiver
            .runtime()
            .peers()
            .upsert(PeerRecord::from_confirmed(&confirmed, None, now * 1_000))
            .unwrap();
        confirmed.responder_static
    }

    fn query(endpoint: Endpoint) -> ReportQuery {
        ReportQuery {
            endpoint,
            start_date: "2040-01-01".into(),
            end_date_exclusive: "2040-01-02".into(),
            timezone: "UTC".into(),
            clients: Vec::new(),
        }
    }

    /// `pull_all` after the grant's rate tokens refilled.
    fn pull_all(receiver: &Agent, clock: &TestClock, endpoint: Endpoint) -> Combined {
        clock.advance(61);
        receiver.pull_all(&query(endpoint), None)
    }

    fn status_of(combined: &Combined, producer: &[u8; 32]) -> PartStatus {
        combined
            .peers
            .iter()
            .find(|peer| peer.producer_static == *producer)
            .unwrap()
            .status
    }

    fn is_empty(combined: &Combined) -> bool {
        match combined.records.as_ref().unwrap() {
            Records::Graph(r) => r.is_empty(),
            Records::Models(r) => r.is_empty(),
            Records::Hourly(r) => r.is_empty(),
            Records::Agents(r) => r.is_empty(),
        }
    }

    fn generation(agent: &Agent) -> u64 {
        agent
            .runtime()
            .store()
            .state()
            .unwrap()
            .reference
            .source_scope_generation
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

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(600)
    }

    /// The producer's own source asked directly: the oracle.
    fn direct(producer: &Agent, endpoint: Endpoint) -> Records {
        fn typed<R: ReportRecord>(body: &[u8], wrap: fn(Vec<R>) -> Records) -> Records {
            wrap(decode_response::<R>(body, None).unwrap().records)
        }
        let body = producer
            .source()
            .report(&request(endpoint, generation(producer)), far())
            .unwrap();
        match endpoint {
            Endpoint::Graph => typed::<GraphRecord>(&body, Records::Graph),
            Endpoint::Models => typed::<ModelsRecord>(&body, Records::Models),
            Endpoint::Hourly => typed::<HourlyRecord>(&body, Records::Hourly),
            Endpoint::Agents => typed::<AgentsRecord>(&body, Records::Agents),
        }
    }

    fn active_grants(agent: &Agent) -> usize {
        agent
            .runtime()
            .store()
            .state()
            .unwrap()
            .reference
            .grants
            .iter()
            .filter(|grant| grant.state == GrantState::Active)
            .count()
    }

    fn sharing(agent: &Agent) -> bool {
        agent
            .runtime()
            .store()
            .state()
            .unwrap()
            .reference
            .sharing_enabled
    }

    fn entries(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    /// Acceptance (1), the Outcome: the receiver's merged report of each
    /// endpoint equals the producer's own records and the fixture's
    /// numbers; after the producer's uninstall (and a restart, so it
    /// answers) the receiver gets nothing, fresh or cached.
    #[test]
    fn e2e_four_endpoints_merge_to_the_producer_fixture_and_nothing_after_uninstall() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        producer.approve_scope().unwrap();
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(producer.runtime(), &receiver, &clock);

        for endpoint in ENDPOINTS {
            let combined = pull_all(&receiver, &clock, endpoint);
            assert_eq!(status_of(&combined, &producer_static), PartStatus::Fresh);
            assert!(!is_empty(&combined), "{endpoint:?}");
            assert_eq!(combined.records.unwrap(), direct(&producer, endpoint));
        }
        let combined = pull_all(&receiver, &clock, Endpoint::Graph);
        let Some(Records::Graph(graph)) = combined.records else {
            panic!()
        };
        let sonnet = graph
            .iter()
            .find(|r| r.model.as_deref() == Some("claude-3-5-sonnet"))
            .unwrap();
        assert_eq!(
            (
                sonnet.input_tokens,
                sonnet.output_tokens,
                sonnet.cache_read_tokens,
                sonnet.cache_write_tokens
            ),
            (300, 70, 11, 13)
        );
        assert!(graph.iter().any(|r| r.client == "codex"));

        producer.uninstall(false).unwrap();
        let producer = start(&producer_home, &clock, ScannerSettings::default());
        let combined = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(status_of(&combined, &producer_static), PartStatus::Refused);
        assert!(is_empty(&combined));
        assert_eq!(
            combined.peers[0].error,
            Some(PullError::Fetch(FetchError::Revoked))
        );
        // The revoked answer marked the peer record and removed the cached
        // entries: nothing is pulled or read any more.
        for endpoint in ENDPOINTS {
            let combined = pull_all(&receiver, &clock, endpoint);
            assert!(combined.peers.is_empty() && is_empty(&combined));
            assert!(
                receiver
                    .runtime()
                    .last_good(&producer_static, &query(endpoint))
                    .unwrap()
                    .is_none()
            );
        }
        drop(producer);
    }

    /// Acceptance (6): with the producer stopped, `pull_all` returns the
    /// last good body, marked as such, with the failed pull's error.
    #[test]
    fn pull_all_falls_back_to_last_good_when_the_producer_is_stopped() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        producer.approve_scope().unwrap();
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(producer.runtime(), &receiver, &clock);
        let fresh = pull_all(&receiver, &clock, Endpoint::Models);
        assert_eq!(status_of(&fresh, &producer_static), PartStatus::Fresh);
        drop(producer);

        let cached = pull_all(&receiver, &clock, Endpoint::Models);
        assert_eq!(status_of(&cached, &producer_static), PartStatus::LastGood);
        assert!(cached.peers[0].error.is_some());
        assert_eq!(cached.records, fresh.records);
        assert!(!is_empty(&cached));
    }

    /// Acceptance (2): unapproved, the producer serves nothing; approving
    /// after pairing ends the earlier grant (pair again); approving first
    /// and pairing after works.
    #[test]
    fn scope_must_be_approved_and_a_first_approval_ends_earlier_grants() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        assert!(!producer.scope_approved());
        let producer_static = pair(producer.runtime(), &receiver, &clock);
        let refused = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(status_of(&refused, &producer_static), PartStatus::Refused);
        assert!(is_empty(&refused));

        let before = generation(&producer);
        producer.approve_scope().unwrap();
        assert!(producer.scope_approved());
        assert_eq!(generation(&producer), before + 1);
        let old_grant = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(
            status_of(&old_grant, &producer_static),
            PartStatus::Refused,
            "a grant made before the first approval still reads"
        );
        assert!(is_empty(&old_grant));

        pair(producer.runtime(), &receiver, &clock);
        let paired = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(status_of(&paired, &producer_static), PartStatus::Fresh);
        assert!(!is_empty(&paired));
    }

    /// Acceptance (3): new scan settings after a restart are not approved
    /// and are refused; `approve_scope` moves the generation and ends the
    /// old grant; approving unchanged inputs again writes nothing and the
    /// grant stays valid.
    #[test]
    fn changed_settings_need_approval_and_end_the_old_grant() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        producer.approve_scope().unwrap();
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(producer.runtime(), &receiver, &clock);
        assert_eq!(
            status_of(
                &pull_all(&receiver, &clock, Endpoint::Graph),
                &producer_static
            ),
            PartStatus::Fresh
        );
        drop(producer);

        let extra = producer_home.0.join("extra");
        fs::create_dir(&extra).unwrap();
        let settings = ScannerSettings {
            extra_scan_paths: BTreeMap::from([("claude".to_owned(), vec![extra])]),
            ..ScannerSettings::default()
        };
        let producer = start(&producer_home, &clock, settings);
        assert!(!producer.scope_approved());
        // The producer answers `internal` (its source denies): a refusal,
        // so the cached body that is still there is not used.
        let denied = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(status_of(&denied, &producer_static), PartStatus::Refused);
        assert_eq!(
            denied.peers[0].error,
            Some(PullError::Fetch(FetchError::Internal))
        );
        assert!(is_empty(&denied));
        assert!(
            receiver
                .runtime()
                .last_good(&producer_static, &query(Endpoint::Graph))
                .unwrap()
                .is_some()
        );
        assert!(
            producer
                .source()
                .report(&request(Endpoint::Graph, generation(&producer)), far())
                .is_err()
        );

        let before = generation(&producer);
        producer.approve_scope().unwrap();
        assert!(producer.scope_approved());
        assert_eq!(generation(&producer), before + 1);
        assert_ne!(
            status_of(
                &pull_all(&receiver, &clock, Endpoint::Graph),
                &producer_static
            ),
            PartStatus::Fresh,
            "the grant from before the change still reads"
        );

        pair(producer.runtime(), &receiver, &clock);
        assert_eq!(
            status_of(
                &pull_all(&receiver, &clock, Endpoint::Graph),
                &producer_static
            ),
            PartStatus::Fresh
        );
        let scope = producer_home.root().join(SCOPE_FILE);
        let (ino, mtime) = {
            let meta = fs::metadata(&scope).unwrap();
            (meta.ino(), meta.mtime_nsec())
        };
        let generation_now = generation(&producer);
        producer.approve_scope().unwrap();
        let meta = fs::metadata(&scope).unwrap();
        assert_eq!((meta.ino(), meta.mtime_nsec()), (ino, mtime));
        assert_eq!(generation(&producer), generation_now);
        assert_eq!(
            status_of(
                &pull_all(&receiver, &clock, Endpoint::Graph),
                &producer_static
            ),
            PartStatus::Fresh
        );
    }

    /// Acceptance (4): `reset` keeps the record but unapproves it; the next
    /// `approve_scope` approves again without moving the generation past
    /// the value `reset` set, and a new pairing reads.
    #[test]
    fn after_reset_approve_scope_reapproves_without_another_commit() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        producer.approve_scope().unwrap();
        let now = clock.os_now_seconds().unwrap();
        producer.runtime().store().reset(now, now * 1_000).unwrap();
        let after_reset = generation(&producer);
        assert!(producer.source().scope_record().unwrap().is_some());
        assert!(!producer.scope_approved());
        assert!(
            producer
                .source()
                .report(&request(Endpoint::Graph, after_reset), far())
                .is_err()
        );

        producer.approve_scope().unwrap();
        assert!(producer.scope_approved());
        assert_eq!(generation(&producer), after_reset);
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(producer.runtime(), &receiver, &clock);
        let pulled = pull_all(&receiver, &clock, Endpoint::Graph);
        assert_eq!(status_of(&pulled, &producer_static), PartStatus::Fresh);
        assert!(!is_empty(&pulled));
    }

    /// Acceptance (7) and review fix 3: control `status` reports `never`
    /// before any scan, also after pulls refused by the scope check; `ok`
    /// with `lastScanAt` and the fixture's client families after a scan;
    /// a later denial leaves `ok`; an engine failure is `error`, keeping
    /// the last success's fields.
    #[test]
    fn status_reports_never_then_ok_then_error() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        let never = |producer: &Agent| {
            let status = call(producer.runtime(), STATUS, json!({}));
            assert_eq!(status["scanStatus"], "never");
            assert_eq!(status["lastScanAt"], Value::Null);
            assert_eq!(status["sourceFamilies"], json!([]));
        };
        never(&producer);
        // A pull before the owner approved is a scope denial, not a scan.
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        pair(producer.runtime(), &receiver, &clock);
        let denied = pull_all(&receiver, &clock, Endpoint::Agents);
        assert_eq!(denied.peers[0].status, PartStatus::Refused);
        never(&producer);

        producer.approve_scope().unwrap();
        pair(producer.runtime(), &receiver, &clock);
        pull_all(&receiver, &clock, Endpoint::Agents);
        let status = call(producer.runtime(), STATUS, json!({}));
        assert_eq!(status["scanStatus"], "ok");
        let at = status["lastScanAt"].as_i64().unwrap();
        assert!(at >= 1_700_000_000, "{at}");
        assert_eq!(status["sourceFamilies"], json!(["claude", "codex"]));

        // A denial after a success leaves `ok` too.
        let wrong = request(Endpoint::Graph, generation(&producer) + 7);
        assert!(producer.source().report(&wrong, far()).is_err());
        assert_eq!(
            call(producer.runtime(), STATUS, json!({}))["scanStatus"],
            "ok"
        );

        // An engine call that fails (a timezone the engine does not know)
        // is a failed scan.
        let mut unknown_zone = request(Endpoint::Graph, generation(&producer));
        unknown_zone.timezone = "Nowhere/Atlantis".into();
        assert!(producer.source().report(&unknown_zone, far()).is_err());
        let status = call(producer.runtime(), STATUS, json!({}));
        assert_eq!(status["scanStatus"], "error");
        assert_eq!(status["lastScanAt"].as_i64(), Some(at));
        assert_eq!(status["sourceFamilies"], json!(["claude", "codex"]));
    }

    /// Review fix 2: a producer that answers and refuses is not covered by
    /// the cached body, which is still there. Here the refusal is
    /// `unauthorized` (`CheckGrantStatus`): revoking another receiver's
    /// grant renumbered this grant's `authEpoch`, so this record is stale.
    #[test]
    fn a_refused_pull_does_not_fall_back_to_the_cached_body() {
        let clock = TestClock::new();
        let (producer_home, receiver_home, other_home) =
            (TempHome::new(), TempHome::new(), TempHome::new());
        let producer = producer(&producer_home, &clock);
        producer.approve_scope().unwrap();
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(producer.runtime(), &receiver, &clock);
        let fresh = pull_all(&receiver, &clock, Endpoint::Hourly);
        assert_eq!(status_of(&fresh, &producer_static), PartStatus::Fresh);

        let other = start(&other_home, &clock, ScannerSettings::default());
        pair(producer.runtime(), &other, &clock);
        let other_grant = other.runtime().peers().peers().unwrap()[0].grant_id;
        call(
            producer.runtime(),
            REVOKE,
            json!({"grantId": hex_encode(&other_grant)}),
        );

        let refused = pull_all(&receiver, &clock, Endpoint::Hourly);
        assert_eq!(status_of(&refused, &producer_static), PartStatus::Refused);
        assert_eq!(
            refused.peers[0].error,
            Some(PullError::Fetch(FetchError::CheckGrantStatus))
        );
        assert!(is_empty(&refused));
        assert!(
            receiver
                .runtime()
                .last_good(&producer_static, &query(Endpoint::Hourly))
                .unwrap()
                .is_some(),
            "the cached body is still there"
        );
    }

    /// A source that answers each request with an empty report of its
    /// endpoint after 200 ms, then moves the clock 61 s on, so the grant's
    /// rate tokens refill for the next request.
    struct Slow(Arc<TestClock>);

    impl ReportSource for Slow {
        fn report(&self, request: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
            thread::sleep(Duration::from_millis(200));
            self.0.advance(61);
            fn empty<R: ReportRecord>(request: &ReportRequest) -> Result<Vec<u8>, SourceError> {
                encode_response(&ReportResponse::<R>::from_request(
                    request,
                    Vec::new(),
                    false,
                ))
                .map_err(|_| SourceError)
            }
            match Endpoint::try_from(request.endpoint).map_err(|_| SourceError)? {
                Endpoint::Graph => empty::<GraphRecord>(request),
                Endpoint::Models => empty::<ModelsRecord>(request),
                Endpoint::Hourly => empty::<HourlyRecord>(request),
                Endpoint::Agents => empty::<AgentsRecord>(request),
            }
        }
    }

    /// Review fix 1: four `pull_all` calls at once, one per endpoint, all
    /// get a fresh part: they queue instead of competing for the
    /// runtime's two fetch slots (`TooMany`).
    #[test]
    fn concurrent_pull_all_calls_queue_and_all_get_fresh_parts() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let options = Options {
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            housekeeping_period: Duration::from_secs(60),
        };
        let mut tries = 0;
        let producer = loop {
            let started = SecureRoot::open_under(&producer_home.0, SUFFIX)
                .map_err(RuntimeError::Store)
                .and_then(|root| {
                    Runtime::start(root, Arc::new(Slow(Arc::clone(&clock))), options.clone())
                });
            match started {
                Err(RuntimeError::Store(StorageError::Busy)) if tries < 200 => {
                    tries += 1;
                    thread::sleep(Duration::from_millis(10));
                }
                other => break other.unwrap(),
            }
        };
        call(
            &producer,
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": free_port()}),
        );
        let receiver = start(&receiver_home, &clock, ScannerSettings::default());
        let producer_static = pair(&producer, &receiver, &clock);

        let barrier = std::sync::Barrier::new(ENDPOINTS.len());
        let results: Vec<Combined> = thread::scope(|scope| {
            let running: Vec<_> = ENDPOINTS
                .iter()
                .map(|endpoint| {
                    let (receiver, barrier) = (&receiver, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        receiver.pull_all(&query(*endpoint), None)
                    })
                })
                .collect();
            running.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for combined in &results {
            assert_eq!(combined.peers[0].error, None);
            assert_eq!(status_of(combined, &producer_static), PartStatus::Fresh);
        }
    }

    /// The installed stand-in for the running binary.
    fn install_into(home: &TempHome) {
        let exe = home.0.join("exe-source");
        fs::write(&exe, b"stand-in binary").unwrap();
        install::install(&home.0, &exe).unwrap();
    }

    /// A paired producer that served one scan, with an extra file in its
    /// source cache, installed into its temp home.
    fn served(producer_home: &TempHome, receiver_home: &TempHome, clock: &Arc<TestClock>) -> Agent {
        let producer = producer(producer_home, clock);
        producer.approve_scope().unwrap();
        let receiver = start(receiver_home, clock, ScannerSettings::default());
        pair(producer.runtime(), &receiver, clock);
        pull_all(&receiver, clock, Endpoint::Graph);
        fs::create_dir_all(producer_home.source_cache().join("nested")).unwrap();
        fs::write(
            producer_home.source_cache().join("nested/session-ids"),
            b"x",
        )
        .unwrap();
        install_into(producer_home);
        assert_eq!(active_grants(&producer), 1);
        assert!(sharing(&producer));
        producer
    }

    /// Acceptance (8): uninstall empties the source cache, ends every grant,
    /// turns sharing off and removes the installed objects; the scope
    /// record stays without `purge`.
    #[test]
    fn uninstall_ends_grants_and_clears_the_source_cache() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = served(&producer_home, &receiver_home, &clock);
        let report = producer.uninstall(false).unwrap();
        assert_eq!(report.install.binary, Outcome::Removed);
        assert_eq!(report.install.autostart, Outcome::Removed);
        assert_eq!(report.source_cache, Outcome::Removed);
        assert!(!report.manual_repair());
        assert!(!report.install.purged && !report.scope_removed);
        assert_eq!(entries(&producer_home.source_cache()), 0);
        assert!(producer_home.root().join(SCOPE_FILE).exists());

        let producer = start(&producer_home, &clock, ScannerSettings::default());
        assert_eq!(active_grants(&producer), 0);
        assert!(!sharing(&producer));
    }

    /// Acceptance (8): with `purge`, `source-scope.json` goes too; a new
    /// start has a new identity and no approved scope.
    #[test]
    fn purge_removes_the_scope_record_and_the_next_start_is_new() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = served(&producer_home, &receiver_home, &clock);
        let identity = producer
            .runtime()
            .store()
            .state()
            .unwrap()
            .identity_public()
            .unwrap();
        let report = producer.uninstall(true).unwrap();
        assert!(report.install.purged && report.scope_removed);
        assert!(!report.manual_repair());
        assert!(!producer_home.root().join(SCOPE_FILE).exists());
        assert_eq!(entries(&producer_home.source_cache()), 0);

        let producer = start(&producer_home, &clock, ScannerSettings::default());
        let fresh = producer
            .runtime()
            .store()
            .state()
            .unwrap()
            .identity_public()
            .unwrap();
        assert_ne!(fresh, identity);
        assert!(!producer.scope_approved());
        assert_eq!(active_grants(&producer), 0);
    }

    /// Acceptance (8): another live handle to the state store makes
    /// uninstall fail with nothing removed.
    #[test]
    fn uninstall_with_another_store_handle_fails_and_removes_nothing() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = served(&producer_home, &receiver_home, &clock);
        let handle = Arc::clone(producer.runtime().store());
        assert_eq!(
            producer.uninstall(true).err(),
            Some(AgentError::Storage(StorageError::Busy))
        );
        assert!(producer_home.root().join(SCOPE_FILE).exists());
        assert!(producer_home.root().join("state.json").exists());
        assert!(
            producer_home
                .source_cache()
                .join("nested/session-ids")
                .exists()
        );
        drop(handle);
        let producer = start(&producer_home, &clock, ScannerSettings::default());
        assert_eq!(active_grants(&producer), 1);
        assert!(sharing(&producer));
        assert!(producer.scope_approved());
    }

    /// Acceptance (8c): a source cache that cannot be emptied (swapped for
    /// a symlink to a decoy) does not stop the uninstall: every grant is
    /// ended, sharing is off, the decoy is untouched and the report asks
    /// for manual repair.
    #[test]
    fn a_source_cache_that_cannot_be_cleared_only_marks_manual_repair() {
        let clock = TestClock::new();
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let producer = served(&producer_home, &receiver_home, &clock);
        let decoy = producer_home.0.join("decoy");
        fs::create_dir(&decoy).unwrap();
        fs::write(decoy.join("keep"), b"decoy").unwrap();
        let cache = producer_home.source_cache();
        fs::rename(&cache, producer_home.0.join("moved-cache")).unwrap();
        symlink(&decoy, &cache).unwrap();

        let report = producer.uninstall(false).unwrap();
        assert_eq!(report.source_cache, Outcome::ManualRepair);
        assert!(report.manual_repair());
        assert_eq!(fs::read(decoy.join("keep")).unwrap(), b"decoy");
        assert!(
            fs::symlink_metadata(&cache)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // The durable uninstall came first: the same state, no grant. The
        // link goes first, or `EngineSource` refuses the cache directory.
        fs::remove_file(&cache).unwrap();
        let producer = start(&producer_home, &clock, ScannerSettings::default());
        assert_eq!(active_grants(&producer), 0);
        assert!(!sharing(&producer));
    }
}
