//! The library entry point (`spec/agent-v1.md`): one secure root, one
//! [`EngineSource`] over it, one [`Runtime`], started together.
//!
//! Nothing here reads the environment: the trusted home and every scan
//! input come from the caller. Usage numbers are computed by the engine
//! (`source.rs`) and summed by the frozen merge (`merge.rs`); this module
//! only wires them. macOS and Linux; elsewhere [`Agent::start`] is
//! [`AgentError::Unsupported`].

use std::path::PathBuf;

use crate::{
    install::{InstallError, Outcome, UninstallReport},
    runtime::{Options, RuntimeError},
    secure_fs::StorageError,
};

/// The engine's scanner settings (custom roots and exclusions).
#[cfg(unix)]
pub use tokscale_core::ScannerSettings;

/// Stand-in where the engine does not build; [`Agent::start`] is
/// `Unsupported` there.
#[cfg(not(unix))]
#[derive(Clone, Debug, Default)]
pub struct ScannerSettings;

#[cfg(any(target_os = "macos", target_os = "linux"))]
const DEFAULT_SUFFIX: &[&str] = crate::secure_fs::STATE_SUFFIX;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const DEFAULT_SUFFIX: &[&str] = &[];

/// What an [`Agent`] is started with. Fixed for the agent's life: to
/// change a scan input, stop it and start a new one.
#[derive(Clone)]
pub struct AgentConfig {
    /// The owner's home: `secure_fs::trusted_home()` in a product, a temp
    /// directory in a test. Also the engine's home, and the home whose
    /// install objects `Agent::uninstall` removes.
    pub trusted_home: PathBuf,
    /// The platform config and data directories the engine resolves
    /// clients against.
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub settings: ScannerSettings,
    /// The secure root below `trusted_home`: the frozen platform suffix
    /// (`secure_fs::STATE_SUFFIX`) unless a test chooses another.
    pub state_suffix: &'static [&'static str],
    pub options: Options,
}

impl AgentConfig {
    /// The frozen platform suffix and the default runtime options.
    pub fn new(
        trusted_home: PathBuf,
        config_dir: PathBuf,
        data_dir: PathBuf,
        settings: ScannerSettings,
    ) -> Self {
        Self {
            trusted_home,
            config_dir,
            data_dir,
            settings,
            state_suffix: DEFAULT_SUFFIX,
            options: Options::default(),
        }
    }
}

/// Why an agent operation failed. Carries no path or OS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentError {
    /// Not macOS or Linux.
    Unsupported,
    /// The secure root, the clock, or a store refused; for
    /// [`Agent::uninstall`], also "another handle to the state store is
    /// alive" (`Busy`), with nothing removed.
    Storage(StorageError),
    Runtime(RuntimeError),
    Install(InstallError),
}

/// What [`Agent::uninstall`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentUninstallReport {
    /// `install::uninstall`: the durable uninstall, the two objects, the
    /// two caches, and `purge`.
    pub install: UninstallReport,
    /// The engine's source cache (`source-cache/`): `Removed` once emptied,
    /// `ManualRepair` when it could not be.
    pub source_cache: Outcome,
    /// `source-scope.json` was removed (only after a purge removed the
    /// state).
    pub scope_removed: bool,
}

impl AgentUninstallReport {
    /// Something is left for the owner to remove by hand.
    pub fn manual_repair(&self) -> bool {
        self.install.manual_repair()
            || self.source_cache == Outcome::ManualRepair
            || (self.install.purged && !self.scope_removed)
    }
}

#[cfg(not(unix))]
/// No agent can exist here.
pub struct Agent(std::convert::Infallible);

#[cfg(not(unix))]
impl Agent {
    pub fn start(config: AgentConfig) -> Result<Self, AgentError> {
        let _ = config;
        Err(AgentError::Unsupported)
    }
}

#[cfg(unix)]
pub use imp::Agent;

#[cfg(unix)]
mod imp {
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex, OnceLock, PoisonError},
        thread,
    };

    use super::{AgentConfig, AgentError, AgentUninstallReport};
    use crate::{
        control::{ScanHook, ScanStatus, ScopeApproveHook, ScopeHook},
        install::{self, Outcome},
        merge::{Combined, FailureClass, PeerData, PeerPart, Report, classify, combine},
        pairing::{Clock, SystemClock},
        peer_store::{PeerRecord, usable},
        report::{
            AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
            decode_response,
        },
        report_peer::{MAX_FETCHES, Records, ReportQuery, ReportSource},
        runtime::Runtime,
        secure_fs::{SecureRoot, StorageError},
        security::{SecurityError, clock_status},
        source::{EngineSource, SCOPE_FILE, SOURCE_CACHE_DIR},
        state_store::StateStore,
    };

    /// The running agent. Dropping it stops the runtime.
    pub struct Agent {
        // Field order is drop order: the runtime stops first.
        runtime: Runtime,
        source: Arc<EngineSource>,
        root: Arc<SecureRoot>,
        clock: Arc<dyn Clock>,
        /// `AgentConfig::trusted_home`: the home of the install objects
        /// `uninstall` removes, the same one the secure root is below.
        trusted_home: PathBuf,
        /// Serializes `approve_scope`, shared with the control
        /// `scopeApprove` hook.
        approving: Arc<Mutex<()>>,
        /// Serializes `pull_all`: the runtime's fetch limiter refuses
        /// (`TooMany`) rather than waits, so overlapping calls would lose
        /// pulls.
        // ponytail: one lock; four endpoint calls wait in line, each
        // bounded by `FETCH_DEADLINE` per batch. A per-peer limiter if that
        // ever matters.
        pulling: Mutex<()>,
    }

    impl std::fmt::Debug for Agent {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Agent { .. }")
        }
    }

    impl Agent {
        /// Opens the secure root `trusted_home/state_suffix`, then starts
        /// the runtime with one `EngineSource` built over the state store's
        /// own root (`Runtime::start_with`). Control `status` reports that
        /// source's scans.
        pub fn start(config: AgentConfig) -> Result<Self, AgentError> {
            let AgentConfig {
                trusted_home,
                config_dir,
                data_dir,
                settings,
                state_suffix,
                options,
            } = config;
            let root =
                SecureRoot::open_under(&trusted_home, state_suffix).map_err(AgentError::Storage)?;
            let clock = Arc::clone(&options.clock);
            // The status hook exists before the source does.
            let slot = Arc::new(OnceLock::<Arc<EngineSource>>::new());
            let read = Arc::clone(&slot);
            let scan: ScanHook = Arc::new(move || {
                read.get()
                    .map_or_else(ScanStatus::default, |source| source.scan_status())
            });
            let fill = Arc::clone(&slot);
            let read = Arc::clone(&slot);
            // Before the source exists (the server starts first): `false`.
            let scope: ScopeHook = Arc::new(move |store| {
                read.get()
                    .is_some_and(|source| scope_approved(store, source))
            });
            let approving = Arc::new(Mutex::new(()));
            let (read, serial) = (Arc::clone(&slot), Arc::clone(&approving));
            let approve: ScopeApproveHook = Arc::new(move |store, digest| {
                let source = read.get().ok_or(StorageError::Unknown)?;
                // The owner consented to the inputs they were shown; the
                // running source may see others (`SA-0G`).
                if digest != source.owner_inputs_sha256() {
                    return Err(StorageError::Refused(SecurityError::Invalid));
                }
                approve_scope(store, source, &serial)
            });
            let home = trusted_home.clone();
            let runtime = Runtime::start_with_scope(
                root,
                move |root| {
                    let source = Arc::new(EngineSource::new(
                        root,
                        trusted_home,
                        config_dir,
                        data_dir,
                        settings,
                    )?);
                    let _ = fill.set(Arc::clone(&source));
                    Ok(source as Arc<dyn ReportSource>)
                },
                scan,
                scope,
                Some(approve),
                options,
            )
            .map_err(AgentError::Runtime)?;
            // `start_with` returned Ok, so `make_source` ran and filled it.
            let source = Arc::clone(
                slot.get()
                    .ok_or(AgentError::Storage(StorageError::Unknown))?,
            );
            Ok(Self {
                root: runtime.store().root(),
                runtime,
                source,
                clock,
                trusted_home: home,
                approving,
                pulling: Mutex::new(()),
            })
        }

        /// Sharing, `pull`, `last_good`, the state and peer stores.
        pub fn runtime(&self) -> &Runtime {
            &self.runtime
        }

        /// The report source (its scope record and scan status).
        pub fn source(&self) -> &EngineSource {
            &self.source
        }

        /// The engine's pricing root inside the secure root. The caller
        /// puts the pricing files there; while it is empty every cost is 0.
        pub fn pricing_dir(&self) -> &Path {
            self.source.pricing_dir()
        }

        /// True only when the approved-scope record exists, its digest is
        /// this agent's inputs, and its generation is the state's
        /// `sourceScopeGeneration`: what `report` requires besides the
        /// request's own generation. False when anything is unreadable.
        /// Control `status` reports the same (`scopeApproved`).
        pub fn scope_approved(&self) -> bool {
            scope_approved(self.runtime.store(), &self.source)
        }

        /// Owner action. No record, or a record for other inputs: the
        /// frozen `source_change_commit` (generation forward, every grant
        /// so far denied), then `approve`. The same inputs at another
        /// generation (after a reset, or a crash between those two steps):
        /// `approve` only. Already approved: nothing is written. Control
        /// `scopeApprove` runs the same body, under the same lock.
        pub fn approve_scope(&self) -> Result<(), StorageError> {
            approve_scope(self.runtime.store(), &self.source, &self.approving)
        }

        /// Pulls `query` from every usable peer (`Runtime::pull`, at most
        /// [`MAX_FETCHES`] at once, no retry). A pull that failed without
        /// the producer answering about authorization
        /// ([`FailureClass::NoAnswer`]) falls back to `Runtime::last_good`;
        /// a refusal or an invalid reply carries no data. Then [`combine`]
        /// with `local`, which the caller computes itself. Calls are
        /// serialized: a second call waits for the first.
        ///
        /// A caller's own concurrent `Runtime::pull` still competes for the
        /// same fetch slots.
        pub fn pull_all(&self, query: &ReportQuery, local: Option<Report>) -> Combined {
            let _pulling = self.pulling.lock().unwrap_or_else(PoisonError::into_inner);
            let store = self.runtime.store();
            let peers: Vec<PeerRecord> = self
                .runtime
                .peers()
                .peers()
                .unwrap_or_default()
                .into_iter()
                .filter(|peer| usable(peer, store))
                .collect();
            let mut parts = Vec::with_capacity(peers.len());
            for batch in peers.chunks(MAX_FETCHES) {
                thread::scope(|scope| {
                    let running: Vec<_> = batch
                        .iter()
                        .map(|peer| (peer, scope.spawn(|| self.part(peer, query))))
                        .collect();
                    for (peer, handle) in running {
                        // A pull that panicked counts as no data.
                        parts.push(handle.join().unwrap_or(PeerPart {
                            producer_static: peer.responder_static,
                            grant_id: peer.grant_id,
                            data: PeerData::None,
                            error: None,
                        }));
                    }
                });
            }
            combine(query.endpoint, local, parts)
        }

        fn part(&self, peer: &PeerRecord, query: &ReportQuery) -> PeerPart {
            let (data, error) = match self.runtime.pull(&peer.responder_static, query) {
                Ok(fetched) => (
                    PeerData::Fresh(Report {
                        records: fetched.records,
                        saturated: fetched.saturated,
                    }),
                    None,
                ),
                Err(error) => {
                    let data = match classify(error) {
                        FailureClass::NoAnswer => self
                            .runtime
                            .last_good(&peer.responder_static, query)
                            .ok()
                            .flatten()
                            .and_then(|cached| decode(query.endpoint, cached.body()))
                            .map_or(PeerData::None, PeerData::LastGood),
                        FailureClass::Refused => PeerData::Refused,
                        FailureClass::InvalidReply => PeerData::InvalidReply,
                    };
                    (data, Some(error))
                }
            };
            PeerPart {
                producer_static: peer.responder_static,
                grant_id: peer.grant_id,
                data,
                error,
            }
        }

        /// In this order: stop the runtime and take the only handle to the
        /// state store (another handle alive: `Storage(Busy)`, nothing
        /// removed); `install::uninstall` (durable uninstall first, then the
        /// objects, the caches, and `purge`); then the engine's source
        /// cache is emptied, a failure there only marking `source_cache`
        /// for manual repair; then, if the purge removed the state,
        /// `source-scope.json`.
        ///
        /// The install objects are looked for below the agent's own
        /// `trusted_home` (from `AgentConfig`).
        pub fn uninstall(self, purge: bool) -> Result<AgentUninstallReport, AgentError> {
            let Self {
                runtime,
                source,
                root,
                clock,
                trusted_home,
                ..
            } = self;
            drop((source, root));
            let store = runtime.into_store().map_err(AgentError::Storage)?;
            uninstall_store(store, &trusted_home, purge, &*clock)
        }

        /// [`uninstall`](Self::uninstall) without a running agent (the
        /// standalone menu, `SA-2C2b` review): takes the owner lock
        /// (`SecureRoot::open_under`; another holder is `Storage(Busy)`,
        /// nothing removed), opens the state store, then the same steps as
        /// `uninstall` after `into_store`. No runtime, control server,
        /// listener, housekeeping or engine source is started. A root
        /// without `state.json` gets a fresh one from `StateStore::open`
        /// first (as at any start), which the durable uninstall then
        /// disables, and a purge removes.
        pub fn uninstall_stopped(
            trusted_home: &Path,
            state_suffix: &[&str],
            purge: bool,
        ) -> Result<AgentUninstallReport, AgentError> {
            let root =
                SecureRoot::open_under(trusted_home, state_suffix).map_err(AgentError::Storage)?;
            let clock = SystemClock;
            let os_now = clock.os_now_seconds().map_err(AgentError::Storage)?;
            let store = StateStore::open(root, os_now).map_err(AgentError::Storage)?;
            uninstall_store(store, trusted_home, purge, &clock)
        }
    }

    /// The steps of an uninstall once `store` is the only handle: the
    /// terminal timestamp, `install::uninstall` (durable uninstall first),
    /// then the engine's source cache, then, after a purge removed the
    /// state, `source-scope.json`.
    fn uninstall_store(
        store: StateStore,
        trusted_home: &Path,
        purge: bool,
        clock: &dyn Clock,
    ) -> Result<AgentUninstallReport, AgentError> {
        let root = store.root();
        let terminal_at_ms = terminal_ms(&store, clock).map_err(AgentError::Storage)?;
        let report = install::uninstall(store, trusted_home, purge, terminal_at_ms)
            .map_err(AgentError::Install)?;
        let source_cache = match root.clear_private_subdir(SOURCE_CACHE_DIR) {
            Ok(()) => Outcome::Removed,
            Err(_) => Outcome::ManualRepair,
        };
        let scope_removed = report.purged && root.remove_file(SCOPE_FILE).is_ok();
        Ok(AgentUninstallReport {
            install: report,
            source_cache,
            scope_removed,
        })
    }

    /// The body of [`Agent::scope_approved`], shared with the control
    /// `status` provider.
    fn scope_approved(store: &StateStore, source: &EngineSource) -> bool {
        let Ok(state) = store.state() else {
            return false;
        };
        matches!(
            source.scope_record(),
            Ok(Some(record)) if record.inputs_match
                && record.generation == state.reference.source_scope_generation
        )
    }

    /// The body of [`Agent::approve_scope`], shared with the control
    /// `scopeApprove` hook; `approving` is the agent's one lock.
    fn approve_scope(
        store: &StateStore,
        source: &EngineSource,
        approving: &Mutex<()>,
    ) -> Result<(), StorageError> {
        let _approving = approving.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = store.state()?.reference.source_scope_generation;
        match source.scope_record()? {
            Some(record) if record.inputs_match && record.generation == generation => Ok(()),
            Some(record) if record.inputs_match => source.approve(store),
            _ => {
                store.transition(|state| state.source_change_commit())?;
                source.approve(store)
            }
        }
    }

    /// A terminal record's timestamp: the effective now, or the durable
    /// wall while the OS clock is unreadable or anomalous (the rule of
    /// `spec/control-v1.md`).
    fn terminal_ms(store: &StateStore, clock: &dyn Clock) -> Result<i64, StorageError> {
        let wall = store.state()?.reference.last_accepted_wall_unix_seconds();
        let now = clock
            .os_now_seconds()
            .ok()
            .map(|os_now| clock_status(os_now, wall))
            .filter(|status| !status.anomaly)
            .map_or(wall, |status| status.effective_now);
        now.checked_mul(1_000).ok_or(StorageError::Refused(
            crate::security::SecurityError::Bounds,
        ))
    }

    /// A cached body, decoded by the frozen decoder.
    // ponytail: the decode is not reserved in the runtime's memory ledger
    // (the ledger is private to the runtime); a cached body is at most
    // `LOGICAL_BODY_MAX`. Reserve here if the runtime exposes its ledger.
    fn decode(endpoint: Endpoint, body: &[u8]) -> Option<Report> {
        fn typed<R: ReportRecord>(body: &[u8], wrap: fn(Vec<R>) -> Records) -> Option<Report> {
            let response = decode_response::<R>(body, None).ok()?;
            Some(Report {
                records: wrap(response.records),
                saturated: response.saturated,
            })
        }
        match endpoint {
            Endpoint::Graph => typed::<GraphRecord>(body, Records::Graph),
            Endpoint::Models => typed::<ModelsRecord>(body, Records::Models),
            Endpoint::Hourly => typed::<HourlyRecord>(body, Records::Hourly),
            Endpoint::Agents => typed::<AgentsRecord>(body, Records::Agents),
        }
    }
}
