//! The library entry point (`spec/agent-v1.md`): one secure root, one
//! [`EngineSource`] over it, one [`Runtime`], started together.
//!
//! Nothing here reads the environment: the trusted home and every scan
//! input come from the caller. Usage numbers are computed by the engine
//! (`source.rs`) and summed by the frozen merge (`merge.rs`); this module
//! only wires them. macOS, Linux and Windows (embedded in an app: no
//! control server, CLI or install there, `spec/agent-v1.md`); a target
//! without a secure root implementation fails closed at
//! `SecureRoot::open_under`, and one that is neither Unix nor Windows has
//! no [`Agent`] at all ([`AgentError::Unsupported`]).

use std::{collections::BTreeMap, path::PathBuf};

use serde::Serialize;

use crate::{
    install::{InstallError, Outcome, UninstallReport},
    runtime::{Options, RuntimeError},
    secure_fs::StorageError,
};

/// The engine's scanner settings (custom roots and exclusions).
pub use tokscale_core::ScannerSettings;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
const DEFAULT_SUFFIX: &[&str] = crate::secure_fs::STATE_SUFFIX;
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const DEFAULT_SUFFIX: &[&str] = &[];

/// What an [`Agent`] is started with. Fixed for the agent's life: to
/// change a scan input, stop it and start a new one.
#[derive(Clone)]
pub struct AgentConfig {
    /// The base of the secure root: `secure_fs::trusted_home()` in a
    /// product, a temp directory in a test. Also the home whose install
    /// objects `Agent::uninstall` removes, and the engine's home unless
    /// `scan_home` is set. On macOS and Linux it is the owner's home; on
    /// Windows it is the LocalAppData known folder, not the profile.
    pub trusted_home: PathBuf,
    /// The engine's home when it is not `trusted_home` (Windows: the
    /// Profile known folder, `default_scan_roots`). An owner input, part of
    /// the scope digest as `home`. `None` (the default): `trusted_home`.
    pub scan_home: Option<PathBuf>,
    /// The config and data directories the engine resolves clients
    /// against: it uses `data_dir` as the XDG data root and
    /// `config_dir/tokscale` as its config root. Not the OS "application
    /// support" directories; use `cli::default_dirs`.
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    /// A separate XDG data root (`EngineSource::new_with_xdg_data_home`):
    /// the engine resolves `XDG_DATA_HOME` to it instead of `data_dir`.
    /// An owner input, part of the scope digest
    /// (`source::owner_inputs_sha256_with_xdg_data_home`), so a disclosure
    /// must show it when set. `None` (the default) is the scan and digest
    /// from before this field.
    pub xdg_data_home: Option<PathBuf>,
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
            scan_home: None,
            config_dir,
            data_dir,
            xdg_data_home: None,
            settings,
            state_suffix: DEFAULT_SUFFIX,
            options: Options::default(),
        }
    }

    /// The frozen platform suffix and the default runtime options, scanning
    /// `roots` (`scan_home`, `config_dir`, `data_dir`, `xdg_data_home`) with
    /// the secure root below `trusted_home`. On Windows:
    /// `with_scan_roots(secure_fs::trusted_home()?, default_scan_roots()?,
    /// settings)`.
    pub fn with_scan_roots(
        trusted_home: PathBuf,
        roots: ScanRoots,
        settings: ScannerSettings,
    ) -> Self {
        Self {
            scan_home: Some(roots.home),
            xdg_data_home: Some(roots.xdg_data_home),
            ..Self::new(trusted_home, roots.config_dir, roots.data_dir, settings)
        }
    }
}

/// The four scan roots an [`AgentConfig`] can be given at once
/// ([`AgentConfig::with_scan_roots`]); on Windows,
/// [`default_scan_roots`] returns the owner's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanRoots {
    /// The engine's home (`scan_home`).
    pub home: PathBuf,
    /// The engine's config root (`config_dir`).
    pub config_dir: PathBuf,
    /// The engine's data-local root (`data_dir`).
    pub data_dir: PathBuf,
    /// The engine's XDG data root (`xdg_data_home`).
    pub xdg_data_home: PathBuf,
}

/// The Windows scan roots of the user this process runs as, each from
/// `SHGetKnownFolderPath` with the process token and
/// `KF_FLAG_DONT_VERIFY`: `home` = the Profile known folder, `config_dir` =
/// RoamingAppData, `data_dir` = LocalAppData, `xdg_data_home` =
/// `home\.local\share` (from the same `home` value). No environment
/// variable is read (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `HOME`,
/// `XDG_DATA_HOME` and the rest do not change the answer), nothing is
/// created or opened. Each path is absolute and not verbatim (no `\\?\`):
/// normally `X:\…`, or a UNC path for a redirected folder. Anything else is
/// `UnsafeState`. The secure root's base is separate:
/// `secure_fs::trusted_home()` (LocalAppData, local drive only).
#[cfg(windows)]
pub fn default_scan_roots() -> Result<ScanRoots, StorageError> {
    use std::path::{Component, Prefix};
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData, KF_FLAG_DONT_VERIFY,
    };
    let root = |id| {
        // The constant is an `i32` (`KNOWN_FOLDER_FLAG`); the call takes a `u32`.
        let path = crate::secure_fs::known_folder(id, KF_FLAG_DONT_VERIFY as u32)?;
        let mut components = path.components();
        let form = matches!(
            components.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(..))
        ) && path.is_absolute()
            && components.all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
        form.then_some(path).ok_or(StorageError::UnsafeState)
    };
    let home = root(&FOLDERID_Profile)?;
    Ok(ScanRoots {
        xdg_data_home: home.join(".local").join("share"),
        config_dir: root(&FOLDERID_RoamingAppData)?,
        data_dir: root(&FOLDERID_LocalAppData)?,
        home,
    })
}

/// What the owner approves (`Agent::scope_disclosure`): the exact strings
/// hashed into `ownerInputsSha256`, and that digest. Show these strings as
/// they are (no canonicalization, case folding or path round trip), and
/// approve with [`Agent::approve_scope_for`] and this digest; never compute
/// a digest yourself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDisclosure {
    pub config_dir: String,
    pub data_dir: String,
    pub excluded_scan_paths: BTreeMap<String, Vec<String>>,
    pub extra_scan_paths: BTreeMap<String, Vec<String>>,
    pub home: String,
    pub opencode_db_paths: Vec<String>,
    pub source_cache_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xdg_data_home: Option<String>,
    /// SHA-256 of the CanonicalJsonV1 encoding of the fields above.
    #[serde(skip)]
    pub owner_inputs_sha256: String,
}

/// Why an agent operation failed. Carries no path or OS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentError {
    /// Neither a Unix nor a Windows target.
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

#[cfg(not(any(unix, windows)))]
/// No agent can exist here.
pub struct Agent(std::convert::Infallible);

#[cfg(not(any(unix, windows)))]
impl Agent {
    pub fn start(config: AgentConfig) -> Result<Self, AgentError> {
        let _ = config;
        Err(AgentError::Unsupported)
    }
}

#[cfg(any(unix, windows))]
pub use imp::Agent;

#[cfg(any(unix, windows))]
mod imp {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Arc, Mutex, OnceLock, PoisonError},
        thread,
    };

    use sha2::{Digest, Sha256};

    use super::{AgentConfig, AgentError, AgentUninstallReport, ScannerSettings, ScopeDisclosure};
    use crate::{
        canonical::CanonicalJsonV1,
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
        security::{SecurityError, clock_status, hex_encode},
        source::{EngineSource, SCOPE_FILE, SOURCE_CACHE_DIR},
        state_store::StateStore,
    };

    /// The running agent. Dropping it stops the runtime.
    pub struct Agent {
        // Field order is drop order: the runtime stops first.
        runtime: Runtime,
        source: Arc<EngineSource>,
        /// The strings `source` hashed, and its digest.
        disclosure: ScopeDisclosure,
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
                scan_home,
                config_dir,
                data_dir,
                xdg_data_home,
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
                approve_scope_for(store, source, digest, &serial)
            });
            let scan_home = scan_home.unwrap_or_else(|| trusted_home.clone());
            let disclosed = Arc::new(OnceLock::<ScopeDisclosure>::new());
            let keep = Arc::clone(&disclosed);
            let runtime = Runtime::start_with_scope(
                root,
                move |root| {
                    let source = Arc::new(EngineSource::new_with_xdg_data_home(
                        root,
                        scan_home.clone(),
                        config_dir.clone(),
                        data_dir.clone(),
                        xdg_data_home.clone(),
                        settings.clone(),
                    )?);
                    // The disclosure is the hashed form of the very values
                    // the source was built with; a digest that differs from
                    // the source's would show the owner other inputs than
                    // the ones approved, so the start fails instead.
                    let disclosure = disclose(
                        &scan_home,
                        &config_dir,
                        &data_dir,
                        xdg_data_home.as_deref(),
                        source.source_cache_dir(),
                        &settings,
                    )
                    .filter(|d| d.owner_inputs_sha256 == source.owner_inputs_sha256())
                    .ok_or(StorageError::Refused(SecurityError::Invalid))?;
                    let _ = keep.set(disclosure);
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
            let disclosure = disclosed
                .get()
                .cloned()
                .ok_or(AgentError::Storage(StorageError::Unknown))?;
            Ok(Self {
                root: runtime.store().root(),
                runtime,
                source,
                disclosure,
                clock,
                trusted_home,
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
        ///
        /// Not on Windows: there the only entry is
        /// [`approve_scope_for`](Self::approve_scope_for), which names the
        /// digest the owner was shown (`spec/agent-v1.md`).
        #[cfg(not(windows))]
        pub fn approve_scope(&self) -> Result<(), StorageError> {
            approve_scope(self.runtime.store(), &self.source, &self.approving)
        }

        /// What the owner is shown before approving: the strings hashed
        /// into this agent's `ownerInputsSha256`, and that digest.
        pub fn scope_disclosure(&self) -> &ScopeDisclosure {
            &self.disclosure
        }

        /// `approve_scope` only for the inputs the owner was shown (every
        /// platform; the only entry on Windows): `digest` must be this agent's
        /// `scope_disclosure().owner_inputs_sha256`, or this is
        /// `Refused(Invalid)` and nothing is written. The same check as
        /// control `scopeApprove`.
        pub fn approve_scope_for(&self, digest: &str) -> Result<(), StorageError> {
            approve_scope_for(self.runtime.store(), &self.source, digest, &self.approving)
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
        /// `trusted_home` (from `AgentConfig`). On Windows `install::uninstall`
        /// is `Unsupported`: this stops the runtime and returns
        /// `Install(Unsupported)`, leaving every file in place.
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

    /// The body of [`Agent::approve_scope_for`], shared with the control
    /// `scopeApprove` hook: the owner consented to the inputs they were
    /// shown; the running source may see others (`SA-0G`).
    fn approve_scope_for(
        store: &StateStore,
        source: &EngineSource,
        digest: &str,
        approving: &Mutex<()>,
    ) -> Result<(), StorageError> {
        if digest != source.owner_inputs_sha256() {
            return Err(StorageError::Refused(SecurityError::Invalid));
        }
        approve_scope(store, source, approving)
    }

    /// The scope disclosure of these inputs: each path as its UTF-8 string,
    /// every list sorted and deduplicated, maps by key (the rules of
    /// `source::owner_inputs_sha256_with_xdg_data_home`), and the SHA-256
    /// of its CanonicalJsonV1 encoding. `None` when a path is not UTF-8 or
    /// the encoder refuses a string.
    fn disclose(
        home: &Path,
        config_dir: &Path,
        data_dir: &Path,
        xdg_data_home: Option<&Path>,
        source_cache_dir: &Path,
        settings: &ScannerSettings,
    ) -> Option<ScopeDisclosure> {
        // Exhaustive, as in source.rs: a new settings field stops compiling.
        let ScannerSettings {
            opencode_db_paths,
            extra_scan_paths,
            excluded_scan_paths,
        } = settings;
        fn text(path: &Path) -> Option<String> {
            path.to_str().map(str::to_owned)
        }
        fn list(paths: &[PathBuf]) -> Option<Vec<String>> {
            let mut texts = paths
                .iter()
                .map(|path| text(path))
                .collect::<Option<Vec<_>>>()?;
            texts.sort_unstable();
            texts.dedup();
            Some(texts)
        }
        fn map(paths: &BTreeMap<String, Vec<PathBuf>>) -> Option<BTreeMap<String, Vec<String>>> {
            paths
                .iter()
                .map(|(client, paths)| Some((client.clone(), list(paths)?)))
                .collect()
        }
        let mut disclosure = ScopeDisclosure {
            config_dir: text(config_dir)?,
            data_dir: text(data_dir)?,
            excluded_scan_paths: map(excluded_scan_paths)?,
            extra_scan_paths: map(extra_scan_paths)?,
            home: text(home)?,
            opencode_db_paths: list(opencode_db_paths)?,
            source_cache_dir: text(source_cache_dir)?,
            xdg_data_home: match xdg_data_home {
                Some(path) => Some(text(path)?),
                None => None,
            },
            owner_inputs_sha256: String::new(),
        };
        let bytes = CanonicalJsonV1::encode(&disclosure).ok()?;
        disclosure.owner_inputs_sha256 = hex_encode(&Sha256::digest(&bytes));
        Some(disclosure)
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
            Some(record) if record.inputs_match => source.approve_unchecked(store),
            _ => {
                store.transition(|state| state.source_change_commit())?;
                source.approve_unchecked(store)
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
