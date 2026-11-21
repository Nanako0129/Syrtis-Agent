//! The product report source (`spec/source-v1.md`).
//!
//! Every scan, parse, dedup, price and fold happens in the pinned engine
//! (`tokscale-core`, `aggregate_remote_usage_from_source_v1`). This module
//! only builds the engine's context from owner-approved inputs, checks the
//! approved-scope record, copies the requested endpoint's records field by
//! field into the frozen `report.rs` types, and encodes them. It never
//! filters or re-aggregates what the engine returns.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokscale_core::{
    RemoteAgentsRecordV1, RemoteGraphRecordV1, RemoteHourlyRecordV1, RemoteModelsRecordV1,
    RemotePricingDiagnostic, RemotePricingSnapshot, RemoteSourceContextV1,
    RemoteSourceScopeTokenV1, RemoteUsageQueryV1, ScannerSettings,
    aggregate_remote_usage_from_source_v1,
};

use crate::{
    canonical::CanonicalJsonV1,
    control::{ScanState, ScanStatus},
    report::{
        AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
        ReportRequest, ReportResponse, encode_response,
    },
    report_peer::{ReportSource, SourceError},
    secure_fs::{SecureRoot, StorageError},
    security::{SecurityError, hex_encode},
    state_store::StateStore,
};

/// The approved-scope record, the second durable file in the secure root.
pub const SCOPE_FILE: &str = "source-scope.json";
pub const SCOPE_SCHEMA_VERSION: u64 = 1;
/// Read bound; the record is about 120 bytes.
pub const SCOPE_FILE_MAX_BYTES: usize = 4096;
/// The engine's source (message) cache, below the secure root.
pub const SOURCE_CACHE_DIR: &str = "source-cache";
/// The engine's pricing cache root, below the secure root.
pub const PRICING_DIR: &str = "pricing";

/// `source-scope.json`: which owner inputs were approved, at which
/// `sourceScopeGeneration`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovedScope {
    generation: u64,
    owner_inputs_sha256: String,
    schema: u64,
}

/// What [`EngineSource::scope_record`] reports about `source-scope.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeRecord {
    /// The `sourceScopeGeneration` the record was approved at.
    pub generation: u64,
    /// Its `ownerInputsSha256` equals this source's inputs.
    pub inputs_match: bool,
}

/// What the consent binds to: only inputs the owner controls, in an
/// encoding this crate fixes (field names here, paths as UTF-8 strings,
/// every list sorted and deduplicated, maps ordered by key). Neither the
/// engine's fingerprint (it hashes the engine's client table and resolver
/// version) nor the engine's serde form of `ScannerSettings` (a new engine
/// field would serialize as a default) is used, so an engine pin alone
/// never changes the digest (D1). `xdgDataHome` is left out when there is
/// no separate XDG data root, so those bytes are the ones from before it
/// existed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerInputs {
    config_dir: String,
    data_dir: String,
    excluded_scan_paths: BTreeMap<String, Vec<String>>,
    extra_scan_paths: BTreeMap<String, Vec<String>>,
    home: String,
    opencode_db_paths: Vec<String>,
    source_cache_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    xdg_data_home: Option<String>,
}

/// `ownerInputsSha256` for these inputs: SHA-256 of the CanonicalJsonV1
/// encoding of [`OwnerInputs`], lowercase hex. `None` when a path is not
/// UTF-8 or a string is not NFC. No separate XDG data root: the digest of
/// [`owner_inputs_sha256_with_xdg_data_home`] with `None`.
pub fn owner_inputs_sha256(
    home: &Path,
    config_dir: &Path,
    data_dir: &Path,
    source_cache_dir: &Path,
    settings: &ScannerSettings,
) -> Option<String> {
    owner_inputs_sha256_with_xdg_data_home(
        home,
        config_dir,
        data_dir,
        None,
        source_cache_dir,
        settings,
    )
}

/// [`owner_inputs_sha256`] with a separate XDG data root (the engine's
/// `*_with_xdg_data_home`). `Some(x)` is hashed as `xdgDataHome` even when
/// `x` equals `data_dir`; `None` leaves the field out.
pub fn owner_inputs_sha256_with_xdg_data_home(
    home: &Path,
    config_dir: &Path,
    data_dir: &Path,
    xdg_data_home: Option<&Path>,
    source_cache_dir: &Path,
    settings: &ScannerSettings,
) -> Option<String> {
    // Exhaustive on purpose, no `..`: an engine pin that adds a settings
    // field stops compiling here, and the field must be either hashed (a
    // consent change) or stated as not an owner input.
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
    let inputs = OwnerInputs {
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
    };
    let bytes = CanonicalJsonV1::encode(&inputs).ok()?;
    Some(hex_encode(&Sha256::digest(&bytes)))
}

/// The engine-backed [`ReportSource`].
pub struct EngineSource {
    root: Arc<SecureRoot>,
    home: PathBuf,
    config_dir: PathBuf,
    data_dir: PathBuf,
    /// Hashed into `owner_inputs_sha256` and passed to every engine call;
    /// set only by the constructor, so no scan uses a value the digest
    /// does not cover.
    xdg_data_home: Option<PathBuf>,
    source_cache_dir: PathBuf,
    pricing_dir: PathBuf,
    settings: ScannerSettings,
    owner_inputs_sha256: String,
    /// Serializes `approve`'s read-compare-write.
    approving: Mutex<()>,
    /// The last scan's outcome, for control `status`.
    scan: Mutex<ScanStatus>,
}

impl std::fmt::Debug for EngineSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EngineSource { .. }")
    }
}

impl EngineSource {
    /// Creates (or checks) the source cache and pricing directories below
    /// `root` and computes the owner-inputs digest. `home`, `config_dir` and
    /// `data_dir` are the owner's absolute roots; custom roots are the
    /// absolute paths in `settings` (`extraScanPaths`, `opencodeDbPaths`).
    /// Anything the engine or the canonical encoder refuses (a relative
    /// path, a non-UTF-8 or non-NFC path) is `Refused(Invalid)`. No
    /// separate XDG data root: [`Self::new_with_xdg_data_home`] with `None`.
    pub fn new(
        root: Arc<SecureRoot>,
        home: PathBuf,
        config_dir: PathBuf,
        data_dir: PathBuf,
        settings: ScannerSettings,
    ) -> Result<Self, StorageError> {
        Self::new_with_xdg_data_home(root, home, config_dir, data_dir, None, settings)
    }

    /// [`Self::new`] with a separate XDG data root `xdg_data_home`: the
    /// engine then resolves `XDG_DATA_HOME` (the XdgData clients and the
    /// OpenCode, Synthetic and Crush databases) to it instead of
    /// `data_dir`, and admits scan roots below it. It is an owner input:
    /// part of `owner_inputs_sha256`. A relative or empty one is
    /// `Refused(Invalid)` (the engine refuses it).
    pub fn new_with_xdg_data_home(
        root: Arc<SecureRoot>,
        home: PathBuf,
        config_dir: PathBuf,
        data_dir: PathBuf,
        xdg_data_home: Option<PathBuf>,
        settings: ScannerSettings,
    ) -> Result<Self, StorageError> {
        // A crash between `stage` and `publish` leaves the temp file, and
        // `stage` creates it exclusively, so `approve` would fail until it
        // is gone.
        root.remove_stale_temp(SCOPE_FILE)?;
        let source_cache_dir = root.private_subdir(SOURCE_CACHE_DIR)?;
        let pricing_dir = root.private_subdir(PRICING_DIR)?;
        let invalid = StorageError::Refused(SecurityError::Invalid);
        RemoteSourceContextV1::preview_fingerprint_with_xdg_data_home(
            &home,
            &config_dir,
            &data_dir,
            xdg_data_home.as_deref(),
            &source_cache_dir,
            &settings,
        )
        .map_err(|_| invalid)?;
        let owner_inputs_sha256 = owner_inputs_sha256_with_xdg_data_home(
            &home,
            &config_dir,
            &data_dir,
            xdg_data_home.as_deref(),
            &source_cache_dir,
            &settings,
        )
        .ok_or(invalid)?;
        Ok(Self {
            root,
            home,
            config_dir,
            data_dir,
            xdg_data_home,
            source_cache_dir,
            pricing_dir,
            settings,
            owner_inputs_sha256,
            approving: Mutex::new(()),
            scan: Mutex::new(ScanStatus::default()),
        })
    }

    /// The separate XDG data root this source scans and hashed, for an
    /// owner disclosure; `None` when there is none.
    pub fn xdg_data_home(&self) -> Option<&Path> {
        self.xdg_data_home.as_deref()
    }

    /// The source cache directory (below the secure root).
    pub fn source_cache_dir(&self) -> &Path {
        &self.source_cache_dir
    }

    /// The pricing root (below the secure root).
    pub fn pricing_dir(&self) -> &Path {
        &self.pricing_dir
    }

    /// The `ownerInputsSha256` of the inputs this source was built with:
    /// the digest control `scopeApprove` must name (`SA-2C2b`).
    pub fn owner_inputs_sha256(&self) -> &str {
        &self.owner_inputs_sha256
    }

    /// Owner action: records this source's inputs as approved at the
    /// store's current `sourceScopeGeneration`. When an approved record for
    /// *different* inputs exists, the generation must have advanced past it
    /// first (`source_change_commit`), or this is `Refused(Conflict)` and
    /// nothing is written. A record that cannot be read or decoded is
    /// returned as that error; nothing is written.
    pub fn approve(&self, store: &StateStore) -> Result<(), StorageError> {
        let _approving = self
            .approving
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The generation must be this root's: a store over another root
        // would approve against a counter no admission here ever reads.
        if !Arc::ptr_eq(&self.root, &store.root()) {
            return Err(StorageError::Refused(SecurityError::Invalid));
        }
        let generation = store.state()?.reference.source_scope_generation;
        if let Some(existing) = self.read_scope()? {
            if existing.owner_inputs_sha256 != self.owner_inputs_sha256
                && generation <= existing.generation
            {
                return Err(StorageError::Refused(SecurityError::Conflict));
            }
        }
        let record = ApprovedScope {
            generation,
            owner_inputs_sha256: self.owner_inputs_sha256.clone(),
            schema: SCOPE_SCHEMA_VERSION,
        };
        let bytes = CanonicalJsonV1::encode(&record).map_err(|_| StorageError::Corrupt)?;
        self.root.stage(SCOPE_FILE, &bytes)?.publish()
    }

    /// The approved-scope record, read-only: its generation and whether
    /// its digest equals this source's inputs. `None` when there is none;
    /// a record that cannot be read or decoded is that error.
    pub fn scope_record(&self) -> Result<Option<ScopeRecord>, StorageError> {
        Ok(self.read_scope()?.map(|scope| ScopeRecord {
            generation: scope.generation,
            inputs_match: scope.owner_inputs_sha256 == self.owner_inputs_sha256,
        }))
    }

    /// The scan fields of control `status`: when the last successful scan
    /// finished (Unix seconds, OS clock), whether the last scan succeeded,
    /// and the clients of the last successful scan, sorted and unique. A
    /// scan is a `report` call that reached the engine: one that fails
    /// there or ends late is `error`. A call refused before the engine (a
    /// passed deadline, an unknown endpoint, a scope denial) is not a scan
    /// and changes nothing here.
    pub fn scan_status(&self) -> ScanStatus {
        self.scan
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn read_scope(&self) -> Result<Option<ApprovedScope>, StorageError> {
        let Some(bytes) = self.root.read_file(SCOPE_FILE, SCOPE_FILE_MAX_BYTES)? else {
            return Ok(None);
        };
        let scope: ApprovedScope =
            CanonicalJsonV1::decode(&bytes).map_err(|_| StorageError::Corrupt)?;
        if scope.schema != SCOPE_SCHEMA_VERSION {
            return Err(StorageError::Incompatible);
        }
        Ok(Some(scope))
    }

    /// Deny unless the approved record exists, names this request's
    /// generation and this source's inputs. The generation is the request's:
    /// the producer admitted it against the durable counter already.
    fn approved(&self, request: &ReportRequest) -> bool {
        matches!(
            self.read_scope(),
            Ok(Some(scope)) if scope.generation == request.source_scope_generation
                && scope.owner_inputs_sha256 == self.owner_inputs_sha256
        )
    }

    /// The engine scan: the body, and the clients of the whole bundle. The
    /// caller has checked the endpoint and the approved scope.
    fn scan(
        &self,
        request: &ReportRequest,
        endpoint: Endpoint,
        node_label: Option<&str>,
    ) -> Result<(Vec<u8>, BTreeSet<String>), SourceError> {
        let fingerprint = RemoteSourceContextV1::preview_fingerprint_with_xdg_data_home(
            &self.home,
            &self.config_dir,
            &self.data_dir,
            self.xdg_data_home.as_deref(),
            &self.source_cache_dir,
            &self.settings,
        )
        .map_err(|_| SourceError)?;
        let context = RemoteSourceContextV1::new_with_xdg_data_home(
            &self.home,
            &self.config_dir,
            &self.data_dir,
            self.xdg_data_home.as_deref(),
            &self.source_cache_dir,
            self.settings.clone(),
            RemoteSourceScopeTokenV1::new(fingerprint, request.source_scope_generation),
        )
        .map_err(|_| SourceError)?;
        let query = RemoteUsageQueryV1 {
            clients: request.clients.clone(),
            start_date: request.start_date.clone(),
            end_date_exclusive: request.end_date_exclusive.clone(),
            timezone: request.timezone.clone(),
            tzdb_revision: request.tzdb_revision.clone(),
        };
        let pricing = RemotePricingSnapshot::from_cache_root(&self.pricing_dir);
        // ponytail: the engine folds all four endpoints per call and three are
        // dropped here; the ceiling is one scan per endpoint request, which the
        // engine's source cache amortizes. Add a per-endpoint seam in the fork
        // if scans are measured to dominate.
        let bundle = aggregate_remote_usage_from_source_v1(&context, &query, &pricing)
            .map_err(|_| SourceError)?;
        // The flag is read here, on the producer, from the snapshot this
        // fold was priced with.
        let meta = Meta {
            saturated: bundle.saturated,
            node_label,
            cost_incomplete: cost_incomplete(pricing.diagnostic()),
        };
        let families: BTreeSet<String> = (bundle.graph.iter().map(|r| &r.client))
            .chain(bundle.models.iter().map(|r| &r.client))
            .chain(bundle.hourly.iter().map(|r| &r.client))
            .chain(bundle.agents.iter().map(|r| &r.client))
            .cloned()
            .collect();
        let body = match endpoint {
            Endpoint::Graph => encode(request, bundle.graph.into_iter().map(graph), meta),
            Endpoint::Models => encode(request, bundle.models.into_iter().map(models), meta),
            Endpoint::Hourly => encode(request, bundle.hourly.into_iter().map(hourly), meta),
            Endpoint::Agents => encode(request, bundle.agents.into_iter().map(agents), meta),
        }?;
        Ok((body, families))
    }

    fn record_scan(&self, families: Option<BTreeSet<String>>) {
        let mut scan = self.scan.lock().unwrap_or_else(PoisonError::into_inner);
        match families {
            Some(families) => {
                scan.state = ScanState::Ok;
                scan.last_scan_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|since| i64::try_from(since.as_secs()).ok());
                // The frozen bound of `sourceFamilies`.
                scan.families = families.into_iter().take(128).collect();
            }
            None => scan.state = ScanState::Error,
        }
    }
}

impl ReportSource for EngineSource {
    /// Errors carry no path or engine text: every failure is [`SourceError`].
    /// A deadline already passed, an unknown endpoint or a scope denial is
    /// refused before the engine runs, and is not recorded as a scan.
    fn report(
        &self,
        request: &ReportRequest,
        node_label: Option<&str>,
        deadline: Instant,
    ) -> Result<Vec<u8>, SourceError> {
        if Instant::now() > deadline {
            return Err(SourceError);
        }
        let endpoint = Endpoint::try_from(request.endpoint).map_err(|_| SourceError)?;
        if !self.approved(request) {
            return Err(SourceError);
        }
        let result = self.scan(request, endpoint, node_label).and_then(|done| {
            (Instant::now() <= deadline)
                .then_some(done)
                .ok_or(SourceError)
        });
        match result {
            Ok((body, families)) => {
                self.record_scan(Some(families));
                Ok(body)
            }
            Err(error) => {
                self.record_scan(None);
                Err(error)
            }
        }
    }
}

/// What the response carries besides the records.
#[derive(Clone, Copy)]
struct Meta<'a> {
    saturated: bool,
    node_label: Option<&'a str>,
    cost_incomplete: bool,
}

/// DR-2b `costIncomplete`: a pricing half that prices nothing (`Missing`,
/// `Corrupt`) can leave costs at zero; a `Stale` table still prices. Only
/// the boolean leaves the producer, never the diagnostic itself (it would
/// tell the clock and how often prices are fetched). Exhaustive: an engine
/// pin that adds a diagnostic stops compiling here.
fn cost_incomplete(diagnostic: Option<RemotePricingDiagnostic>) -> bool {
    match diagnostic {
        Some(RemotePricingDiagnostic::Missing | RemotePricingDiagnostic::Corrupt) => true,
        Some(RemotePricingDiagnostic::Stale) | None => false,
    }
}

fn encode<R: ReportRecord>(
    request: &ReportRequest,
    records: impl Iterator<Item = R>,
    meta: Meta<'_>,
) -> Result<Vec<u8>, SourceError> {
    encode_response(&ReportResponse {
        node_label: meta.node_label.map(str::to_owned),
        cost_incomplete: meta.cost_incomplete,
        ..ReportResponse::from_request(request, records.collect(), meta.saturated)
    })
    .map_err(|_| SourceError)
}

fn graph(record: RemoteGraphRecordV1) -> GraphRecord {
    GraphRecord {
        date: record.date,
        client: record.client,
        model: record.model,
        provider: record.provider,
        input_tokens: record.input_tokens,
        output_tokens: record.output_tokens,
        cache_read_tokens: record.cache_read_tokens,
        cache_write_tokens: record.cache_write_tokens,
        reasoning_tokens: record.reasoning_tokens,
        total_tokens: record.total_tokens,
        message_count: record.message_count,
        turn_count: record.turn_count,
        cost_nano_usd: record.cost_nano_usd,
    }
}

fn models(record: RemoteModelsRecordV1) -> ModelsRecord {
    ModelsRecord {
        client: record.client,
        model: record.model,
        provider: record.provider,
        input_tokens: record.input_tokens,
        output_tokens: record.output_tokens,
        cache_read_tokens: record.cache_read_tokens,
        cache_write_tokens: record.cache_write_tokens,
        reasoning_tokens: record.reasoning_tokens,
        total_tokens: record.total_tokens,
        message_count: record.message_count,
        turn_count: record.turn_count,
        cost_nano_usd: record.cost_nano_usd,
        duration_millis: record.duration_millis,
        timed_tokens: record.timed_tokens,
        sample_count: record.sample_count,
    }
}

fn hourly(record: RemoteHourlyRecordV1) -> HourlyRecord {
    HourlyRecord {
        bucket_start_unix_ms: record.bucket_start_unix_ms,
        utc_offset_seconds: record.utc_offset_seconds,
        client: record.client,
        model: record.model,
        provider: record.provider,
        input_tokens: record.input_tokens,
        output_tokens: record.output_tokens,
        cache_read_tokens: record.cache_read_tokens,
        cache_write_tokens: record.cache_write_tokens,
        reasoning_tokens: record.reasoning_tokens,
        total_tokens: record.total_tokens,
        message_count: record.message_count,
        turn_count: record.turn_count,
        cost_nano_usd: record.cost_nano_usd,
    }
}

fn agents(record: RemoteAgentsRecordV1) -> AgentsRecord {
    AgentsRecord {
        agent: record.agent,
        client: record.client,
        model: record.model,
        provider: record.provider,
        input_tokens: record.input_tokens,
        output_tokens: record.output_tokens,
        cache_read_tokens: record.cache_read_tokens,
        cache_write_tokens: record.cache_write_tokens,
        reasoning_tokens: record.reasoning_tokens,
        total_tokens: record.total_tokens,
        message_count: record.message_count,
        turn_count: record.turn_count,
        cost_nano_usd: record.cost_nano_usd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DR-2b (e): Missing and Corrupt are incomplete; None and Stale are not.
    #[test]
    fn cost_is_incomplete_only_for_a_missing_or_corrupt_table() {
        assert!(cost_incomplete(Some(RemotePricingDiagnostic::Missing)));
        assert!(cost_incomplete(Some(RemotePricingDiagnostic::Corrupt)));
        assert!(!cost_incomplete(Some(RemotePricingDiagnostic::Stale)));
        assert!(!cost_incomplete(None));
    }
}
