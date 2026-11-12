//! The product report source (`spec/source-v1.md`).
//!
//! Every scan, parse, dedup, price and fold happens in the pinned engine
//! (`tokscale-core`, `aggregate_remote_usage_from_source_v1`). This module
//! only builds the engine's context from owner-approved inputs, checks the
//! approved-scope record, copies the requested endpoint's records field by
//! field into the frozen `report.rs` types, and encodes them. It never
//! filters or re-aggregates what the engine returns.
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokscale_core::{
    RemoteAgentsRecordV1, RemoteGraphRecordV1, RemoteHourlyRecordV1, RemoteModelsRecordV1,
    RemotePricingSnapshot, RemoteSourceContextV1, RemoteSourceScopeTokenV1, RemoteUsageQueryV1,
    ScannerSettings, aggregate_remote_usage_from_source_v1,
};

use crate::{
    canonical::CanonicalJsonV1,
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

/// What the consent binds to: only inputs the owner controls, in an
/// encoding this crate fixes (field names here, paths as UTF-8 strings,
/// every list sorted and deduplicated, maps ordered by key). Neither the
/// engine's fingerprint (it hashes the engine's client table and resolver
/// version) nor the engine's serde form of `ScannerSettings` (a new engine
/// field would serialize as a default) is used, so an engine pin alone
/// never changes the digest (D1).
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
}

/// `ownerInputsSha256` for these inputs: SHA-256 of the CanonicalJsonV1
/// encoding of [`OwnerInputs`], lowercase hex. `None` when a path is not
/// UTF-8 or a string is not NFC.
pub fn owner_inputs_sha256(
    home: &Path,
    config_dir: &Path,
    data_dir: &Path,
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
    source_cache_dir: PathBuf,
    pricing_dir: PathBuf,
    settings: ScannerSettings,
    owner_inputs_sha256: String,
    /// Serializes `approve`'s read-compare-write.
    approving: Mutex<()>,
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
    /// path, a non-UTF-8 or non-NFC path) is `Refused(Invalid)`.
    pub fn new(
        root: Arc<SecureRoot>,
        home: PathBuf,
        config_dir: PathBuf,
        data_dir: PathBuf,
        settings: ScannerSettings,
    ) -> Result<Self, StorageError> {
        // A crash between `stage` and `publish` leaves the temp file, and
        // `stage` creates it exclusively, so `approve` would fail until it
        // is gone.
        root.remove_stale_temp(SCOPE_FILE)?;
        let source_cache_dir = root.private_subdir(SOURCE_CACHE_DIR)?;
        let pricing_dir = root.private_subdir(PRICING_DIR)?;
        let invalid = StorageError::Refused(SecurityError::Invalid);
        RemoteSourceContextV1::preview_fingerprint(
            &home,
            &config_dir,
            &data_dir,
            &source_cache_dir,
            &settings,
        )
        .map_err(|_| invalid)?;
        let owner_inputs_sha256 =
            owner_inputs_sha256(&home, &config_dir, &data_dir, &source_cache_dir, &settings)
                .ok_or(invalid)?;
        Ok(Self {
            root,
            home,
            config_dir,
            data_dir,
            source_cache_dir,
            pricing_dir,
            settings,
            owner_inputs_sha256,
            approving: Mutex::new(()),
        })
    }

    /// The source cache directory (below the secure root).
    pub fn source_cache_dir(&self) -> &Path {
        &self.source_cache_dir
    }

    /// The pricing root (below the secure root).
    pub fn pricing_dir(&self) -> &Path {
        &self.pricing_dir
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

    fn body(&self, request: &ReportRequest) -> Result<Vec<u8>, SourceError> {
        let endpoint = Endpoint::try_from(request.endpoint).map_err(|_| SourceError)?;
        if !self.approved(request) {
            return Err(SourceError);
        }
        let fingerprint = RemoteSourceContextV1::preview_fingerprint(
            &self.home,
            &self.config_dir,
            &self.data_dir,
            &self.source_cache_dir,
            &self.settings,
        )
        .map_err(|_| SourceError)?;
        let context = RemoteSourceContextV1::new(
            &self.home,
            &self.config_dir,
            &self.data_dir,
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
        let saturated = bundle.saturated;
        match endpoint {
            Endpoint::Graph => encode(request, bundle.graph.into_iter().map(graph), saturated),
            Endpoint::Models => encode(request, bundle.models.into_iter().map(models), saturated),
            Endpoint::Hourly => encode(request, bundle.hourly.into_iter().map(hourly), saturated),
            Endpoint::Agents => encode(request, bundle.agents.into_iter().map(agents), saturated),
        }
    }
}

impl ReportSource for EngineSource {
    /// Errors carry no path or engine text: every failure is [`SourceError`].
    fn report(&self, request: &ReportRequest, deadline: Instant) -> Result<Vec<u8>, SourceError> {
        let body = self.body(request)?;
        if Instant::now() > deadline {
            return Err(SourceError);
        }
        Ok(body)
    }
}

fn encode<R: ReportRecord>(
    request: &ReportRequest,
    records: impl Iterator<Item = R>,
    saturated: bool,
) -> Result<Vec<u8>, SourceError> {
    encode_response(&ReportResponse::from_request(
        request,
        records.collect(),
        saturated,
    ))
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
