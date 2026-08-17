use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    canonical::CanonicalJsonV1,
    canonical::constant_time_eq,
    report::{
        AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportError,
        ReportRequest, decode_response,
    },
    security::{decode_fixed_hex, hex_encode},
};

pub const CACHE_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheRole {
    Producer,
    Receiver,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheKey {
    pub aggregation_revision: u16,
    pub auth_epoch: u64,
    pub clients: Vec<String>,
    pub end_date_exclusive: String,
    pub endpoint: u16,
    pub grant_id: String,
    pub peer_static: String,
    pub report_schema: u16,
    pub role: CacheRole,
    pub source_scope_generation: u64,
    pub start_date: String,
    pub timezone: String,
    pub tzdb_revision: String,
}

impl CacheKey {
    pub fn validate(&self) -> Result<(), CacheError> {
        let request = ReportRequest {
            aggregation_revision: self.aggregation_revision,
            auth_epoch: self.auth_epoch,
            clients: self.clients.clone(),
            end_date_exclusive: self.end_date_exclusive.clone(),
            endpoint: self.endpoint,
            grant_id: self.grant_id.clone(),
            protocol: 1,
            report_schema: self.report_schema,
            request_id: "00".repeat(16),
            source_scope_generation: self.source_scope_generation,
            start_date: self.start_date.clone(),
            timezone: self.timezone.clone(),
            tzdb_revision: self.tzdb_revision.clone(),
        };
        request.validate().map_err(CacheError::from_report)?;
        if decode_fixed_hex::<32>(&self.peer_static).is_err() {
            return Err(CacheError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheMetadata {
    pub body_sha256: String,
    pub cache_key: CacheKey,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl CacheMetadata {
    pub fn for_body(
        cache_key: CacheKey,
        created_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        body: &[u8],
    ) -> Self {
        Self {
            body_sha256: body_sha256(body),
            cache_key,
            created_at_unix_ms,
            expires_at_unix_ms,
        }
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), CacheError> {
        self.validate_shape()?;
        if now_ms >= self.expires_at_unix_ms {
            return Err(CacheError::Expired);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CacheError> {
        self.cache_key.validate()?;
        if decode_fixed_hex::<32>(&self.body_sha256).is_err()
            || self.expires_at_unix_ms <= self.created_at_unix_ms
            || self
                .expires_at_unix_ms
                .checked_sub(self.created_at_unix_ms)
                .is_none_or(|duration| duration > CACHE_RETENTION_MILLIS)
        {
            return Err(CacheError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCacheEntry {
    pub metadata: CacheMetadata,
    pub body: Vec<u8>,
    pub endpoint: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheError {
    BodyHashMismatch,
    BodyInvalid,
    Bounds,
    Canonical,
    CrossRoot,
    Expired,
    Invalid,
    KeyFilenameMismatch,
}

impl CacheError {
    fn from_report(error: ReportError) -> Self {
        match error {
            ReportError::Bounds => Self::Bounds,
            ReportError::Canonical => Self::Canonical,
            _ => Self::Invalid,
        }
    }
}

pub fn encode_metadata(metadata: &CacheMetadata) -> Result<Vec<u8>, CacheError> {
    metadata.validate_shape()?;
    CanonicalJsonV1::encode(metadata).map_err(|_| CacheError::Canonical)
}

pub fn decode_metadata(bytes: &[u8]) -> Result<CacheMetadata, CacheError> {
    CanonicalJsonV1::decode(bytes).map_err(|_| CacheError::Canonical)
}

pub fn cache_key_json(key: &CacheKey) -> Result<Vec<u8>, CacheError> {
    key.validate()?;
    CanonicalJsonV1::encode(key).map_err(|_| CacheError::Canonical)
}

pub fn cache_filename(key: &CacheKey) -> Result<String, CacheError> {
    let digest = Sha256::digest(cache_key_json(key)?);
    Ok(hex_encode(&digest))
}

pub fn body_sha256(body: &[u8]) -> String {
    hex_encode(&Sha256::digest(body))
}

pub fn validate_entry(
    metadata_bytes: &[u8],
    body: &[u8],
    filename: &str,
    expected_role: CacheRole,
    now_ms: i64,
) -> Result<ValidatedCacheEntry, CacheError> {
    let metadata = decode_metadata(metadata_bytes)?;
    metadata.validate(now_ms)?;
    if metadata.cache_key.role != expected_role {
        return Err(CacheError::CrossRoot);
    }
    if cache_filename(&metadata.cache_key)? != filename {
        return Err(CacheError::KeyFilenameMismatch);
    }
    let expected_hash =
        decode_fixed_hex::<32>(&metadata.body_sha256).map_err(|_| CacheError::Invalid)?;
    let actual_hash: [u8; 32] = Sha256::digest(body).into();
    if !constant_time_eq(&expected_hash, &actual_hash) {
        return Err(CacheError::BodyHashMismatch);
    }

    let endpoint =
        Endpoint::try_from(metadata.cache_key.endpoint).map_err(|_| CacheError::Invalid)?;
    let request = match endpoint {
        Endpoint::Graph => decode_response::<GraphRecord>(body, None)
            .map(|response| response.request())
            .map_err(|_| CacheError::BodyInvalid)?,
        Endpoint::Models => decode_response::<ModelsRecord>(body, None)
            .map(|response| response.request())
            .map_err(|_| CacheError::BodyInvalid)?,
        Endpoint::Hourly => decode_response::<HourlyRecord>(body, None)
            .map(|response| response.request())
            .map_err(|_| CacheError::BodyInvalid)?,
        Endpoint::Agents => decode_response::<AgentsRecord>(body, None)
            .map(|response| response.request())
            .map_err(|_| CacheError::BodyInvalid)?,
    };
    if request.aggregation_revision != metadata.cache_key.aggregation_revision
        || request.auth_epoch != metadata.cache_key.auth_epoch
        || request.clients != metadata.cache_key.clients
        || request.end_date_exclusive != metadata.cache_key.end_date_exclusive
        || request.endpoint != metadata.cache_key.endpoint
        || request.grant_id != metadata.cache_key.grant_id
        || request.report_schema != metadata.cache_key.report_schema
        || request.source_scope_generation != metadata.cache_key.source_scope_generation
        || request.start_date != metadata.cache_key.start_date
        || request.timezone != metadata.cache_key.timezone
        || request.tzdb_revision != metadata.cache_key.tzdb_revision
    {
        return Err(CacheError::BodyInvalid);
    }
    Ok(ValidatedCacheEntry {
        metadata,
        body: body.to_vec(),
        endpoint,
    })
}
