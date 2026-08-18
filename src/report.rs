use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::{
    canonical::{CanonicalError, CanonicalJsonV1},
    security::{
        AGGREGATION_REVISION, PEER_PROTOCOL_VERSION, REPORT_SCHEMA_VERSION, TZDB_REVISION,
        decode_fixed_hex,
    },
};

pub const DIRECT_SUM_AGGREGATION: &str = "directSum";
pub const DUPLICATE_WARNING: bool = true;
pub const DUPLICATE_WARNING_TEXT: &str = "同步過的歷史資料可能重複計算";
pub const MAX_TEXT_BYTES: usize = 255;
pub const MAX_CLIENTS: usize = 128;
pub const MAX_RANGE_DAYS: i64 = 370;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportError {
    Bounds,
    Canonical,
    Duplicate,
    EchoMismatch,
    Invalid,
    UnsupportedEndpoint,
}

impl From<CanonicalError> for ReportError {
    fn from(_: CanonicalError) -> Self {
        Self::Canonical
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Endpoint {
    Graph = 1,
    Models = 2,
    Hourly = 3,
    Agents = 4,
}

impl TryFrom<u16> for Endpoint {
    type Error = ReportError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Graph),
            2 => Ok(Self::Models),
            3 => Ok(Self::Hourly),
            4 => Ok(Self::Agents),
            _ => Err(ReportError::UnsupportedEndpoint),
        }
    }
}

impl From<Endpoint> for u16 {
    fn from(value: Endpoint) -> Self {
        value as Self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportRequest {
    pub aggregation_revision: u16,
    pub auth_epoch: u64,
    pub clients: Vec<String>,
    pub end_date_exclusive: String,
    pub endpoint: u16,
    pub grant_id: String,
    pub protocol: u16,
    pub report_schema: u16,
    pub request_id: String,
    pub source_scope_generation: u64,
    pub start_date: String,
    pub timezone: String,
    pub tzdb_revision: String,
}

impl ReportRequest {
    pub fn validate(&self) -> Result<(), ReportError> {
        if self.aggregation_revision != AGGREGATION_REVISION
            || self.protocol != PEER_PROTOCOL_VERSION
            || self.report_schema != REPORT_SCHEMA_VERSION
            || self.tzdb_revision != TZDB_REVISION
        {
            return Err(ReportError::Invalid);
        }
        Endpoint::try_from(self.endpoint)?;
        fixed_hex::<16>(&self.request_id)?;
        fixed_hex::<16>(&self.grant_id)?;
        validate_date_range(&self.start_date, &self.end_date_exclusive)?;
        validate_text(&self.timezone, false)?;
        if self.clients.len() > MAX_CLIENTS {
            return Err(ReportError::Bounds);
        }
        for client in &self.clients {
            validate_text(client, false)?;
        }
        if self
            .clients
            .windows(2)
            .any(|window| cmp_text(&window[0], &window[1]) != Ordering::Less)
        {
            return Err(ReportError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphRecord {
    pub date: String,
    pub client: String,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    pub message_count: u64,
    pub turn_count: u64,
    pub cost_nano_usd: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelsRecord {
    pub client: String,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    pub message_count: u64,
    pub turn_count: u64,
    pub cost_nano_usd: u64,
    pub duration_millis: u64,
    pub timed_tokens: u64,
    pub sample_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HourlyRecord {
    pub bucket_start_unix_ms: i64,
    pub utc_offset_seconds: i32,
    pub client: String,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    pub message_count: u64,
    pub turn_count: u64,
    pub cost_nano_usd: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentsRecord {
    pub agent: String,
    pub client: String,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    pub message_count: u64,
    pub turn_count: u64,
    pub cost_nano_usd: u64,
}

pub trait ReportRecord:
    Clone + Serialize + for<'de> Deserialize<'de> + Eq + std::fmt::Debug
{
    const ENDPOINT: Endpoint;

    fn validate(&self) -> Result<(), ReportError>;
    fn cmp_identity(&self, other: &Self) -> Ordering;
    fn same_identity(&self, other: &Self) -> bool {
        self.cmp_identity(other) == Ordering::Equal
    }
    fn add_saturating(&mut self, other: &Self, saturated: &mut bool);
    fn client(&self) -> &str;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportResponse<R> {
    pub aggregation_revision: u16,
    pub auth_epoch: u64,
    pub clients: Vec<String>,
    pub end_date_exclusive: String,
    pub endpoint: u16,
    pub grant_id: String,
    pub protocol: u16,
    pub report_schema: u16,
    pub request_id: String,
    pub source_scope_generation: u64,
    pub start_date: String,
    pub timezone: String,
    pub tzdb_revision: String,
    pub records: Vec<R>,
    pub saturated: bool,
}

impl<R: ReportRecord> ReportResponse<R> {
    pub fn from_request(request: &ReportRequest, records: Vec<R>, saturated: bool) -> Self {
        Self {
            aggregation_revision: request.aggregation_revision,
            auth_epoch: request.auth_epoch,
            clients: request.clients.clone(),
            end_date_exclusive: request.end_date_exclusive.clone(),
            endpoint: request.endpoint,
            grant_id: request.grant_id.clone(),
            protocol: request.protocol,
            report_schema: request.report_schema,
            request_id: request.request_id.clone(),
            source_scope_generation: request.source_scope_generation,
            start_date: request.start_date.clone(),
            timezone: request.timezone.clone(),
            tzdb_revision: request.tzdb_revision.clone(),
            records,
            saturated,
        }
    }

    pub fn request(&self) -> ReportRequest {
        ReportRequest {
            aggregation_revision: self.aggregation_revision,
            auth_epoch: self.auth_epoch,
            clients: self.clients.clone(),
            end_date_exclusive: self.end_date_exclusive.clone(),
            endpoint: self.endpoint,
            grant_id: self.grant_id.clone(),
            protocol: self.protocol,
            report_schema: self.report_schema,
            request_id: self.request_id.clone(),
            source_scope_generation: self.source_scope_generation,
            start_date: self.start_date.clone(),
            timezone: self.timezone.clone(),
            tzdb_revision: self.tzdb_revision.clone(),
        }
    }

    pub fn validate(&self, expected: Option<&ReportRequest>) -> Result<(), ReportError> {
        let request = self.request();
        request.validate()?;
        if R::ENDPOINT as u16 != self.endpoint {
            return Err(ReportError::UnsupportedEndpoint);
        }
        if expected.is_some_and(|expected| expected != &request) {
            return Err(ReportError::EchoMismatch);
        }
        validate_records(&self.records)?;
        if !self.clients.is_empty()
            && self.records.iter().any(|record| {
                self.clients
                    .binary_search_by(|client| cmp_text(client, record.client()))
                    .is_err()
            })
        {
            return Err(ReportError::Invalid);
        }
        Ok(())
    }
}

pub fn encode_response<R: ReportRecord>(
    response: &ReportResponse<R>,
) -> Result<Vec<u8>, ReportError> {
    response.validate(None)?;
    CanonicalJsonV1::encode(response).map_err(Into::into)
}

pub fn decode_response<R: ReportRecord>(
    bytes: &[u8],
    expected: Option<&ReportRequest>,
) -> Result<ReportResponse<R>, ReportError> {
    let response: ReportResponse<R> = CanonicalJsonV1::decode(bytes)?;
    response.validate(expected)?;
    Ok(response)
}

pub type GraphResponse = ReportResponse<GraphRecord>;
pub type ModelsResponse = ReportResponse<ModelsRecord>;
pub type HourlyResponse = ReportResponse<HourlyRecord>;
pub type AgentsResponse = ReportResponse<AgentsRecord>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeResult<R> {
    pub records: Vec<R>,
    pub saturated: bool,
}

pub fn validate_graph_records(records: &[GraphRecord]) -> Result<(), ReportError> {
    validate_records(records)
}

pub fn validate_models_records(records: &[ModelsRecord]) -> Result<(), ReportError> {
    validate_records(records)
}

pub fn validate_hourly_records(records: &[HourlyRecord]) -> Result<(), ReportError> {
    validate_records(records)
}

pub fn validate_agents_records(records: &[AgentsRecord]) -> Result<(), ReportError> {
    validate_records(records)
}

pub fn merge_graph(records: &[GraphRecord]) -> Result<MergeResult<GraphRecord>, ReportError> {
    merge_records(records)
}

pub fn merge_models(records: &[ModelsRecord]) -> Result<MergeResult<ModelsRecord>, ReportError> {
    merge_records(records)
}

pub fn merge_hourly(records: &[HourlyRecord]) -> Result<MergeResult<HourlyRecord>, ReportError> {
    merge_records(records)
}

pub fn merge_agents(records: &[AgentsRecord]) -> Result<MergeResult<AgentsRecord>, ReportError> {
    merge_records(records)
}

fn validate_records<R: ReportRecord>(records: &[R]) -> Result<(), ReportError> {
    for record in records {
        record.validate()?;
    }
    if records
        .windows(2)
        .any(|window| window[0].cmp_identity(&window[1]) != Ordering::Less)
    {
        return Err(ReportError::Duplicate);
    }
    Ok(())
}

fn merge_records<R: ReportRecord>(records: &[R]) -> Result<MergeResult<R>, ReportError> {
    let mut sorted = records.to_vec();
    for record in &sorted {
        record.validate()?;
    }
    sorted.sort_by(|left, right| left.cmp_identity(right));
    let mut merged: Vec<R> = Vec::with_capacity(sorted.len());
    let mut saturated = false;
    for record in sorted {
        if let Some(previous) = merged.last_mut() {
            if previous.same_identity(&record) {
                previous.add_saturating(&record, &mut saturated);
                continue;
            }
        }
        merged.push(record);
    }
    Ok(MergeResult {
        records: merged,
        saturated,
    })
}

impl ReportRecord for GraphRecord {
    const ENDPOINT: Endpoint = Endpoint::Graph;

    fn validate(&self) -> Result<(), ReportError> {
        validate_date(&self.date)?;
        validate_client_dimensions(&self.client, &self.model, &self.provider)
    }

    fn cmp_identity(&self, other: &Self) -> Ordering {
        cmp_text(&self.date, &other.date)
            .then_with(|| cmp_text(&self.client, &other.client))
            .then_with(|| cmp_optional(&self.model, &other.model))
            .then_with(|| cmp_optional(&self.provider, &other.provider))
    }

    fn add_saturating(&mut self, other: &Self, saturated: &mut bool) {
        add_common(self, other, saturated);
    }

    fn client(&self) -> &str {
        &self.client
    }
}

impl ReportRecord for ModelsRecord {
    const ENDPOINT: Endpoint = Endpoint::Models;

    fn validate(&self) -> Result<(), ReportError> {
        validate_client_dimensions(&self.client, &self.model, &self.provider)
    }

    fn cmp_identity(&self, other: &Self) -> Ordering {
        cmp_text(&self.client, &other.client)
            .then_with(|| cmp_optional(&self.model, &other.model))
            .then_with(|| cmp_optional(&self.provider, &other.provider))
    }

    fn add_saturating(&mut self, other: &Self, saturated: &mut bool) {
        add_common(self, other, saturated);
        add(&mut self.duration_millis, other.duration_millis, saturated);
        add(&mut self.timed_tokens, other.timed_tokens, saturated);
        add(&mut self.sample_count, other.sample_count, saturated);
    }

    fn client(&self) -> &str {
        &self.client
    }
}

impl ReportRecord for HourlyRecord {
    const ENDPOINT: Endpoint = Endpoint::Hourly;

    fn validate(&self) -> Result<(), ReportError> {
        validate_client_dimensions(&self.client, &self.model, &self.provider)
    }

    fn cmp_identity(&self, other: &Self) -> Ordering {
        self.bucket_start_unix_ms
            .cmp(&other.bucket_start_unix_ms)
            .then_with(|| self.utc_offset_seconds.cmp(&other.utc_offset_seconds))
            .then_with(|| cmp_text(&self.client, &other.client))
            .then_with(|| cmp_optional(&self.model, &other.model))
            .then_with(|| cmp_optional(&self.provider, &other.provider))
    }

    fn add_saturating(&mut self, other: &Self, saturated: &mut bool) {
        add_common(self, other, saturated);
    }

    fn client(&self) -> &str {
        &self.client
    }
}

impl ReportRecord for AgentsRecord {
    const ENDPOINT: Endpoint = Endpoint::Agents;

    fn validate(&self) -> Result<(), ReportError> {
        validate_text(&self.agent, false)?;
        validate_client_dimensions(&self.client, &self.model, &self.provider)
    }

    fn cmp_identity(&self, other: &Self) -> Ordering {
        cmp_text(&self.agent, &other.agent)
            .then_with(|| cmp_text(&self.client, &other.client))
            .then_with(|| cmp_optional(&self.model, &other.model))
            .then_with(|| cmp_optional(&self.provider, &other.provider))
    }

    fn add_saturating(&mut self, other: &Self, saturated: &mut bool) {
        add_common(self, other, saturated);
    }

    fn client(&self) -> &str {
        &self.client
    }
}

trait CommonNumerators {
    fn input_tokens_mut(&mut self) -> &mut u64;
    fn output_tokens_mut(&mut self) -> &mut u64;
    fn cache_read_tokens_mut(&mut self) -> &mut u64;
    fn cache_write_tokens_mut(&mut self) -> &mut u64;
    fn reasoning_tokens_mut(&mut self) -> &mut u64;
    fn total_tokens_mut(&mut self) -> &mut u64;
    fn message_count_mut(&mut self) -> &mut u64;
    fn turn_count_mut(&mut self) -> &mut u64;
    fn cost_nano_usd_mut(&mut self) -> &mut u64;
    fn input_tokens(&self) -> u64;
    fn output_tokens(&self) -> u64;
    fn cache_read_tokens(&self) -> u64;
    fn cache_write_tokens(&self) -> u64;
    fn reasoning_tokens(&self) -> u64;
    fn total_tokens(&self) -> u64;
    fn message_count(&self) -> u64;
    fn turn_count(&self) -> u64;
    fn cost_nano_usd(&self) -> u64;
}

macro_rules! common_numerators {
    ($type:ty) => {
        impl CommonNumerators for $type {
            fn input_tokens_mut(&mut self) -> &mut u64 {
                &mut self.input_tokens
            }
            fn output_tokens_mut(&mut self) -> &mut u64 {
                &mut self.output_tokens
            }
            fn cache_read_tokens_mut(&mut self) -> &mut u64 {
                &mut self.cache_read_tokens
            }
            fn cache_write_tokens_mut(&mut self) -> &mut u64 {
                &mut self.cache_write_tokens
            }
            fn reasoning_tokens_mut(&mut self) -> &mut u64 {
                &mut self.reasoning_tokens
            }
            fn total_tokens_mut(&mut self) -> &mut u64 {
                &mut self.total_tokens
            }
            fn message_count_mut(&mut self) -> &mut u64 {
                &mut self.message_count
            }
            fn turn_count_mut(&mut self) -> &mut u64 {
                &mut self.turn_count
            }
            fn cost_nano_usd_mut(&mut self) -> &mut u64 {
                &mut self.cost_nano_usd
            }
            fn input_tokens(&self) -> u64 {
                self.input_tokens
            }
            fn output_tokens(&self) -> u64 {
                self.output_tokens
            }
            fn cache_read_tokens(&self) -> u64 {
                self.cache_read_tokens
            }
            fn cache_write_tokens(&self) -> u64 {
                self.cache_write_tokens
            }
            fn reasoning_tokens(&self) -> u64 {
                self.reasoning_tokens
            }
            fn total_tokens(&self) -> u64 {
                self.total_tokens
            }
            fn message_count(&self) -> u64 {
                self.message_count
            }
            fn turn_count(&self) -> u64 {
                self.turn_count
            }
            fn cost_nano_usd(&self) -> u64 {
                self.cost_nano_usd
            }
        }
    };
}

common_numerators!(GraphRecord);
common_numerators!(ModelsRecord);
common_numerators!(HourlyRecord);
common_numerators!(AgentsRecord);

fn add_common<T: CommonNumerators>(left: &mut T, right: &T, saturated: &mut bool) {
    add(left.input_tokens_mut(), right.input_tokens(), saturated);
    add(left.output_tokens_mut(), right.output_tokens(), saturated);
    add(
        left.cache_read_tokens_mut(),
        right.cache_read_tokens(),
        saturated,
    );
    add(
        left.cache_write_tokens_mut(),
        right.cache_write_tokens(),
        saturated,
    );
    add(
        left.reasoning_tokens_mut(),
        right.reasoning_tokens(),
        saturated,
    );
    add(left.total_tokens_mut(), right.total_tokens(), saturated);
    add(left.message_count_mut(), right.message_count(), saturated);
    add(left.turn_count_mut(), right.turn_count(), saturated);
    add(left.cost_nano_usd_mut(), right.cost_nano_usd(), saturated);
}

fn add(left: &mut u64, right: u64, saturated: &mut bool) {
    let (value, overflowed) = left.overflowing_add(right);
    if overflowed {
        *left = u64::MAX;
        *saturated = true;
    } else {
        *left = value;
    }
}

fn validate_client_dimensions(
    client: &str,
    model: &Option<String>,
    provider: &Option<String>,
) -> Result<(), ReportError> {
    validate_text(client, false)?;
    validate_optional_text(model)?;
    validate_optional_text(provider)
}

fn validate_optional_text(value: &Option<String>) -> Result<(), ReportError> {
    value
        .as_deref()
        .map_or(Ok(()), |value| validate_text(value, true))
}

fn validate_text(value: &str, allow_empty: bool) -> Result<(), ReportError> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAX_TEXT_BYTES
        || !value.is_char_boundary(value.len())
    {
        return Err(ReportError::Invalid);
    }
    if !value.nfc().eq(value.chars()) {
        return Err(ReportError::Invalid);
    }
    Ok(())
}

fn validate_date(value: &str) -> Result<(), ReportError> {
    let _ = date_days(value)?;
    Ok(())
}

fn validate_date_range(start: &str, end: &str) -> Result<(), ReportError> {
    let start_day = date_days(start)?;
    let end_day = date_days(end)?;
    let span = end_day.checked_sub(start_day).ok_or(ReportError::Bounds)?;
    if !(1..=MAX_RANGE_DAYS).contains(&span) {
        return Err(ReportError::Bounds);
    }
    Ok(())
}

fn date_days(value: &str) -> Result<i64, ReportError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' || !value.is_ascii() {
        return Err(ReportError::Invalid);
    }
    let year = parse_digits(&bytes[0..4])?;
    let month = parse_digits(&bytes[5..7])?;
    let day = parse_digits(&bytes[8..10])?;
    if !(1..=12).contains(&month) {
        return Err(ReportError::Invalid);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > month_days[month as usize - 1] {
        return Err(ReportError::Invalid);
    }
    let year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(era * 146_097 + day_of_era - 719_468)
}

fn parse_digits(bytes: &[u8]) -> Result<u32, ReportError> {
    if bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(ReportError::Invalid);
    }
    Ok(bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0')))
}

fn fixed_hex<const N: usize>(value: &str) -> Result<(), ReportError> {
    decode_fixed_hex::<N>(value)
        .map(|_| ())
        .map_err(|_| ReportError::Invalid)
}

fn cmp_text(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

fn cmp_optional(left: &Option<String>, right: &Option<String>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => cmp_text(left, right),
    }
}
