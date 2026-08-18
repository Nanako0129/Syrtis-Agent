use serde_json::{Value, json};
use syrtis_agent::{
    cache::{
        CacheKey, CacheMetadata, CacheRole, body_sha256, cache_filename, cache_key_json,
        encode_metadata, validate_entry,
    },
    canonical::CanonicalJsonV1,
    report::{
        AgentsRecord, AgentsResponse, GraphRecord, GraphResponse, HourlyRecord, HourlyResponse,
        MergeResult, ModelsRecord, ModelsResponse, ReportError, ReportRequest, encode_response,
        merge_agents, merge_graph, merge_hourly, merge_models,
    },
    security::{AGGREGATION_REVISION, PEER_PROTOCOL_VERSION, REPORT_SCHEMA_VERSION, TZDB_REVISION},
};

const START: &str = "2025-01-01";
const END: &str = "2025-02-01";
const TIMEZONE: &str = "America/Los_Angeles";
const REQUEST_ID: &str = "11";
const GRANT_ID: &str = "22";

fn request(endpoint: u16) -> ReportRequest {
    ReportRequest {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: 7,
        clients: vec!["claude".into(), "codex".into()],
        end_date_exclusive: END.into(),
        endpoint,
        grant_id: GRANT_ID.repeat(16),
        protocol: PEER_PROTOCOL_VERSION,
        report_schema: REPORT_SCHEMA_VERSION,
        request_id: REQUEST_ID.repeat(16),
        source_scope_generation: 3,
        start_date: START.into(),
        timezone: TIMEZONE.into(),
        tzdb_revision: TZDB_REVISION.into(),
    }
}

fn graph(
    date: &str,
    client: &str,
    model: Option<&str>,
    provider: Option<&str>,
    value: u64,
) -> GraphRecord {
    GraphRecord {
        date: date.into(),
        client: client.into(),
        model: model.map(str::to_owned),
        provider: provider.map(str::to_owned),
        input_tokens: value,
        output_tokens: value + 1,
        cache_read_tokens: value + 2,
        cache_write_tokens: value + 3,
        reasoning_tokens: value + 4,
        total_tokens: value + 5,
        message_count: value + 6,
        turn_count: value + 7,
        cost_nano_usd: value + 8,
    }
}

fn models(client: &str, model: Option<&str>, provider: Option<&str>, value: u64) -> ModelsRecord {
    ModelsRecord {
        client: client.into(),
        model: model.map(str::to_owned),
        provider: provider.map(str::to_owned),
        input_tokens: value,
        output_tokens: value + 1,
        cache_read_tokens: value + 2,
        cache_write_tokens: value + 3,
        reasoning_tokens: value + 4,
        total_tokens: value + 5,
        message_count: value + 6,
        turn_count: value + 7,
        cost_nano_usd: value + 8,
        duration_millis: value + 9,
        timed_tokens: value + 10,
        sample_count: value + 11,
    }
}

fn hourly(
    bucket: i64,
    offset: i32,
    client: &str,
    model: Option<&str>,
    provider: Option<&str>,
    value: u64,
) -> HourlyRecord {
    HourlyRecord {
        bucket_start_unix_ms: bucket,
        utc_offset_seconds: offset,
        client: client.into(),
        model: model.map(str::to_owned),
        provider: provider.map(str::to_owned),
        input_tokens: value,
        output_tokens: value + 1,
        cache_read_tokens: value + 2,
        cache_write_tokens: value + 3,
        reasoning_tokens: value + 4,
        total_tokens: value + 5,
        message_count: value + 6,
        turn_count: value + 7,
        cost_nano_usd: value + 8,
    }
}

fn agents(
    agent: &str,
    client: &str,
    model: Option<&str>,
    provider: Option<&str>,
    value: u64,
) -> AgentsRecord {
    AgentsRecord {
        agent: agent.into(),
        client: client.into(),
        model: model.map(str::to_owned),
        provider: provider.map(str::to_owned),
        input_tokens: value,
        output_tokens: value + 1,
        cache_read_tokens: value + 2,
        cache_write_tokens: value + 3,
        reasoning_tokens: value + 4,
        total_tokens: value + 5,
        message_count: value + 6,
        turn_count: value + 7,
        cost_nano_usd: value + 8,
    }
}

fn key(role: CacheRole, endpoint: u16) -> CacheKey {
    CacheKey {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: 7,
        clients: vec!["claude".into(), "codex".into()],
        end_date_exclusive: END.into(),
        endpoint,
        grant_id: GRANT_ID.repeat(16),
        peer_static: "33".repeat(32),
        report_schema: REPORT_SCHEMA_VERSION,
        role,
        source_scope_generation: 3,
        start_date: START.into(),
        timezone: TIMEZONE.into(),
        tzdb_revision: TZDB_REVISION.into(),
    }
}

fn assert_golden<T: syrtis_agent::report::ReportRecord>(
    response: &syrtis_agent::report::ReportResponse<T>,
    fixture: &[u8],
) {
    let bytes = encode_response(response).unwrap();
    assert_eq!(
        bytes,
        std::str::from_utf8(fixture).unwrap().trim_end().as_bytes()
    );
    assert_eq!(
        syrtis_agent::report::decode_response::<T>(&bytes, Some(&response.request())).unwrap(),
        *response
    );
}

#[test]
fn report_golden_bytes_and_identity_order() {
    let graph_rows = merge_graph(&[
        graph("2025-01-03", "codex", None, Some("openai"), 30),
        graph("2025-01-01", "claude", Some("opus"), Some("anthropic"), 10),
    ])
    .unwrap();
    assert!(!graph_rows.saturated);
    assert_golden(
        &GraphResponse::from_request(&request(1), graph_rows.records, graph_rows.saturated),
        include_bytes!("fixtures/v1/report/graph.json"),
    );

    let models_rows = merge_models(&[
        models("codex", None, Some("openai"), 30),
        models("claude", Some("opus"), Some("anthropic"), 10),
    ])
    .unwrap();
    assert_golden(
        &ModelsResponse::from_request(&request(2), models_rows.records, models_rows.saturated),
        include_bytes!("fixtures/v1/report/models.json"),
    );

    let hourly_rows = merge_hourly(&[
        hourly(
            1_735_732_800_000,
            -28_800,
            "codex",
            None,
            Some("openai"),
            30,
        ),
        hourly(
            1_735_732_800_000,
            -28_800,
            "claude",
            Some("opus"),
            Some("anthropic"),
            10,
        ),
        hourly(
            1_735_732_800_000,
            -25_200,
            "claude",
            Some("opus"),
            Some("anthropic"),
            20,
        ),
    ])
    .unwrap();
    assert_eq!(hourly_rows.records.len(), 3);
    assert_golden(
        &HourlyResponse::from_request(&request(3), hourly_rows.records, hourly_rows.saturated),
        include_bytes!("fixtures/v1/report/hourly.json"),
    );

    let agents_rows = merge_agents(&[
        agents("zeta", "codex", None, Some("openai"), 30),
        agents("alpha", "claude", Some("opus"), Some("anthropic"), 10),
    ])
    .unwrap();
    assert_golden(
        &AgentsResponse::from_request(&request(4), agents_rows.records, agents_rows.saturated),
        include_bytes!("fixtures/v1/report/agents.json"),
    );
}

#[test]
fn duplicate_merge_saturates_and_response_rejects_duplicates() {
    let left = graph(
        "2025-01-01",
        "claude",
        Some("opus"),
        Some("anthropic"),
        u64::MAX - 8,
    );
    let right = graph("2025-01-01", "claude", Some("opus"), Some("anthropic"), 10);
    let MergeResult { records, saturated } = merge_graph(&[right.clone(), left.clone()]).unwrap();
    assert!(saturated);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].input_tokens, u64::MAX);
    assert_eq!(records[0].output_tokens, u64::MAX);

    let duplicate = GraphResponse::from_request(&request(1), vec![left.clone(), left], false);
    assert_eq!(encode_response(&duplicate), Err(ReportError::Duplicate));
}

#[test]
fn strict_report_echo_and_field_validation() {
    let response = GraphResponse::from_request(
        &request(1),
        vec![graph("2025-01-01", "claude", None, None, 1)],
        false,
    );
    let bytes = encode_response(&response).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(1));
    let unknown = CanonicalJsonV1::encode(&value).unwrap();
    assert!(syrtis_agent::report::decode_response::<GraphRecord>(&unknown, None).is_err());

    let mut missing = serde_json::from_slice::<Value>(&bytes).unwrap();
    missing.as_object_mut().unwrap().remove("records");
    let missing = CanonicalJsonV1::encode(&missing).unwrap();
    assert!(syrtis_agent::report::decode_response::<GraphRecord>(&missing, None).is_err());

    let mut wrong_echo = response.clone();
    wrong_echo.timezone = "UTC".into();
    assert_eq!(
        encode_response(&wrong_echo),
        Ok(CanonicalJsonV1::encode(&wrong_echo).unwrap())
    );
    assert!(
        syrtis_agent::report::decode_response::<GraphRecord>(
            &encode_response(&wrong_echo).unwrap(),
            Some(&response.request())
        )
        .is_err()
    );
}

#[test]
fn cache_golden_and_each_rejection_class() {
    let response = GraphResponse::from_request(
        &request(1),
        vec![graph("2025-01-01", "claude", None, None, 1)],
        false,
    );
    let body = encode_response(&response).unwrap();
    assert_eq!(
        body_sha256(&body),
        include_str!("fixtures/v1/cache/body.sha256").trim()
    );
    let cache_key = key(CacheRole::Producer, 1);
    assert_eq!(
        cache_key_json(&cache_key).unwrap(),
        include_str!("fixtures/v1/cache/key.json")
            .trim_end()
            .as_bytes()
    );
    let filename = cache_filename(&cache_key).unwrap();
    assert_eq!(
        filename,
        include_str!("fixtures/v1/cache/filename.txt").trim()
    );
    let metadata = CacheMetadata::for_body(
        cache_key.clone(),
        1_800_000_000_000,
        1_800_100_000_000,
        &body,
    );
    let metadata_bytes = encode_metadata(&metadata).unwrap();
    assert_eq!(
        metadata_bytes,
        include_str!("fixtures/v1/cache/metadata.json")
            .trim_end()
            .as_bytes()
    );
    assert!(
        validate_entry(
            &metadata_bytes,
            &body,
            &filename,
            CacheRole::Producer,
            1_800_050_000_000
        )
        .is_ok()
    );

    assert!(
        validate_entry(
            &metadata_bytes,
            &body,
            &filename,
            CacheRole::Receiver,
            1_800_050_000_000
        )
        .is_err()
    );
    assert!(
        validate_entry(
            &metadata_bytes,
            &body,
            "00",
            CacheRole::Producer,
            1_800_050_000_000
        )
        .is_err()
    );
    assert!(
        validate_entry(
            &metadata_bytes,
            b"tampered",
            &filename,
            CacheRole::Producer,
            1_800_050_000_000
        )
        .is_err()
    );
    assert!(
        validate_entry(
            &metadata_bytes,
            &body,
            &filename,
            CacheRole::Producer,
            1_800_100_000_000
        )
        .is_err()
    );

    let mut unknown: Value = serde_json::from_slice(&metadata_bytes).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(true));
    let unknown = CanonicalJsonV1::encode(&unknown).unwrap();
    assert!(
        validate_entry(
            &unknown,
            &body,
            &filename,
            CacheRole::Producer,
            1_800_050_000_000
        )
        .is_err()
    );

    let mut missing: Value = serde_json::from_slice(&metadata_bytes).unwrap();
    missing.as_object_mut().unwrap().remove("cacheKey");
    let missing = CanonicalJsonV1::encode(&missing).unwrap();
    assert!(
        validate_entry(
            &missing,
            &body,
            &filename,
            CacheRole::Producer,
            1_800_050_000_000
        )
        .is_err()
    );
}
