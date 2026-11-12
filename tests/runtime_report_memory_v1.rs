//! SA-2B2b2 acceptance (5), measured: the receiver reserves
//! `report_peer::decode_reservation` before the frozen `decode_response`
//! runs, so that reservation must bound what the decoder really holds at
//! once. A counting global allocator (std only) records, for the measuring
//! thread, the live bytes above the level at the start of the decode and
//! their peak; each body shape below asserts `peak <= reserved` and prints
//! both.
//!
//! The allocator charges each allocation its size rounded up to 16 bytes,
//! the granularity the reservation also charges. `realloc` is left to the
//! `GlobalAlloc` default (allocate, copy, free), so a growing `Vec` counts
//! its old and new buffers at once, as a moving `realloc` holds them.
//!
//! Needs no secure root: runs on every platform. One test, so the large
//! bodies are built and decoded one at a time.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use syrtis_agent::{
    report::{
        AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
        ReportRequest, ReportResponse, decode_response, encode_response,
    },
    report_peer::{VALUE_STRINGS_MAX, decode_reservation, scan},
    security::{FRAME_PAYLOAD_MAX, LOGICAL_BODY_MAX, REMOTE_MEMORY_MAX},
};

struct Counting;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn charge(layout: Layout) -> isize {
    ((layout.size() + 15) & !15) as isize
}

/// Never panics and never allocates: a thread being torn down just
/// stops counting.
fn record(delta: isize) {
    let _ = TRACKING.try_with(|tracking| {
        if tracking.get() {
            LIVE.with(|live| {
                let now = live.get() + delta;
                live.set(now);
                PEAK.with(|peak| peak.set(peak.get().max(now)));
            });
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(charge(layout));
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(pointer, layout) };
        record(-charge(layout));
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The decoder's peak above its starting level, while it decodes `body`
/// against `request` (as `fetch` calls it).
fn peak_of<R: ReportRecord>(body: &[u8], request: &ReportRequest) -> usize {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    let decoded = decode_response::<R>(body, Some(request));
    TRACKING.with(|tracking| tracking.set(false));
    assert!(decoded.is_ok(), "{:?}", decoded.err());
    drop(decoded);
    PEAK.with(Cell::get) as usize
}

fn request(endpoint: Endpoint) -> ReportRequest {
    ReportRequest {
        aggregation_revision: 1,
        auth_epoch: 1,
        clients: Vec::new(),
        end_date_exclusive: "2025-02-01".into(),
        endpoint: endpoint.into(),
        grant_id: "11".repeat(16),
        protocol: 1,
        report_schema: 1,
        request_id: "22".repeat(16),
        source_scope_generation: 1,
        start_date: "2025-01-01".into(),
        timezone: "UTC".into(),
        tzdb_revision: "2026c".into(),
    }
}

fn body<R: ReportRecord>(request: &ReportRequest, records: Vec<R>) -> Vec<u8> {
    encode_response(&ReportResponse::from_request(request, records, false)).unwrap()
}

/// The canonical body of `count(n)` records `make(0..n)`, with `n` as
/// large as fits in `limit` bytes. Every record encodes to the same length.
fn largest<R: ReportRecord>(
    request: &ReportRequest,
    make: impl Fn(usize) -> R,
    limit: usize,
) -> Vec<u8> {
    let one = body(request, vec![make(0)]).len();
    let per = body(request, vec![make(0), make(1)]).len() - one;
    let count = (limit - (one - per)) / per;
    let bytes = body(request, (0..count).map(&make).collect());
    assert!(bytes.len() <= limit && bytes.len() + per > limit);
    bytes
}

fn graph(n: usize) -> GraphRecord {
    GraphRecord {
        date: "2025-01-01".into(),
        client: format!("{n:06}"),
        model: None,
        provider: None,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        message_count: 0,
        turn_count: 0,
        cost_nano_usd: 0,
    }
}

fn models(n: usize) -> ModelsRecord {
    ModelsRecord {
        client: format!("{n:06}"),
        model: None,
        provider: None,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        message_count: 0,
        turn_count: 0,
        cost_nano_usd: 0,
        duration_millis: 0,
        timed_tokens: 0,
        sample_count: 0,
    }
}

fn hourly(n: usize) -> HourlyRecord {
    HourlyRecord {
        bucket_start_unix_ms: 1_700_000_000_000 + n as i64 * 3_600_000,
        utc_offset_seconds: 0,
        client: "c".into(),
        model: None,
        provider: None,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        message_count: 0,
        turn_count: 0,
        cost_nano_usd: 0,
    }
}

fn agents(n: usize) -> AgentsRecord {
    AgentsRecord {
        agent: format!("{n:06}"),
        client: "c".into(),
        model: None,
        provider: None,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        message_count: 0,
        turn_count: 0,
        cost_nano_usd: 0,
    }
}

/// Every string field at 255 bytes, the longest a record may hold.
fn long_agents(n: usize) -> AgentsRecord {
    let text = |tag: &str| format!("{tag}{}{n:06}", "x".repeat(255 - 7));
    AgentsRecord {
        agent: text("a"),
        client: text("c"),
        model: Some(text("m")),
        provider: Some(text("p")),
        ..agents(n)
    }
}

const MIB: f64 = 1024.0 * 1024.0;

/// Asserts the bound for one body and prints the numbers.
fn check<R: ReportRecord>(label: &str, endpoint: Endpoint, bytes: &[u8]) -> (usize, usize) {
    let request = request(endpoint);
    let counts = scan(bytes, endpoint).unwrap();
    let reserved = decode_reservation(bytes, endpoint).unwrap();
    let peak = peak_of::<R>(bytes, &request);
    let body_reservation = bytes.len().div_ceil(FRAME_PAYLOAD_MAX) * FRAME_PAYLOAD_MAX;
    eprintln!(
        "{label}: body {} B ({:.2} MiB), {} records, decoder peak {} B ({:.1} MiB), reserved {} B ({:.1} MiB), ratio {:.3}, body+reserved {:.1} MiB of {:.0} MiB",
        bytes.len(),
        bytes.len() as f64 / MIB,
        counts.records,
        peak,
        peak as f64 / MIB,
        reserved,
        reserved as f64 / MIB,
        peak as f64 / reserved as f64,
        (reserved + body_reservation) as f64 / MIB,
        REMOTE_MEMORY_MAX as f64 / MIB,
    );
    assert!(
        peak <= reserved,
        "{label}: peak {peak} > reserved {reserved}"
    );
    (peak, reserved)
}

/// The reservation bounds the decoder's real peak for: the smallest
/// record of each endpoint filling a body up to 16 MiB (the most records,
/// so the most nodes, a body can hold); 255-byte strings in every string
/// field, in a body just over 8 MiB (where the re-encoding buffer, which
/// doubles, is closest to its 3x allowance); and the same records up to
/// the 8 MiB value-string limit.
#[test]
fn the_reservation_bounds_the_decoders_measured_peak() {
    let graph_body = largest(&request(Endpoint::Graph), graph, LOGICAL_BODY_MAX);
    check::<GraphRecord>(
        "graph, smallest records, 16 MiB",
        Endpoint::Graph,
        &graph_body,
    );
    drop(graph_body);
    let models_body = largest(&request(Endpoint::Models), models, LOGICAL_BODY_MAX);
    check::<ModelsRecord>(
        "models, smallest records, 16 MiB",
        Endpoint::Models,
        &models_body,
    );
    drop(models_body);
    let hourly_body = largest(&request(Endpoint::Hourly), hourly, LOGICAL_BODY_MAX);
    check::<HourlyRecord>(
        "hourly, smallest records, 16 MiB",
        Endpoint::Hourly,
        &hourly_body,
    );
    drop(hourly_body);
    let agents_body = largest(&request(Endpoint::Agents), agents, LOGICAL_BODY_MAX);
    check::<AgentsRecord>(
        "agents, smallest records, 16 MiB",
        Endpoint::Agents,
        &agents_body,
    );
    drop(agents_body);

    // Just over 8 MiB: the smallest whole number of records past 2^23.
    let request_agents = request(Endpoint::Agents);
    let per = body(&request_agents, vec![long_agents(0), long_agents(1)]).len()
        - body(&request_agents, vec![long_agents(0)]).len();
    let over = largest(&request_agents, long_agents, 8 * 1024 * 1024 + per);
    assert!(over.len() > 8 * 1024 * 1024);
    check::<AgentsRecord>(
        "agents, 255-byte strings, just over 8 MiB",
        Endpoint::Agents,
        &over,
    );
    drop(over);

    // Up to the value-string limit: 4 strings of 255 bytes per record.
    let count = VALUE_STRINGS_MAX / (4 * 255);
    let at_limit = body(&request_agents, (0..count).map(long_agents).collect());
    check::<AgentsRecord>(
        "agents, 255-byte strings, at the 8 MiB string limit",
        Endpoint::Agents,
        &at_limit,
    );
}
