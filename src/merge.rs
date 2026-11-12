//! Combining the local report with the reports pulled from producers
//! (`spec/agent-v1.md`, "Merge").
//!
//! This module only arranges inputs: it orders the peers, keeps one part
//! per producer, validates each part with the frozen `validate_*_records`,
//! leaves out a part that fails, carries `saturated`, and hands everything
//! left to the frozen `merge_graph` / `merge_models` / `merge_hourly` /
//! `merge_agents` (direct sum, saturating). Every number comes from those
//! functions or from the parts unchanged.

use crate::{
    report::{
        Endpoint, MergeResult, ReportError, merge_agents, merge_graph, merge_hourly, merge_models,
        validate_agents_records, validate_graph_records, validate_hourly_records,
        validate_models_records,
    },
    report_peer::{FetchError, Records},
    runtime::PullError,
};

/// What a failed pull says about the producer's authorization of the
/// cached body (`spec/agent-v1.md`, "Last-good fallback").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// No answer about authorization: the cached body may still be used.
    NoAnswer,
    /// The producer answered and refused, or this side no longer has a
    /// usable record: the cached body is not used.
    Refused,
    /// The producer's reply broke the protocol or the body failed
    /// validation: the cached body is not used.
    InvalidReply,
}

/// The fixed classification of every [`PullError`].
pub fn classify(error: PullError) -> FailureClass {
    match error {
        PullError::NoPeer => FailureClass::Refused,
        PullError::Fetch(error) => match error {
            FetchError::TooMany
            | FetchError::Busy
            | FetchError::Timeout
            | FetchError::Transport(_)
            | FetchError::TooLarge
            | FetchError::Memory
            | FetchError::InvalidQuery => FailureClass::NoAnswer,
            FetchError::Unusable
            | FetchError::Expired
            | FetchError::Revoked
            | FetchError::CheckGrantStatus
            | FetchError::Rejected
            | FetchError::Internal => FailureClass::Refused,
            FetchError::Protocol | FetchError::Invalid => FailureClass::InvalidReply,
        },
    }
}

/// One endpoint's records and whether their producer saturated a sum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub records: Records,
    pub saturated: bool,
}

/// Where a peer's part came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerData {
    /// A pull that succeeded now.
    Fresh(Report),
    /// The receiver cache: the last successful pull, the pull now failed.
    LastGood(Report),
    /// Nothing to show: the pull failed without an answer and no cached
    /// body was found.
    None,
    /// The pull was refused ([`FailureClass::Refused`]); a cached body is
    /// not used.
    Refused,
    /// The reply was invalid ([`FailureClass::InvalidReply`]); a cached
    /// body is not used.
    InvalidReply,
}

/// One producer's contribution to [`combine`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPart {
    pub producer_static: [u8; 32],
    pub grant_id: [u8; 16],
    pub data: PeerData,
    /// Why the pull failed, when it did (with `LastGood` or `None`).
    pub error: Option<PullError>,
}

/// What [`combine`] did with one part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartStatus {
    /// Merged, fresh.
    Fresh,
    /// Merged, from the receiver cache.
    LastGood,
    /// No data; nothing merged.
    Unavailable,
    /// The producer refused the pull; nothing merged.
    Refused,
    /// The producer's reply was invalid; nothing merged.
    InvalidReply,
    /// Left out: the records are not of the endpoint, or fail the frozen
    /// `validate_*_records`.
    Invalid,
    /// Left out: another part of the same producer was kept.
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerOutcome {
    pub producer_static: [u8; 32],
    pub grant_id: [u8; 16],
    pub status: PartStatus,
    pub error: Option<PullError>,
}

/// The merged report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Combined {
    /// The frozen merge of every kept part; `None` only if that merge
    /// refused its input (each part passed `validate_*_records` first, so
    /// no such input is known).
    pub records: Option<Records>,
    /// Some kept part was saturated, or the merge saturated a sum.
    pub saturated: bool,
    /// What happened to the local part: `None` when none was given,
    /// otherwise `Fresh` (merged) or `Invalid` (left out).
    pub local: Option<PartStatus>,
    /// One per part given, in the order they were considered (by
    /// producer static, then `Fresh` before `LastGood` before no data,
    /// then grant ID).
    pub peers: Vec<PeerOutcome>,
}

/// Merges `local` and `peers` for `endpoint`. The result does not depend
/// on the order of `peers`: they are sorted by producer static, then
/// `Fresh` before `LastGood` before the kinds without data, then grant ID. Of the parts of
/// one producer only the first is considered, the others are
/// `Duplicate`. A part whose records are not `endpoint`'s or fail the
/// frozen validation is left out alone; the rest are merged.
pub fn combine(endpoint: Endpoint, local: Option<Report>, mut peers: Vec<PeerPart>) -> Combined {
    peers.sort_by(|left, right| {
        left.producer_static
            .cmp(&right.producer_static)
            .then_with(|| rank(&left.data).cmp(&rank(&right.data)))
            .then_with(|| left.grant_id.cmp(&right.grant_id))
    });
    let mut kept = Vec::new();
    let mut saturated = false;
    let mut take = |report: Report| {
        if valid(endpoint, &report.records) {
            saturated |= report.saturated;
            kept.push(report.records);
            true
        } else {
            false
        }
    };
    let local = local.map(|report| {
        if take(report) {
            PartStatus::Fresh
        } else {
            PartStatus::Invalid
        }
    });
    let mut previous: Option<[u8; 32]> = None;
    let mut outcomes = Vec::with_capacity(peers.len());
    for part in peers {
        let status = if previous == Some(part.producer_static) {
            PartStatus::Duplicate
        } else {
            previous = Some(part.producer_static);
            let (report, kept_as) = match part.data {
                PeerData::Fresh(report) => (Some(report), PartStatus::Fresh),
                PeerData::LastGood(report) => (Some(report), PartStatus::LastGood),
                PeerData::None => (None, PartStatus::Unavailable),
                PeerData::Refused => (None, PartStatus::Refused),
                PeerData::InvalidReply => (None, PartStatus::InvalidReply),
            };
            match report.map(&mut take) {
                Some(false) => PartStatus::Invalid,
                _ => kept_as,
            }
        };
        outcomes.push(PeerOutcome {
            producer_static: part.producer_static,
            grant_id: part.grant_id,
            status,
            error: part.error,
        });
    }
    let merged = merge(endpoint, kept);
    Combined {
        saturated: saturated || merged.as_ref().is_some_and(|(_, saturated)| *saturated),
        records: merged.map(|(records, _)| records),
        local,
        peers: outcomes,
    }
}

fn rank(data: &PeerData) -> u8 {
    match data {
        PeerData::Fresh(_) => 0,
        PeerData::LastGood(_) => 1,
        PeerData::None | PeerData::Refused | PeerData::InvalidReply => 2,
    }
}

fn valid(endpoint: Endpoint, records: &Records) -> bool {
    match (endpoint, records) {
        (Endpoint::Graph, Records::Graph(records)) => validate_graph_records(records).is_ok(),
        (Endpoint::Models, Records::Models(records)) => validate_models_records(records).is_ok(),
        (Endpoint::Hourly, Records::Hourly(records)) => validate_hourly_records(records).is_ok(),
        (Endpoint::Agents, Records::Agents(records)) => validate_agents_records(records).is_ok(),
        _ => false,
    }
}

/// The frozen merge of every part, all already of `endpoint`.
fn merge(endpoint: Endpoint, parts: Vec<Records>) -> Option<(Records, bool)> {
    fn typed<R>(
        parts: Vec<Records>,
        take: fn(Records) -> Option<Vec<R>>,
        merge: fn(&[R]) -> Result<MergeResult<R>, ReportError>,
        wrap: fn(Vec<R>) -> Records,
    ) -> Option<(Records, bool)> {
        let all: Vec<R> = parts.into_iter().filter_map(take).flatten().collect();
        let merged = merge(&all).ok()?;
        Some((wrap(merged.records), merged.saturated))
    }
    match endpoint {
        Endpoint::Graph => typed(
            parts,
            |r| match r {
                Records::Graph(v) => Some(v),
                _ => None,
            },
            merge_graph,
            Records::Graph,
        ),
        Endpoint::Models => typed(
            parts,
            |r| match r {
                Records::Models(v) => Some(v),
                _ => None,
            },
            merge_models,
            Records::Models,
        ),
        Endpoint::Hourly => typed(
            parts,
            |r| match r {
                Records::Hourly(v) => Some(v),
                _ => None,
            },
            merge_hourly,
            Records::Hourly,
        ),
        Endpoint::Agents => typed(
            parts,
            |r| match r {
                Records::Agents(v) => Some(v),
                _ => None,
            },
            merge_agents,
            Records::Agents,
        ),
    }
}
