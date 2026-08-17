use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalJsonV1, constant_time_eq};

pub const PEER_PROTOCOL_VERSION: u16 = 1;
pub const REPORT_SCHEMA_VERSION: u16 = 1;
pub const STATE_SCHEMA_VERSION: u16 = 1;
pub const FRAME_VERSION: u16 = 1;
pub const CONTROL_VERSION: u16 = 1;
pub const AGGREGATION_REVISION: u16 = 1;
pub const TZDB_REVISION: &str = "2026c";
pub const TZDB_SHA256: &str = "e4a178a4477f3d0ea77cc31828ff72aa38feff8d61aa13e7e99e142e9d902be4";
pub const CONSENT_SCOPE: &str = "usage.aggregate.read.v1";
pub const NOISE_SUITE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_PROLOGUE: &[u8] = b"syrtis-peer-v1\0";

pub const FRAME_HEADER_LEN: usize = 38;
pub const FRAME_PLAINTEXT_MAX: usize = 61_440;
pub const FRAME_PAYLOAD_MAX: usize = 61_402;
pub const FRAME_CIPHERTEXT_MAX: usize = 61_456;
pub const ERROR_PAYLOAD_MAX: usize = 4_096;
pub const LOGICAL_BODY_MAX: usize = 16_777_216;
pub const RESPONSE_CHUNKS_MAX: u32 = 274;
pub const REMOTE_MEMORY_MAX: usize = 384 * 1024 * 1024;

/// Raw paste bound, applied before any parsing work is done on it.
pub const PAIR_URL_RAW_MAX: usize = 16_384;
/// Bound on the Pair URL itself, applied once the grammar has identified one.
///
/// There is deliberately no third bound on the decoded offer JSON. One existed,
/// at 4096 bytes, and could never bind: hex doubles, so a URL of at most 8192
/// bytes carries at most (8192 - 20) / 2 = 4086 decoded bytes. A bound that
/// cannot be reached is not defence in depth, it is the dead-bound shape this
/// contract already removed once.
pub const PAIR_URL_MAX: usize = 8_192;

/// Largest tolerated backward step of the OS clock, in seconds.
pub const MAX_CLOCK_ROLLBACK_SECONDS: i64 = 300;
/// Largest tolerated forward jump of the OS clock, in seconds.
pub const MAX_CLOCK_FORWARD_SECONDS: i64 = 86_400;

/// Creation stops one record short of [`MAX_RECORDS`]. The reserved slot is
/// what lets a full state still record a termination; see [`MAX_RECORDS`].
pub const MAX_CREATION_RECORDS: usize = 255;
/// Total record cap, reachable only by the paths that terminate a record.
///
/// Revoke, disable, reset, uninstall and reject are deliberately absent from
/// every record-count check: a terminal record leaves only through compaction,
/// which needs a cleanup report, ninety days and a sane clock, so failing them
/// on record count would leave a full state unrevocable for months.
pub const MAX_RECORDS: usize = 256;

const PAIR_URL_PREFIX: &str = "syrtis://pair?offer=";

const OFFER_SECRET_TAG: &[u8] = b"syrtis-offer-secret-v1\0";
const CONTROL_KEY_TAG: &[u8] = b"syrtis-control-key-v1\0";
const CONTROL_SERVER_TAG: &[u8] = b"syrtis-control-server-v1\0";
const CONTROL_COMMAND_TAG: &[u8] = b"syrtis-control-command-v1\0";
const CONTROL_RESPONSE_TAG: &[u8] = b"syrtis-control-response-v1\0";
const PAIR_SAS_TAG: &[u8] = b"syrtis-pair-sas-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityError {
    Bounds,
    Canonical,
    Conflict,
    Expired,
    Invalid,
    Unauthorized,
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn hex_decode(value: &str) -> Result<Vec<u8>, SecurityError> {
    if value.len() % 2 != 0
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(SecurityError::Invalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

pub fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], SecurityError> {
    let bytes = hex_decode(value)?;
    bytes.try_into().map_err(|_| SecurityError::Invalid)
}

fn hex_nibble(byte: u8) -> Result<u8, SecurityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SecurityError::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Request = 1,
    Response = 2,
    Error = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub final_chunk: bool,
    pub request_id: [u8; 16],
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, SecurityError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(b"SYR1");
        bytes.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.push(u8::from(self.final_chunk));
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.chunk_index.to_be_bytes());
        bytes.extend_from_slice(&self.chunk_count.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() < FRAME_HEADER_LEN || bytes.len() > FRAME_PLAINTEXT_MAX {
            return Err(SecurityError::Bounds);
        }
        if &bytes[0..4] != b"SYR1"
            || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != FRAME_VERSION
            || bytes[7] & !1 != 0
            || u16::from_be_bytes(bytes[36..38].try_into().unwrap()) != 0
        {
            return Err(SecurityError::Invalid);
        }
        let kind = match bytes[6] {
            1 => FrameKind::Request,
            2 => FrameKind::Response,
            3 => FrameKind::Error,
            _ => return Err(SecurityError::Invalid),
        };
        let payload_len = u32::from_be_bytes(bytes[32..36].try_into().unwrap()) as usize;
        if payload_len > FRAME_PAYLOAD_MAX
            || FRAME_HEADER_LEN.checked_add(payload_len) != Some(bytes.len())
        {
            return Err(SecurityError::Bounds);
        }
        let frame = Self {
            kind,
            final_chunk: bytes[7] == 1,
            request_id: bytes[8..24].try_into().unwrap(),
            chunk_index: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
            chunk_count: u32::from_be_bytes(bytes[28..32].try_into().unwrap()),
            payload: bytes[38..].to_vec(),
        };
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<(), SecurityError> {
        if self.payload.len() > FRAME_PAYLOAD_MAX {
            return Err(SecurityError::Bounds);
        }
        match self.kind {
            FrameKind::Request => {
                if self.chunk_count != 1 || self.chunk_index != 0 || !self.final_chunk {
                    return Err(SecurityError::Invalid);
                }
            }
            FrameKind::Error => {
                if self.chunk_count != 1
                    || self.chunk_index != 0
                    || !self.final_chunk
                    || self.payload.len() > ERROR_PAYLOAD_MAX
                {
                    return Err(SecurityError::Invalid);
                }
            }
            FrameKind::Response => {
                if self.chunk_count == 0
                    || self.chunk_count > RESPONSE_CHUNKS_MAX
                    || self.chunk_index >= self.chunk_count
                    || self.final_chunk != (self.chunk_index + 1 == self.chunk_count)
                {
                    return Err(SecurityError::Invalid);
                }
            }
        }
        Ok(())
    }
}

pub fn encode_outer(ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if ciphertext.len() > FRAME_CIPHERTEXT_MAX {
        return Err(SecurityError::Bounds);
    }
    let mut bytes = Vec::with_capacity(4 + ciphertext.len());
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    Ok(bytes)
}

pub fn decode_outer(bytes: &[u8]) -> Result<&[u8], SecurityError> {
    if bytes.len() < 4 {
        return Err(SecurityError::Bounds);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > FRAME_CIPHERTEXT_MAX || length.checked_add(4) != Some(bytes.len()) {
        return Err(SecurityError::Bounds);
    }
    Ok(&bytes[4..])
}

pub fn assemble_response(frames: &[Frame]) -> Result<Vec<u8>, SecurityError> {
    let first = frames.first().ok_or(SecurityError::Invalid)?;
    if first.kind != FrameKind::Response || frames.len() != first.chunk_count as usize {
        return Err(SecurityError::Invalid);
    }
    let mut length = 0_usize;
    for (index, frame) in frames.iter().enumerate() {
        frame.validate()?;
        if frame.kind != FrameKind::Response
            || frame.request_id != first.request_id
            || frame.chunk_count != first.chunk_count
            || frame.chunk_index as usize != index
        {
            return Err(SecurityError::Invalid);
        }
        length = length
            .checked_add(frame.payload.len())
            .filter(|length| *length <= LOGICAL_BODY_MAX)
            .ok_or(SecurityError::Bounds)?;
    }
    let mut body = Vec::with_capacity(length);
    for frame in frames {
        body.extend_from_slice(&frame.payload);
    }
    Ok(body)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairOffer {
    pub expires_at: i64,
    pub host: String,
    pub offer_id: String,
    pub port: u16,
    pub responder_static: String,
    pub secret: String,
    pub version: u16,
}

pub fn pair_url(offer: &PairOffer) -> Result<String, SecurityError> {
    validate_pair_offer(offer, None)?;
    let json = CanonicalJsonV1::encode(offer).map_err(|_| SecurityError::Canonical)?;
    let url = format!("{PAIR_URL_PREFIX}{}", hex_encode(&json));
    if url.len() > PAIR_URL_MAX {
        return Err(SecurityError::Bounds);
    }
    Ok(url)
}

pub fn parse_pair_url(value: &str, effective_now_ms: i64) -> Result<PairOffer, SecurityError> {
    // Two bounds, two distinct objects, each applied to its own: the raw paste
    // before any parsing work, and the URL once the grammar has identified one.
    // Applying two bounds to the same object is what makes the tighter one dead
    // code, which is why there is no third bound on the decoded offer JSON —
    // see `PAIR_URL_MAX`.
    if value.len() > PAIR_URL_RAW_MAX {
        return Err(SecurityError::Bounds);
    }
    let encoded = value
        .strip_prefix(PAIR_URL_PREFIX)
        .ok_or(SecurityError::Invalid)?;
    if value.len() > PAIR_URL_MAX {
        return Err(SecurityError::Bounds);
    }
    let bytes = hex_decode(encoded)?;
    let offer: PairOffer = CanonicalJsonV1::decode(&bytes).map_err(|_| SecurityError::Canonical)?;
    validate_pair_offer(&offer, Some(effective_now_ms))?;
    if pair_url(&offer)? != value {
        return Err(SecurityError::Canonical);
    }
    Ok(offer)
}

fn validate_pair_offer(offer: &PairOffer, now_ms: Option<i64>) -> Result<(), SecurityError> {
    if offer.version != PEER_PROTOCOL_VERSION
        || offer.port < 1024
        || decode_fixed_hex::<16>(&offer.offer_id).is_err()
        || decode_fixed_hex::<32>(&offer.responder_static).is_err()
        || decode_fixed_hex::<32>(&offer.secret).is_err()
        || !canonical_host(&offer.host)
    {
        return Err(SecurityError::Invalid);
    }
    if let Some(now_ms) = now_ms {
        let remaining = offer
            .expires_at
            .checked_sub(now_ms)
            .ok_or(SecurityError::Expired)?;
        if !(1..=900_000).contains(&remaining) {
            return Err(SecurityError::Expired);
        }
    }
    Ok(())
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return address.to_string() == host;
    }
    if host
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return false;
    }
    if let Ok(address) = host.parse::<Ipv6Addr>() {
        return address.to_string() == host;
    }
    if host.contains(':')
        || host.ends_with('.')
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

pub fn offer_secret_hash(
    offer_id: &[u8; 16],
    secret: &[u8; 32],
    responder_static: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OFFER_SECRET_TAG);
    hasher.update(offer_id);
    hasher.update(secret);
    hasher.update(responder_static);
    hasher.finalize().into()
}

pub fn pair_sas(
    protocol_version: u16,
    offer_id: &[u8; 16],
    responder_static: &[u8; 32],
    initiator_static: &[u8; 32],
    h_final: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PAIR_SAS_TAG);
    hasher.update(protocol_version.to_be_bytes());
    hasher.update(offer_id);
    hasher.update(responder_static);
    hasher.update(initiator_static);
    hasher.update(h_final);
    let digest: [u8; 32] = hasher.finalize().into();
    let first = hex_encode(&digest[..4]).to_ascii_uppercase();
    format!("{}-{}", &first[..4], &first[4..])
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts every key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn control_key(control_token: &[u8; 32]) -> [u8; 32] {
    hmac(control_token, &[CONTROL_KEY_TAG])
}

pub fn control_server_mac(
    key: &[u8; 32],
    version: u16,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    hmac(
        key,
        &[
            CONTROL_SERVER_TAG,
            &version.to_be_bytes(),
            client_nonce,
            server_nonce,
        ],
    )
}

pub fn control_command_mac(
    key: &[u8; 32],
    version: u16,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    request_id: &[u8; 16],
    command_id: u16,
    command_json: &[u8],
) -> Result<[u8; 32], SecurityError> {
    let length = u32::try_from(command_json.len()).map_err(|_| SecurityError::Bounds)?;
    let digest: [u8; 32] = Sha256::digest(command_json).into();
    Ok(hmac(
        key,
        &[
            CONTROL_COMMAND_TAG,
            &version.to_be_bytes(),
            client_nonce,
            server_nonce,
            request_id,
            &command_id.to_be_bytes(),
            &length.to_be_bytes(),
            &digest,
        ],
    ))
}

pub fn control_response_mac(
    key: &[u8; 32],
    version: u16,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    request_id: &[u8; 16],
    code: u16,
    response_json: &[u8],
) -> Result<[u8; 32], SecurityError> {
    let length = u32::try_from(response_json.len()).map_err(|_| SecurityError::Bounds)?;
    let digest: [u8; 32] = Sha256::digest(response_json).into();
    Ok(hmac(
        key,
        &[
            CONTROL_RESPONSE_TAG,
            &version.to_be_bytes(),
            client_nonce,
            server_nonce,
            request_id,
            &code.to_be_bytes(),
            &length.to_be_bytes(),
            &digest,
        ],
    ))
}

pub fn verify_control_command(
    command_json: &[u8],
    request_id: &[u8; 16],
    command_id: u16,
) -> Result<(), SecurityError> {
    let value =
        CanonicalJsonV1::decode_value(command_json).map_err(|_| SecurityError::Canonical)?;
    let object = value.as_object().ok_or(SecurityError::Invalid)?;
    exact_keys(
        object,
        &["body", "commandId", "controlVersion", "requestId"],
    )?;
    if integer(object, "controlVersion")? != u64::from(CONTROL_VERSION)
        || integer(object, "commandId")? != u64::from(command_id)
        || string(object, "requestId")? != hex_encode(request_id)
        || !(1..=9).contains(&command_id)
    {
        return Err(SecurityError::Invalid);
    }
    let body = object
        .get("body")
        .and_then(Value::as_object)
        .ok_or(SecurityError::Invalid)?;
    validate_command_body(command_id, body)
}

fn validate_command_body(command_id: u16, body: &Map<String, Value>) -> Result<(), SecurityError> {
    match command_id {
        1 | 4 | 9 => exact_keys(body, &[]),
        2 => {
            exact_keys(body, &["ttlSeconds"])?;
            if (1..=900).contains(&integer(body, "ttlSeconds")?) {
                Ok(())
            } else {
                Err(SecurityError::Bounds)
            }
        }
        3 => {
            exact_keys(body, &["offerId"])?;
            decode_fixed_hex::<16>(string(body, "offerId")?).map(|_| ())
        }
        5 | 6 => {
            exact_keys(body, &["pendingId", "sasGeneration"])?;
            decode_fixed_hex::<16>(string(body, "pendingId")?)?;
            integer(body, "sasGeneration")?;
            Ok(())
        }
        7 => {
            exact_keys(body, &["grantId"])?;
            decode_fixed_hex::<16>(string(body, "grantId")?).map(|_| ())
        }
        8 => {
            exact_keys(body, &["bindHost", "bindPort"])?;
            let port = integer(body, "bindPort")?;
            if canonical_host(string(body, "bindHost")?) && (1024..=65535).contains(&port) {
                Ok(())
            } else {
                Err(SecurityError::Invalid)
            }
        }
        _ => Err(SecurityError::Invalid),
    }
}

pub fn verify_control_response(
    response_json: &[u8],
    request_id: &[u8; 16],
    command_id: u16,
    code: u16,
) -> Result<(), SecurityError> {
    let value =
        CanonicalJsonV1::decode_value(response_json).map_err(|_| SecurityError::Canonical)?;
    let object = value.as_object().ok_or(SecurityError::Invalid)?;
    exact_keys(object, &["code", "controlVersion", "data", "requestId"])?;
    if integer(object, "controlVersion")? != u64::from(CONTROL_VERSION)
        || integer(object, "code")? != u64::from(code)
        || string(object, "requestId")? != hex_encode(request_id)
        || code > 8
    {
        return Err(SecurityError::Invalid);
    }
    let data = object.get("data").ok_or(SecurityError::Invalid)?;
    if code != 0 {
        return if data.is_null() {
            Ok(())
        } else {
            Err(SecurityError::Invalid)
        };
    }
    match command_id {
        1 => validate_status_data(data),
        2 => validate_offer_data(data),
        4 => validate_pending_data(data),
        3 | 5..=9 if data.is_null() => Ok(()),
        _ => Err(SecurityError::Invalid),
    }
}

fn validate_status_data(data: &Value) -> Result<(), SecurityError> {
    let object = data.as_object().ok_or(SecurityError::Invalid)?;
    exact_keys(
        object,
        &[
            "activeGrantCount",
            "activeOfferCount",
            "bindHost",
            "bindPort",
            "lastScanAt",
            "nodeLabel",
            "pendingCount",
            "scanStatus",
            "sharingEnabled",
            "sourceFamilies",
        ],
    )?;
    for key in ["activeGrantCount", "activeOfferCount", "pendingCount"] {
        integer(object, key)?;
    }
    let port = integer(object, "bindPort")?;
    if !(1024..=65535).contains(&port)
        || !canonical_host(string(object, "bindHost")?)
        || string(object, "nodeLabel")?.len() > 128
        || !matches!(string(object, "scanStatus")?, "never" | "ok" | "error")
        || object
            .get("sharingEnabled")
            .and_then(Value::as_bool)
            .is_none()
        || !object
            .get("lastScanAt")
            .is_some_and(|value| value.is_null() || value.as_i64().is_some())
    {
        return Err(SecurityError::Invalid);
    }
    let families = object
        .get("sourceFamilies")
        .and_then(Value::as_array)
        .ok_or(SecurityError::Invalid)?;
    if families.len() > 128 {
        return Err(SecurityError::Bounds);
    }
    let strings: Vec<&str> = families
        .iter()
        .map(|value| value.as_str().ok_or(SecurityError::Invalid))
        .collect::<Result<_, _>>()?;
    if strings
        .windows(2)
        .any(|window| window[0].as_bytes() >= window[1].as_bytes())
    {
        return Err(SecurityError::Invalid);
    }
    Ok(())
}

fn validate_offer_data(data: &Value) -> Result<(), SecurityError> {
    let object = data.as_object().ok_or(SecurityError::Invalid)?;
    exact_keys(object, &["expiresAt", "offerId", "pairUrl"])?;
    object
        .get("expiresAt")
        .and_then(Value::as_i64)
        .ok_or(SecurityError::Invalid)?;
    decode_fixed_hex::<16>(string(object, "offerId")?)?;
    let url = string(object, "pairUrl")?;
    // Same bound `parse_pair_url` applies to a URL, so the control plane cannot
    // hand back a Pair URL that its own parser would reject on length.
    if url.len() <= PAIR_URL_MAX && url.starts_with(PAIR_URL_PREFIX) {
        Ok(())
    } else {
        Err(SecurityError::Invalid)
    }
}

fn validate_pending_data(data: &Value) -> Result<(), SecurityError> {
    let entries = data.as_array().ok_or(SecurityError::Invalid)?;
    let mut previous: Option<&str> = None;
    for entry in entries {
        let object = entry.as_object().ok_or(SecurityError::Invalid)?;
        exact_keys(object, &["expiresAt", "pendingId", "sasCode"])?;
        object
            .get("expiresAt")
            .and_then(Value::as_i64)
            .ok_or(SecurityError::Invalid)?;
        let pending_id = string(object, "pendingId")?;
        decode_fixed_hex::<16>(pending_id)?;
        if previous.is_some_and(|previous| previous.as_bytes() >= pending_id.as_bytes())
            || !valid_sas(string(object, "sasCode")?)
        {
            return Err(SecurityError::Invalid);
        }
        previous = Some(pending_id);
    }
    Ok(())
}

fn valid_sas(value: &str) -> bool {
    value.len() == 9
        && value.as_bytes()[4] == b'-'
        && value.bytes().enumerate().all(|(index, byte)| {
            index == 4 || byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
        })
}

fn exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), SecurityError> {
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual == expected {
        Ok(())
    } else {
        Err(SecurityError::Invalid)
    }
}

fn integer(object: &Map<String, Value>, key: &str) -> Result<u64, SecurityError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(SecurityError::Invalid)
}

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, SecurityError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SecurityError::Invalid)
}

/// Grant lifecycle.
///
/// There is deliberately no intermediate revocation state: revocation is one
/// immutable commit, so a state sitting between "still authorized" and
/// "revoked" would contradict the frozen rule rather than implement it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GrantState {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferState {
    Active,
    Consumed,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offer {
    pub offer_id: [u8; 16],
    pub secret_hash: [u8; 32],
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: OfferState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingState {
    AwaitingApproval,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    pub pending_id: [u8; 16],
    pub offer_id: [u8; 16],
    pub initiator_static: [u8; 32],
    pub sas_code: String,
    pub sas_generation: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: PendingState,
}

/// Grant state record.
///
/// The serializer is the guard: its key set must be exactly the ten fields
/// frozen for the grant state record in `spec/v1.md`, so a missing or extra
/// field is a test failure rather than a silent divergence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    #[serde(serialize_with = "serialize_hex_16")]
    pub grant_id: [u8; 16],
    #[serde(serialize_with = "serialize_hex_32")]
    pub initiator_static: [u8; 32],
    #[serde(serialize_with = "serialize_hex_32")]
    pub responder_static: [u8; 32],
    pub scope: &'static str,
    pub endpoints: [u16; 4],
    pub auth_epoch: u64,
    pub source_scope_generation: u64,
    #[serde(rename = "createdAt")]
    pub created_at_ms: i64,
    #[serde(rename = "expiresAt")]
    pub expires_at_ms: i64,
    pub state: GrantState,
}

fn serialize_hex_16<S: serde::Serializer>(
    value: &[u8; 16],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex_encode(value))
}

fn serialize_hex_32<S: serde::Serializer>(
    value: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex_encode(value))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub sharing_enabled: bool,
    pub auth_epoch: u64,
    pub deny_floor: u64,
    pub source_scope_generation: u64,
    pub counter_source_scope_generation: u64,
    pub os_now_unix_seconds: i64,
    pub last_accepted_wall_unix_seconds: i64,
    pub endpoint: u16,
}

/// The complete positive authorization predicate.
///
/// Nine conjuncts, each independently falsifiable. `AuthorizationRequest` is
/// assembled by the caller from the *current* durable state; a request derived
/// from the grant it is meant to constrain cannot fail, which is exactly how
/// eight of these nine went untested through a frozen-contract acceptance.
pub fn authorize(grant: &Grant, request: &AuthorizationRequest) -> bool {
    let effective_seconds = request
        .os_now_unix_seconds
        .max(request.last_accepted_wall_unix_seconds);
    let effective_ms = effective_seconds.checked_mul(1_000).unwrap_or(i64::MAX);
    request.sharing_enabled
        && grant.state == GrantState::Active
        && request.auth_epoch == grant.auth_epoch
        && grant.auth_epoch > request.deny_floor
        && request.source_scope_generation == grant.source_scope_generation
        && grant.source_scope_generation == request.counter_source_scope_generation
        && effective_ms < grant.expires_at_ms
        && grant.endpoints.contains(&request.endpoint)
        && grant.scope == CONSENT_SCOPE
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockStatus {
    pub effective_now: i64,
    pub anomaly: bool,
}

pub fn clock_status(os_now: i64, last_accepted: i64) -> ClockStatus {
    ClockStatus {
        effective_now: os_now.max(last_accepted),
        anomaly: os_now < last_accepted.saturating_sub(MAX_CLOCK_ROLLBACK_SECONDS)
            || os_now > last_accepted.saturating_add(MAX_CLOCK_FORWARD_SECONDS),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalKind {
    Offer,
    Pending,
    Grant,
    Reset,
    Uninstall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Terminal {
    pub record_id: [u8; 16],
    pub kind: TerminalKind,
    pub auth_epoch: u64,
    pub terminal_at_ms: i64,
    pub cleanup_complete: bool,
}

/// Arguments of the claim transition.
///
/// Grouped rather than positional: `offer_id` and `pending_id` are both
/// `[u8; 16]`, so a positional list lets a caller swap them and still compile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferClaim {
    pub offer_id: [u8; 16],
    pub secret: [u8; 32],
    pub responder_static: [u8; 32],
    pub pending_id: [u8; 16],
    pub initiator_static: [u8; 32],
    pub sas_code: String,
    pub sas_generation: u64,
}

/// Arguments of the approval transition.
///
/// `responder_static` is explicit here: the reference state holds no identity
/// of its own, and the state top level is frozen, so approval receives the
/// responder key rather than reading one out of the state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    pub pending_id: [u8; 16],
    pub sas_generation: u64,
    pub grant_id: [u8; 16],
    pub responder_static: [u8; 32],
    pub grant_expires_at_ms: i64,
    pub disclosure_exact: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceState {
    pub sharing_enabled: bool,
    pub next_auth_epoch: u64,
    pub deny_floor: u64,
    pub source_scope_generation: u64,
    /// Durable wall clock, in seconds.
    ///
    /// Private on purpose. It is a State counter that never decreases, and it
    /// advances only through [`ReferenceState::accept_clock`]. A test that can
    /// assign it can also hide the fact that no transition ever writes it,
    /// which is what happened here: the field was declared, read and
    /// initialized, never assigned, and twelve green tests said nothing.
    last_accepted_wall_unix_seconds: i64,
    pub offers: Vec<Offer>,
    pub pending: Vec<Pending>,
    pub grants: Vec<Grant>,
    pub terminal: Vec<Terminal>,
}

impl ReferenceState {
    /// Builds a state from the install-time wall clock, in seconds.
    ///
    /// The domain is strictly positive. A zero wall would make every real Unix
    /// timestamp read as a forward jump of decades and refuse every clock-bound
    /// transition, and no in-crate transition can lower a counter again. A
    /// *future* wall is fail-closed the same way and is deliberate: recovery is
    /// the runtime's job (`SA-2B`), which discards the state and rebuilds it
    /// from a correct clock.
    pub fn new(install_wall_unix_seconds: i64) -> Result<Self, SecurityError> {
        if install_wall_unix_seconds <= 0 {
            return Err(SecurityError::Invalid);
        }
        Ok(Self {
            sharing_enabled: false,
            next_auth_epoch: 1,
            deny_floor: 0,
            source_scope_generation: 1,
            last_accepted_wall_unix_seconds: install_wall_unix_seconds,
            offers: Vec::new(),
            pending: Vec::new(),
            grants: Vec::new(),
            terminal: Vec::new(),
        })
    }

    /// The durable wall clock the caller must put into an [`AuthorizationRequest`].
    pub fn last_accepted_wall_unix_seconds(&self) -> i64 {
        self.last_accepted_wall_unix_seconds
    }

    /// Does not advance the wall: it takes no clock reading at all.
    pub fn enable_sharing(&self) -> Result<Self, SecurityError> {
        if self.sharing_enabled {
            return Err(SecurityError::Conflict);
        }
        let mut next = self.clone();
        next.sharing_enabled = true;
        Ok(next)
    }

    /// Advances the wall: `os_now_seconds` is a checked clock reading.
    pub fn create_offer(&self, offer: Offer, os_now_seconds: i64) -> Result<Self, SecurityError> {
        let (accepted_wall, effective_now_ms) = self.accept_clock(os_now_seconds)?;
        let lifetime_ms = offer
            .expires_at_ms
            .checked_sub(offer.created_at_ms)
            .ok_or(SecurityError::Unauthorized)?;
        if !self.sharing_enabled
            || offer.state != OfferState::Active
            || !(1_000..=900_000).contains(&lifetime_ms)
            || offer.created_at_ms > effective_now_ms
            || offer.expires_at_ms <= effective_now_ms
            || self
                .offers
                .iter()
                .filter(|offer| offer.state == OfferState::Active)
                .count()
                >= 5
            || self.record_count() >= MAX_CREATION_RECORDS
            || self.id_seen(offer.offer_id)
        {
            return Err(SecurityError::Unauthorized);
        }
        let mut next = self.clone();
        next.last_accepted_wall_unix_seconds = accepted_wall;
        next.offers.push(offer);
        Ok(next)
    }

    /// Advances the wall: `os_now_seconds` is a checked clock reading.
    pub fn claim_offer(
        &self,
        claim: OfferClaim,
        os_now_seconds: i64,
    ) -> Result<(Self, [u8; 16], u64), SecurityError> {
        let (accepted_wall, effective_now_ms) = self.accept_clock(os_now_seconds)?;
        // The bearer proves possession before anything else is disclosed or
        // consumed, and a wrong secret leaves the offer active: consuming it
        // would turn one guess into a denial of service on the real initiator.
        let offer_index = self
            .offers
            .iter()
            .position(|offer| offer.offer_id == claim.offer_id)
            .ok_or(SecurityError::Unauthorized)?;
        let offer = &self.offers[offer_index];
        let presented = offer_secret_hash(&claim.offer_id, &claim.secret, &claim.responder_static);
        if !constant_time_eq(&presented, &offer.secret_hash) {
            return Err(SecurityError::Unauthorized);
        }
        if let Some(existing) = self
            .pending
            .iter()
            .find(|pending| pending.offer_id == claim.offer_id)
        {
            // A terminal pending is never authority, so it yields neither a
            // success nor its generation, however the retry is addressed.
            if existing.state != PendingState::AwaitingApproval
                || existing.initiator_static != claim.initiator_static
            {
                return Err(SecurityError::Unauthorized);
            }
            let (pending_id, sas_generation) = (existing.pending_id, existing.sas_generation);
            let mut next = self.clone();
            next.last_accepted_wall_unix_seconds = accepted_wall;
            return Ok((next, pending_id, sas_generation));
        }
        if offer.state != OfferState::Active
            || effective_now_ms >= offer.expires_at_ms
            || !valid_sas(&claim.sas_code)
            || self
                .pending
                .iter()
                .filter(|pending| pending.state == PendingState::AwaitingApproval)
                .count()
                >= 5
            || self.record_count() >= MAX_CREATION_RECORDS
            || self.id_seen(claim.pending_id)
        {
            return Err(SecurityError::Unauthorized);
        }
        let expires_at_ms = offer.expires_at_ms;
        let mut next = self.clone();
        next.last_accepted_wall_unix_seconds = accepted_wall;
        next.offers[offer_index].state = OfferState::Consumed;
        next.pending.push(Pending {
            pending_id: claim.pending_id,
            offer_id: claim.offer_id,
            initiator_static: claim.initiator_static,
            sas_code: claim.sas_code,
            sas_generation: claim.sas_generation,
            created_at_ms: effective_now_ms,
            expires_at_ms,
            state: PendingState::AwaitingApproval,
        });
        Ok((next, claim.pending_id, claim.sas_generation))
    }

    /// Advances the wall: `os_now_seconds` is a checked clock reading.
    pub fn approve_pending(
        &self,
        approval: PendingApproval,
        os_now_seconds: i64,
    ) -> Result<Self, SecurityError> {
        let (accepted_wall, effective_now_ms) = self.accept_clock(os_now_seconds)?;
        let pending_index = self
            .pending
            .iter()
            .position(|pending| {
                pending.pending_id == approval.pending_id
                    && pending.state == PendingState::AwaitingApproval
                    && pending.sas_generation == approval.sas_generation
                    && effective_now_ms < pending.expires_at_ms
            })
            .ok_or(SecurityError::Unauthorized)?;
        let pending = &self.pending[pending_index];
        let consumed_offer_exists = self
            .offers
            .iter()
            .any(|offer| offer.offer_id == pending.offer_id && offer.state == OfferState::Consumed);
        if !self.sharing_enabled
            || !approval.disclosure_exact
            || !consumed_offer_exists
            || approval.grant_expires_at_ms <= effective_now_ms
            || self
                .grants
                .iter()
                .filter(|grant| grant.state == GrantState::Active)
                .count()
                >= 16
            || self.record_count() >= MAX_CREATION_RECORDS
            || self.id_seen(approval.grant_id)
        {
            return Err(SecurityError::Unauthorized);
        }
        let initiator_static = pending.initiator_static;
        let mut next = self.clone();
        next.last_accepted_wall_unix_seconds = accepted_wall;
        let epoch = next.next_auth_epoch;
        next.next_auth_epoch = epoch.checked_add(1).ok_or(SecurityError::Bounds)?;
        next.pending[pending_index].state = PendingState::Approved;
        next.grants.push(Grant {
            grant_id: approval.grant_id,
            initiator_static,
            responder_static: approval.responder_static,
            scope: CONSENT_SCOPE,
            endpoints: [1, 2, 3, 4],
            auth_epoch: epoch,
            source_scope_generation: next.source_scope_generation,
            created_at_ms: effective_now_ms,
            expires_at_ms: approval.grant_expires_at_ms,
            state: GrantState::Active,
        });
        Ok(next)
    }

    /// Does not advance the wall: `terminal_at_ms` is a record timestamp, not a
    /// clock reading. Letting record data drive the durable clock would let one
    /// absurd timestamp lock it into the future.
    ///
    /// Never fails on record count: refusing to record a rejection because the
    /// state is full would leave the claim awaiting approval instead.
    pub fn reject_pending(
        &self,
        pending_id: [u8; 16],
        sas_generation: u64,
        terminal_at_ms: i64,
    ) -> Result<Self, SecurityError> {
        let pending_index = self
            .pending
            .iter()
            .position(|pending| {
                pending.pending_id == pending_id
                    && pending.state == PendingState::AwaitingApproval
                    && pending.sas_generation == sas_generation
            })
            .ok_or(SecurityError::Unauthorized)?;
        let mut next = self.clone();
        next.pending[pending_index].state = PendingState::Rejected;
        next.terminal.push(Terminal {
            record_id: pending_id,
            kind: TerminalKind::Pending,
            auth_epoch: 0,
            terminal_at_ms,
            cleanup_complete: false,
        });
        Ok(next)
    }

    /// Does not advance the wall: `terminal_at_ms` is a record timestamp.
    pub fn cancel_offer(
        &self,
        offer_id: [u8; 16],
        terminal_at_ms: i64,
    ) -> Result<Self, SecurityError> {
        let offer_index = self
            .offers
            .iter()
            .position(|offer| offer.offer_id == offer_id && offer.state == OfferState::Active)
            .ok_or(SecurityError::Invalid)?;
        if self.record_count() >= MAX_RECORDS {
            return Err(SecurityError::Bounds);
        }
        let mut next = self.clone();
        next.offers[offer_index].state = OfferState::Cancelled;
        next.terminal.push(Terminal {
            record_id: offer_id,
            kind: TerminalKind::Offer,
            auth_epoch: 0,
            terminal_at_ms,
            cleanup_complete: false,
        });
        Ok(next)
    }

    /// Does not advance the wall: `now_ms` is the record timestamp written into
    /// the terminal record, not a checked clock reading.
    pub fn expire_one(&self, record_id: [u8; 16], now_ms: i64) -> Result<Self, SecurityError> {
        if self.record_count() >= MAX_RECORDS {
            return Err(SecurityError::Bounds);
        }
        let mut next = self.clone();
        if let Some(offer) = next.offers.iter_mut().find(|offer| {
            offer.offer_id == record_id
                && offer.state == OfferState::Active
                && now_ms >= offer.expires_at_ms
        }) {
            offer.state = OfferState::Expired;
            next.terminal.push(Terminal {
                record_id,
                kind: TerminalKind::Offer,
                auth_epoch: 0,
                terminal_at_ms: now_ms,
                cleanup_complete: false,
            });
            return Ok(next);
        }
        if let Some(pending) = next.pending.iter_mut().find(|pending| {
            pending.pending_id == record_id
                && pending.state == PendingState::AwaitingApproval
                && now_ms >= pending.expires_at_ms
        }) {
            pending.state = PendingState::Expired;
            next.terminal.push(Terminal {
                record_id,
                kind: TerminalKind::Pending,
                auth_epoch: 0,
                terminal_at_ms: now_ms,
                cleanup_complete: false,
            });
            return Ok(next);
        }
        if let Some(grant) = next.grants.iter_mut().find(|grant| {
            grant.grant_id == record_id
                && grant.state == GrantState::Active
                && now_ms >= grant.expires_at_ms
        }) {
            grant.state = GrantState::Expired;
            next.terminal.push(Terminal {
                record_id,
                kind: TerminalKind::Grant,
                auth_epoch: grant.auth_epoch,
                terminal_at_ms: now_ms,
                cleanup_complete: false,
            });
            return Ok(next);
        }
        Err(SecurityError::Invalid)
    }

    /// Does not advance the wall: `terminal_at_ms` is a record timestamp.
    ///
    /// Never fails on record count. A terminal record leaves only through
    /// compaction, which needs a cleanup report, ninety days and a sane clock;
    /// a revoke that could fail on a full state would be unrevocable for
    /// months, which is what the terminal reserve exists to prevent.
    pub fn revoke_commit(
        &self,
        grant_id: [u8; 16],
        terminal_at_ms: i64,
    ) -> Result<Self, SecurityError> {
        if !self
            .grants
            .iter()
            .any(|grant| grant.grant_id == grant_id && grant.state == GrantState::Active)
        {
            return Err(SecurityError::Invalid);
        }
        let mut next = self.clone();
        next.raise_deny_floor()?;
        let mut revoked_epoch = 0;
        for grant in &mut next.grants {
            if grant.state != GrantState::Active {
                continue;
            }
            if grant.grant_id == grant_id {
                revoked_epoch = grant.auth_epoch;
                grant.state = GrantState::Revoked;
            } else {
                grant.auth_epoch = next.next_auth_epoch;
                next.next_auth_epoch = next
                    .next_auth_epoch
                    .checked_add(1)
                    .ok_or(SecurityError::Bounds)?;
            }
        }
        next.terminal.push(Terminal {
            record_id: grant_id,
            kind: TerminalKind::Grant,
            auth_epoch: revoked_epoch,
            terminal_at_ms,
            cleanup_complete: false,
        });
        Ok(next)
    }

    /// Does not advance the wall: `terminal_at_ms` is a record timestamp.
    /// Never fails on record count, for the reason given on `revoke_commit`.
    pub fn disable_commit(
        &self,
        record_id: [u8; 16],
        terminal_at_ms: i64,
    ) -> Result<Self, SecurityError> {
        let mut next = self.clone();
        next.raise_deny_floor()?;
        next.sharing_enabled = false;
        for grant in &mut next.grants {
            if grant.state == GrantState::Active {
                grant.state = GrantState::Revoked;
            }
        }
        next.terminal.push(Terminal {
            record_id,
            kind: TerminalKind::Reset,
            auth_epoch: next.deny_floor,
            terminal_at_ms,
            cleanup_complete: false,
        });
        Ok(next)
    }

    /// Does not advance the wall: `terminal_at_ms` is a record timestamp.
    /// Never fails on record count, for the reason given on `revoke_commit`.
    pub fn uninstall_commit(
        &self,
        record_id: [u8; 16],
        terminal_at_ms: i64,
    ) -> Result<Self, SecurityError> {
        let mut next = self.disable_commit(record_id, terminal_at_ms)?;
        next.terminal.last_mut().unwrap().kind = TerminalKind::Uninstall;
        Ok(next)
    }

    /// Does not advance the wall: it takes no clock reading at all.
    pub fn source_change_commit(&self) -> Result<Self, SecurityError> {
        let mut next = self.clone();
        next.raise_deny_floor()?;
        next.source_scope_generation = next
            .source_scope_generation
            .checked_add(1)
            .ok_or(SecurityError::Bounds)?;
        Ok(next)
    }

    /// Advances the wall: `os_now_seconds` is a checked clock reading.
    ///
    /// The runtime reports that physical cleanup finished for one terminal
    /// record. Nothing else can set `cleanup_complete`, and without it
    /// compaction is inert — which is precisely why compaction's own missing
    /// clock check went unnoticed. Changes no counter but the wall.
    pub fn mark_cleanup_complete(
        &self,
        record_id: [u8; 16],
        os_now_seconds: i64,
    ) -> Result<Self, SecurityError> {
        let (accepted_wall, _) = self.accept_clock(os_now_seconds)?;
        let index = self
            .terminal
            .iter()
            .position(|terminal| terminal.record_id == record_id && !terminal.cleanup_complete)
            .ok_or(SecurityError::Invalid)?;
        let mut next = self.clone();
        next.last_accepted_wall_unix_seconds = accepted_wall;
        next.terminal[index].cleanup_complete = true;
        Ok(next)
    }

    /// Advances the wall: `os_now_seconds` is a checked clock reading.
    ///
    /// Refused outright while the clock is anomalous, so a rolled-back or
    /// jumped clock cannot age records out of the audit trail early.
    pub fn compact_terminals(&self, os_now_seconds: i64) -> Result<Self, SecurityError> {
        const NINETY_DAYS_MS: i64 = 90 * 24 * 60 * 60 * 1_000;
        let (accepted_wall, effective_now_ms) = self.accept_clock(os_now_seconds)?;
        let mut next = self.clone();
        next.last_accepted_wall_unix_seconds = accepted_wall;
        next.terminal.sort_by_key(|terminal| {
            (
                terminal.terminal_at_ms,
                terminal_kind_rank(terminal.kind),
                terminal.record_id,
            )
        });
        next.terminal.retain(|terminal| {
            !(terminal.cleanup_complete
                && effective_now_ms.saturating_sub(terminal.terminal_at_ms) >= NINETY_DAYS_MS)
        });
        Ok(next)
    }

    fn raise_deny_floor(&mut self) -> Result<(), SecurityError> {
        let used = self
            .next_auth_epoch
            .checked_sub(1)
            .ok_or(SecurityError::Bounds)?;
        self.deny_floor = self.deny_floor.max(used);
        Ok(())
    }

    /// Checks a clock reading and returns `(accepted wall seconds, effective now
    /// in milliseconds)`.
    ///
    /// The accepted wall is `max(osNow,lastAcceptedWall)`, so it never
    /// decreases even when the reading steps back within tolerance. This is the
    /// only place the durable clock may be sourced from, and callers in the
    /// advancing set must write the first element back into the returned state.
    fn accept_clock(&self, os_now_seconds: i64) -> Result<(i64, i64), SecurityError> {
        let clock = clock_status(os_now_seconds, self.last_accepted_wall_unix_seconds);
        if clock.anomaly {
            return Err(SecurityError::Unauthorized);
        }
        let effective_now_ms = clock
            .effective_now
            .checked_mul(1_000)
            .ok_or(SecurityError::Bounds)?;
        Ok((clock.effective_now, effective_now_ms))
    }

    fn record_count(&self) -> usize {
        self.offers.len() + self.pending.len() + self.grants.len() + self.terminal.len()
    }

    fn id_seen(&self, id: [u8; 16]) -> bool {
        self.offers.iter().any(|offer| offer.offer_id == id)
            || self.pending.iter().any(|pending| pending.pending_id == id)
            || self.grants.iter().any(|grant| grant.grant_id == id)
            || self
                .terminal
                .iter()
                .any(|terminal| terminal.record_id == id)
    }
}

fn terminal_kind_rank(kind: TerminalKind) -> u8 {
    match kind {
        TerminalKind::Offer => 0,
        TerminalKind::Pending => 1,
        TerminalKind::Grant => 2,
        TerminalKind::Reset => 3,
        TerminalKind::Uninstall => 4,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootMetadata {
    pub absolute: bool,
    pub local_filesystem: bool,
    pub owner_matches: bool,
    pub no_symlink_or_reparse: bool,
    pub private_permissions: bool,
}

pub fn resolve_secure_root(
    platform: Platform,
    trusted_profile_home: Option<&str>,
    _process_environment_home: Option<&str>,
    metadata: RootMetadata,
) -> Result<String, SecurityError> {
    let home = trusted_profile_home.ok_or(SecurityError::Unauthorized)?;
    if !metadata.absolute
        || !metadata.local_filesystem
        || !metadata.owner_matches
        || !metadata.no_symlink_or_reparse
        || !metadata.private_permissions
        || !absolute_platform_path(platform, home)
    {
        return Err(SecurityError::Unauthorized);
    }
    Ok(match platform {
        Platform::MacOs => format!("{home}/Library/Application Support/com.nyanako.syrtis.agent/"),
        Platform::Linux => format!("{home}/.local/state/syrtis-agent/"),
        Platform::Windows => format!("{home}\\Nyanako\\Syrtis Agent\\"),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallObjects {
    pub binary: String,
    pub autostart_object: String,
    pub command: Vec<String>,
    pub uses_shell_or_path_search: bool,
}

pub fn install_objects(
    platform: Platform,
    trusted_home: &str,
) -> Result<InstallObjects, SecurityError> {
    if !absolute_platform_path(platform, trusted_home) {
        return Err(SecurityError::Invalid);
    }
    let (binary, autostart_object) = match platform {
        Platform::MacOs => (
            format!("{trusted_home}/.local/bin/syrtis-agent"),
            format!("{trusted_home}/Library/LaunchAgents/com.nyanako.syrtis.agent.plist"),
        ),
        Platform::Linux => (
            format!("{trusted_home}/.local/bin/syrtis-agent"),
            format!("{trusted_home}/.config/systemd/user/syrtis-agent.service"),
        ),
        Platform::Windows => (
            format!("{trusted_home}\\Programs\\Syrtis Agent\\syrtis-agent.exe"),
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Syrtis Agent".into(),
        ),
    };
    Ok(InstallObjects {
        command: vec![binary.clone(), "run".into()],
        binary,
        autostart_object,
        uses_shell_or_path_search: false,
    })
}

fn absolute_platform_path(platform: Platform, path: &str) -> bool {
    match platform {
        Platform::MacOs | Platform::Linux => path.starts_with('/') && !path.starts_with("//"),
        Platform::Windows => {
            let bytes = path.as_bytes();
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/')
                && !path.starts_with("\\\\")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSourcePolicy {
    pub use_env_roots: bool,
    pub source_scope_generation: u64,
    pub custom_roots: Vec<String>,
    pub owner_reconsent_required: bool,
}

impl Default for RemoteSourcePolicy {
    fn default() -> Self {
        Self {
            use_env_roots: false,
            source_scope_generation: 1,
            custom_roots: Vec::new(),
            owner_reconsent_required: false,
        }
    }
}

impl RemoteSourcePolicy {
    pub fn add_owner_approved_root(&self, root: String) -> Result<Self, SecurityError> {
        if !root.starts_with('/') || self.custom_roots.contains(&root) {
            return Err(SecurityError::Invalid);
        }
        let mut next = self.clone();
        next.custom_roots.push(root);
        next.custom_roots.sort();
        next.source_scope_generation = next
            .source_scope_generation
            .checked_add(1)
            .ok_or(SecurityError::Bounds)?;
        next.owner_reconsent_required = true;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstallState {
    pub sharing_enabled: bool,
    pub active_grants: usize,
    pub deny_floor: u64,
    pub next_auth_epoch: u64,
    pub listener_running: bool,
    pub control_running: bool,
    pub autostart_present: bool,
    pub binary_present: bool,
    pub cache_entries: usize,
    pub identity_present: bool,
    pub manual_repair: bool,
}

pub fn uninstall_reference(
    state: &UninstallState,
    purge: bool,
    candidate_objects_safe: bool,
) -> Result<UninstallState, SecurityError> {
    let mut next = state.clone();
    next.deny_floor = next.deny_floor.max(
        next.next_auth_epoch
            .checked_sub(1)
            .ok_or(SecurityError::Bounds)?,
    );
    next.next_auth_epoch = next
        .next_auth_epoch
        .checked_add(1)
        .ok_or(SecurityError::Bounds)?;
    next.sharing_enabled = false;
    next.active_grants = 0;
    next.listener_running = false;
    next.control_running = false;
    if candidate_objects_safe {
        next.autostart_present = false;
        next.binary_present = false;
        next.cache_entries = 0;
        if purge {
            next.identity_present = false;
        }
    } else {
        next.manual_repair = true;
    }
    Ok(next)
}

#[derive(Clone, Debug)]
pub struct MemoryLedger(Arc<AtomicUsize>);

impl Default for MemoryLedger {
    fn default() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }
}

impl MemoryLedger {
    pub fn used(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    pub fn reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(bytes)
                .filter(|next| *next <= REMOTE_MEMORY_MAX)?;
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(MemoryReservation {
                        ledger: self.clone(),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

pub struct MemoryReservation {
    ledger: MemoryLedger,
    bytes: usize,
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        self.ledger.0.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub fn charged_capacity<T>(
    elements: usize,
    control_bytes: usize,
    allocator_round: usize,
) -> Option<usize> {
    if allocator_round == 0 || !allocator_round.is_power_of_two() {
        return None;
    }
    let raw = elements
        .checked_mul(std::mem::size_of::<T>())?
        .checked_add(control_bytes)?;
    raw.checked_add(allocator_round - 1)
        .map(|value| value & !(allocator_round - 1))
}

pub const SHARED_FIELDS: &[&str] = &[
    "agent",
    "bucketStartUnixMs",
    "cacheReadTokens",
    "cacheWriteTokens",
    "client",
    "costNanoUsd",
    "date",
    "durationMillis",
    "inputTokens",
    "messageCount",
    "model",
    "outputTokens",
    "provider",
    "reasoningTokens",
    "sampleCount",
    "timedTokens",
    "totalTokens",
    "turnCount",
    "utcOffsetSeconds",
];

pub const PROTOCOL_FIELDS: &[&str] = &[
    "activeGrantCount",
    "activeOfferCount",
    "aggregationRevision",
    "authEpoch",
    "bindHost",
    "bindPort",
    "body",
    "clients",
    "code",
    "commandId",
    "controlVersion",
    "data",
    "endDateExclusive",
    "endpoint",
    "expiresAt",
    "grantId",
    "host",
    "lastScanAt",
    "nodeLabel",
    "offerId",
    "pairUrl",
    "pendingCount",
    "pendingId",
    "port",
    "protocol",
    "records",
    "reportSchema",
    "requestId",
    "responderStatic",
    "sasCode",
    "sasGeneration",
    "saturated",
    "scanStatus",
    "secret",
    "sharingEnabled",
    "sourceFamilies",
    "sourceScopeGeneration",
    "startDate",
    "timezone",
    "ttlSeconds",
    "tzdbRevision",
    "version",
];

pub const LOCAL_ONLY_FIELDS: &[&str] = &[
    "authEpoch",
    "bindHost",
    "bindPort",
    "bodySha256",
    "cacheKey",
    "cleanupComplete",
    "config",
    "controlToken",
    "counters",
    "createdAt",
    "createdAtUnixMs",
    "denyFloor",
    "endpoints",
    "expiresAt",
    "expiresAtUnixMs",
    "grantId",
    "grants",
    "identityPrivate",
    "initiatorStatic",
    "kind",
    "lastAcceptedWallUnixSeconds",
    "nextAuthEpoch",
    "nodeLabel",
    "offerId",
    "offers",
    "peerStatic",
    "pending",
    "pendingId",
    "recordId",
    "responderStatic",
    "role",
    "sasCode",
    "sasGeneration",
    "schema",
    "scope",
    "secretHash",
    "sharingEnabled",
    "sourceScopeGeneration",
    "state",
    "terminal",
    "terminalAt",
];

pub const LOG_FIELDS: &[&str] = &[
    "coarseDurationBucket",
    "operationClass",
    "redactedNodeId",
    "resultCode",
];

pub const UI_FIELDS: &[&str] = &[
    "duplicateWarning",
    "expiresAt",
    "nodeLabel",
    "sasCode",
    "sharingEnabled",
    "staleAge",
    "status",
];

pub const FORBIDDEN_FIELDS: &[&str] = &[
    "accountIdentifier",
    "credential",
    "ipAddress",
    "mergedReport",
    "osError",
    "panicText",
    "path",
    "prompt",
    "quota",
    "rawSessionId",
    "receiverCache",
    "responseText",
    "serdeError",
    "sessionFingerprint",
    "sourceFile",
    "tokensPerMinute",
    "trace",
    "workspace",
];

pub fn consent_registry() -> Value {
    json!({
        "aggregation": "directSum",
        "duplicateWarning": true,
        "endpoints": [1, 2, 3, 4],
        "forbiddenFields": FORBIDDEN_FIELDS,
        "localOnlyFields": LOCAL_ONLY_FIELDS,
        "logFields": LOG_FIELDS,
        "protocolFields": PROTOCOL_FIELDS,
        "retentionDays": 30,
        "scope": CONSENT_SCOPE,
        "sharedFields": SHARED_FIELDS,
        "transitiveSharing": false,
        "uiFields": UI_FIELDS,
        "version": 1
    })
}

pub fn verify_mac(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    constant_time_eq(expected, actual)
}
