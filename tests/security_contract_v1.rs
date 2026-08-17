use std::collections::BTreeSet;

use blake2::{Blake2s256, Digest as BlakeDigest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use serde_json::{Value, json};
use snow::{Builder, params::NoiseParams};
use syrtis_agent::{
    canonical::{CanonicalError, CanonicalJsonV1},
    security::*,
};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

const NOW_MS: i64 = 1_700_000_000_000;

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    decode_fixed_hex(hex).unwrap()
}

#[test]
fn canonical_json_and_pair_url_contract() {
    let composed = r#"{"a":"é","b":0,"c":[true,null]}"#.as_bytes();
    assert!(CanonicalJsonV1::decode_value(composed).is_ok());
    for invalid in [
        br#" {"a":1}"#.as_slice(),
        r#"{"b":0,"a":"é"}"#.as_bytes(),
        br#"{"a":1,"a":1}"#,
        r#"{"a":"é"}"#.as_bytes(),
        br#"{"a":"\u00e9"}"#,
        br#"{"a":-0}"#,
        br#"{"a":1.0}"#,
        br#"{"a":1e0}"#,
    ] {
        assert!(
            CanonicalJsonV1::decode_value(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    assert_eq!(
        CanonicalJsonV1::decode_value(b"\xef\xbb\xbf{}").unwrap_err(),
        CanonicalError::Bom
    );

    let offer = PairOffer {
        expires_at: NOW_MS + 600_000,
        host: "peer.example".into(),
        offer_id: "00".repeat(16),
        port: 49_152,
        responder_static: "11".repeat(32),
        secret: "22".repeat(32),
        version: 1,
    };
    let url = pair_url(&offer).unwrap();
    assert_eq!(
        url,
        include_str!("fixtures/v1/security/pair_url.txt").trim()
    );
    assert_eq!(parse_pair_url(&url, NOW_MS).unwrap(), offer);

    for invalid in [
        url.replace("syrtis://", "SYRTIS://"),
        format!("{url}&x=1"),
        url.replace("offer=", "offer=%"),
        url.replace('a', "A"),
    ] {
        assert!(parse_pair_url(&invalid, NOW_MS).is_err());
    }
    for host in [
        "Peer.example",
        "peer.example.",
        "-peer.example",
        "127.0.0.01",
        "a..b",
    ] {
        let mut bad = offer.clone();
        bad.host = host.into();
        assert!(pair_url(&bad).is_err(), "accepted host {host}");
    }
    assert!(parse_pair_url(&url, NOW_MS + 600_000).is_err());
}

fn response_frames(length: usize) -> Vec<Frame> {
    let count = length.div_ceil(FRAME_PAYLOAD_MAX).max(1);
    (0..count)
        .map(|index| {
            let consumed = index * FRAME_PAYLOAD_MAX;
            let payload_len = (length - consumed).min(FRAME_PAYLOAD_MAX);
            Frame {
                kind: FrameKind::Response,
                final_chunk: index + 1 == count,
                request_id: [7; 16],
                chunk_index: index as u32,
                chunk_count: count as u32,
                payload: vec![0x5a; payload_len],
            }
        })
        .collect()
}

#[test]
fn frame_caps_and_mutations() {
    for length in [FRAME_PAYLOAD_MAX - 1, FRAME_PAYLOAD_MAX] {
        let request = Frame {
            kind: FrameKind::Request,
            final_chunk: true,
            request_id: [1; 16],
            chunk_index: 0,
            chunk_count: 1,
            payload: vec![0; length],
        };
        let encoded = request.encode().unwrap();
        assert_eq!(Frame::decode(&encoded).unwrap(), request);
    }
    assert!(
        Frame {
            kind: FrameKind::Request,
            final_chunk: true,
            request_id: [1; 16],
            chunk_index: 0,
            chunk_count: 1,
            payload: vec![0; FRAME_PAYLOAD_MAX + 1],
        }
        .encode()
        .is_err()
    );
    for length in [ERROR_PAYLOAD_MAX - 1, ERROR_PAYLOAD_MAX] {
        assert!(
            Frame {
                kind: FrameKind::Error,
                final_chunk: true,
                request_id: [2; 16],
                chunk_index: 0,
                chunk_count: 1,
                payload: vec![0; length],
            }
            .encode()
            .is_ok()
        );
    }
    assert!(
        Frame {
            kind: FrameKind::Error,
            final_chunk: true,
            request_id: [2; 16],
            chunk_index: 0,
            chunk_count: 1,
            payload: vec![0; ERROR_PAYLOAD_MAX + 1],
        }
        .encode()
        .is_err()
    );
    for length in [LOGICAL_BODY_MAX - 1, LOGICAL_BODY_MAX] {
        assert_eq!(
            assemble_response(&response_frames(length)).unwrap().len(),
            length
        );
    }
    assert!(assemble_response(&response_frames(LOGICAL_BODY_MAX + 1)).is_err());

    let mut encoded = response_frames(1)[0].encode().unwrap();
    encoded[0] = b'X';
    assert!(Frame::decode(&encoded).is_err());
    let mut encoded = response_frames(1)[0].encode().unwrap();
    encoded[7] = 2;
    assert!(Frame::decode(&encoded).is_err());
    let mut gap = response_frames(FRAME_PAYLOAD_MAX + 1);
    gap[1].chunk_index = 0;
    assert!(assemble_response(&gap).is_err());
    assert!(encode_outer(&vec![0; FRAME_CIPHERTEXT_MAX + 1]).is_err());
    let mut outer = encode_outer(&[1, 2, 3]).unwrap();
    outer[3] = 4;
    assert!(decode_outer(&outer).is_err());
}

#[derive(Debug, Eq, PartialEq)]
struct NoiseOracle {
    message1: Vec<u8>,
    message2: Vec<u8>,
    h_final: [u8; 32],
}

#[derive(Clone, Copy)]
struct NoiseKeys {
    initiator_static: [u8; 32],
    initiator_ephemeral: [u8; 32],
    responder_static: [u8; 32],
    responder_ephemeral: [u8; 32],
}

fn blake2s(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut padded = [0_u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut inner = [0x36_u8; 64];
    let mut outer = [0x5c_u8; 64];
    for index in 0..64 {
        inner[index] ^= padded[index];
        outer[index] ^= padded[index];
    }
    let inner_hash = blake2s(&[&inner, data]);
    blake2s(&[&outer, &inner_hash])
}

fn hkdf2(chaining_key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_blake2s(chaining_key, input);
    let first = hmac_blake2s(&temp, &[1]);
    let mut second_input = [0_u8; 33];
    second_input[..32].copy_from_slice(&first);
    second_input[32] = 2;
    (first, hmac_blake2s(&temp, &second_input))
}

fn encrypt_and_hash(key: &[u8; 32], hash: &mut [u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&[0_u8; 12].into(), hash, &mut ciphertext)
        .unwrap();
    ciphertext.extend_from_slice(&tag);
    *hash = blake2s(&[hash, &ciphertext]);
    ciphertext
}

fn independent_noise_ik_oracle(
    keys: NoiseKeys,
    initiator_payload: &[u8],
    responder_payload: &[u8],
) -> NoiseOracle {
    let initiator_static = x25519(keys.initiator_static, X25519_BASEPOINT_BYTES);
    let initiator_ephemeral = x25519(keys.initiator_ephemeral, X25519_BASEPOINT_BYTES);
    let responder_static = x25519(keys.responder_static, X25519_BASEPOINT_BYTES);
    let responder_ephemeral = x25519(keys.responder_ephemeral, X25519_BASEPOINT_BYTES);

    let mut hash = blake2s(&[NOISE_SUITE.as_bytes()]);
    let mut chaining_key = hash;
    hash = blake2s(&[&hash, NOISE_PROLOGUE]);
    hash = blake2s(&[&hash, &responder_static]);

    let mut message1 = initiator_ephemeral.to_vec();
    hash = blake2s(&[&hash, &initiator_ephemeral]);
    let (next_chaining_key, key) = hkdf2(
        &chaining_key,
        &x25519(keys.initiator_ephemeral, responder_static),
    );
    chaining_key = next_chaining_key;
    message1.extend_from_slice(&encrypt_and_hash(&key, &mut hash, &initiator_static));
    let (next_chaining_key, key) = hkdf2(
        &chaining_key,
        &x25519(keys.initiator_static, responder_static),
    );
    chaining_key = next_chaining_key;
    message1.extend_from_slice(&encrypt_and_hash(&key, &mut hash, initiator_payload));

    let mut message2 = responder_ephemeral.to_vec();
    hash = blake2s(&[&hash, &responder_ephemeral]);
    let (next_chaining_key, _) = hkdf2(
        &chaining_key,
        &x25519(keys.responder_ephemeral, initiator_ephemeral),
    );
    chaining_key = next_chaining_key;
    let (next_chaining_key, key) = hkdf2(
        &chaining_key,
        &x25519(keys.responder_ephemeral, initiator_static),
    );
    chaining_key = next_chaining_key;
    message2.extend_from_slice(&encrypt_and_hash(&key, &mut hash, responder_payload));
    let _ = chaining_key;

    NoiseOracle {
        message1,
        message2,
        h_final: hash,
    }
}

fn snow_handshake(
    prologue: &[u8],
    keys: &NoiseKeys,
    initiator_payload: &[u8],
    responder_payload: &[u8],
) -> NoiseOracle {
    let responder_static_public = x25519(keys.responder_static, X25519_BASEPOINT_BYTES);
    let params: NoiseParams = NOISE_SUITE.parse().unwrap();
    let mut initiator = Builder::new(params.clone())
        .local_private_key(&keys.initiator_static)
        .unwrap()
        .remote_public_key(&responder_static_public)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&keys.initiator_ephemeral)
        .prologue(prologue)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = Builder::new(params)
        .local_private_key(&keys.responder_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&keys.responder_ephemeral)
        .prologue(prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut message1 = vec![0; 65_535];
    let length1 = initiator
        .write_message(initiator_payload, &mut message1)
        .unwrap();
    message1.truncate(length1);
    let mut payload = vec![0; 65_535];
    let read1 = responder.read_message(&message1, &mut payload).unwrap();
    assert_eq!(&payload[..read1], initiator_payload);
    let mut message2 = vec![0; 65_535];
    let length2 = responder
        .write_message(responder_payload, &mut message2)
        .unwrap();
    message2.truncate(length2);
    let read2 = initiator.read_message(&message2, &mut payload).unwrap();
    assert_eq!(&payload[..read2], responder_payload);
    NoiseOracle {
        message1,
        message2,
        h_final: initiator.get_handshake_hash().try_into().unwrap(),
    }
}

#[test]
fn noise_official_vector_independent_oracle_and_sas() {
    let init_static = bytes("b7e117ce8ede06ceb89500799a3778d097fc54a3f90bea744493dfc24ec21f32");
    let init_ephemeral = bytes("cc95b4ccc4912c5a52c8d2f6b808e13712392c4468f4e3f02a7d2d1590cb9178");
    let resp_static = bytes("e3187f5c10734e934be3a73c398c7fae07ba3e0cde2fcd9ab03a1c93dcae10f8");
    let resp_ephemeral = bytes("587f83fe736432043d2665fbd47b0506b2cd103b6ba8577f72e117c7ffeb5105");
    let resp_public = bytes("ea82fd2e81d1285f1b2029e46ca7bcaeeeafed15396d002bd434624a4d580655");
    let keys = NoiseKeys {
        initiator_static: init_static,
        initiator_ephemeral: init_ephemeral,
        responder_static: resp_static,
        responder_ephemeral: resp_ephemeral,
    };
    assert_eq!(x25519(resp_static, X25519_BASEPOINT_BYTES), resp_public);
    let official_prologue = hex_decode("5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e").unwrap();
    let payload1 =
        hex_decode("910ef4a7c04090f66403fcd8ffaed066e70ed38b576792c4a554cc5016fe5120").unwrap();
    let payload2 =
        hex_decode("3ce1e4d6e5f02bfeea1d6620cbf1473b5f55372d6954e98d3e12b6ffd04879d5").unwrap();
    let official = snow_handshake(&official_prologue, &keys, &payload1, &payload2);
    assert_eq!(
        hex_encode(&official.message1),
        "df44a475167152d3e4767b9ad5b28468fb8bd6aaa0b0e7181afd87ede7a8c971e818de301c97393bfa71ac250becfc8acef64a969e039f407fe44c5ffc3d66d94ff57627ad4cc53882a1b2993babac3940edd1eaff34a3d3f08c53570166b3d29d06bd5de3cfb9b85b66001a60a5bb98d72b80da9485655f86db72b46f745c4e"
    );
    assert_eq!(
        hex_encode(&official.message2),
        "2818be348d38de5f9e3ef545c62e8e276c12e2a64410801a0284e02dfb0d450a848d1001977ef31dfe04b5c824acc04c7bda8490eab6cb6aaa844c4ddf0fda83ec84ed26cd6bee22fab17360b73de5b8"
    );

    let oracle = independent_noise_ik_oracle(keys, b"initiator", b"responder");
    let snow = snow_handshake(NOISE_PROLOGUE, &keys, b"initiator", b"responder");
    assert_eq!(snow, oracle);
    let formatted = format!(
        "message1={}\nmessage2={}\nhFinal={}\n",
        hex_encode(&oracle.message1),
        hex_encode(&oracle.message2),
        hex_encode(&oracle.h_final)
    );
    assert_eq!(
        formatted,
        include_str!("fixtures/v1/security/noise_ik_oracle.hex")
    );

    let sas = pair_sas(
        1,
        &[0x33; 16],
        &resp_public,
        &x25519(init_static, X25519_BASEPOINT_BYTES),
        &oracle.h_final,
    );
    assert_eq!(
        format!("{sas}\n"),
        include_str!("fixtures/v1/security/sas.txt")
    );
}

#[test]
fn control_mac_kats_and_strict_shapes() {
    let token = [0x10; 32];
    let client_nonce = [0x20; 32];
    let server_nonce = [0x30; 32];
    let request_id = [0x40; 16];
    let command = CanonicalJsonV1::encode(&json!({
        "body": {"ttlSeconds": 600},
        "commandId": 2,
        "controlVersion": 1,
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    verify_control_command(&command, &request_id, 2).unwrap();
    let response = CanonicalJsonV1::encode(&json!({
        "code": 0,
        "controlVersion": 1,
        "data": {"expiresAt": NOW_MS + 600_000, "offerId": "55".repeat(16), "pairUrl": include_str!("fixtures/v1/security/pair_url.txt").trim()},
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    verify_control_response(&response, &request_id, 2, 0).unwrap();
    let key = control_key(&token);
    let server = control_server_mac(&key, 1, &client_nonce, &server_nonce);
    let command_mac = control_command_mac(
        &key,
        1,
        &client_nonce,
        &server_nonce,
        &request_id,
        2,
        &command,
    )
    .unwrap();
    let response_mac = control_response_mac(
        &key,
        1,
        &client_nonce,
        &server_nonce,
        &request_id,
        0,
        &response,
    )
    .unwrap();
    let fixture = format!(
        "controlKey={}\nserverMac={}\ncommandMac={}\nresponseMac={}\n",
        hex_encode(&key),
        hex_encode(&server),
        hex_encode(&command_mac),
        hex_encode(&response_mac)
    );
    assert_eq!(
        fixture,
        include_str!("fixtures/v1/security/control_mac.hex")
    );
    assert!(!verify_mac(
        &server,
        &control_server_mac(&key, 2, &client_nonce, &server_nonce)
    ));
    assert!(!verify_mac(
        &command_mac,
        &control_command_mac(
            &key,
            1,
            &client_nonce,
            &[0x31; 32],
            &request_id,
            2,
            &command
        )
        .unwrap()
    ));

    let wrong_body = CanonicalJsonV1::encode(&json!({
        "body": {"grantId": "00".repeat(16)},
        "commandId": 2,
        "controlVersion": 1,
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    assert!(verify_control_command(&wrong_body, &request_id, 2).is_err());
    let wrong_data = CanonicalJsonV1::encode(&json!({
        "code": 0,
        "controlVersion": 1,
        "data": {"expiresAt": NOW_MS, "pendingId": "00".repeat(16), "sasCode": "ABCD-EF01"},
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    assert!(verify_control_response(&wrong_data, &request_id, 2, 0).is_err());
    let error_with_data = CanonicalJsonV1::encode(&json!({
        "code": 1, "controlVersion": 1, "data": {}, "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    assert!(verify_control_response(&error_with_data, &request_id, 2, 1).is_err());
    let status = CanonicalJsonV1::encode(&json!({
        "code": 0,
        "controlVersion": 1,
        "data": {"activeGrantCount": 1, "activeOfferCount": 0, "bindHost": "127.0.0.1", "bindPort": 49152, "lastScanAt": null, "nodeLabel": "node", "pendingCount": 0, "scanStatus": "never", "sharingEnabled": true, "sourceFamilies": ["claude", "codex"]},
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    verify_control_response(&status, &request_id, 1, 0).unwrap();
    let pending = CanonicalJsonV1::encode(&json!({
        "code": 0,
        "controlVersion": 1,
        "data": [{"expiresAt": NOW_MS, "pendingId": "01".repeat(16), "sasCode": "ABCD-EF01"}, {"expiresAt": NOW_MS, "pendingId": "02".repeat(16), "sasCode": "1234-5678"}],
        "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    verify_control_response(&pending, &request_id, 4, 0).unwrap();
    let null_success = CanonicalJsonV1::encode(&json!({
        "code": 0, "controlVersion": 1, "data": null, "requestId": hex_encode(&request_id)
    }))
    .unwrap();
    verify_control_response(&null_success, &request_id, 7, 0).unwrap();
    assert!(verify_control_response(&status, &request_id, 4, 0).is_err());
}

const WALL_SECONDS: i64 = NOW_MS / 1_000;
const OFFER_SECRET: [u8; 32] = [0x9a; 32];
const RESPONDER_STATIC: [u8; 32] = [0x9b; 32];
const INITIATOR_STATIC: [u8; 32] = [0x78; 32];

/// Models the runtime assembly frozen in `spec/security-v1.md`: counters come
/// from the *current* durable state, identity from the grant.
///
/// Used only by the transition tests, which are about what a transition did to
/// the state. The nine conjunct tests below deliberately do not use it: a
/// request derived from the grant it constrains cannot fail, and that is how
/// eight of the nine conjuncts once went untested.
fn runtime_request(
    state: &ReferenceState,
    grant: &Grant,
    os_now_seconds: i64,
) -> AuthorizationRequest {
    AuthorizationRequest {
        sharing_enabled: state.sharing_enabled,
        auth_epoch: grant.auth_epoch,
        deny_floor: state.deny_floor,
        source_scope_generation: grant.source_scope_generation,
        counter_source_scope_generation: state.source_scope_generation,
        os_now_unix_seconds: os_now_seconds,
        last_accepted_wall_unix_seconds: state.last_accepted_wall_unix_seconds(),
        endpoint: 1,
    }
}

fn enabled_state() -> ReferenceState {
    ReferenceState::new(WALL_SECONDS)
        .unwrap()
        .enable_sharing()
        .unwrap()
}

fn offer_record(offer_id: [u8; 16], expires_at_ms: i64) -> Offer {
    Offer {
        offer_id,
        secret_hash: offer_secret_hash(&offer_id, &OFFER_SECRET, &RESPONDER_STATIC),
        created_at_ms: NOW_MS,
        expires_at_ms,
        state: OfferState::Active,
    }
}

fn claim_for(
    offer_id: [u8; 16],
    pending_id: [u8; 16],
    initiator_static: [u8; 32],
    sas_generation: u64,
) -> OfferClaim {
    OfferClaim {
        offer_id,
        secret: OFFER_SECRET,
        responder_static: RESPONDER_STATIC,
        pending_id,
        initiator_static,
        sas_code: "ABCD-EF01".into(),
        sas_generation,
    }
}

fn approval_for(
    pending_id: [u8; 16],
    sas_generation: u64,
    grant_id: [u8; 16],
    grant_expires_at_ms: i64,
) -> PendingApproval {
    PendingApproval {
        pending_id,
        sas_generation,
        grant_id,
        responder_static: RESPONDER_STATIC,
        grant_expires_at_ms,
        disclosure_exact: true,
    }
}

fn add_approved_grant(
    state: ReferenceState,
    offer_id: [u8; 16],
    pending_id: [u8; 16],
    grant_id: [u8; 16],
) -> ReferenceState {
    let state = state
        .create_offer(offer_record(offer_id, NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    let (state, pending_id, generation) = state
        .claim_offer(
            claim_for(offer_id, pending_id, INITIATOR_STATIC, 1),
            WALL_SECONDS,
        )
        .unwrap();
    state
        .approve_pending(
            approval_for(pending_id, generation, grant_id, NOW_MS + 600_000),
            WALL_SECONDS,
        )
        .unwrap()
}

// Authorization fixture. Every value is a literal, and no two conjuncts read
// the same one, so exactly one conjunct can be falsified at a time.
const AUTH_EPOCH: u64 = 9;
const AUTH_DENY_FLOOR: u64 = 4;
const AUTH_SCOPE_GENERATION: u64 = 6;
const AUTH_OS_NOW_SECONDS: i64 = 1_400;
const AUTH_WALL_SECONDS: i64 = 1_500;
const AUTH_EFFECTIVE_MS: i64 = AUTH_WALL_SECONDS * 1_000;
const AUTH_ENDPOINT: u16 = 3;

fn authorized_grant() -> Grant {
    Grant {
        grant_id: [0xa1; 16],
        initiator_static: [0xa2; 32],
        responder_static: [0xa3; 32],
        scope: CONSENT_SCOPE,
        endpoints: [1, 2, 3, 4],
        auth_epoch: AUTH_EPOCH,
        source_scope_generation: AUTH_SCOPE_GENERATION,
        created_at_ms: 900_000,
        expires_at_ms: AUTH_EFFECTIVE_MS + 1,
        state: GrantState::Active,
    }
}

fn authorized_request() -> AuthorizationRequest {
    AuthorizationRequest {
        sharing_enabled: true,
        auth_epoch: AUTH_EPOCH,
        deny_floor: AUTH_DENY_FLOOR,
        source_scope_generation: AUTH_SCOPE_GENERATION,
        counter_source_scope_generation: AUTH_SCOPE_GENERATION,
        os_now_unix_seconds: AUTH_OS_NOW_SECONDS,
        last_accepted_wall_unix_seconds: AUTH_WALL_SECONDS,
        endpoint: AUTH_ENDPOINT,
    }
}

#[test]
fn authorize_accepts_the_complete_predicate() {
    assert!(authorize(&authorized_grant(), &authorized_request()));
}

#[test]
fn authorize_requires_sharing_enabled() {
    let mut request = authorized_request();
    request.sharing_enabled = false;
    assert!(!authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_an_active_grant() {
    for state in [GrantState::Revoked, GrantState::Expired] {
        let mut grant = authorized_grant();
        grant.state = state;
        assert!(!authorize(&grant, &authorized_request()), "{state:?}");
    }
}

#[test]
fn authorize_requires_the_request_epoch_to_equal_the_grant_epoch() {
    // The grant epoch stays above the deny floor, so only the equality fails.
    let mut request = authorized_request();
    request.auth_epoch = AUTH_EPOCH + 1;
    assert!(!authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_the_grant_epoch_above_the_deny_floor() {
    // The request still echoes the grant epoch, so only the floor comparison
    // fails. Equal is denied; one below is allowed.
    let mut request = authorized_request();
    request.deny_floor = AUTH_EPOCH;
    assert!(!authorize(&authorized_grant(), &request));
    request.deny_floor = AUTH_EPOCH - 1;
    assert!(authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_the_request_source_scope_to_equal_the_grant() {
    // The counter still equals the grant generation, so only this equality
    // fails.
    let mut request = authorized_request();
    request.source_scope_generation = AUTH_SCOPE_GENERATION + 1;
    assert!(!authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_the_counter_source_scope_to_equal_the_grant() {
    // The request still equals the grant generation, so only this equality
    // fails. This is the conjunct a source change relies on.
    let mut request = authorized_request();
    request.counter_source_scope_generation = AUTH_SCOPE_GENERATION + 1;
    assert!(!authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_effective_now_before_expiry() {
    // Effective now is the durable wall, not the OS reading, so a rolled-back
    // OS clock cannot revive the grant. Equal is denied; one millisecond later
    // is allowed.
    let mut grant = authorized_grant();
    grant.expires_at_ms = AUTH_EFFECTIVE_MS;
    assert!(!authorize(&grant, &authorized_request()));
    grant.expires_at_ms = AUTH_EFFECTIVE_MS + 1;
    assert!(authorize(&grant, &authorized_request()));
}

#[test]
fn authorize_requires_the_endpoint_to_be_granted() {
    let mut request = authorized_request();
    request.endpoint = 5;
    assert!(!authorize(&authorized_grant(), &request));
}

#[test]
fn authorize_requires_the_exact_consent_scope() {
    let mut grant = authorized_grant();
    grant.scope = "usage.aggregate.read.v2";
    assert!(!authorize(&grant, &authorized_request()));
}

#[test]
fn authorization_state_clock_and_crash_points() {
    let enabled = ReferenceState::new(1).unwrap().enable_sharing().unwrap();
    let expired_offer = Offer {
        offer_id: [0x01; 16],
        secret_hash: [0x02; 32],
        created_at_ms: 1_000,
        expires_at_ms: 1_999,
        state: OfferState::Active,
    };
    assert!(enabled.create_offer(expired_offer, 2).is_err());
    assert!(enabled.offers.is_empty());
    for (created_at_ms, expires_at_ms, now_seconds) in [
        (1_000, 1_999, 1),
        (1_000, 901_001, 1),
        (1_000, 1_000, 1),
        (1_000, 2_000, 2),
    ] {
        assert!(
            enabled
                .create_offer(
                    Offer {
                        offer_id: [expires_at_ms as u8; 16],
                        secret_hash: [0x03; 32],
                        created_at_ms,
                        expires_at_ms,
                        state: OfferState::Active,
                    },
                    now_seconds,
                )
                .is_err()
        );
    }
    assert!(
        enabled
            .create_offer(
                Offer {
                    offer_id: [0x04; 16],
                    secret_hash: [0x05; 32],
                    created_at_ms: 1_000,
                    expires_at_ms: 2_000,
                    state: OfferState::Active,
                },
                1,
            )
            .is_ok()
    );
    assert!(
        enabled
            .approve_pending(approval_for([7; 16], 1, [7; 16], 999), 2)
            .is_err()
    );
    assert!(enabled.grants.is_empty());

    let offer = offer_record([0x10; 16], NOW_MS + 600_000);
    assert!(
        ReferenceState::new(WALL_SECONDS)
            .unwrap()
            .create_offer(offer.clone(), WALL_SECONDS)
            .is_err()
    );
    let pairing = enabled_state().create_offer(offer, WALL_SECONDS).unwrap();
    let (pairing, pending_id, generation) = pairing
        .claim_offer(
            claim_for([0x10; 16], [0x20; 16], [0x30; 32], 7),
            WALL_SECONDS,
        )
        .unwrap();
    let unchanged = pairing.clone();
    let mut retry_claim = claim_for([0x10; 16], [0x21; 16], [0x30; 32], 99);
    retry_claim.sas_code = "FFFF-FFFF".into();
    let (retry, retry_id, retry_generation) =
        pairing.claim_offer(retry_claim, WALL_SECONDS).unwrap();
    assert_eq!(retry, pairing);
    assert_eq!((retry_id, retry_generation), (pending_id, generation));
    assert!(
        pairing
            .claim_offer(
                claim_for([0x10; 16], [0x22; 16], [0x31; 32], 7),
                WALL_SECONDS
            )
            .is_err()
    );
    assert_eq!(pairing, unchanged);
    assert!(
        pairing
            .approve_pending(
                approval_for(pending_id, generation + 1, [0x40; 16], NOW_MS + 1_000_000),
                WALL_SECONDS,
            )
            .is_err()
    );
    let mut without_disclosure =
        approval_for(pending_id, generation, [0x40; 16], NOW_MS + 1_000_000);
    without_disclosure.disclosure_exact = false;
    assert!(
        pairing
            .approve_pending(without_disclosure, WALL_SECONDS)
            .is_err()
    );
    assert_eq!(pairing, unchanged);
    let approved = pairing
        .approve_pending(
            approval_for(pending_id, generation, [0x40; 16], NOW_MS + 1_000_000),
            WALL_SECONDS,
        )
        .unwrap();
    assert_eq!(approved.pending[0].state, PendingState::Approved);
    assert_eq!(approved.grants[0].state, GrantState::Active);
    // The grant binds the identities of the pair it was approved for.
    assert_eq!(approved.grants[0].initiator_static, [0x30; 32]);
    assert_eq!(approved.grants[0].responder_static, RESPONDER_STATIC);
    assert_eq!(approved.grants[0].created_at_ms, NOW_MS);
    let mut broken_link = pairing.clone();
    broken_link.offers[0].state = OfferState::Active;
    assert!(
        broken_link
            .approve_pending(
                approval_for(pending_id, generation, [0x41; 16], NOW_MS + 1_000_000),
                WALL_SECONDS,
            )
            .is_err()
    );
    assert!(
        pairing
            .approve_pending(
                approval_for(pending_id, generation, [0x42; 16], NOW_MS + 1_000_000),
                WALL_SECONDS + 601,
            )
            .is_err()
    );

    let cancellation = enabled_state()
        .create_offer(offer_record([0x50; 16], NOW_MS + 1_000), WALL_SECONDS)
        .unwrap();
    let cancelled = cancellation.cancel_offer([0x50; 16], NOW_MS).unwrap();
    assert_eq!(cancelled.offers[0].state, OfferState::Cancelled);
    assert!(cancelled.cancel_offer([0x50; 16], NOW_MS).is_err());

    let expiration = enabled_state()
        .create_offer(offer_record([0x60; 16], NOW_MS + 1_000), WALL_SECONDS)
        .unwrap();
    let expiration = expiration.expire_one([0x60; 16], NOW_MS + 1_001).unwrap();
    assert_eq!(expiration.offers[0].state, OfferState::Expired);

    let state = enabled_state();
    let state = add_approved_grant(state, [0x70; 16], [0x71; 16], [1; 16]);
    let state = add_approved_grant(state, [0x72; 16], [0x73; 16], [2; 16]);
    let target = state.grants[0].clone();
    assert!(authorize(
        &target,
        &runtime_request(&state, &target, WALL_SECONDS)
    ));

    let before_commit = state.clone();
    let after_commit = state.revoke_commit([1; 16], NOW_MS).unwrap();
    assert!(authorize(
        &target,
        &runtime_request(&before_commit, &target, WALL_SECONDS)
    ));
    let revoked = after_commit
        .grants
        .iter()
        .find(|grant| grant.grant_id == [1; 16])
        .unwrap();
    assert!(!authorize(
        revoked,
        &runtime_request(&after_commit, revoked, WALL_SECONDS)
    ));
    let survivor = after_commit
        .grants
        .iter()
        .find(|grant| grant.grant_id == [2; 16])
        .unwrap();
    assert!(survivor.auth_epoch > after_commit.deny_floor);
    assert!(authorize(
        survivor,
        &runtime_request(&after_commit, survivor, WALL_SECONDS)
    ));

    let changed = after_commit.source_change_commit().unwrap();
    assert!(!authorize(
        survivor,
        &runtime_request(&changed, survivor, WALL_SECONDS)
    ));
    let disabled = after_commit.disable_commit([9; 16], NOW_MS).unwrap();
    assert!(!disabled.sharing_enabled);
    assert!(
        disabled
            .grants
            .iter()
            .all(|grant| grant.state != GrantState::Active)
    );
    let uninstalled = after_commit.uninstall_commit([8; 16], NOW_MS).unwrap();
    assert_eq!(
        uninstalled.terminal.last().unwrap().kind,
        TerminalKind::Uninstall
    );
    assert!(!uninstalled.sharing_enabled);

    assert!(clock_status(1_000, 1_301).anomaly);
    assert!(clock_status(87_000, 1).anomaly);
    assert_eq!(clock_status(900, 1_000).effective_now, 1_000);
    // A rolled-back OS clock does not revive an expired grant: the durable wall
    // wins, and the state's wall is the one the grant was issued against.
    let mut expired = target.clone();
    expired.expires_at_ms = NOW_MS - 1;
    assert!(!authorize(
        &expired,
        &runtime_request(&state, &expired, WALL_SECONDS - 100)
    ));

    // `state_transitions.json` freezes the twelve specification-level
    // transition *names*. It is not a list of this crate's methods and must not
    // be read as one: it names `reset`, which has no method, while
    // `cancel_offer` and `mark_cleanup_complete` are methods it does not name.
    let transitions =
        serde_json::from_str::<Value>(include_str!("fixtures/v1/security/state_transitions.json"))
            .unwrap()["transitions"]
            .clone();
    assert_eq!(
        transitions,
        json!([
            "sharing.enable",
            "offer.create",
            "claim",
            "approve",
            "reject",
            "expiry",
            "revoke",
            "sharing.disable",
            "source.change",
            "reset",
            "uninstall",
            "compact"
        ])
    );
    let names: Vec<&str> = transitions
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert!(names.contains(&"reset"));
    assert!(!names.contains(&"offer.cancel"));
    assert!(!names.contains(&"cleanup.complete"));
}

#[test]
fn state_construction_requires_a_positive_install_wall_clock() {
    // Not "0 means unchecked": a zero wall would make every real Unix timestamp
    // look like a forward jump of decades, and no transition can lower a
    // counter again, so the state would refuse every clock-bound transition
    // forever. It is refused at construction instead.
    assert_eq!(ReferenceState::new(0).unwrap_err(), SecurityError::Invalid);
    assert_eq!(ReferenceState::new(-1).unwrap_err(), SecurityError::Invalid);
    assert_eq!(
        ReferenceState::new(i64::MIN).unwrap_err(),
        SecurityError::Invalid
    );
    let state = ReferenceState::new(1).unwrap();
    assert_eq!(state.last_accepted_wall_unix_seconds(), 1);
}

#[test]
fn a_bootstrapped_state_accepts_real_time_and_advances_its_wall() {
    // The regression this exists for: with a wall of zero, `clock_status`
    // called every real timestamp an anomaly, so `create_offer` failed
    // unconditionally and every test hand-set the field to hide it.
    let state = ReferenceState::new(WALL_SECONDS)
        .unwrap()
        .enable_sharing()
        .unwrap();
    assert_eq!(state.last_accepted_wall_unix_seconds(), WALL_SECONDS);
    let later = WALL_SECONDS + 60;
    let state = state
        .create_offer(
            Offer {
                offer_id: [0xb0; 16],
                secret_hash: offer_secret_hash(&[0xb0; 16], &OFFER_SECRET, &RESPONDER_STATIC),
                created_at_ms: later * 1_000,
                expires_at_ms: later * 1_000 + 600_000,
                state: OfferState::Active,
            },
            later,
        )
        .unwrap();
    assert_eq!(state.last_accepted_wall_unix_seconds(), later);
}

#[test]
fn every_advancing_transition_writes_the_durable_wall() {
    let step = 60;
    let state = enabled_state();
    assert_eq!(state.last_accepted_wall_unix_seconds(), WALL_SECONDS);

    let state = state
        .create_offer(
            offer_record([0xc0; 16], NOW_MS + 600_000),
            WALL_SECONDS + step,
        )
        .unwrap();
    assert_eq!(state.last_accepted_wall_unix_seconds(), WALL_SECONDS + step);

    let (state, pending_id, generation) = state
        .claim_offer(
            claim_for([0xc0; 16], [0xc1; 16], INITIATOR_STATIC, 1),
            WALL_SECONDS + 2 * step,
        )
        .unwrap();
    assert_eq!(
        state.last_accepted_wall_unix_seconds(),
        WALL_SECONDS + 2 * step
    );

    let state = state
        .approve_pending(
            approval_for(pending_id, generation, [0xc2; 16], NOW_MS + 600_000),
            WALL_SECONDS + 3 * step,
        )
        .unwrap();
    assert_eq!(
        state.last_accepted_wall_unix_seconds(),
        WALL_SECONDS + 3 * step
    );

    let state = state.revoke_commit([0xc2; 16], NOW_MS).unwrap();
    let state = state
        .mark_cleanup_complete([0xc2; 16], WALL_SECONDS + 4 * step)
        .unwrap();
    assert_eq!(
        state.last_accepted_wall_unix_seconds(),
        WALL_SECONDS + 4 * step
    );

    let state = state.compact_terminals(WALL_SECONDS + 5 * step).unwrap();
    assert_eq!(
        state.last_accepted_wall_unix_seconds(),
        WALL_SECONDS + 5 * step
    );

    // A reading inside the rollback tolerance is accepted but never lowers the
    // wall: it is a State counter.
    let state = state
        .compact_terminals(WALL_SECONDS + 5 * step - 200)
        .unwrap();
    assert_eq!(
        state.last_accepted_wall_unix_seconds(),
        WALL_SECONDS + 5 * step
    );
}

#[test]
fn record_timestamps_never_advance_the_durable_wall() {
    // The rule this pins: a record timestamp is data supplied with the
    // transition. If it could advance the wall, one absurd `terminalAt` would
    // lock the durable clock into the future and every honest reading after it
    // would look like a rollback.
    let absurd_ms = NOW_MS + 4_000 * 365 * 24 * 60 * 60 * 1_000;
    let base = add_approved_grant(enabled_state(), [0xd0; 16], [0xd1; 16], [0xd2; 16]);
    let with_pending = base
        .create_offer(offer_record([0xd3; 16], NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    let (with_pending, pending_id, generation) = with_pending
        .claim_offer(
            claim_for([0xd3; 16], [0xd4; 16], [0x66; 32], 5),
            WALL_SECONDS,
        )
        .unwrap();
    assert_eq!(with_pending.last_accepted_wall_unix_seconds(), WALL_SECONDS);

    let cases: Vec<(&str, ReferenceState)> = vec![
        (
            "reject",
            with_pending
                .reject_pending(pending_id, generation, absurd_ms)
                .unwrap(),
        ),
        (
            "cancel",
            base.create_offer(offer_record([0xd5; 16], NOW_MS + 600_000), WALL_SECONDS)
                .unwrap()
                .cancel_offer([0xd5; 16], absurd_ms)
                .unwrap(),
        ),
        ("expiry", base.expire_one([0xd2; 16], absurd_ms).unwrap()),
        ("revoke", base.revoke_commit([0xd2; 16], absurd_ms).unwrap()),
        (
            "disable",
            base.disable_commit([0xd6; 16], absurd_ms).unwrap(),
        ),
        (
            "uninstall",
            base.uninstall_commit([0xd7; 16], absurd_ms).unwrap(),
        ),
        ("source.change", base.source_change_commit().unwrap()),
        (
            "sharing.enable",
            ReferenceState::new(WALL_SECONDS)
                .unwrap()
                .enable_sharing()
                .unwrap(),
        ),
    ];
    for (name, state) in cases {
        assert_eq!(
            state.last_accepted_wall_unix_seconds(),
            WALL_SECONDS,
            "{name} advanced the wall"
        );
    }
}

#[test]
fn clock_anomaly_thresholds_are_exact_at_both_edges() {
    // Literals, not the constants: an expectation read out of the value under
    // test moves with it, and a widened tolerance would stay green.
    assert_eq!(MAX_CLOCK_ROLLBACK_SECONDS, 300);
    assert_eq!(MAX_CLOCK_FORWARD_SECONDS, 86_400);
    let wall = WALL_SECONDS;
    assert!(!clock_status(wall - 300, wall).anomaly);
    assert!(clock_status(wall - 301, wall).anomaly);
    assert!(!clock_status(wall + 86_400, wall).anomaly);
    assert!(clock_status(wall + 86_401, wall).anomaly);

    // Same four values at a transition, which is where the policy is enforced.
    // Each offer is built live at its own effective now, so the only thing that
    // can differ between the four cases is the clock verdict.
    let state = enabled_state();
    for (index, (offset, allowed)) in [(-300, true), (-301, false), (86_400, true), (86_401, false)]
        .into_iter()
        .enumerate()
    {
        let effective_ms = wall.max(wall + offset) * 1_000;
        let mut offer = offer_record([index as u8; 16], effective_ms + 600_000);
        offer.created_at_ms = effective_ms;
        assert_eq!(
            state.create_offer(offer, wall + offset).is_ok(),
            allowed,
            "offset {offset}"
        );
    }
}

/// Walks the durable wall forward the way a running agent would.
///
/// A pure state machine cannot advance its own clock between transitions, so a
/// test that needs a state ninety days older must take the steps. That is the
/// structural ceiling recorded in `spec/security-v1.md`, not a defect.
fn advance_wall(mut state: ReferenceState, seconds: i64) -> ReferenceState {
    let target = state.last_accepted_wall_unix_seconds() + seconds;
    while state.last_accepted_wall_unix_seconds() < target {
        let step =
            (state.last_accepted_wall_unix_seconds() + MAX_CLOCK_FORWARD_SECONDS).min(target);
        state = state.compact_terminals(step).unwrap();
    }
    state
}

#[test]
fn compaction_is_inert_until_the_runtime_reports_cleanup() {
    // F-3 and F-4 are one defect from two directions: nothing could set
    // `cleanup_complete`, so compaction never removed anything, which is what
    // kept its missing clock check invisible.
    let day = 24 * 60 * 60;
    let base = add_approved_grant(enabled_state(), [0xe0; 16], [0xe1; 16], [0xe2; 16]);
    let revoked = base.revoke_commit([0xe2; 16], NOW_MS).unwrap();
    assert_eq!(revoked.terminal.len(), 1);
    assert!(!revoked.terminal[0].cleanup_complete);

    // Ninety-one days of compaction attempts remove nothing while cleanup has
    // not been reported.
    let aged = advance_wall(revoked, 91 * day);
    assert_eq!(aged.terminal.len(), 1);

    let now = aged.last_accepted_wall_unix_seconds();
    let reported = aged.mark_cleanup_complete([0xe2; 16], now).unwrap();
    assert!(reported.terminal[0].cleanup_complete);
    let floor = reported.deny_floor;
    let epoch = reported.next_auth_epoch;
    let compacted = reported.compact_terminals(now).unwrap();
    assert!(compacted.terminal.is_empty());
    assert_eq!(compacted.deny_floor, floor);
    assert_eq!(compacted.next_auth_epoch, epoch);

    // Reported cleanup is not enough on its own: eighty-nine days stays.
    let base = add_approved_grant(enabled_state(), [0xe9; 16], [0xea; 16], [0xeb; 16]);
    let young = advance_wall(base.revoke_commit([0xeb; 16], NOW_MS).unwrap(), 89 * day);
    let now = young.last_accepted_wall_unix_seconds();
    let young = young.mark_cleanup_complete([0xeb; 16], now).unwrap();
    assert_eq!(young.compact_terminals(now).unwrap().terminal.len(), 1);
}

#[test]
fn compaction_and_cleanup_refuse_an_anomalous_clock() {
    let base = add_approved_grant(enabled_state(), [0xe3; 16], [0xe4; 16], [0xe5; 16]);
    let revoked = base.revoke_commit([0xe5; 16], NOW_MS).unwrap();
    let rolled_back = WALL_SECONDS - MAX_CLOCK_ROLLBACK_SECONDS - 1;
    assert_eq!(
        revoked.compact_terminals(rolled_back).unwrap_err(),
        SecurityError::Unauthorized
    );
    assert_eq!(
        revoked
            .mark_cleanup_complete([0xe5; 16], rolled_back)
            .unwrap_err(),
        SecurityError::Unauthorized
    );
    let jumped = WALL_SECONDS + MAX_CLOCK_FORWARD_SECONDS + 1;
    assert_eq!(
        revoked.compact_terminals(jumped).unwrap_err(),
        SecurityError::Unauthorized
    );
    assert_eq!(
        revoked
            .mark_cleanup_complete([0xe5; 16], jumped)
            .unwrap_err(),
        SecurityError::Unauthorized
    );
}

#[test]
fn cleanup_reports_need_an_existing_incomplete_terminal_record() {
    let base = add_approved_grant(enabled_state(), [0xe6; 16], [0xe7; 16], [0xe8; 16]);
    let revoked = base.revoke_commit([0xe8; 16], NOW_MS).unwrap();
    assert_eq!(
        revoked
            .mark_cleanup_complete([0xff; 16], WALL_SECONDS)
            .unwrap_err(),
        SecurityError::Invalid
    );
    let reported = revoked
        .mark_cleanup_complete([0xe8; 16], WALL_SECONDS)
        .unwrap();
    assert_eq!(
        reported
            .mark_cleanup_complete([0xe8; 16], WALL_SECONDS)
            .unwrap_err(),
        SecurityError::Invalid
    );
}

#[test]
fn a_claim_must_prove_possession_of_the_offer_secret() {
    let state = enabled_state()
        .create_offer(offer_record([0xf0; 16], NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    let mut wrong = claim_for([0xf0; 16], [0xf1; 16], INITIATOR_STATIC, 1);
    wrong.secret = [0x00; 32];
    assert_eq!(
        state.claim_offer(wrong, WALL_SECONDS).unwrap_err(),
        SecurityError::Unauthorized
    );
    // A wrong guess must not consume the offer, or one probe denies the real
    // initiator their pairing.
    assert_eq!(state.offers[0].state, OfferState::Active);
    assert!(state.pending.is_empty());

    let mut wrong_responder = claim_for([0xf0; 16], [0xf1; 16], INITIATOR_STATIC, 1);
    wrong_responder.responder_static = [0x00; 32];
    assert_eq!(
        state
            .claim_offer(wrong_responder, WALL_SECONDS)
            .unwrap_err(),
        SecurityError::Unauthorized
    );

    let (claimed, _, _) = state
        .claim_offer(
            claim_for([0xf0; 16], [0xf1; 16], INITIATOR_STATIC, 1),
            WALL_SECONDS,
        )
        .unwrap();
    assert_eq!(claimed.offers[0].state, OfferState::Consumed);
}

#[test]
fn a_terminal_pending_yields_neither_success_nor_generation() {
    let state = enabled_state()
        .create_offer(offer_record([0xf2; 16], NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    let (state, pending_id, generation) = state
        .claim_offer(
            claim_for([0xf2; 16], [0xf3; 16], INITIATOR_STATIC, 3),
            WALL_SECONDS,
        )
        .unwrap();
    // While awaiting approval, the same initiator retrying is idempotent.
    let (_, retry_id, retry_generation) = state
        .claim_offer(
            claim_for([0xf2; 16], [0xf4; 16], INITIATOR_STATIC, 9),
            WALL_SECONDS,
        )
        .unwrap();
    assert_eq!((retry_id, retry_generation), (pending_id, generation));

    for terminal in [
        state
            .reject_pending(pending_id, generation, NOW_MS)
            .unwrap(),
        state.expire_one(pending_id, NOW_MS + 600_001).unwrap(),
    ] {
        assert_eq!(
            terminal
                .claim_offer(
                    claim_for([0xf2; 16], [0xf4; 16], INITIATOR_STATIC, 9),
                    WALL_SECONDS,
                )
                .unwrap_err(),
            SecurityError::Unauthorized
        );
    }
}

#[test]
fn the_terminal_reserve_keeps_a_full_state_revocable() {
    // The 255/256 asymmetry is the reserve, not an inconsistency. Creation
    // stops one short; the paths that stop the bleeding never consult the
    // count at all, because a terminal record only leaves through compaction
    // and "cannot revoke" would then persist for months.
    let base = add_approved_grant(enabled_state(), [0x11; 16], [0x12; 16], [0x13; 16]);
    let with_pending = base
        .create_offer(offer_record([0x14; 16], NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    let (mut full, pending_id, generation) = with_pending
        .claim_offer(
            claim_for([0x14; 16], [0x15; 16], [0x44; 32], 2),
            WALL_SECONDS,
        )
        .unwrap();
    // Literals, not the constants: filling to `MAX_CREATION_RECORDS` would move
    // with the value under test and a widened cap would stay green.
    assert_eq!(MAX_CREATION_RECORDS, 255);
    assert_eq!(MAX_RECORDS, 256);
    let mut filler = 0_u32;
    while full.offers.len() + full.pending.len() + full.grants.len() + full.terminal.len() < 255 {
        let mut record_id = [0x80; 16];
        record_id[..4].copy_from_slice(&filler.to_be_bytes());
        full.terminal.push(Terminal {
            record_id,
            kind: TerminalKind::Offer,
            auth_epoch: 0,
            terminal_at_ms: NOW_MS,
            cleanup_complete: false,
        });
        filler += 1;
    }

    // One record below the reserve, creation still works: what follows is about
    // the count and nothing else.
    let mut one_short = full.clone();
    one_short.terminal.pop();
    let one_short = one_short
        .create_offer(offer_record([0x1c; 16], NOW_MS + 600_000), WALL_SECONDS)
        .unwrap();
    assert_eq!(
        one_short
            .claim_offer(
                claim_for([0x1c; 16], [0x1d; 16], [0x45; 32], 1),
                WALL_SECONDS
            )
            .unwrap_err(),
        SecurityError::Unauthorized
    );

    // Creation stops at the reserve.
    assert_eq!(
        full.create_offer(offer_record([0x16; 16], NOW_MS + 600_000), WALL_SECONDS)
            .unwrap_err(),
        SecurityError::Unauthorized
    );
    assert_eq!(
        full.approve_pending(
            approval_for(pending_id, generation, [0x17; 16], NOW_MS + 600_000),
            WALL_SECONDS,
        )
        .unwrap_err(),
        SecurityError::Unauthorized
    );

    // Stopping the bleeding does not.
    assert!(full.revoke_commit([0x13; 16], NOW_MS).is_ok());
    assert!(full.disable_commit([0x18; 16], NOW_MS).is_ok());
    assert!(full.uninstall_commit([0x19; 16], NOW_MS).is_ok());
    assert!(full.reject_pending(pending_id, generation, NOW_MS).is_ok());

    // And they still work past the cap, which is what the reserve is for.
    let mut over = full.clone();
    while over.offers.len() + over.pending.len() + over.grants.len() + over.terminal.len() <= 256 {
        let mut record_id = [0x90; 16];
        record_id[..4].copy_from_slice(&filler.to_be_bytes());
        over.terminal.push(Terminal {
            record_id,
            kind: TerminalKind::Offer,
            auth_epoch: 0,
            terminal_at_ms: NOW_MS,
            cleanup_complete: false,
        });
        filler += 1;
    }
    assert!(over.revoke_commit([0x13; 16], NOW_MS).is_ok());
    assert!(over.disable_commit([0x1a; 16], NOW_MS).is_ok());
    assert!(over.uninstall_commit([0x1b; 16], NOW_MS).is_ok());
    assert!(over.reject_pending(pending_id, generation, NOW_MS).is_ok());
}

#[test]
fn the_grant_state_record_has_exactly_the_frozen_field_set() {
    // Bound to the type, not to a second literal list: deleting a field from
    // `Grant` removes a key here and turns this red.
    let state = add_approved_grant(enabled_state(), [0x21; 16], [0x22; 16], [0x23; 16]);
    let encoded = CanonicalJsonV1::encode(&state.grants[0]).unwrap();
    let value = CanonicalJsonV1::decode_value(&encoded).unwrap();
    let keys: BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "authEpoch",
            "createdAt",
            "endpoints",
            "expiresAt",
            "grantId",
            "initiatorStatic",
            "responderStatic",
            "scope",
            "sourceScopeGeneration",
            "state",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    assert_eq!(value["grantId"], hex_encode(&[0x23; 16]));
    assert_eq!(value["initiatorStatic"], hex_encode(&INITIATOR_STATIC));
    assert_eq!(value["responderStatic"], hex_encode(&RESPONDER_STATIC));
    assert_eq!(value["scope"], CONSENT_SCOPE);
    assert_eq!(value["state"], "active");

    // Exhaustive: re-adding an intermediate revocation state fails to compile
    // here rather than quietly becoming unreachable.
    fn wire_name(state: GrantState) -> &'static str {
        match state {
            GrantState::Active => "active",
            GrantState::Revoked => "revoked",
            GrantState::Expired => "expired",
        }
    }
    for state in [GrantState::Active, GrantState::Revoked, GrantState::Expired] {
        assert_eq!(
            serde_json::to_value(state).unwrap(),
            Value::String(wire_name(state).into())
        );
    }
}

#[test]
fn pair_url_bounds_apply_to_their_own_object() {
    let offer = PairOffer {
        expires_at: NOW_MS + 600_000,
        host: "peer.example".into(),
        offer_id: "00".repeat(16),
        port: 49_152,
        responder_static: "11".repeat(32),
        secret: "22".repeat(32),
        version: 1,
    };
    let url = pair_url(&offer).unwrap();
    assert!(url.len() <= PAIR_URL_MAX);

    // Raw paste bound, checked before any parsing work.
    let oversize_paste = format!("{url}{}", "0".repeat(PAIR_URL_RAW_MAX));
    assert_eq!(
        parse_pair_url(&oversize_paste, NOW_MS).unwrap_err(),
        SecurityError::Bounds
    );
    // URL bound, checked once the grammar has identified a URL. This length is
    // under the raw bound and its payload is under the offer-JSON bound, so
    // only the URL bound can reject it.
    let hex_len = PAIR_URL_MAX - "syrtis://pair?offer=".len() + 2;
    let oversize_url = format!("syrtis://pair?offer={}", "0".repeat(hex_len));
    assert!(oversize_url.len() > PAIR_URL_MAX && oversize_url.len() <= PAIR_URL_RAW_MAX);
    assert!(hex_len / 2 <= PAIR_OFFER_JSON_MAX);
    assert_eq!(
        parse_pair_url(&oversize_url, NOW_MS).unwrap_err(),
        SecurityError::Bounds
    );

    // The control plane may not hand back a URL its own parser would reject.
    let long_url = format!("syrtis://pair?offer={}", "0".repeat(PAIR_URL_MAX));
    let response = CanonicalJsonV1::encode(&json!({
        "code": 0,
        "controlVersion": 1,
        "data": {"expiresAt": NOW_MS, "offerId": "55".repeat(16), "pairUrl": long_url},
        "requestId": hex_encode(&[0x40; 16])
    }))
    .unwrap();
    assert!(verify_control_response(&response, &[0x40; 16], 2, 0).is_err());
}

#[test]
fn consent_surface_and_privacy_registry() {
    let fixture = include_bytes!("fixtures/v1/security/consent.json");
    let fixture = fixture.strip_suffix(b"\n").unwrap_or(fixture);
    let consent = consent_registry();
    assert_eq!(CanonicalJsonV1::encode(&consent).unwrap(), fixture);
    assert_eq!(CanonicalJsonV1::decode_value(fixture).unwrap(), consent);
    for fields in [
        SHARED_FIELDS,
        PROTOCOL_FIELDS,
        LOCAL_ONLY_FIELDS,
        LOG_FIELDS,
        UI_FIELDS,
        FORBIDDEN_FIELDS,
    ] {
        assert!(
            fields
                .windows(2)
                .all(|window| window[0].as_bytes() < window[1].as_bytes())
        );
    }
    let shared_surfaces: &[&[&str]] = &[
        &[
            "cacheReadTokens",
            "cacheWriteTokens",
            "client",
            "costNanoUsd",
            "date",
            "inputTokens",
            "messageCount",
            "model",
            "outputTokens",
            "provider",
            "reasoningTokens",
            "totalTokens",
            "turnCount",
        ],
        &[
            "cacheReadTokens",
            "cacheWriteTokens",
            "client",
            "costNanoUsd",
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
        ],
        &[
            "bucketStartUnixMs",
            "cacheReadTokens",
            "cacheWriteTokens",
            "client",
            "costNanoUsd",
            "inputTokens",
            "messageCount",
            "model",
            "outputTokens",
            "provider",
            "reasoningTokens",
            "totalTokens",
            "turnCount",
            "utcOffsetSeconds",
        ],
        &[
            "agent",
            "cacheReadTokens",
            "cacheWriteTokens",
            "client",
            "costNanoUsd",
            "inputTokens",
            "messageCount",
            "model",
            "outputTokens",
            "provider",
            "reasoningTokens",
            "totalTokens",
            "turnCount",
        ],
    ];
    let protocol_surfaces: &[&[&str]] = &[
        &[
            "expiresAt",
            "host",
            "offerId",
            "port",
            "responderStatic",
            "secret",
            "version",
        ],
        &[
            "aggregationRevision",
            "authEpoch",
            "clients",
            "endDateExclusive",
            "endpoint",
            "grantId",
            "protocol",
            "reportSchema",
            "requestId",
            "sourceScopeGeneration",
            "startDate",
            "timezone",
            "tzdbRevision",
        ],
        &[
            "aggregationRevision",
            "authEpoch",
            "clients",
            "endDateExclusive",
            "endpoint",
            "grantId",
            "protocol",
            "records",
            "reportSchema",
            "requestId",
            "saturated",
            "sourceScopeGeneration",
            "startDate",
            "timezone",
            "tzdbRevision",
        ],
        &["body", "commandId", "controlVersion", "requestId"],
        &[
            "bindHost",
            "bindPort",
            "grantId",
            "offerId",
            "pendingId",
            "sasGeneration",
            "ttlSeconds",
        ],
        &["code", "controlVersion", "data", "requestId"],
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
        &["expiresAt", "offerId", "pairUrl"],
        &["expiresAt", "pendingId", "sasCode"],
    ];
    let local_surfaces: &[&[&str]] = &[
        &[
            "config",
            "controlToken",
            "counters",
            "grants",
            "identityPrivate",
            "offers",
            "pending",
            "schema",
            "terminal",
        ],
        &["bindHost", "bindPort", "nodeLabel", "sharingEnabled"],
        &[
            "denyFloor",
            "lastAcceptedWallUnixSeconds",
            "nextAuthEpoch",
            "sourceScopeGeneration",
        ],
        &["createdAt", "expiresAt", "offerId", "secretHash", "state"],
        &[
            "createdAt",
            "expiresAt",
            "initiatorStatic",
            "offerId",
            "pendingId",
            "sasCode",
            "sasGeneration",
            "state",
        ],
        &[
            "authEpoch",
            "createdAt",
            "endpoints",
            "expiresAt",
            "grantId",
            "initiatorStatic",
            "responderStatic",
            "scope",
            "sourceScopeGeneration",
            "state",
        ],
        &[
            "authEpoch",
            "cleanupComplete",
            "kind",
            "recordId",
            "terminalAt",
        ],
        &["peerStatic", "role"],
        &[
            "bodySha256",
            "cacheKey",
            "createdAtUnixMs",
            "expiresAtUnixMs",
        ],
    ];
    fn union<'a>(surfaces: &[&[&'a str]]) -> BTreeSet<&'a str> {
        surfaces
            .iter()
            .flat_map(|fields| fields.iter().copied())
            .collect::<BTreeSet<_>>()
    }
    assert_eq!(
        union(shared_surfaces),
        SHARED_FIELDS.iter().copied().collect()
    );
    assert_eq!(
        union(protocol_surfaces),
        PROTOCOL_FIELDS.iter().copied().collect()
    );
    assert_eq!(
        union(local_surfaces),
        LOCAL_ONLY_FIELDS.iter().copied().collect()
    );

    let forbidden: BTreeSet<&str> = FORBIDDEN_FIELDS.iter().copied().collect();
    for fields in shared_surfaces
        .iter()
        .chain(protocol_surfaces)
        .chain(local_surfaces)
        .chain([LOG_FIELDS, UI_FIELDS].iter())
    {
        assert!(fields.iter().all(|field| !forbidden.contains(field)));
    }
    assert!(
        protocol_surfaces[1..]
            .iter()
            .all(|fields| !fields.contains(&"secret"))
    );
    assert_eq!(consent["duplicateWarning"], true);
    assert_eq!(consent["transitiveSharing"], false);
}

#[test]
fn secure_root_remote_source_uninstall_and_memory_policies() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/v1/security/linux_roots.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let metadata = RootMetadata {
            absolute: case["absolute"].as_bool().unwrap(),
            local_filesystem: case["localFilesystem"].as_bool().unwrap(),
            owner_matches: case["ownerMatches"].as_bool().unwrap(),
            no_symlink_or_reparse: case["noSymlink"].as_bool().unwrap(),
            private_permissions: case["privatePermissions"].as_bool().unwrap(),
        };
        let result = resolve_secure_root(
            Platform::Linux,
            case["trustedHome"].as_str(),
            case["environmentHome"].as_str(),
            metadata,
        );
        assert_eq!(
            result.is_ok(),
            case["allowed"].as_bool().unwrap(),
            "{}",
            case["case"]
        );
    }
    let safe = RootMetadata {
        absolute: true,
        local_filesystem: true,
        owner_matches: true,
        no_symlink_or_reparse: true,
        private_permissions: true,
    };
    assert_eq!(
        resolve_secure_root(
            Platform::MacOs,
            Some("/Users/owner"),
            Some("/tmp/evil"),
            safe
        )
        .unwrap(),
        "/Users/owner/Library/Application Support/com.nyanako.syrtis.agent/"
    );
    assert_eq!(
        resolve_secure_root(
            Platform::Windows,
            Some("C:\\Users\\owner\\AppData\\Local"),
            Some("\\\\evil\\share"),
            safe,
        )
        .unwrap(),
        "C:\\Users\\owner\\AppData\\Local\\Nyanako\\Syrtis Agent\\"
    );
    assert!(resolve_secure_root(Platform::Windows, Some("\\\\evil\\share"), None, safe).is_err());
    for (platform, home) in [
        (Platform::MacOs, "/Users/owner"),
        (Platform::Linux, "/home/owner"),
        (Platform::Windows, "C:\\Users\\owner\\AppData\\Local"),
    ] {
        let objects = install_objects(platform, home).unwrap();
        assert_eq!(objects.command, vec![objects.binary.clone(), "run".into()]);
        assert!(!objects.uses_shell_or_path_search);
    }

    let policy = RemoteSourcePolicy::default();
    assert!(!policy.use_env_roots);
    let changed = policy
        .add_owner_approved_root("/trusted/custom".into())
        .unwrap();
    assert_eq!(changed.source_scope_generation, 2);
    assert!(changed.owner_reconsent_required);
    let source_fixture: Value =
        serde_json::from_str(include_str!("fixtures/v1/security/remote_source.json")).unwrap();
    assert_eq!(
        source_fixture["ignoredEnvironment"],
        json!(["TOKSCALE_EXTRA_DIRS", "HOME", "XDG_STATE_HOME"])
    );

    let installed = UninstallState {
        sharing_enabled: true,
        active_grants: 2,
        deny_floor: 0,
        next_auth_epoch: 3,
        listener_running: true,
        control_running: true,
        autostart_present: true,
        binary_present: true,
        cache_entries: 4,
        identity_present: true,
        manual_repair: false,
    };
    let removed = uninstall_reference(&installed, false, true).unwrap();
    assert!(!removed.sharing_enabled && !removed.listener_running && !removed.control_running);
    assert_eq!(removed.active_grants, 0);
    assert!(removed.identity_present && removed.deny_floor >= 2);
    let reinstalled = removed.clone();
    assert!(!reinstalled.sharing_enabled && reinstalled.active_grants == 0);
    let unsafe_removal = uninstall_reference(&installed, true, false).unwrap();
    assert!(unsafe_removal.manual_repair && unsafe_removal.identity_present);
    assert!(!unsafe_removal.sharing_enabled && unsafe_removal.active_grants == 0);
    let uninstall_fixture: Value =
        serde_json::from_str(include_str!("fixtures/v1/security/uninstall.json")).unwrap();
    assert_eq!(uninstall_fixture["defaultPreservesIdentity"], true);
    assert_eq!(uninstall_fixture["unsafeKeepsDeny"], true);

    assert_eq!(charged_capacity::<u64>(3, 1, 8), Some(32));
    assert_eq!(charged_capacity::<u64>(usize::MAX, 0, 8), None);
    let ledger = MemoryLedger::default();
    {
        let _first = ledger.reserve(REMOTE_MEMORY_MAX - 1).unwrap();
        assert!(ledger.reserve(2).is_none());
        assert_eq!(ledger.used(), REMOTE_MEMORY_MAX - 1);
    }
    assert_eq!(ledger.used(), 0);
    let memory_fixture: Value =
        serde_json::from_str(include_str!("fixtures/v1/security/memory_budget.json")).unwrap();
    assert_eq!(memory_fixture["hardBytes"], REMOTE_MEMORY_MAX);
    assert_eq!(memory_fixture["allocationOrder"], "reserveBeforeAllocate");
}

#[test]
fn tzdb_and_dependency_provenance_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/v1/security/provenance.json")).unwrap();
    assert_eq!(fixture["tzdb"]["revision"], TZDB_REVISION);
    assert_eq!(fixture["tzdb"]["sha256"], TZDB_SHA256);
    assert_eq!(fixture["snow"]["version"], "0.10.0");
    assert_eq!(
        fixture["snow"]["checksum"],
        "599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82"
    );
    assert_eq!(
        fixture["unicodeNormalization"]["checksum"],
        "5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8"
    );
}
