//! Noise IK transport for the peer wire (`spec/pairing-v1.md`).
//!
//! One TCP connection carries one `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! handshake with empty payloads, then one request frame and one reply
//! frame. Handshake messages are length-prefixed with their exact IK
//! lengths; transport messages use the frozen outer length prefix
//! (`security::encode_outer` / `decode_outer`). Every read and write runs
//! against an absolute monotonic deadline that partial progress never
//! extends.

use std::{
    fmt,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

use crate::{
    secure_fs::StorageError,
    security::{
        FRAME_CIPHERTEXT_MAX, Frame, MemoryLedger, MemoryReservation, NOISE_PROLOGUE, NOISE_SUITE,
        decode_outer, encode_outer,
    },
    state_store::{Secret32, StoredState},
};

/// IK message 1 with an empty payload: `e` (32) + encrypted `s` (48) + tag (16).
pub const MESSAGE1_LEN: usize = 96;
/// IK message 2 with an empty payload: `e` (32) + tag (16).
pub const MESSAGE2_LEN: usize = 48;
const TAG_LEN: usize = 16;

/// Connect plus handshake, on both sides.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESPONDER_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESPONDER_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
pub const INITIATOR_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const INITIATOR_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Transport failures. They carry no peer bytes, OS error text or key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseError {
    /// Connect, read or write failed, or the peer closed.
    Io,
    /// The absolute deadline passed.
    Timeout,
    /// A handshake length prefix was not the exact message length, or a
    /// transport length prefix exceeded the frozen ciphertext maximum.
    Framing,
    /// Handshake or transport authentication failed.
    Crypto,
    /// A handshake message decrypted to a non-empty payload.
    Payload,
    /// The memory ledger refused the reservation for the declared length.
    Memory,
    /// The decrypted plaintext is not a valid frame.
    Frame,
    /// The CSPRNG or a Noise primitive is unavailable.
    Unavailable,
}

/// An absolute point on the monotonic clock.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn after(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }

    fn remaining(self) -> Result<Duration, NoiseError> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(NoiseError::Timeout)
        } else {
            Ok(left)
        }
    }
}

/// A static X25519 key pair. `Debug` never shows the private half.
#[derive(Clone, Debug)]
pub struct StaticKey {
    private: Secret32,
    public: [u8; 32],
}

impl StaticKey {
    /// A fresh key pair from the Noise CSPRNG.
    pub fn generate() -> Result<Self, NoiseError> {
        let pair = Builder::new(params()?)
            .generate_keypair()
            .map_err(|_| NoiseError::Unavailable)?;
        Ok(Self {
            private: Secret32::new(
                pair.private
                    .as_slice()
                    .try_into()
                    .map_err(|_| NoiseError::Unavailable)?,
            ),
            public: pair
                .public
                .as_slice()
                .try_into()
                .map_err(|_| NoiseError::Unavailable)?,
        })
    }

    /// The agent identity held in the durable state.
    pub fn from_state(state: &StoredState) -> Result<Self, StorageError> {
        Ok(Self {
            private: state.identity_private.clone(),
            public: state.identity_public()?,
        })
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// A completed handshake: the transport keys, `hFinal` and the peer's
/// authenticated static key.
pub struct Session {
    stream: TcpStream,
    transport: TransportState,
    h_final: [u8; 32],
    remote_static: [u8; 32],
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Session(redacted)")
    }
}

/// One received frame and the ledger reservation that paid for it. The
/// reservation is returned when this is dropped.
pub struct Received {
    frame: Frame,
    _reservation: MemoryReservation,
}

impl Received {
    /// Borrowed only: moving the frame out would outlive its reservation.
    pub fn frame(&self) -> &Frame {
        &self.frame
    }
}

/// Redacted: a request frame's payload can carry the Pair bearer secret.
impl fmt::Debug for Received {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Received(redacted)")
    }
}

/// Initiator: connects and runs IK with `remote_static` pinned, all within
/// one [`HANDSHAKE_TIMEOUT`]. Name resolution (`getaddrinfo`) runs first and
/// is not bounded by that deadline: std offers no way to bound it. Once a
/// TCP connection is up, a handshake failure ends the call: no other
/// address is tried.
pub fn connect(
    host: &str,
    port: u16,
    local: &StaticKey,
    remote_static: &[u8; 32],
) -> Result<Session, NoiseError> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| NoiseError::Io)?
        .collect();
    let deadline = Deadline::after(HANDSHAKE_TIMEOUT);
    let mut stream = connect_addrs(&addresses, deadline, TcpStream::connect_timeout)?;
    let mut state = Builder::new(params()?)
        .local_private_key(local.private.expose())
        .and_then(|builder| builder.remote_public_key(remote_static))
        .and_then(|builder| builder.prologue(NOISE_PROLOGUE))
        .and_then(Builder::build_initiator)
        .map_err(|_| NoiseError::Unavailable)?;
    let mut message1 = [0; MESSAGE1_LEN];
    if state.write_message(&[], &mut message1) != Ok(MESSAGE1_LEN) {
        return Err(NoiseError::Crypto);
    }
    write_handshake(&mut stream, &message1, deadline)?;
    let message2 = read_handshake::<MESSAGE2_LEN>(&mut stream, deadline)?;
    read_handshake_payload(&mut state, &message2)?;
    finish(stream, state)
}

/// Responder: runs IK on an accepted stream within one [`HANDSHAKE_TIMEOUT`].
/// Touches no agent state: the identity is passed in.
pub fn accept(mut stream: TcpStream, local: &StaticKey) -> Result<Session, NoiseError> {
    let deadline = Deadline::after(HANDSHAKE_TIMEOUT);
    // An accepted stream may inherit non-blocking mode from its listener
    // (OS-dependent); the deadline loops would then spin on `WouldBlock`.
    stream.set_nonblocking(false).map_err(|_| NoiseError::Io)?;
    let mut state = Builder::new(params()?)
        .local_private_key(local.private.expose())
        .and_then(|builder| builder.prologue(NOISE_PROLOGUE))
        .and_then(Builder::build_responder)
        .map_err(|_| NoiseError::Unavailable)?;
    let message1 = read_handshake::<MESSAGE1_LEN>(&mut stream, deadline)?;
    read_handshake_payload(&mut state, &message1)?;
    let mut message2 = [0; MESSAGE2_LEN];
    if state.write_message(&[], &mut message2) != Ok(MESSAGE2_LEN) {
        return Err(NoiseError::Crypto);
    }
    write_handshake(&mut stream, &message2, deadline)?;
    finish(stream, state)
}

impl Session {
    pub fn h_final(&self) -> &[u8; 32] {
        &self.h_final
    }

    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    /// Encrypts one frame and writes `u32be(len) || ciphertext`.
    pub fn send(&mut self, frame: &Frame, deadline: Deadline) -> Result<(), NoiseError> {
        let plaintext = frame.encode().map_err(|_| NoiseError::Frame)?;
        let mut ciphertext = vec![0; plaintext.len() + TAG_LEN];
        let length = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|_| NoiseError::Crypto)?;
        ciphertext.truncate(length);
        let outer = encode_outer(&ciphertext).map_err(|_| NoiseError::Framing)?;
        write_all(&mut self.stream, &outer, deadline)
    }

    /// Reads one transport message. The declared length is checked against
    /// the frozen maximum, then 3x that length (ciphertext, plaintext and
    /// the decoded payload copy) is reserved on `ledger`, and only then is
    /// anything allocated or read.
    pub fn receive(
        &mut self,
        ledger: &MemoryLedger,
        deadline: Deadline,
    ) -> Result<Received, NoiseError> {
        let mut prefix = [0; 4];
        read_exact(&mut self.stream, &mut prefix, deadline)?;
        let declared = u32::from_be_bytes(prefix) as usize;
        if declared > FRAME_CIPHERTEXT_MAX {
            return Err(NoiseError::Framing);
        }
        let reservation = ledger
            .reserve(declared.checked_mul(3).ok_or(NoiseError::Framing)?)
            .ok_or(NoiseError::Memory)?;
        let mut outer = vec![0; 4 + declared];
        outer[..4].copy_from_slice(&prefix);
        read_exact(&mut self.stream, &mut outer[4..], deadline)?;
        let ciphertext = decode_outer(&outer).map_err(|_| NoiseError::Framing)?;
        let mut plaintext = vec![0; ciphertext.len()];
        let length = self
            .transport
            .read_message(ciphertext, &mut plaintext)
            .map_err(|_| NoiseError::Crypto)?;
        plaintext.truncate(length);
        let frame = Frame::decode(&plaintext).map_err(|_| NoiseError::Frame)?;
        Ok(Received {
            frame,
            _reservation: reservation,
        })
    }
}

/// Tries each resolved address in order, all under one absolute deadline.
/// Each address gets the time left divided by the addresses not yet tried,
/// so an unresponsive first address cannot take the whole deadline.
fn connect_addrs(
    addresses: &[SocketAddr],
    deadline: Deadline,
    mut connect: impl FnMut(&SocketAddr, Duration) -> std::io::Result<TcpStream>,
) -> Result<TcpStream, NoiseError> {
    for (index, address) in addresses.iter().enumerate() {
        let untried = u32::try_from(addresses.len() - index).unwrap_or(u32::MAX);
        if let Ok(stream) = connect(address, deadline.remaining()? / untried) {
            return Ok(stream);
        }
    }
    Err(NoiseError::Io)
}

fn params() -> Result<NoiseParams, NoiseError> {
    NOISE_SUITE.parse().map_err(|_| NoiseError::Unavailable)
}

/// Reads one handshake message and refuses a non-empty payload.
///
/// Under exact framing a payload cannot arrive (the message length leaves
/// room only for the tag), so this check is defense in depth; its unit test
/// feeds a longer message here directly, bypassing the framing.
pub(crate) fn read_handshake_payload(
    state: &mut HandshakeState,
    message: &[u8],
) -> Result<(), NoiseError> {
    let mut payload = vec![0; message.len()];
    let length = state
        .read_message(message, &mut payload)
        .map_err(|_| NoiseError::Crypto)?;
    if length != 0 {
        return Err(NoiseError::Payload);
    }
    Ok(())
}

fn finish(stream: TcpStream, state: HandshakeState) -> Result<Session, NoiseError> {
    let h_final = state
        .get_handshake_hash()
        .try_into()
        .map_err(|_| NoiseError::Crypto)?;
    let remote_static = state
        .get_remote_static()
        .and_then(|key| key.try_into().ok())
        .ok_or(NoiseError::Crypto)?;
    let transport = state
        .into_transport_mode()
        .map_err(|_| NoiseError::Crypto)?;
    Ok(Session {
        stream,
        transport,
        h_final,
        remote_static,
    })
}

/// `u32be(N) || message`. A prefix other than `N` closes the connection
/// before any body byte is read.
fn read_handshake<const N: usize>(
    stream: &mut TcpStream,
    deadline: Deadline,
) -> Result<[u8; N], NoiseError> {
    let mut prefix = [0; 4];
    read_exact(stream, &mut prefix, deadline)?;
    if u32::from_be_bytes(prefix) as usize != N {
        return Err(NoiseError::Framing);
    }
    let mut message = [0; N];
    read_exact(stream, &mut message, deadline)?;
    Ok(message)
}

fn write_handshake(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Deadline,
) -> Result<(), NoiseError> {
    let mut bytes = (message.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(message);
    write_all(stream, &bytes, deadline)
}

/// Each system call gets the time left until `deadline`, so a peer that
/// trickles bytes cannot extend it.
fn read_exact(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Deadline,
) -> Result<(), NoiseError> {
    let mut filled = 0;
    while filled < buffer.len() {
        stream
            .set_read_timeout(Some(deadline.remaining()?))
            .map_err(|_| NoiseError::Io)?;
        #[cfg(test)]
        tests::READ_CALLS.with(|calls| calls.set(calls.get() + 1));
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(NoiseError::Io),
            Ok(read) => filled += read,
            Err(error) if retry(error.kind()) => {}
            Err(_) => return Err(NoiseError::Io),
        }
    }
    Ok(())
}

fn write_all(stream: &mut TcpStream, bytes: &[u8], deadline: Deadline) -> Result<(), NoiseError> {
    let mut written = 0;
    while written < bytes.len() {
        stream
            .set_write_timeout(Some(deadline.remaining()?))
            .map_err(|_| NoiseError::Io)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(NoiseError::Io),
            Ok(count) => written += count,
            Err(error) if retry(error.kind()) => {}
            Err(_) => return Err(NoiseError::Io),
        }
    }
    Ok(())
}

/// A timed-out or interrupted call loops back to the deadline check.
fn retry(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, net::TcpListener};

    use super::*;

    thread_local! {
        /// `read` system calls made by `read_exact` on this thread.
        pub(super) static READ_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// B1: `accept` on a stream left in non-blocking mode puts it back in
    /// blocking mode, so the handshake read waits for the peer instead of
    /// spinning on `WouldBlock` until the deadline. The peer sends a bad
    /// prefix after 300 ms; a blocking read gets it in one call.
    #[test]
    fn accept_reads_a_non_blocking_stream_in_blocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            stream.write_all(&97_u32.to_be_bytes()).unwrap();
            let _ = stream.read_to_end(&mut Vec::new());
        });
        let (stream, _) = listener.accept().unwrap();
        // Set explicitly: inheritance from the listener differs by OS.
        stream.set_nonblocking(true).unwrap();
        READ_CALLS.with(|calls| calls.set(0));
        let key = StaticKey::generate().unwrap();
        assert_eq!(accept(stream, &key).err(), Some(NoiseError::Framing));
        let reads = READ_CALLS.with(Cell::get);
        peer.join().unwrap();
        assert!(reads <= 4, "{reads} reads: the handshake read spun");
    }

    /// B3: a refused first address does not end the connect; the next
    /// resolved address is tried under the same deadline.
    #[test]
    fn connect_tries_every_resolved_address() {
        // Both bound at once, so the two ports differ (C7); then one closes.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = closed.local_addr().unwrap();
        let open = listener.local_addr().unwrap();
        drop(closed);
        let deadline = || Deadline::after(HANDSHAKE_TIMEOUT);
        let stream =
            connect_addrs(&[refused, open], deadline(), TcpStream::connect_timeout).unwrap();
        assert_eq!(stream.peer_addr().unwrap(), open);
        // Control: the refused address alone fails.
        assert_eq!(
            connect_addrs(&[refused], deadline(), TcpStream::connect_timeout).err(),
            Some(NoiseError::Io)
        );
    }

    /// C3: each address gets the time left divided by the addresses not yet
    /// tried. Four addresses that each hang for their whole budget all get
    /// tried within one deadline; handing the first one everything left
    /// would end the call after one try.
    #[test]
    fn connect_splits_the_deadline_across_the_addresses() {
        let addresses: Vec<SocketAddr> = (1..=4)
            .map(|n| SocketAddr::from(([127, 0, 0, 1], n)))
            .collect();
        let total = Duration::from_secs(1);
        let mut budgets = Vec::new();
        let result = connect_addrs(&addresses, Deadline::after(total), |_, budget| {
            budgets.push(budget);
            std::thread::sleep(budget);
            Err(std::io::ErrorKind::TimedOut.into())
        });
        assert_eq!(result.err(), Some(NoiseError::Io));
        assert_eq!(budgets.len(), 4, "{budgets:?}");
        assert!(budgets[0] <= total / 4, "{budgets:?}");
        assert!(
            budgets.iter().all(|budget| !budget.is_zero()),
            "{budgets:?}"
        );
    }

    fn pair() -> (HandshakeState, HandshakeState, StaticKey) {
        let initiator = StaticKey::generate().unwrap();
        let responder = StaticKey::generate().unwrap();
        let build = |key: &StaticKey, remote: Option<&[u8; 32]>| {
            let builder = Builder::new(params().unwrap())
                .local_private_key(key.private.expose())
                .unwrap()
                .prologue(NOISE_PROLOGUE)
                .unwrap();
            match remote {
                Some(remote) => builder
                    .remote_public_key(remote)
                    .unwrap()
                    .build_initiator()
                    .unwrap(),
                None => builder.build_responder().unwrap(),
            }
        };
        (
            build(&initiator, Some(&responder.public)),
            build(&responder, None),
            initiator,
        )
    }

    /// Acceptance (8), the part exact framing makes unreachable on the wire:
    /// a message 1 or 2 that decrypts to a payload is refused by the read
    /// helper itself, fed here without the length framing.
    #[test]
    fn a_handshake_message_with_a_payload_is_refused_by_the_read_helper() {
        // Message 1 carrying one payload byte.
        let (mut initiator, mut responder, _) = pair();
        let mut message = [0; MESSAGE1_LEN + 1];
        assert_eq!(
            initiator.write_message(&[0x42], &mut message),
            Ok(MESSAGE1_LEN + 1)
        );
        assert_eq!(
            read_handshake_payload(&mut responder, &message),
            Err(NoiseError::Payload)
        );

        // Message 2 carrying one payload byte.
        let (mut initiator, mut responder, _) = pair();
        let mut message1 = [0; MESSAGE1_LEN];
        initiator.write_message(&[], &mut message1).unwrap();
        read_handshake_payload(&mut responder, &message1).unwrap();
        let mut message2 = [0; MESSAGE2_LEN + 1];
        assert_eq!(
            responder.write_message(&[0x42], &mut message2),
            Ok(MESSAGE2_LEN + 1)
        );
        assert_eq!(
            read_handshake_payload(&mut initiator, &message2),
            Err(NoiseError::Payload)
        );

        // Control: the same flow with empty payloads completes, and the
        // responder learns the initiator's static key.
        let (mut initiator, mut responder, initiator_key) = pair();
        let mut message1 = [0; MESSAGE1_LEN];
        initiator.write_message(&[], &mut message1).unwrap();
        read_handshake_payload(&mut responder, &message1).unwrap();
        let mut message2 = [0; MESSAGE2_LEN];
        responder.write_message(&[], &mut message2).unwrap();
        read_handshake_payload(&mut initiator, &message2).unwrap();
        assert_eq!(
            responder.get_remote_static(),
            Some(&initiator_key.public[..])
        );
        assert_eq!(
            initiator.get_handshake_hash(),
            responder.get_handshake_hash()
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = StaticKey::generate().unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains("Secret32(redacted)"));
        assert!(!shown.contains(&crate::security::hex_encode(key.private.expose())));
        assert!(!shown.contains(&format!("{:?}", key.private.expose())));
    }
}
