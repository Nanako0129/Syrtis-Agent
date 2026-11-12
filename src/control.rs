//! Local control (`spec/control-v1.md`): the agent's Unix domain socket
//! server and its client, one mutually proven command per connection.
//!
//! All cryptography is the frozen `control_*` functions of
//! `src/security.rs`; command and response shapes are the frozen envelopes
//! of `spec/v1.md`, checked by `verify_control_command` and
//! `verify_control_response`. Every state change goes through
//! [`StateStore`] or [`crate::pairing::approve`]. macOS and Linux only;
//! every other platform fails closed with [`ControlError::Unsupported`],
//! like `secure_fs`. Writes no log.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde_json::Value;

use crate::{
    pairing::Clock,
    secure_fs::StorageError,
    state_store::{Secret32, StateStore},
};

/// The socket's name inside the secure root.
pub const SOCKET_NAME: &str = "control.sock";
/// Connections served at once, from accept until close.
pub const PRE_AUTH_CONNECTIONS: usize = 4;
/// Heap bytes all pre-auth connections may hold together.
pub const PRE_AUTH_MEMORY_MAX: usize = 64 * 1024;
/// Largest command JSON a client may send.
pub const COMMAND_JSON_MAX: usize = 4_096;
/// Largest response JSON a client accepts (the control body budget).
pub const RESPONSE_JSON_MAX: usize = 65_536;
/// Each server phase (hello, command, response write) has this absolute
/// monotonic deadline.
pub const PHASE_DEADLINE: Duration = Duration::from_secs(2);
/// One absolute deadline for a whole client call.
pub const CLIENT_DEADLINE: Duration = Duration::from_secs(10);

// Command IDs (`spec/v1.md`, "Control bodies and results").
pub const STATUS: u16 = 1;
pub const OFFER_CREATE: u16 = 2;
pub const OFFER_CANCEL: u16 = 3;
pub const PENDING_LIST: u16 = 4;
pub const APPROVE: u16 = 5;
pub const REJECT: u16 = 6;
pub const REVOKE: u16 = 7;
pub const LISTEN_CONFIGURE: u16 = 8;
pub const SHUTDOWN: u16 = 9;
pub const SHARING_SET: u16 = 10;
pub const SCOPE_APPROVE: u16 = 11;

// Result codes.
pub const OK: u16 = 0;
pub const INVALID: u16 = 1;
pub const UNAUTHORIZED: u16 = 2;
pub const EXPIRED: u16 = 3;
pub const BUSY: u16 = 5;
pub const UNSAFE_STATE: u16 = 7;
pub const INTERNAL: u16 = 8;

/// Why a server did not start or a call failed. Carries no path, OS error,
/// token, Pair URL or peer bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    /// No local control on this platform.
    Unsupported,
    /// The socket path does not fit `sun_path`.
    PathTooLong,
    /// `control.sock` is something other than this UID's socket, or the
    /// bound socket failed its post-bind check. Left in place.
    UnsafeSocket,
    /// Bind, connect, a read or write, a deadline, or an early close,
    /// before the whole command was written. For a client call: the
    /// command did not run.
    Socket,
    /// The whole command was written, then the reply did not arrive (a
    /// deadline, an early close, a read error). The command may have run
    /// (`SA-2C2b` review).
    NoReply,
    /// The CSPRNG is unavailable.
    Unavailable,
    /// The command could not be encoded, or is over [`COMMAND_JSON_MAX`].
    Command,
    /// The server proof did not verify. No command byte was sent.
    ServerProof,
    /// The response failed its MAC, bound or the frozen validator.
    Response,
}

/// One command: its ID and its body, sent as given. The server checks the
/// body with the frozen validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub id: u16,
    pub body: Value,
}

/// A verified response. `Debug` omits `data`, which for `offerCreate`
/// holds the Pair URL.
#[derive(Clone, Eq, PartialEq)]
pub struct Response {
    pub code: u16,
    pub data: Value,
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Response {{ code: {}, .. }}", self.code)
    }
}

/// Called on the serving thread after an authenticated `shutdown` was
/// answered `ok`. It must not stop the server synchronously: stopping
/// joins that same thread.
pub type ShutdownHook = Arc<dyn Fn() + Send + Sync>;

/// Called on the serving thread after `listenConfigure` committed, before
/// the reply is written. The runtime restarts the peer listener here
/// (`spec/runtime-v1.md`). Like [`ShutdownHook`], it must not stop the
/// server.
pub type ListenHook = Arc<dyn Fn() + Send + Sync>;

/// `scanStatus` of `status` (`spec/v1.md`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScanState {
    #[default]
    Never,
    Ok,
    Error,
}

/// The scan fields of `status`. The default is what a runtime without a
/// scanning source reports: `null`, `never`, `[]`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanStatus {
    /// `lastScanAt`: Unix seconds of the last successful scan.
    pub last_scan_at: Option<i64>,
    pub state: ScanState,
    /// `sourceFamilies`; `status` sorts, deduplicates and keeps the first
    /// 128 (the frozen bound), whatever the provider returns.
    pub families: Vec<String>,
}

/// Supplies the scan fields of each `status` reply. Runs on the serving
/// thread; it must not block on the store.
pub type ScanHook = Arc<dyn Fn() -> ScanStatus + Send + Sync>;

/// Supplies `scopeApproved` of each `status` reply (`SA-0G`), given the
/// server's store. Runs on the serving thread. It may read the store and
/// the scope record (`Agent`'s provider does), so `scopeApproved` and the
/// other `status` fields are not guaranteed to come from one snapshot.
/// Without one, `false`.
pub type ScopeHook = Arc<dyn Fn(&StateStore) -> bool + Send + Sync>;

/// Runs `sharingSet{enabled}` (`SA-2C2b`): the runtime passes its enable
/// gate and F-7 disable (`spec/runtime-v1.md`). Runs on the serving thread;
/// like [`ShutdownHook`], it must not stop the server. Its error is mapped
/// like every store error. Without one, `sharingSet` is `internal`.
pub type SharingHook = Arc<dyn Fn(bool) -> Result<(), StorageError> + Send + Sync>;

/// Runs `scopeApprove{ownerInputsSha256}` (`SA-2C2b`) with the server's
/// store and the body's digest: `Agent` compares the digest with its
/// running source's and calls its scope approval. A refusal is
/// `Refused(_)`, mapped to `invalid`. Runs on the serving thread; it must
/// not stop the server. Without one, `scopeApprove` is `internal`.
pub type ScopeApproveHook =
    Arc<dyn Fn(&StateStore, &str) -> Result<(), StorageError> + Send + Sync>;

/// Every hook a server runs. [`Server::start`] and the other constructors
/// fill what they do not take with the defaults stated on each.
pub struct Hooks {
    pub on_shutdown: ShutdownHook,
    pub on_listen_configured: ListenHook,
    pub scan: ScanHook,
    pub scope: ScopeHook,
    pub sharing: Option<SharingHook>,
    pub scope_approve: Option<ScopeApproveHook>,
}

/// The control client: the token and the socket path.
pub struct Client {
    token: Secret32,
    path: PathBuf,
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Client { .. }")
    }
}

impl Client {
    pub fn new(token: Secret32, path: PathBuf) -> Self {
        Self { token, path }
    }

    /// One command on a new connection. Sends no command byte before the
    /// server proof verifies; returns a response only after its MAC and the
    /// frozen `verify_control_response` (request ID, code, and the success
    /// data shape for `command.id`) pass. A call refused before the server
    /// proof (for example, all [`PRE_AUTH_CONNECTIONS`] busy) is
    /// [`ControlError::Socket`]; the caller may retry. Once the whole
    /// command is written, a missing reply is [`ControlError::NoReply`] and
    /// a reply that fails its checks is [`ControlError::Response`]: the
    /// command may have run.
    pub fn call(&self, command: &Command) -> Result<Response, ControlError> {
        imp::call(self, command)
    }
}

/// The running control server. Dropping it stops it.
pub struct Server(imp::Server);

impl fmt::Debug for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Server { .. }")
    }
}

impl Server {
    /// Binds `control.sock` in the store's secure root and starts
    /// accepting. `clock` supplies the OS wall clock for transitions.
    pub fn start(
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        on_shutdown: ShutdownHook,
    ) -> Result<Self, ControlError> {
        Self::start_with_listen_hook(store, clock, on_shutdown, Arc::new(|| {}))
    }

    /// [`start`](Self::start), plus `on_listen_configured`, called after
    /// each committed `listenConfigure`. The scan fields of `status` are the
    /// [`ScanStatus`] default.
    pub fn start_with_listen_hook(
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        on_shutdown: ShutdownHook,
        on_listen_configured: ListenHook,
    ) -> Result<Self, ControlError> {
        Self::start_with_hooks(
            store,
            clock,
            on_shutdown,
            on_listen_configured,
            Arc::new(ScanStatus::default),
        )
    }

    /// [`start_with_listen_hook`](Self::start_with_listen_hook), plus
    /// `scan`, which supplies the scan fields of every `status` reply.
    pub fn start_with_hooks(
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        on_shutdown: ShutdownHook,
        on_listen_configured: ListenHook,
        scan: ScanHook,
    ) -> Result<Self, ControlError> {
        Self::start_with_scope_hook(
            store,
            clock,
            on_shutdown,
            on_listen_configured,
            scan,
            Arc::new(|_| false),
        )
    }

    /// [`start_with_hooks`](Self::start_with_hooks), plus `scope`, which
    /// supplies `scopeApproved` of every `status` reply.
    pub fn start_with_scope_hook(
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        on_shutdown: ShutdownHook,
        on_listen_configured: ListenHook,
        scan: ScanHook,
        scope: ScopeHook,
    ) -> Result<Self, ControlError> {
        Self::start_with_all_hooks(
            store,
            clock,
            Hooks {
                on_shutdown,
                on_listen_configured,
                scan,
                scope,
                sharing: None,
                scope_approve: None,
            },
        )
    }

    /// Every hook, including the `sharingSet` and `scopeApprove` effects
    /// (`SA-2C2b`).
    pub fn start_with_all_hooks(
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        hooks: Hooks,
    ) -> Result<Self, ControlError> {
        imp::Server::start(store, clock, hooks).map(Self)
    }

    pub fn socket_path(&self) -> &Path {
        self.0.socket_path()
    }

    /// Bytes the pre-auth ledger holds now.
    pub fn pre_auth_memory_used(&self) -> usize {
        self.0.pre_auth_memory_used()
    }

    /// Stops accepting, shuts every connection down and joins every
    /// thread. Idempotent. The socket file stays; the next start replaces it.
    pub fn stop(&mut self) {
        self.0.stop();
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use std::convert::Infallible;

    use super::*;

    pub(super) struct Server(Infallible);

    impl Server {
        pub(super) fn start(
            _: Arc<StateStore>,
            _: Arc<dyn Clock>,
            _: Hooks,
        ) -> Result<Self, ControlError> {
            Err(ControlError::Unsupported)
        }

        pub(super) fn socket_path(&self) -> &Path {
            match self.0 {}
        }

        pub(super) fn pre_auth_memory_used(&self) -> usize {
            match self.0 {}
        }

        pub(super) fn stop(&mut self) {
            match self.0 {}
        }
    }

    pub(super) fn call(client: &Client, _: &Command) -> Result<Response, ControlError> {
        // Fails closed; the fields are read only on macOS and Linux.
        let _ = (&client.token, &client.path);
        Err(ControlError::Unsupported)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod imp {
    use std::{
        collections::HashMap,
        fs,
        io::{self, ErrorKind, Read, Write},
        net::Shutdown,
        os::{
            fd::AsRawFd,
            unix::{
                fs::{FileTypeExt, MetadataExt, PermissionsExt},
                net::{SocketAddr, UnixListener, UnixStream},
            },
        },
        sync::{
            Mutex, MutexGuard, PoisonError,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
        time::Instant,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        canonical::CanonicalJsonV1,
        listener::bind_address,
        pairing,
        secure_fs::StorageError,
        security::{
            CONTROL_VERSION, GrantState, Offer, OfferState, PEER_PROTOCOL_VERSION, PairOffer,
            Pending, PendingState, ReferenceState, SecurityError, clock_status,
            control_command_mac, control_key, control_response_mac, control_server_mac,
            decode_fixed_hex, hex_encode, offer_secret_hash, pair_url, verify_control_command,
            verify_control_response, verify_mac,
        },
        state_store::{StoredState, random},
    };

    // ponytail: polling accept like the peer listener; poll(2) if idle
    // wakeups ever matter.
    const ACCEPT_POLL: Duration = Duration::from_millis(50);
    const HELLO_LEN: usize = 2 + 32;
    const PROOF_LEN: usize = 32 + 32;
    const COMMAND_HEADER_LEN: usize = 16 + 2 + 4;
    const RESPONSE_HEADER_LEN: usize = 2 + 4;
    const MAC_LEN: usize = 32;

    /// What every connection thread shares.
    struct Shared {
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        on_shutdown: ShutdownHook,
        on_listen_configured: ListenHook,
        scan: ScanHook,
        scope: ScopeHook,
        sharing: Option<SharingHook>,
        scope_approve: Option<ScopeApproveHook>,
        /// The pre-auth memory ledger, in bytes.
        memory: AtomicUsize,
        /// A `try_clone` of each connection, so `stop` can shut it down;
        /// its size is the number of slots taken.
        live: Mutex<HashMap<u64, UnixStream>>,
        /// Test-only: the peer UID the owner check sees instead of the
        /// kernel's answer. No such field exists outside test builds.
        #[cfg(test)]
        peer_uid: Option<libc::uid_t>,
    }

    pub(super) struct Server {
        path: PathBuf,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        accept: Option<JoinHandle<()>>,
    }

    impl Server {
        pub(super) fn start(
            store: Arc<StateStore>,
            clock: Arc<dyn Clock>,
            hooks: Hooks,
        ) -> Result<Self, ControlError> {
            let Hooks {
                on_shutdown,
                on_listen_configured,
                scan,
                scope,
                sharing,
                scope_approve,
            } = hooks;
            Self::spawn(Shared {
                store,
                clock,
                on_shutdown,
                on_listen_configured,
                scan,
                scope,
                sharing,
                scope_approve,
                memory: AtomicUsize::new(0),
                live: Mutex::new(HashMap::new()),
                #[cfg(test)]
                peer_uid: None,
            })
        }

        fn spawn(shared: Shared) -> Result<Self, ControlError> {
            let path = shared.store.root().path().join(SOCKET_NAME);
            SocketAddr::from_pathname(&path).map_err(|_| ControlError::PathTooLong)?;
            clear_residue(&path)?;
            // Binding by pathname is the one sanctioned exception to "never
            // reopen by pathname after a check" (`spec/control-v1.md`).
            let listener = UnixListener::bind(&path).map_err(|_| ControlError::Socket)?;
            // `chmod` follows a link: a same-UID swap after the bind is the
            // same-UID non-claim, and the `lstat` below then fails closed.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| ControlError::UnsafeSocket)?;
            let meta = fs::symlink_metadata(&path).map_err(|_| ControlError::UnsafeSocket)?;
            if !(meta.file_type().is_socket() && meta.uid() == euid()) {
                return Err(ControlError::UnsafeSocket);
            }
            listener
                .set_nonblocking(true)
                .map_err(|_| ControlError::Socket)?;
            let shared = Arc::new(shared);
            let stop = Arc::new(AtomicBool::new(false));
            let (worker, flag) = (Arc::clone(&shared), Arc::clone(&stop));
            let accept = thread::Builder::new()
                .spawn(move || accept_loop(listener, &worker, &flag))
                .map_err(|_| ControlError::Socket)?;
            Ok(Self {
                path,
                shared,
                stop,
                accept: Some(accept),
            })
        }

        pub(super) fn socket_path(&self) -> &Path {
            &self.path
        }

        pub(super) fn pre_auth_memory_used(&self) -> usize {
            self.shared.memory.load(Ordering::Acquire)
        }

        pub(super) fn stop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(accept) = self.accept.take() {
                let _ = accept.join();
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// `lstat` (never follows): absent is fine; this UID's socket is
    /// removed (`unlink` never follows); anything else fails closed and is
    /// left where it is.
    fn clear_residue(path: &Path) -> Result<(), ControlError> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == euid() => {
                fs::remove_file(path).map_err(|_| ControlError::UnsafeSocket)
            }
            _ => Err(ControlError::UnsafeSocket),
        }
    }

    fn euid() -> libc::uid_t {
        unsafe { libc::geteuid() }
    }

    fn accept_loop(listener: UnixListener, shared: &Arc<Shared>, stop: &AtomicBool) {
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        let mut next_id: u64 = 0;
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let accepted = Instant::now();
                    workers.retain(|worker| !worker.is_finished());
                    // The owner check comes before any slot, worker or read;
                    // a mismatch (or no answer) just drops the stream.
                    if peer_uid(shared, &stream) != Some(euid()) {
                        continue;
                    }
                    next_id += 1;
                    if let Some(worker) = admit(shared, next_id, stream, accepted) {
                        workers.push(worker);
                    }
                }
                // Idle, or a failed accept: wait, never spin.
                Err(_) => thread::sleep(ACCEPT_POLL),
            }
        }
        drop(listener);
        for stream in lock(&shared.live).values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for worker in workers {
            let _ = worker.join();
        }
    }

    fn peer_uid(
        #[cfg_attr(not(test), allow(unused_variables))] shared: &Shared,
        stream: &UnixStream,
    ) -> Option<libc::uid_t> {
        #[cfg(test)]
        if let Some(uid) = shared.peer_uid {
            return Some(uid);
        }
        kernel_peer_uid(stream)
    }

    #[cfg(target_os = "macos")]
    fn kernel_peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
        let (mut uid, mut gid) = (0, 0);
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }

    #[cfg(target_os = "linux")]
    fn kernel_peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::ucred>();
        let mut len = libc::socklen_t::try_from(size).ok()?;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        (rc == 0 && usize::try_from(len).ok() == Some(size)).then_some(cred.uid)
    }

    /// Takes a slot and spawns the worker, or closes the stream unread when
    /// all [`PRE_AUTH_CONNECTIONS`] slots are taken.
    fn admit(
        shared: &Arc<Shared>,
        id: u64,
        stream: UnixStream,
        accepted: Instant,
    ) -> Option<JoinHandle<()>> {
        {
            let mut live = lock(&shared.live);
            if live.len() >= PRE_AUTH_CONNECTIONS {
                return None;
            }
            live.insert(id, stream.try_clone().ok()?);
        }
        let worker = Arc::clone(shared);
        let spawned = thread::Builder::new().spawn(move || {
            let _slot = Slot(&worker, id);
            let mut stream = stream;
            let _ = serve(&worker, &mut stream, accepted);
        });
        match spawned {
            Ok(handle) => Some(handle),
            Err(_) => {
                lock(&shared.live).remove(&id);
                None
            }
        }
    }

    /// Frees the slot when the worker ends, panic included.
    struct Slot<'a>(&'a Shared, u64);

    impl Drop for Slot<'_> {
        fn drop(&mut self) {
            lock(&self.0.live).remove(&self.1);
        }
    }

    /// One pre-auth heap reservation, returned on drop.
    struct Reserved<'a>(&'a AtomicUsize, usize);

    impl<'a> Reserved<'a> {
        fn new(ledger: &'a AtomicUsize, bytes: usize) -> Option<Self> {
            // The CAS loop of the frozen `MemoryLedger`, with this cap.
            let mut current = ledger.load(Ordering::Acquire);
            loop {
                let next = current
                    .checked_add(bytes)
                    .filter(|next| *next <= PRE_AUTH_MEMORY_MAX)?;
                match ledger.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Some(Self(ledger, bytes)),
                    Err(observed) => current = observed,
                }
            }
        }
    }

    impl Drop for Reserved<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::AcqRel);
        }
    }

    /// One connection. `None` closes it without a response: a wrong
    /// version, a deadline, EOF, an oversize length, a failed MAC, or an
    /// unreadable state.
    fn serve(shared: &Shared, stream: &mut UnixStream, accepted: Instant) -> Option<()> {
        // Deadline I/O is non-blocking plus poll(2) (`read_by`).
        stream.set_nonblocking(true).ok()?;
        let mut hello = [0; HELLO_LEN];
        read_by(stream, &mut hello, accepted + PHASE_DEADLINE).ok()?;
        if u16::from_be_bytes([hello[0], hello[1]]) != CONTROL_VERSION {
            return None;
        }
        let client_nonce: [u8; 32] = hello[2..].try_into().ok()?;
        // Read per connection, never cached: after a reset the old token
        // fails at the very next server proof.
        let key = control_key(shared.store.state().ok()?.control_token.expose());
        let server_nonce: [u8; 32] = random().ok()?;
        let mut proof = [0; PROOF_LEN];
        proof[..32].copy_from_slice(&server_nonce);
        proof[32..].copy_from_slice(&control_server_mac(
            &key,
            CONTROL_VERSION,
            &client_nonce,
            &server_nonce,
        ));
        write_by(stream, &proof, Instant::now() + PHASE_DEADLINE).ok()?;

        let deadline = Instant::now() + PHASE_DEADLINE;
        let mut header = [0; COMMAND_HEADER_LEN];
        read_by(stream, &mut header, deadline).ok()?;
        let request_id: [u8; 16] = header[..16].try_into().ok()?;
        let command_id = u16::from_be_bytes([header[16], header[17]]);
        let len = usize::try_from(u32::from_be_bytes(header[18..].try_into().ok()?)).ok()?;
        if len > COMMAND_JSON_MAX {
            return None;
        }
        let _reserved = Reserved::new(&shared.memory, len + MAC_LEN)?;
        let mut rest = vec![0; len + MAC_LEN];
        read_by(stream, &mut rest, deadline).ok()?;
        let (json, mac) = rest.split_at(len);
        let expected = control_command_mac(
            &key,
            CONTROL_VERSION,
            &client_nonce,
            &server_nonce,
            &request_id,
            command_id,
            json,
        )
        .ok()?;
        if !verify_mac(&expected, mac.try_into().ok()?) {
            return None;
        }
        // The key was read at the hello, up to two deadlines ago. A reset
        // since then issued a new token: a command authenticated under the
        // old one must not run against the new state.
        let current = control_key(shared.store.state().ok()?.control_token.expose());
        if !verify_mac(&key, &current) {
            return None;
        }

        let (code, data) = match verify_control_command(json, &request_id, command_id) {
            Ok(()) => {
                let body = CanonicalJsonV1::decode_value(json)
                    .ok()
                    .and_then(|mut value| value.get_mut("body").map(Value::take))
                    .unwrap_or(Value::Null);
                match execute(shared, command_id, &body) {
                    Ok(data) => (OK, data),
                    Err(code) => (code, Value::Null),
                }
            }
            Err(_) => (INVALID, Value::Null),
        };
        let response = CanonicalJsonV1::encode(&json!({
            "code": code,
            "controlVersion": CONTROL_VERSION,
            "data": data,
            "requestId": hex_encode(&request_id),
        }))
        .ok()?;
        let mac = control_response_mac(
            &key,
            CONTROL_VERSION,
            &client_nonce,
            &server_nonce,
            &request_id,
            code,
            &response,
        )
        .ok()?;
        let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + response.len() + MAC_LEN);
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&u32::try_from(response.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&response);
        out.extend_from_slice(&mac);
        let written = write_by(stream, &out, Instant::now() + PHASE_DEADLINE);
        if command_id == SHUTDOWN && code == OK {
            (shared.on_shutdown)();
        }
        written.ok()
    }

    /// Runs one validated command. `Err` is the result code; error data is
    /// always `null`.
    fn execute(shared: &Shared, command_id: u16, body: &Value) -> Result<Value, u16> {
        let store = &*shared.store;
        let clock = &*shared.clock;
        match command_id {
            STATUS => {
                let state = store.state().map_err(code_of)?;
                let now_ms = record_ms(&state.reference, clock).map_err(|_| INTERNAL)?;
                Ok(status(
                    &state,
                    now_ms,
                    (shared.scan)(),
                    (shared.scope)(store),
                ))
            }
            OFFER_CREATE => offer_create(shared, body),
            OFFER_CANCEL => {
                let offer_id = id(body, "offerId")?;
                store
                    .transition(|state| state.cancel_offer(offer_id, record_ms(state, clock)?))
                    .map_err(code_of)?;
                Ok(Value::Null)
            }
            PENDING_LIST => {
                let state = store.state().map_err(code_of)?;
                let now_ms = record_ms(&state.reference, clock).map_err(|_| INTERNAL)?;
                Ok(pending_list(&state, now_ms))
            }
            APPROVE => {
                let (pending_id, generation) = (id(body, "pendingId")?, generation(body)?);
                let os_now = clock.os_now_seconds().map_err(code_of)?;
                // The server cannot see what the owner was shown; showing
                // the disclosure and getting consent is the caller's duty.
                pairing::approve(store, pending_id, generation, true, os_now).map_err(code_of)?;
                Ok(Value::Null)
            }
            REJECT => {
                let (pending_id, generation) = (id(body, "pendingId")?, generation(body)?);
                store
                    .transition(|state| {
                        state.reject_pending(pending_id, generation, record_ms(state, clock)?)
                    })
                    .map_err(code_of)?;
                Ok(Value::Null)
            }
            REVOKE => {
                let grant_id = id(body, "grantId")?;
                store
                    .transition(|state| state.revoke_commit(grant_id, record_ms(state, clock)?))
                    .map_err(code_of)?;
                Ok(Value::Null)
            }
            LISTEN_CONFIGURE => {
                let host = body
                    .get("bindHost")
                    .and_then(Value::as_str)
                    .ok_or(INVALID)?;
                let port = body
                    .get("bindPort")
                    .and_then(Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok())
                    .ok_or(INVALID)?;
                // The listener's own rule, not a copy: the frozen validator
                // and the store accept hostnames the listener never binds.
                bind_address(host, port).map_err(|_| INVALID)?;
                let label = store.state().map_err(code_of)?.config.node_label;
                store
                    .set_listen_config(Some(host.to_owned()), port, label)
                    .map_err(code_of)?;
                // Before the reply: once the client sees `ok`, the listener
                // already serves the new address (or is stopped).
                (shared.on_listen_configured)();
                Ok(Value::Null)
            }
            SHUTDOWN => Ok(Value::Null),
            // The effect is the hook's, never a transition here: the
            // runtime's enable gate and F-7 disable, the agent's scope
            // approval. Without a hook: `internal`, nothing written.
            SHARING_SET => {
                let hook = shared.sharing.as_ref().ok_or(INTERNAL)?;
                let enabled = body
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or(INVALID)?;
                hook(enabled).map_err(code_of)?;
                Ok(Value::Null)
            }
            SCOPE_APPROVE => {
                let hook = shared.scope_approve.as_ref().ok_or(INTERNAL)?;
                let digest = body
                    .get("ownerInputsSha256")
                    .and_then(Value::as_str)
                    .ok_or(INVALID)?;
                hook(store, digest).map_err(code_of)?;
                Ok(Value::Null)
            }
            _ => Err(INVALID),
        }
    }

    fn offer_create(shared: &Shared, body: &Value) -> Result<Value, u16> {
        let ttl_ms = body
            .get("ttlSeconds")
            .and_then(Value::as_u64)
            .and_then(|ttl| i64::try_from(ttl).ok())
            .and_then(|ttl| ttl.checked_mul(1_000))
            .ok_or(INVALID)?;
        let state = shared.store.state().map_err(code_of)?;
        let (host, port) = (state.config.bind_host.clone(), state.config.bind_port);
        let host = host.ok_or(INVALID)?;
        bind_address(&host, port).map_err(|_| INVALID)?;
        // The identity as of now: a reset after this turns sharing off, so
        // the frozen `create_offer` below refuses an offer bound to it.
        let responder = state.identity_public().map_err(code_of)?;
        drop(state);
        let offer_id: [u8; 16] = random().map_err(code_of)?;
        let secret = Secret32::new(random().map_err(code_of)?);
        let os_now = shared.clock.os_now_seconds().map_err(code_of)?;
        let mut expires_at = 0;
        shared
            .store
            .transition(|state| {
                let now_ms = clock_status(os_now, state.last_accepted_wall_unix_seconds())
                    .effective_now
                    .checked_mul(1_000)
                    .ok_or(SecurityError::Bounds)?;
                expires_at = now_ms.checked_add(ttl_ms).ok_or(SecurityError::Bounds)?;
                state.create_offer(
                    Offer {
                        offer_id,
                        secret_hash: offer_secret_hash(&offer_id, secret.expose(), &responder),
                        created_at_ms: now_ms,
                        expires_at_ms: expires_at,
                        state: OfferState::Active,
                    },
                    os_now,
                )
            })
            .map_err(code_of)?;
        // The frozen `PairOffer` derives a `Debug` that prints the secret:
        // it lives only as this temporary.
        let url = pair_url(&PairOffer {
            expires_at,
            host,
            offer_id: hex_encode(&offer_id),
            port,
            responder_static: hex_encode(&responder),
            secret: hex_encode(secret.expose()),
            version: PEER_PROTOCOL_VERSION,
        })
        .map_err(|_| INTERNAL)?;
        Ok(json!({
            "expiresAt": expires_at,
            "offerId": hex_encode(&offer_id),
            "pairUrl": url,
        }))
    }

    /// `now_ms` is [`record_ms`]: offers and pending records past their
    /// `expiresAt` by then are left out even before the housekeeping sweep
    /// stores them as expired. Grants are counted as stored.
    fn status(state: &StoredState, now_ms: i64, scan: ScanStatus, scope_approved: bool) -> Value {
        let reference = &state.reference;
        let mut families = scan.families;
        families.sort_unstable();
        families.dedup();
        families.truncate(128);
        json!({
            "activeGrantCount": reference
                .grants
                .iter()
                .filter(|grant| grant.state == GrantState::Active)
                .count(),
            "activeOfferCount": reference
                .offers
                .iter()
                .filter(|offer| offer.state == OfferState::Active && now_ms < offer.expires_at_ms)
                .count(),
            "bindHost": state.config.bind_host,
            "bindPort": state.config.bind_port,
            "lastScanAt": scan.last_scan_at,
            "nodeLabel": state.config.node_label,
            "pendingCount": reference
                .pending
                .iter()
                .filter(|pending| awaiting(pending, now_ms))
                .count(),
            "scanStatus": match scan.state {
                ScanState::Never => "never",
                ScanState::Ok => "ok",
                ScanState::Error => "error",
            },
            "scopeApproved": scope_approved,
            "sharingEnabled": reference.sharing_enabled,
            "sourceFamilies": families,
        })
    }

    /// Awaiting approval and not past `expiresAt` at `now_ms`.
    fn awaiting(pending: &Pending, now_ms: i64) -> bool {
        pending.state == PendingState::AwaitingApproval && now_ms < pending.expires_at_ms
    }

    fn pending_list(state: &StoredState, now_ms: i64) -> Value {
        let mut listed: Vec<_> = state
            .reference
            .pending
            .iter()
            .filter(|pending| awaiting(pending, now_ms))
            .collect();
        listed.sort_by_key(|pending| pending.pending_id);
        listed
            .into_iter()
            .map(|pending| {
                json!({
                    "expiresAt": pending.expires_at_ms,
                    "pendingId": hex_encode(&pending.pending_id),
                    "sasCode": pending.sas_code,
                })
            })
            .collect()
    }

    /// A terminal record's timestamp: the effective now, or the durable
    /// wall while the OS clock is unavailable or anomalous. Never refuses
    /// for the clock, so a revoke never waits on it.
    fn record_ms(state: &ReferenceState, clock: &dyn Clock) -> Result<i64, SecurityError> {
        let wall = state.last_accepted_wall_unix_seconds();
        let now = clock.os_now_seconds().map_or(wall, |os_now| {
            let status = clock_status(os_now, wall);
            if status.anomaly {
                wall
            } else {
                status.effective_now
            }
        });
        now.checked_mul(1_000).ok_or(SecurityError::Bounds)
    }

    fn id(body: &Value, key: &str) -> Result<[u8; 16], u16> {
        body.get(key)
            .and_then(Value::as_str)
            .and_then(|value| decode_fixed_hex(value).ok())
            .ok_or(INVALID)
    }

    fn generation(body: &Value) -> Result<u64, u16> {
        body.get("sasGeneration")
            .and_then(Value::as_u64)
            .ok_or(INVALID)
    }

    /// Local control may say `unsafeState`; the peer wire folds it into
    /// `internal`.
    fn code_of(error: StorageError) -> u16 {
        match error {
            StorageError::Refused(SecurityError::Unauthorized) => UNAUTHORIZED,
            StorageError::Refused(SecurityError::Expired) => EXPIRED,
            StorageError::Refused(_) => INVALID,
            StorageError::Busy => BUSY,
            StorageError::UnsafeState => UNSAFE_STATE,
            StorageError::Unknown
            | StorageError::Incompatible
            | StorageError::Corrupt
            | StorageError::Unavailable => INTERNAL,
        }
    }

    pub(super) fn call(client: &Client, command: &Command) -> Result<Response, ControlError> {
        let deadline = Instant::now() + CLIENT_DEADLINE;
        let socket = |_| ControlError::Socket;
        let mut stream = UnixStream::connect(&client.path).map_err(socket)?;
        stream.set_nonblocking(true).map_err(socket)?;
        let key = control_key(client.token.expose());
        let client_nonce: [u8; 32] = random().map_err(|_| ControlError::Unavailable)?;
        let mut hello = [0; HELLO_LEN];
        hello[..2].copy_from_slice(&CONTROL_VERSION.to_be_bytes());
        hello[2..].copy_from_slice(&client_nonce);
        write_by(&mut stream, &hello, deadline).map_err(socket)?;
        let mut proof = [0; PROOF_LEN];
        read_by(&mut stream, &mut proof, deadline).map_err(socket)?;
        let server_nonce: [u8; 32] = proof[..32].try_into().map_err(|_| ControlError::Socket)?;
        let server_mac: [u8; 32] = proof[32..].try_into().map_err(|_| ControlError::Socket)?;
        let expected = control_server_mac(&key, CONTROL_VERSION, &client_nonce, &server_nonce);
        if !verify_mac(&expected, &server_mac) {
            return Err(ControlError::ServerProof);
        }

        let request_id: [u8; 16] = random().map_err(|_| ControlError::Unavailable)?;
        let json = CanonicalJsonV1::encode(&json!({
            "body": command.body,
            "commandId": command.id,
            "controlVersion": CONTROL_VERSION,
            "requestId": hex_encode(&request_id),
        }))
        .map_err(|_| ControlError::Command)?;
        if json.len() > COMMAND_JSON_MAX {
            return Err(ControlError::Command);
        }
        let mac = control_command_mac(
            &key,
            CONTROL_VERSION,
            &client_nonce,
            &server_nonce,
            &request_id,
            command.id,
            &json,
        )
        .map_err(|_| ControlError::Command)?;
        let mut frame = Vec::with_capacity(COMMAND_HEADER_LEN + json.len() + MAC_LEN);
        frame.extend_from_slice(&request_id);
        frame.extend_from_slice(&command.id.to_be_bytes());
        frame.extend_from_slice(
            &u32::try_from(json.len())
                .map_err(|_| ControlError::Command)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(&json);
        frame.extend_from_slice(&mac);
        write_by(&mut stream, &frame, deadline).map_err(socket)?;

        let mut header = [0; RESPONSE_HEADER_LEN];
        // From here the command is out: a missing reply says nothing about
        // whether it ran.
        let no_reply = |_| ControlError::NoReply;
        read_by(&mut stream, &mut header, deadline).map_err(no_reply)?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::try_from(u32::from_be_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| ControlError::Response)?;
        if len > RESPONSE_JSON_MAX {
            return Err(ControlError::Response);
        }
        let mut rest = vec![0; len + MAC_LEN];
        read_by(&mut stream, &mut rest, deadline).map_err(no_reply)?;
        let (json, mac) = rest.split_at(len);
        let expected = control_response_mac(
            &key,
            CONTROL_VERSION,
            &client_nonce,
            &server_nonce,
            &request_id,
            code,
            json,
        )
        .map_err(|_| ControlError::Response)?;
        let mac: &[u8; 32] = mac.try_into().map_err(|_| ControlError::Response)?;
        if !verify_mac(&expected, mac) {
            return Err(ControlError::Response);
        }
        verify_control_response(json, &request_id, command.id, code)
            .map_err(|_| ControlError::Response)?;
        let data = CanonicalJsonV1::decode_value(json)
            .ok()
            .and_then(|mut value| value.get_mut("data").map(Value::take))
            .ok_or(ControlError::Response)?;
        Ok(Response { code, data })
    }

    fn remaining(deadline: Instant) -> io::Result<Duration> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }

    /// Waits for `events` on the non-blocking `stream` until `deadline`.
    /// poll(2), not `SO_RCVTIMEO`: macOS refuses `setsockopt` with `EINVAL`
    /// once the peer has closed, even while its last bytes are unread.
    fn wait(stream: &UnixStream, events: libc::c_short, deadline: Instant) -> io::Result<()> {
        let millis = remaining(deadline)?.as_millis().max(1);
        let mut fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let timeout = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
        match unsafe { libc::poll(&mut fd, 1, timeout) } {
            0 => Err(ErrorKind::TimedOut.into()),
            ready if ready > 0 => Ok(()),
            _ => match io::Error::last_os_error() {
                error if error.kind() == ErrorKind::Interrupted => Ok(()),
                error => Err(error),
            },
        }
    }

    /// Fills `buf` from the non-blocking `stream` before the absolute
    /// `deadline`; partial reads do not extend it.
    fn read_by(stream: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match stream.read(&mut buf[done..]) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(read) => done += read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    wait(stream, libc::POLLIN, deadline)?
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Writes all of `buf` to the non-blocking `stream` before the absolute
    /// `deadline`.
    fn write_by(stream: &mut UnixStream, buf: &[u8], deadline: Instant) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match stream.write(&buf[done..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(written) => done += written,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    wait(stream, libc::POLLOUT, deadline)?
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            os::unix::fs::PermissionsExt,
            sync::atomic::{AtomicUsize, Ordering},
        };

        use super::*;
        use crate::{pairing::SystemClock, secure_fs::SecureRoot};

        /// A short temporary home, so the socket path fits `sun_path`.
        struct ShortHome(PathBuf);

        impl ShortHome {
            fn new() -> Self {
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                let path = PathBuf::from(format!(
                    "/tmp/scu-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                Self(path)
            }
        }

        impl Drop for ShortHome {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        /// SA-2B2c1 acceptance (5): a peer whose UID is not this process's
        /// is closed at once: no server proof, no slot, and the 4 slots
        /// stay free for a same-UID peer. The kernel answer is replaced by
        /// the test-only `peer_uid`; the real cross-UID refusal is not
        /// observable without a second user.
        #[test]
        fn a_peer_with_another_uid_is_closed_before_any_slot_or_read() {
            let home = ShortHome::new();
            let root = SecureRoot::open_under(&home.0, &["r"]).unwrap();
            let store = Arc::new(StateStore::open(root, 1_700_000_000).unwrap());
            let foreign = euid().wrapping_add(1);
            let mut server = Server::spawn(Shared {
                store,
                clock: Arc::new(SystemClock),
                on_shutdown: Arc::new(|| {}),
                on_listen_configured: Arc::new(|| {}),
                scan: Arc::new(ScanStatus::default),
                scope: Arc::new(|_| false),
                sharing: None,
                scope_approve: None,
                memory: AtomicUsize::new(0),
                live: Mutex::new(HashMap::new()),
                peer_uid: Some(foreign),
            })
            .unwrap();
            // More than the slot count: none of them may take a slot.
            for n in 0..(PRE_AUTH_CONNECTIONS + 2) {
                let mut stream = UnixStream::connect(server.socket_path()).unwrap();
                let _ = stream.write_all(&[0, 1]);
                let started = Instant::now();
                if stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .is_err()
                {
                    // macOS refuses `setsockopt` once the peer has closed.
                    stream.set_nonblocking(true).unwrap();
                }
                let mut byte = [0; 1];
                match stream.read(&mut byte) {
                    Ok(0) => {}
                    Err(error) if error.kind() == ErrorKind::ConnectionReset => {}
                    other => panic!("connection {n} was not closed at once: {other:?}"),
                }
                assert!(started.elapsed() < Duration::from_millis(900), "{n}");
                assert!(lock(&server.shared.live).is_empty(), "{n}");
            }
            assert_eq!(server.pre_auth_memory_used(), 0);
            server.stop();
        }
    }
}
