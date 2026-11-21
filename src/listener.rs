//! The producer's product TCP listener (`spec/pairing-v1.md`, "Listener").
//!
//! Binds the listen address from the durable state, serves each accepted
//! connection with [`Producer::serve`] on its own thread, at most
//! [`MAX_CONNECTIONS`] at once, and on [`Listener::stop`] shuts every
//! in-flight socket down so no thread outlives it. Writes no log.

use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    noise::StaticKey,
    pairing::{Clock, Producer, RateLimiter},
    report_peer::Reports,
    secure_fs::StorageError,
    security::MemoryLedger,
    state_store::StateStore,
};

/// Connections served at once, in the handshake or after it.
pub const MAX_CONNECTIONS: usize = 8;
/// How often the accept loop checks for a stop when no connection arrives.
// ponytail: polling accept, ~20 idle wakeups/s; a self-connect wake-up or
// poll(2) if that ever matters. Polling cannot hang `stop`, a wake-up can.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Why the listener did not start. Carries no address text or OS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerError {
    /// `bindHost` is null: nothing to bind.
    NotConfigured,
    /// `bindHost` is not an IP literal, is unspecified, or the port is
    /// below 1024.
    InvalidAddress,
    /// The OS refused the bind (e.g. the port is in use). No other address
    /// or port is tried.
    Bind,
    /// The state could not be read.
    Store(StorageError),
}

/// The bind address for a stored listen config, re-validated here rather
/// than trusted from the store: the host must parse as an IP literal (so a
/// hostname, or `0x0`, which the OS resolver would turn into `0.0.0.0`, is
/// refused), must not be unspecified (`0.0.0.0`, `::`, `::ffff:0.0.0.0`),
/// and the port must be at least 1024.
pub fn bind_address(host: &str, port: u16) -> Result<SocketAddr, ListenerError> {
    let ip: IpAddr = host.parse().map_err(|_| ListenerError::InvalidAddress)?;
    if ip.to_canonical().is_unspecified() || port < 1024 {
        return Err(ListenerError::InvalidAddress);
    }
    Ok(SocketAddr::new(ip, port))
}

/// macOS and Linux: `std`'s bind (it sets `SO_REUSEADDR`, which there
/// lets a port in `TIME_WAIT` be bound again but never a port in use).
#[cfg(not(windows))]
fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address)
}

/// Windows: `SO_EXCLUSIVEADDRUSE` before the bind, so no other socket can
/// take the port with `SO_REUSEADDR` while this one holds it (`std` cannot
/// set an option before its bind). `socket2::Socket::new` creates it with
/// `WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED` and starts WinSock;
/// the socket is owned by `socket` until the one conversion at the end.
/// `IPV6_V6ONLY` keeps the Windows default (on), as `std` would.
#[cfg(windows)]
fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, WSAGetLastError, setsockopt,
    };
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    let on: i32 = 1;
    // SAFETY: `socket` is a live socket owned here for the whole call; the
    // option value points at a live `i32` and its length is that size.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&on as *const i32).cast(),
            size_of::<i32>() as i32,
        )
    };
    if result != 0 {
        // SAFETY: reads this thread's last WinSock error; no arguments.
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    socket.bind(&address.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

/// The running listener. Dropping it stops it.
pub struct Listener {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Listener { .. }")
    }
}

/// What every connection thread shares.
struct Shared {
    store: Arc<StateStore>,
    ledger: MemoryLedger,
    limiter: Arc<RateLimiter>,
    clock: Arc<dyn Clock>,
    reports: Arc<Reports>,
    /// A `try_clone` of each in-flight connection, so `stop` can shut it
    /// down; its size is the number of connections being served.
    live: Mutex<HashMap<u64, TcpStream>>,
}

impl Listener {
    /// Binds `bindHost:bindPort` from `store.state()` and starts accepting.
    /// `reports` is the report path's shared state (`spec/report-peer-v1.md`).
    pub fn start(
        store: Arc<StateStore>,
        ledger: MemoryLedger,
        limiter: Arc<RateLimiter>,
        clock: Arc<dyn Clock>,
        reports: Arc<Reports>,
    ) -> Result<Self, ListenerError> {
        let config = store.state().map_err(ListenerError::Store)?.config;
        let host = config.bind_host.ok_or(ListenerError::NotConfigured)?;
        let address = bind_address(&host, config.bind_port)?;
        // A `SocketAddr`, never a string: nothing reaches the resolver.
        let listener = bind(address).map_err(|_| ListenerError::Bind)?;
        let local_addr = listener.local_addr().map_err(|_| ListenerError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ListenerError::Bind)?;
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            store,
            ledger,
            limiter,
            clock,
            reports,
            live: Mutex::new(HashMap::new()),
        });
        let flag = Arc::clone(&stop);
        let accept = thread::Builder::new()
            .spawn(move || accept_loop(listener, &shared, &flag))
            .map_err(|_| ListenerError::Bind)?;
        Ok(Self {
            local_addr,
            stop,
            accept: Some(accept),
        })
    }

    /// The address actually bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting, shuts down every in-flight connection and joins
    /// every thread. Idempotent.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, shared: &Arc<Shared>, stop: &AtomicBool) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut next_id: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                workers.retain(|worker| !worker.is_finished());
                next_id += 1;
                if let Some(worker) = admit(shared, next_id, stream) {
                    workers.push(worker);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            // A failed accept (e.g. the peer reset first) ends nothing. It
            // waits like an idle poll: an error that persists (no file
            // descriptor left) must not spin this thread.
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

/// Registers and spawns one connection, or closes it unread when
/// [`MAX_CONNECTIONS`] are in flight or it cannot be tracked.
fn admit(shared: &Arc<Shared>, id: u64, stream: TcpStream) -> Option<JoinHandle<()>> {
    {
        let mut live = lock(&shared.live);
        if live.len() >= MAX_CONNECTIONS {
            return None;
        }
        live.insert(id, stream.try_clone().ok()?);
    }
    let worker = Arc::clone(shared);
    let spawned = thread::Builder::new().spawn(move || {
        let _slot = Slot(&worker, id);
        serve(&worker, stream);
    });
    match spawned {
        Ok(handle) => Some(handle),
        Err(_) => {
            lock(&shared.live).remove(&id);
            None
        }
    }
}

/// Reads the identity now, so a reset takes effect on the next connection;
/// the handshake itself touches no state. Unreadable state closes it.
fn serve(shared: &Shared, stream: TcpStream) {
    let Ok(state) = shared.store.state() else {
        return;
    };
    let Ok(identity) = StaticKey::from_state(&state) else {
        return;
    };
    drop(state);
    Producer {
        store: &shared.store,
        identity: &identity,
        ledger: &shared.ledger,
        limiter: &shared.limiter,
        clock: &*shared.clock,
        reports: &shared.reports,
    }
    .serve(stream);
}

/// Frees the connection's slot when its thread ends, panic included.
struct Slot<'a>(&'a Shared, u64);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        lock(&self.0.live).remove(&self.1);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SA-2B2a3 acceptance (3), the re-validation itself.
    #[test]
    fn bind_address_accepts_only_a_specific_ip_and_a_port_from_1024() {
        for host in ["0.0.0.0", "::", "::ffff:0.0.0.0", "0x0", "localhost"] {
            assert_eq!(
                bind_address(host, 50_000),
                Err(ListenerError::InvalidAddress),
                "{host}"
            );
        }
        assert_eq!(
            bind_address("127.0.0.1", 50_000),
            Ok(SocketAddr::from(([127, 0, 0, 1], 50_000)))
        );
        assert_eq!(
            bind_address("::1", 1_024),
            Ok(SocketAddr::new("::1".parse().unwrap(), 1_024))
        );
        assert_eq!(
            bind_address("127.0.0.1", 1_023),
            Err(ListenerError::InvalidAddress)
        );
    }
}

/// W3b: the Windows bind (`SO_EXCLUSIVEADDRUSE`, no handle inheritance,
/// `IPV6_V6ONLY` on). Every failure names the address and the OS error.
#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::io::AsRawSocket;

    use socket2::{Domain, Protocol, Socket, Type};
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};

    use super::*;

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// Another socket that sets `SO_REUSEADDR` and binds `address`: how a
    /// second process would try to take the port.
    fn reuse_bind(address: SocketAddr) -> std::io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&address.into())?;
        Ok(socket)
    }

    #[test]
    fn exclusive_address_use_refuses_a_reuseaddr_bind_of_the_same_port() {
        // Control: a listener made without the option lets the
        // `SO_REUSEADDR` socket bind its port, so the refusal below comes
        // from `SO_EXCLUSIVEADDRUSE` and nothing else.
        let plain = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        plain.bind(&loopback().into()).unwrap();
        plain.listen(128).unwrap();
        let plain_address = plain.local_addr().unwrap().as_socket().unwrap();
        let control = reuse_bind(plain_address);
        assert!(
            control.is_ok(),
            "control: an SO_REUSEADDR bind of {plain_address} next to a listener without \
             SO_EXCLUSIVEADDRUSE was refused: {:?}",
            control.err()
        );

        let listener = bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        match reuse_bind(address) {
            Ok(_) => panic!(
                "an SO_REUSEADDR bind of {address} succeeded next to the agent's listener \
                 (SO_EXCLUSIVEADDRUSE missing)"
            ),
            Err(error) => eprintln!("SO_REUSEADDR bind of {address} refused: {error:?}"),
        }
        // A plain second bind is refused too.
        assert!(
            TcpListener::bind(address).is_err(),
            "plain bind of {address}"
        );
    }

    #[test]
    fn the_listening_socket_is_not_inheritable() {
        let listener = bind(loopback()).unwrap();
        let mut flags = 0u32;
        // SAFETY: the socket is a live handle owned by `listener`; `flags`
        // is an out parameter.
        let ok = unsafe { GetHandleInformation(listener.as_raw_socket() as HANDLE, &mut flags) };
        assert_ne!(
            ok,
            0,
            "GetHandleInformation failed: {:?}",
            std::io::Error::last_os_error()
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0, "handle flags {flags:#x}");
    }

    /// SR P3-2: with `IPV6_V6ONLY` on (the Windows default), an IPv4-mapped
    /// bind host cannot be bound: it fails closed rather than binding IPv4.
    #[test]
    fn an_ipv4_mapped_bind_host_fails_closed() {
        let address = bind_address("::ffff:127.0.0.1", 50_000).unwrap();
        let result = bind(SocketAddr::new(address.ip(), 0));
        assert!(
            result.is_err(),
            "{address} bound as {:?}",
            result.map(|listener| listener.local_addr())
        );
    }
}
