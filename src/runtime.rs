//! The agent runtime (`spec/runtime-v1.md`): one state store, one peer
//! store, one control server, at most one peer listener and one
//! housekeeping thread, started together and stopped in a fixed order.
//!
//! It also owns the two sharing entry points no control command has: the
//! F-7 disable composition and the enable gate. Every state change is one
//! [`StateStore::transition`] closure over frozen `ReferenceState`
//! transitions. macOS and Linux only: elsewhere the control server fails
//! closed, so [`Runtime::start`] does too. Writes no log.
//!
//! On the receiver side it owns the receiver report cache: [`Runtime::pull`]
//! fills it, [`Runtime::last_good`] reads it, housekeeping purges what has
//! expired.

use std::{
    fmt,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    cache::{CACHE_RETENTION_MILLIS, CacheKey, CacheRole},
    cache_store::{CacheStore, CachedBody},
    control::{self, ControlError},
    listener::{Listener, bind_address},
    pairing::{Clock, RateLimiter, SystemClock},
    peer_store::{PeerRecord, PeerState, PeerStore, usable},
    report_peer::{FetchError, FetchLimiter, Fetched, ReportQuery, ReportSource, Reports, fetch},
    secure_fs::{SecureRoot, StorageError},
    security::{
        AGGREGATION_REVISION, GrantState, MemoryLedger, OfferState, PendingState,
        REPORT_SCHEMA_VERSION, ReferenceState, SecurityError, TZDB_REVISION, clock_status,
        hex_encode,
    },
    state_store::{StateStore, random},
};

/// Housekeeping runs at least this often.
pub const HOUSEKEEPING_PERIOD: Duration = Duration::from_secs(60);
/// The shortest pause between two housekeeping rounds that a coming
/// expiry can cause. The wall clock has whole seconds, so an expiry inside
/// the current second could otherwise wake the thread again and again.
// ponytail: an expiry is swept up to 1 s late; nothing reads the stored
// state as authority before then (claims, approvals and authorization all
// compare `expiresAt` with the effective now themselves).
const MIN_PAUSE: Duration = Duration::from_secs(1);

/// What a runtime is started with besides its root and report source.
#[derive(Clone)]
pub struct Options {
    /// Every clock reading: transitions, expiry, checkpoints.
    pub clock: Arc<dyn Clock>,
    /// The longest housekeeping pause, [`HOUSEKEEPING_PERIOD`] in
    /// production. A test shortens it to drive rounds with an injected
    /// clock.
    pub housekeeping_period: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            housekeeping_period: HOUSEKEEPING_PERIOD,
        }
    }
}

/// Why a runtime did not start. Carries no path or OS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// The OS clock, the state store or the peer store.
    Store(StorageError),
    /// The control server (on other platforms, `Unsupported`).
    Control(ControlError),
    /// A thread could not be spawned.
    Thread,
}

/// Why [`Runtime::pull`] failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullError {
    /// No readable peer record names that producer. Nothing was sent.
    NoPeer,
    /// `report_peer::fetch` failed (`Unusable` included: nothing was sent).
    Fetch(FetchError),
}

/// The listener slot. One mutex guards both fields, so a `listenConfigure`
/// hook and [`Runtime::stop`] never interleave.
struct ListenerSlot {
    listener: Option<Listener>,
    stopping: bool,
}

#[derive(Default)]
struct Signal {
    /// Someone asked for shutdown: control `shutdown` or `stop`.
    shutdown: bool,
    /// The housekeeping thread must end.
    halt: bool,
}

/// What the hooks and the housekeeping thread share.
struct Inner {
    store: Arc<StateStore>,
    clock: Arc<dyn Clock>,
    period: Duration,
    // One of each per process, kept across listener restarts.
    ledger: MemoryLedger,
    limiter: Arc<RateLimiter>,
    reports: Arc<Reports>,
    /// The receiver cache; `None` when it did not open at start.
    cache: Option<CacheStore>,
    listener: Mutex<ListenerSlot>,
    signal: Mutex<Signal>,
    wake: Condvar,
    /// Test-only: runs at the start of each listener restart, before the
    /// slot mutex is taken. No such field exists outside test builds.
    #[cfg(test)]
    before_restart: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// The running agent. Dropping it stops it.
pub struct Runtime {
    inner: Arc<Inner>,
    peers: PeerStore,
    fetches: FetchLimiter,
    socket_path: PathBuf,
    control: Mutex<Option<control::Server>>,
    housekeeping: Mutex<Option<JoinHandle<()>>>,
    /// Serializes `stop`, so every caller returns only after every thread
    /// has ended.
    stop_serial: Mutex<()>,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime { .. }")
    }
}

impl Runtime {
    /// Opens the state store, the peer store and the receiver cache in
    /// `root` (a cache that does not open leaves the runtime without one),
    /// starts the control server, the peer listener when the stored `bindHost` is set
    /// and binds (otherwise none, and the runtime runs without it), and the
    /// housekeeping thread, whose first round runs at once.
    pub fn start(
        root: SecureRoot,
        source: Arc<dyn ReportSource>,
        options: Options,
    ) -> Result<Self, RuntimeError> {
        Self::start_inner(
            root,
            source,
            options,
            #[cfg(test)]
            None,
        )
    }

    fn start_inner(
        root: SecureRoot,
        source: Arc<dyn ReportSource>,
        options: Options,
        #[cfg(test)] before_restart: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Self, RuntimeError> {
        let os_now = options
            .clock
            .os_now_seconds()
            .map_err(RuntimeError::Store)?;
        let store = Arc::new(StateStore::open(root, os_now).map_err(RuntimeError::Store)?);
        let peers = PeerStore::open(store.root()).map_err(RuntimeError::Store)?;
        let ledger = MemoryLedger::default();
        // Not retried: a cache that is unsafe or busy now stays off until
        // the next start. `pull` works without it.
        let cache = CacheStore::open(store.root(), CacheRole::Receiver, ledger.clone()).ok();
        let inner = Arc::new(Inner {
            store: Arc::clone(&store),
            clock: options.clock,
            period: options.housekeeping_period,
            ledger,
            limiter: Arc::new(RateLimiter::default()),
            reports: Arc::new(Reports::new(source)),
            cache,
            listener: Mutex::new(ListenerSlot {
                listener: None,
                stopping: false,
            }),
            signal: Mutex::new(Signal::default()),
            wake: Condvar::new(),
            #[cfg(test)]
            before_restart,
        });
        let (on_shutdown, on_listen) = (Arc::clone(&inner), Arc::clone(&inner));
        let server = control::Server::start_with_listen_hook(
            store,
            Arc::clone(&inner.clock),
            Arc::new(move || request_shutdown(&on_shutdown)),
            Arc::new(move || restart_listener(&on_listen)),
        )
        .map_err(RuntimeError::Control)?;
        let runtime = Self {
            socket_path: server.socket_path().to_path_buf(),
            inner,
            peers,
            fetches: FetchLimiter::default(),
            control: Mutex::new(Some(server)),
            housekeeping: Mutex::new(None),
            stop_serial: Mutex::new(()),
        };
        restart_listener(&runtime.inner);
        let worker = Arc::clone(&runtime.inner);
        // On failure, dropping `runtime` stops what already runs.
        let handle = thread::Builder::new()
            .spawn(move || housekeeping(&worker))
            .map_err(|_| RuntimeError::Thread)?;
        *lock(&runtime.housekeeping) = Some(handle);
        Ok(runtime)
    }

    pub fn store(&self) -> &Arc<StateStore> {
        &self.inner.store
    }

    pub fn peers(&self) -> &PeerStore {
        &self.peers
    }

    /// The control socket (`control.sock` in the root).
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// The address the peer listener is bound to, if one runs.
    pub fn listener_addr(&self) -> Option<SocketAddr> {
        lock(&self.inner.listener)
            .listener
            .as_ref()
            .map(Listener::local_addr)
    }

    /// F-7 disable, one transition: the frozen `disable_commit` (sharing
    /// off, every active grant revoked), then `reject_pending` for every
    /// awaiting pending, then `cancel_offer` for every active offer. A
    /// cancel refused with `Bounds` (the record table is full) is skipped
    /// and the state before it kept, so the disable never fails on record
    /// count; [`enable_sharing`](Self::enable_sharing) refuses while such
    /// an offer can still be claimed.
    pub fn disable_sharing(&self) -> Result<(), StorageError> {
        let record_id = random()?;
        let os_now = self.inner.clock.os_now_seconds().ok();
        let mut nothing_to_do = false;
        let result = self.inner.store.transition(|state| {
            // Already off with nothing left to end: write nothing. Every
            // disable adds a terminal record, so a caller that disables on
            // each launch would otherwise fill the record table.
            if !state.sharing_enabled
                && state
                    .pending
                    .iter()
                    .all(|pending| pending.state != PendingState::AwaitingApproval)
                && state
                    .offers
                    .iter()
                    .all(|offer| offer.state != OfferState::Active)
                && state
                    .grants
                    .iter()
                    .all(|grant| grant.state != GrantState::Active)
            {
                nothing_to_do = true;
                return Err(SecurityError::Conflict);
            }
            let at = record_ms(state, os_now)?;
            let mut next = state.disable_commit(record_id, at)?;
            let awaiting: Vec<_> = next
                .pending
                .iter()
                .filter(|pending| pending.state == PendingState::AwaitingApproval)
                .map(|pending| (pending.pending_id, pending.sas_generation))
                .collect();
            for (pending_id, generation) in awaiting {
                next = next.reject_pending(pending_id, generation, at)?;
            }
            cancel_active_offers(next, at)
        });
        if nothing_to_do {
            return Ok(());
        }
        result
    }

    /// The enable gate, one transition: when sharing is already on, the
    /// frozen `enable_sharing` refusal (`Refused(Conflict)`), nothing
    /// written; otherwise `reject_pending` for every awaiting pending, then
    /// `cancel_offer` again for every active offer (skipping `Bounds`);
    /// then, while any offer is still active with `expiresAt` after the
    /// durable wall, [`StorageError::Busy`] and nothing is written;
    /// otherwise the frozen `enable_sharing`.
    ///
    /// No clock is compared beyond that: a claim's effective now is never
    /// below the wall, so an offer that passes the gate can never be
    /// claimed, and only a reset lowers the wall, which removes every offer.
    pub fn enable_sharing(&self) -> Result<(), StorageError> {
        let os_now = self.inner.clock.os_now_seconds().ok();
        let mut gated = false;
        let result = self.inner.store.transition(|state| {
            // Already on: the frozen refusal, before anything below could
            // touch a pending or an offer that is in use.
            if state.sharing_enabled {
                return state.enable_sharing();
            }
            let at = record_ms(state, os_now)?;
            // Sharing is off, and a claim is refused while it is off, so a
            // pending still awaiting here predates the last disable or
            // uninstall (an uninstall rejects none). It must not become
            // approvable again.
            let mut next = state.clone();
            let awaiting: Vec<_> = next
                .pending
                .iter()
                .filter(|pending| pending.state == PendingState::AwaitingApproval)
                .map(|pending| (pending.pending_id, pending.sas_generation))
                .collect();
            for (pending_id, generation) in awaiting {
                next = next.reject_pending(pending_id, generation, at)?;
            }
            let next = cancel_active_offers(next, at)?;
            let wall_ms = next
                .last_accepted_wall_unix_seconds()
                .checked_mul(1_000)
                .ok_or(SecurityError::Bounds)?;
            if next
                .offers
                .iter()
                .any(|offer| offer.state == OfferState::Active && offer.expires_at_ms > wall_ms)
            {
                gated = true;
                return Err(SecurityError::Conflict);
            }
            next.enable_sharing()
        });
        if gated {
            return Err(StorageError::Busy);
        }
        result
    }

    /// Asks the producer `responder_static` for one report with
    /// `report_peer::fetch` (this runtime's ledger and fetch limiter). On
    /// success the body goes into the receiver cache, under a key built
    /// from the record used for the fetch, until the earlier of now + 30
    /// days and the grant's `expiresAt`; a failed cache write changes
    /// nothing in the result. On `Revoked` or `Expired` the record is first
    /// marked so in `peers.json` (durable; a refusal or failure does not
    /// stop what follows), then every cache entry of that producer is
    /// removed, then the error is returned. Any other error leaves the
    /// cache alone.
    pub fn pull(
        &self,
        responder_static: &[u8; 32],
        query: &ReportQuery,
    ) -> Result<Fetched, PullError> {
        let record = self.peer(responder_static).ok_or(PullError::NoPeer)?;
        let result = fetch(
            &record,
            query,
            &self.inner.store,
            &self.inner.ledger,
            &self.fetches,
        );
        match &result {
            Ok(fetched) => self.remember(&record, query, &fetched.body),
            Err(FetchError::Revoked) => self.forget(&record, PeerState::Revoked),
            Err(FetchError::Expired) => self.forget(&record, PeerState::Expired),
            Err(_) => {}
        }
        result.map_err(PullError::Fetch)
    }

    /// The cached body of the last successful [`pull`](Self::pull) of
    /// `query` from `responder_static`, or `None`: no cache, no readable
    /// record, a record no longer usable (`peer_store::usable`), an
    /// unreadable clock, or no valid unexpired entry under the key of that
    /// same record. Expiry is checked against the effective now
    /// (`max(osNow, lastAcceptedWall)`).
    pub fn last_good(
        &self,
        responder_static: &[u8; 32],
        query: &ReportQuery,
    ) -> Result<Option<CachedBody>, StorageError> {
        let (Some(cache), Some(record)) = (&self.inner.cache, self.peer(responder_static)) else {
            return Ok(None);
        };
        if !usable(&record, &self.inner.store) {
            return Ok(None);
        }
        let Some(now_ms) = effective_now_ms(&self.inner) else {
            return Ok(None);
        };
        cache.get(&cache_key(&record, query), now_ms)
    }

    fn peer(&self, responder_static: &[u8; 32]) -> Option<PeerRecord> {
        self.peers
            .peers()
            .ok()?
            .into_iter()
            .find(|peer| peer.responder_static == *responder_static)
    }

    fn remember(&self, record: &PeerRecord, query: &ReportQuery, body: &[u8]) {
        let (Some(cache), Some(now_ms)) = (&self.inner.cache, effective_now_ms(&self.inner)) else {
            return;
        };
        let expires_at_ms = now_ms
            .saturating_add(CACHE_RETENTION_MILLIS)
            .min(record.expires_at_ms);
        let _ = cache.put(&cache_key(record, query), body, now_ms, expires_at_ms);
    }

    /// `set_state` first: read access ends once that is durable. A removal
    /// that fails after it only leaves files no usable record can name.
    fn forget(&self, record: &PeerRecord, state: PeerState) {
        let _ = self
            .peers
            .set_state(&record.responder_static, &record.grant_id, state);
        if let Some(cache) = &self.inner.cache {
            let _ = cache.remove_peer(&hex_encode(&record.responder_static));
        }
    }

    /// Blocks until shutdown is asked for: control `shutdown`, or
    /// [`stop`](Self::stop). Call `stop` afterwards.
    pub fn wait(&self) {
        let signal = lock(&self.inner.signal);
        drop(
            self.inner
                .wake
                .wait_while(signal, |signal| !signal.shutdown)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Stops the control server first (joining every worker that could
    /// run a hook), then the listener, then the housekeeping thread, which
    /// takes a final checkpoint. Returns after every thread has ended.
    /// Idempotent. The control socket file stays; the next start replaces
    /// it.
    pub fn stop(&self) {
        let _serial = lock(&self.stop_serial);
        request_shutdown(&self.inner);
        if let Some(mut server) = lock(&self.control).take() {
            server.stop();
        }
        {
            let mut slot = lock(&self.inner.listener);
            slot.stopping = true;
            if let Some(mut listener) = slot.listener.take() {
                listener.stop();
            }
        }
        lock(&self.inner.signal).halt = true;
        self.inner.wake.notify_all();
        if let Some(handle) = lock(&self.housekeeping).take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The control `shutdown` hook: a flag and a wake-up only. Stopping the
/// server here would join the connection thread this runs on.
fn request_shutdown(inner: &Inner) {
    lock(&inner.signal).shutdown = true;
    inner.wake.notify_all();
}

/// The `listenConfigure` hook, also run once at start and by housekeeping
/// while a `bindHost` is set and no listener runs: under the slot mutex,
/// unless stopping, keeps a listener already bound to the address stored
/// now; otherwise stops the old listener and starts one on that address
/// (`Listener::start` reads it). An address that does not bind leaves no
/// listener; no other address is tried.
fn restart_listener(inner: &Inner) {
    #[cfg(test)]
    if let Some(gate) = &inner.before_restart {
        gate();
    }
    let mut slot = lock(&inner.listener);
    if slot.stopping {
        return;
    }
    if let Some(old) = &slot.listener {
        let stored = inner.store.state().ok().and_then(|state| {
            let config = state.config;
            bind_address(config.bind_host.as_deref()?, config.bind_port).ok()
        });
        if stored == Some(old.local_addr()) {
            return;
        }
    }
    if let Some(mut old) = slot.listener.take() {
        old.stop();
    }
    slot.listener = Listener::start(
        Arc::clone(&inner.store),
        inner.ledger.clone(),
        Arc::clone(&inner.limiter),
        Arc::clone(&inner.clock),
        Arc::clone(&inner.reports),
    )
    .ok();
}

/// `cancel_offer` on every active offer of `state`; a `Bounds` refusal
/// keeps the state before that cancel.
fn cancel_active_offers(
    mut state: ReferenceState,
    at_ms: i64,
) -> Result<ReferenceState, SecurityError> {
    let active: Vec<_> = state
        .offers
        .iter()
        .filter(|offer| offer.state == OfferState::Active)
        .map(|offer| offer.offer_id)
        .collect();
    for offer_id in active {
        match state.cancel_offer(offer_id, at_ms) {
            Ok(next) => state = next,
            Err(SecurityError::Bounds) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(state)
}

/// The receiver cache key of `query` from the producer of `record`: every
/// field from that record, the query and the protocol revisions, as
/// `report_peer::fetch` builds the request.
fn cache_key(record: &PeerRecord, query: &ReportQuery) -> CacheKey {
    CacheKey {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: record.auth_epoch,
        clients: query.clients.clone(),
        end_date_exclusive: query.end_date_exclusive.clone(),
        endpoint: query.endpoint.into(),
        grant_id: hex_encode(&record.grant_id),
        peer_static: hex_encode(&record.responder_static),
        report_schema: REPORT_SCHEMA_VERSION,
        role: CacheRole::Receiver,
        source_scope_generation: record.source_scope_generation,
        start_date: query.start_date.clone(),
        timezone: query.timezone.clone(),
        tzdb_revision: TZDB_REVISION.into(),
    }
}

/// `max(osNow, lastAcceptedWall)` in ms; `None` when the clock or the
/// state is unreadable, or while the clock is anomalous: a cache read at a
/// wrong time would delete entries that are still valid, and a write would
/// stamp them with it. Housekeeping skips such a round for the same reason.
fn effective_now_ms(inner: &Inner) -> Option<i64> {
    let os_now = inner.clock.os_now_seconds().ok()?;
    let wall = inner
        .store
        .state()
        .ok()?
        .reference
        .last_accepted_wall_unix_seconds();
    let status = clock_status(os_now, wall);
    if status.anomaly {
        return None;
    }
    status.effective_now.checked_mul(1_000)
}

/// A terminal record's timestamp: the effective now, or the durable wall
/// while the OS clock is unavailable or anomalous (the rule of
/// `spec/control-v1.md`, "Commands").
fn record_ms(state: &ReferenceState, os_now: Option<i64>) -> Result<i64, SecurityError> {
    let wall = state.last_accepted_wall_unix_seconds();
    let now = os_now.map_or(wall, |os_now| {
        let status = clock_status(os_now, wall);
        if status.anomaly {
            wall
        } else {
            status.effective_now
        }
    });
    now.checked_mul(1_000).ok_or(SecurityError::Bounds)
}

fn housekeeping(inner: &Inner) {
    loop {
        let pause = round(inner);
        let signal = lock(&inner.signal);
        let (signal, _) = inner
            .wake
            .wait_timeout_while(signal, pause, |signal| !signal.halt)
            .unwrap_or_else(PoisonError::into_inner);
        if signal.halt {
            break;
        }
    }
    if let Ok(os_now) = inner.clock.os_now_seconds() {
        let _ = inner.store.checkpoint(os_now);
    }
}

/// One round. First, while a `bindHost` is stored and no listener runs (an
/// earlier bind failed), one listener restart. Then SEC-SPLIT-02: the
/// checkpoint, the receiver cache's `purge_expired`, then the frozen
/// `expire_one` for every active offer or grant and awaiting pending whose
/// `expiresAt` the effective now has reached. Skipped (nothing written)
/// when the clock is unreadable or anomalous or the store is
/// sticky-unknown. Failures are ignored: the next round tries again.
/// Returns the pause before the next round: the period, or less when
/// something not yet expired expires sooner, never below [`MIN_PAUSE`]
/// unless the period is.
fn round(inner: &Inner) -> Duration {
    let period = inner.period;
    // `restart_listener` itself returns while stopping.
    let idle = lock(&inner.listener).listener.is_none();
    if idle
        && inner
            .store
            .state()
            .is_ok_and(|state| state.config.bind_host.is_some())
    {
        restart_listener(inner);
    }
    let Ok(os_now) = inner.clock.os_now_seconds() else {
        return period;
    };
    let Ok(state) = inner.store.state() else {
        return period;
    };
    let reference = &state.reference;
    let status = clock_status(os_now, reference.last_accepted_wall_unix_seconds());
    if status.anomaly {
        return period;
    }
    let Some(now_ms) = status.effective_now.checked_mul(1_000) else {
        return period;
    };
    let _ = inner.store.checkpoint(os_now);
    if let Some(cache) = &inner.cache {
        let _ = cache.purge_expired(now_ms);
    }
    let mut next_expiry = None::<i64>;
    let mut due = Vec::new();
    let records = reference
        .offers
        .iter()
        .filter(|offer| offer.state == OfferState::Active)
        .map(|offer| (offer.offer_id, offer.expires_at_ms))
        .chain(
            reference
                .pending
                .iter()
                .filter(|pending| pending.state == PendingState::AwaitingApproval)
                .map(|pending| (pending.pending_id, pending.expires_at_ms)),
        )
        .chain(
            reference
                .grants
                .iter()
                .filter(|grant| grant.state == GrantState::Active)
                .map(|grant| (grant.grant_id, grant.expires_at_ms)),
        );
    for (record_id, expires_at_ms) in records {
        if now_ms >= expires_at_ms {
            due.push(record_id);
        } else {
            next_expiry = Some(next_expiry.map_or(expires_at_ms, |next| next.min(expires_at_ms)));
        }
    }
    for record_id in due {
        let _ = inner
            .store
            .transition(|state| state.expire_one(record_id, now_ms));
    }
    next_expiry
        .and_then(|expiry| u64::try_from(expiry - now_ms).ok())
        .map_or(period, |millis| {
            Duration::from_millis(millis).max(MIN_PAUSE).min(period)
        })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use std::{
        fs,
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::Instant,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        control::{Client, Command, LISTEN_CONFIGURE, OFFER_CREATE, REVOKE},
        noise::StaticKey,
        pairing::{ClaimAttempts, PairingClient, approve},
        report::{AgentsRecord, Endpoint, ReportRequest, ReportResponse, encode_response},
        report_peer::{NoSource, SourceError},
        secure_fs::{
            Step,
            seams::{self, Reset},
        },
        state_store::Secret32,
    };

    /// A short temporary home, so the socket path fits `sun_path`.
    struct ShortHome(PathBuf);

    impl ShortHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = PathBuf::from(format!(
                "/tmp/sru-{}-{}",
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

    fn free_port() -> u16 {
        TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn listening(port: u16) -> bool {
        TcpStream::connect(("127.0.0.1", port)).is_ok()
    }

    /// SA-2B2c2 acceptance (6b), first half: `stop()` while a
    /// `listenConfigure` hook is held (by the test-only gate, before it
    /// takes the slot mutex). `stop()` cannot return while the hook is
    /// held, and once released, it returns with neither the old nor the
    /// new port listening: no listener outlives `stop()`.
    #[test]
    fn stop_during_a_held_listen_configure_hook_leaves_no_port_open() {
        let home = ShortHome::new();
        let (old_port, new_port) = (free_port(), free_port());
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_armed = Arc::clone(&armed);
        let gate: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if gate_armed.load(Ordering::SeqCst) {
                let _ = lock(&entered_tx).send(());
                let _ = lock(&release_rx).recv();
            }
        });
        let root = SecureRoot::open_under(&home.0, &["r"]).unwrap();
        let runtime = Arc::new(
            Runtime::start_inner(root, Arc::new(NoSource), Options::default(), Some(gate)).unwrap(),
        );
        let state = runtime.store().state().unwrap();
        runtime
            .store()
            .set_listen_config(Some("127.0.0.1".into()), old_port, None)
            .unwrap();
        restart_listener(&runtime.inner);
        assert!(listening(old_port));
        armed.store(true, Ordering::SeqCst);

        let client = Client::new(
            Secret32::new(*state.control_token.expose()),
            runtime.socket_path().to_path_buf(),
        );
        let configure = thread::spawn(move || {
            client.call(&Command {
                id: LISTEN_CONFIGURE,
                body: json!({"bindHost": "127.0.0.1", "bindPort": new_port}),
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the hook was not reached");
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let stopper = Arc::clone(&runtime);
        let stop = thread::spawn(move || {
            stopper.stop();
            stopped_tx.send(Instant::now()).unwrap();
        });
        assert!(
            stopped_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "stop() returned while a hook was still running"
        );
        let released = Instant::now();
        release_tx.send(()).unwrap();
        let stopped = stopped_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stop() did not return");
        assert!(stopped >= released);
        stop.join().unwrap();
        assert!(!listening(new_port), "the new port outlived stop()");
        assert!(!listening(old_port), "the old port outlived stop()");
        // The client's call ends either way (reply or closed connection).
        let _ = configure.join().unwrap();
        // The config was committed before the hook ran.
        assert_eq!(runtime.store().state().unwrap().config.bind_port, new_port);
        assert!(runtime.listener_addr().is_none());
    }

    /// An empty agents report echoing the request.
    struct Empty;

    impl ReportSource for Empty {
        fn report(&self, request: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
            encode_response(&ReportResponse::<AgentsRecord>::from_request(
                request,
                Vec::new(),
                false,
            ))
            .map_err(|_| SourceError)
        }
    }

    /// Starts a runtime on `home`, retrying while a reopen still sees the
    /// owner lock.
    fn start(home: &ShortHome, source: Arc<dyn ReportSource>) -> Runtime {
        for _ in 0..200 {
            let root = SecureRoot::open_under(&home.0, &["r"]);
            match root.and_then(|root| {
                Runtime::start(root, Arc::clone(&source), Options::default())
                    .map_err(|_| StorageError::Busy)
            }) {
                Ok(runtime) => return runtime,
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("the runtime did not start");
    }

    fn call(runtime: &Runtime, id: u16, body: serde_json::Value) -> serde_json::Value {
        let token = *runtime.store().state().unwrap().control_token.expose();
        let reply = Client::new(Secret32::new(token), runtime.socket_path().to_path_buf())
            .call(&Command { id, body })
            .unwrap();
        assert_eq!(reply.code, crate::control::OK);
        reply.data
    }

    fn receiver_files(home: &ShortHome) -> usize {
        fs::read_dir(home.0.join("r"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("rcache-")
            })
            .count()
    }

    /// SA-2B3b acceptance (3c): the producer answers `revoked` and the
    /// process dies at the first cache `unlink` (that step and every one
    /// after it on this thread fail). After a restart `last_good` is
    /// `None`, although the entry is still on disk: `peers.json` was
    /// marked before the cache was touched.
    #[test]
    fn a_crash_at_the_cache_unlink_after_revoked_leaves_nothing_readable() {
        let (producer_home, receiver_home) = (ShortHome::new(), ShortHome::new());
        let producer = start(&producer_home, Arc::new(Empty));
        let port = free_port();
        call(
            &producer,
            LISTEN_CONFIGURE,
            json!({"bindHost": "127.0.0.1", "bindPort": port}),
        );
        producer.enable_sharing().unwrap();
        let offer = call(&producer, OFFER_CREATE, json!({"ttlSeconds": 600}));
        let url = offer["pairUrl"].as_str().unwrap().to_owned();

        let receiver = start(&receiver_home, Arc::new(NoSource));
        let identity = StaticKey::from_state(&receiver.store().state().unwrap()).unwrap();
        let (ledger, clock) = (MemoryLedger::default(), SystemClock);
        let client = PairingClient {
            identity: &identity,
            ledger: &ledger,
            clock: &clock,
        };
        let now = clock.os_now_seconds().unwrap();
        let claimed = client
            .claim(&url, now * 1_000, &mut ClaimAttempts::default())
            .unwrap();
        approve(producer.store(), claimed.pending_id, 1, true, now).unwrap();
        let confirmed = client.poll(&claimed).unwrap();
        receiver
            .peers()
            .upsert(PeerRecord::from_confirmed(&confirmed, None, now * 1_000))
            .unwrap();
        let producer_static = confirmed.responder_static;
        let query = ReportQuery {
            endpoint: Endpoint::Agents,
            start_date: "2025-01-01".into(),
            end_date_exclusive: "2025-02-01".into(),
            timezone: "UTC".into(),
            clients: vec![],
        };
        receiver.pull(&producer_static, &query).unwrap();
        assert_eq!(receiver_files(&receiver_home), 1);
        call(
            &producer,
            REVOKE,
            json!({"grantId": hex_encode(&confirmed.grant_id)}),
        );

        let _reset = Reset;
        let mut crashed = false;
        seams::set_hook(Some(Box::new(move |step| {
            crashed |= step == Step::Unlink;
            if crashed {
                Err(std::io::Error::other("crashed"))
            } else {
                Ok(())
            }
        })));
        assert_eq!(
            receiver.pull(&producer_static, &query).err(),
            Some(PullError::Fetch(FetchError::Revoked))
        );
        seams::set_hook(None);
        // The crash happened: the entry is still there.
        assert_eq!(receiver_files(&receiver_home), 1);
        drop(receiver);

        let receiver = start(&receiver_home, Arc::new(NoSource));
        assert_eq!(receiver_files(&receiver_home), 1);
        assert!(
            receiver
                .last_good(&producer_static, &query)
                .unwrap()
                .is_none(),
            "a revoked producer's entry is readable after the crash"
        );
    }
}
