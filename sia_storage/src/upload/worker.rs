//! The worker half of the upload.
//!
//! One task per connected host. A worker asks the request queue for a shard it
//! is allowed to write, writes it, and reports it. Nothing hands work to a
//! host, so a host that is connected is never idle while shards are waiting,
//! and a host keeps being used across slabs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use log::debug;
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::signing::PublicKey;

use crate::app_client::{self, SectorPinParams};
use crate::hosts::{Hosts, RPCError, RPC_IDLE_TIMEOUT};
use crate::pool::{BanReason, HostPool, HostStats, HostView, LeaveReason};
use crate::schedule::{FinishedSlab, RequestQueue, SlabSeed};
use crate::slabs::Slab;
use crate::task::AbortOnDropHandle;
use crate::time::{sleep, Duration, Instant};
use crate::upload::{pin_uploaded_slab, UploadError, UploadLimiter};
use crate::{
    AppKey, Sector, ShardAttemptCallback, ShardAttemptInfo, ShardProgress, ShardProgressCallback,
};

/// How many hosts the pool keeps connected.
pub(crate) const WORKER_TARGET: usize = 64;

/// How long a worker with nothing to do sleeps before looking again.
const PARK: Duration = Duration::from_millis(100);

/// Host statistics for the pool's dial score.
///
/// The only number the pool uses is the write rate, which the metric layer does
/// not expose yet, so every candidate is scored on its own dial record. The pool
/// still ranks by that record, which is what the bans are for.
pub(crate) struct HostsView(pub(crate) Hosts);

impl HostView for HostsView {
    fn stats(&self, _host: &PublicKey) -> HostStats {
        HostStats::unsampled()
    }
}

/// Everything the workers share with the upload that owns them.
pub(crate) struct WorkerState {
    queue: Mutex<RequestQueue>,
    pool: Mutex<HostPool<HostsView>>,
    limiter: Arc<UploadLimiter>,
    client: Hosts,
    api_client: app_client::Client,
    app_key: Arc<AppKey>,
    /// Finished slabs, indexed by slab order. Filled by whichever worker pins
    /// the last shard of a slab.
    pinned: Mutex<Vec<Option<Slab>>>,
    /// Slabs handed to the schedule, and slabs pinned.
    registered: AtomicUsize,
    finished: AtomicUsize,
    /// Slabs holding shard memory right now, bounded by `max_buffered`.
    buffered: AtomicUsize,
    max_buffered: usize,
    closed: AtomicBool,
    /// Set when a slab could not be pinned and no retry can help.
    stalled: AtomicBool,
    /// The error that stopped the upload, so `finish` can return it rather than
    /// a generic one.
    failure: Mutex<Option<UploadError>>,
    /// Pin attempts per slab, for the stale retry cap.
    pin_attempts: Mutex<HashMap<u64, usize>>,
    workers: Mutex<Vec<AbortOnDropHandle<()>>>,
    /// A shard became available.
    work: tokio::sync::Notify,
    /// A slab was pinned, or the upload stalled.
    done: tokio::sync::Notify,
    /// A slab's memory was released.
    slot: tokio::sync::Notify,
    progress: Option<ShardProgressCallback>,
    attempt: Option<ShardAttemptCallback>,
}

impl WorkerState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client: Hosts,
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
        limiter: Arc<UploadLimiter>,
        total_shards: usize,
        max_buffered: usize,
        progress: Option<ShardProgressCallback>,
        attempt: Option<ShardAttemptCallback>,
    ) -> Self {
        let candidates = client.upload_eligible_hosts();
        Self {
            queue: Mutex::new(RequestQueue::new()),
            pool: Mutex::new(HostPool::new(
                HostsView(client.clone()),
                candidates,
                WORKER_TARGET,
            )),
            limiter,
            client,
            api_client,
            app_key,
            pinned: Mutex::new(Vec::new()),
            registered: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            buffered: AtomicUsize::new(0),
            max_buffered,
            closed: AtomicBool::new(false),
            stalled: AtomicBool::new(false),
            failure: Mutex::new(None),
            pin_attempts: Mutex::new(HashMap::new()),
            workers: Mutex::new(Vec::new()),
            work: tokio::sync::Notify::new(),
            done: tokio::sync::Notify::new(),
            slot: tokio::sync::Notify::new(),
            progress,
            attempt,
        }
    }

    /// Registers a slab and returns its place in the upload.
    pub(crate) fn register(&self, shards: Vec<bytes::Bytes>, seed: SlabSeed) -> u64 {
        let id = self.queue.lock().unwrap().add_slab(shards, seed);
        {
            let mut pinned = self.pinned.lock().unwrap();
            let index = (id.0 as usize).saturating_sub(1);
            if index >= pinned.len() {
                pinned.resize(index + 1, None);
            }
        }
        self.registered.fetch_add(1, Ordering::SeqCst);
        id.0
    }

    pub(crate) fn slack_available(&self) -> bool {
        self.buffered.load(Ordering::SeqCst) < self.max_buffered
    }

    pub(crate) fn take_slot(&self) {
        self.buffered.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn release_slot(&self) {
        self.buffered.fetch_sub(1, Ordering::SeqCst);
        self.slot.notify_waiters();
    }

    pub(crate) fn notify_work(&self) {
        self.work.notify_waiters();
    }

    pub(crate) fn registered(&self) -> usize {
        self.registered.load(Ordering::SeqCst)
    }

    pub(crate) fn finished(&self) -> usize {
        self.finished.load(Ordering::SeqCst)
    }

    pub(crate) fn stalled(&self) -> bool {
        self.stalled.load(Ordering::SeqCst)
    }

    /// The error that stopped the upload, if one was recorded.
    pub(crate) fn take_failure(&self) -> Option<UploadError> {
        self.failure.lock().unwrap().take()
    }

    /// Stops the upload with a reason.
    pub(crate) fn stall(&self, error: UploadError) {
        let mut failure = self.failure.lock().unwrap();
        if failure.is_none() {
            *failure = Some(error);
        }
        drop(failure);
        self.stalled.store(true, Ordering::SeqCst);
        self.done.notify_waiters();
    }

    /// Wakes a caller waiting on [`WorkerState::done`].
    pub(crate) fn done_notify(&self) -> tokio::sync::futures::Notified<'_> {
        self.done.notified()
    }

    pub(crate) fn slot_notify(&self) -> tokio::sync::futures::Notified<'_> {
        self.slot.notified()
    }

    /// Stops every worker and returns the pinned slabs in order.
    pub(crate) fn shutdown(&self) -> Vec<Slab> {
        self.closed.store(true, Ordering::SeqCst);
        self.work.notify_waiters();
        // Dropping an AbortOnDropHandle aborts the task behind it.
        let workers: Vec<AbortOnDropHandle<()>> = std::mem::take(&mut *self.workers.lock().unwrap());
        drop(workers);
        let pinned = self.pinned.lock().unwrap();
        pinned.iter().flatten().cloned().collect()
    }

    fn progress(&self) -> Option<&ShardProgressCallback> {
        self.progress.as_ref()
    }

    fn attempt(&self) -> Option<&ShardAttemptCallback> {
        self.attempt.as_ref()
    }
}

/// Dials as many hosts as the pool is short by, and starts a worker for each.
///
/// Idempotent: the pool reserves what it hands out, so a second call while a
/// dial is in flight returns nothing for that host.
pub(crate) fn ensure_workers(state: &Arc<WorkerState>) {
    if state.closed.load(Ordering::SeqCst) {
        return;
    }
    let planned = state.pool.lock().unwrap().plan();
    spawn_dials(state, planned);
}

fn spawn_dials(state: &Arc<WorkerState>, planned: Vec<PublicKey>) {
    for host in planned {
        let worker_state = Arc::clone(state);
        let handle = AbortOnDropHandle::new(maybe_spawn!(async move {
            dial_and_work(worker_state, host).await
        }));
        state.workers.lock().unwrap().push(handle);
    }
}

async fn dial_and_work(state: Arc<WorkerState>, host: PublicKey) {
    let outcome = state.client.connect(host, RPC_IDLE_TIMEOUT).await;
    match outcome {
        Ok(()) => {
            state.pool.lock().unwrap().settle(host, None);
            debug!("[pool] {}", state.pool.lock().unwrap().describe());
            run_worker(state, host).await;
        }
        Err(error) => {
            let reason = dial_reason(&error);
            state.pool.lock().unwrap().settle(host, Some(reason));
            debug!(
                "[pool] {} could not be dialled: {} ({})",
                short(&host),
                reason.as_str(),
                state.pool.lock().unwrap().describe(),
            );
            // The pool is short again, so ask for the next candidate.
            ensure_workers(&state);
        }
    }
}

async fn run_worker(state: Arc<WorkerState>, host: PublicKey) {
    loop {
        if state.closed.load(Ordering::SeqCst) {
            return;
        }
        // The permit comes before the shard, so a worker never holds sector
        // memory it is not allowed to send. That is what keeps the buffered
        // bytes bounded by the write gate.
        let permit = state.limiter.acquire().await;
        if state.closed.load(Ordering::SeqCst) {
            drop(permit);
            return;
        }

        let request = { state.queue.lock().unwrap().take(&host) };
        let Some(request) = request else {
            drop(permit);
            park(&state).await;
            continue;
        };

        let started = Instant::now();
        let uploaded_at = Utc::now();
        let slab_index = (request.slab.0 as usize).saturating_sub(1);
        let shard_index = request.shard;
        let data = request.data.clone();
        let result = state
            .client
            .write_sector(host, &state.app_key.0, data, RPC_IDLE_TIMEOUT)
            .await;

        match result {
            Ok(root) => {
                if let Some(callback) = state.progress() {
                    callback(ShardProgress {
                        host_key: host,
                        shard_index,
                        slab_index,
                        shard_size: SECTOR_SIZE,
                        elapsed: started.elapsed(),
                    });
                }
                let placed = SectorPinParams {
                    sector: Sector { root, host_key: host },
                    uploaded_at: Some(uploaded_at),
                };
                let finished = { state.queue.lock().unwrap().placed(&host, &request, placed) };
                drop(permit);
                if let Some(finished) = finished {
                    pin(&state, finished).await;
                }
            }
            Err(error) => {
                drop(permit);
                let reason = write_reason(&error);
                if let Some(callback) = state.attempt() {
                    callback(ShardAttemptInfo {
                        host_key: host,
                        shard_index,
                        slab_index,
                        ok: false,
                        elapsed: started.elapsed(),
                        error: Some(error.to_string()),
                        in_flight: 0,
                        committed: 0,
                        waiting: 0,
                        retrying: 0,
                        limit: 0,
                    });
                }
                state.pool.lock().unwrap().leave(host, LeaveReason::Failed(reason));
                state.queue.lock().unwrap().failed(request);
                debug!(
                    "[pool] banned {}: {} ({})",
                    short(&host),
                    reason.as_str(),
                    state.pool.lock().unwrap().describe(),
                );
                state.work.notify_waiters();
                ensure_workers(&state);
                // This host is out, so its worker ends here.
                return;
            }
        }
    }
}

/// Sleeps until there is work.
///
/// Parking is normal: the write gate only lets so many shards run, and a host
/// that already served a slab has nothing to take from it. The upload is stuck
/// only when no connected host could write any pending shard and there is no
/// candidate left to dial, which is what this checks.
async fn park(state: &Arc<WorkerState>) {
    if state.closed.load(Ordering::SeqCst) {
        return;
    }
    let pending = state.queue.lock().unwrap().pending();
    if pending > 0 {
        let connected: Vec<PublicKey> = {
            let pool = state.pool.lock().unwrap();
            pool.workers().copied().collect()
        };
        let servable = state.queue.lock().unwrap().servable_by(&connected);
        if !servable {
            // Every connected host has served the slab that still wants shards,
            // so one more host is the only way forward.
            let extra = state.pool.lock().unwrap().plan_extra(1);
            if extra.is_empty() {
                debug!(
                    "[pool] stalled: {pending} shards no connected host may write, and no candidate left",
                );
                state.stall(UploadError::NotEnoughShards(
                    0,
                    state.registered().min(u8::MAX as usize) as u8,
                ));
            } else {
                debug!("[pool] dialling one more host for the {pending} remaining shards");
                spawn_dials(state, extra);
            }
        }
    }
    tokio::select! {
        _ = state.work.notified() => {},
        _ = sleep(PARK) => {},
    }
}

async fn pin(state: &Arc<WorkerState>, finished: FinishedSlab) {
    let index = (finished.id.0 as usize).saturating_sub(1);
    let length = finished.seed.length;
    match pin_uploaded_slab(&state.api_client, &state.app_key, finished.pin.clone()).await {
        Ok(()) => {
            let slab = Slab {
                length,
                ..Slab::from(&finished.pin)
            };
            {
                let mut pinned = state.pinned.lock().unwrap();
                if index < pinned.len() {
                    pinned[index] = Some(slab);
                }
            }
            state.release_slot();
            let done = state.finished.fetch_add(1, Ordering::SeqCst) + 1;
            debug!(
                "[upload] slab {} pinned ({done} of {})",
                finished.id.0,
                state.registered(),
            );
            state.done.notify_waiters();
        }
        Err(UploadError::ApiError(error)) if error.is_slab_upload_too_old() => {
            // The indexer refused it for age. The bytes are still here, so the
            // same shards go out again rather than being encoded once more.
            let attempts = {
                let mut attempts = state.pin_attempts.lock().unwrap();
                let count = attempts.entry(finished.id.0).or_insert(0);
                *count += 1;
                *count
            };
            if attempts >= super::MAX_SLAB_ATTEMPTS {
                debug!(
                    "[upload] slab {} was stale {attempts} times, giving up",
                    finished.id.0,
                );
                state.stall(UploadError::StaleSlab(attempts));
                return;
            }
            debug!(
                "[upload] slab {} was stale, sending its shards again (attempt {attempts})",
                finished.id.0,
            );
            state
                .queue
                .lock()
                .unwrap()
                .readd_slab(finished.id, finished.order, finished.shards, finished.seed);
            state.work.notify_waiters();
        }
        Err(error) => {
            debug!("[upload] slab {} could not be pinned: {error}", finished.id.0);
            state.stall(error);
        }
    }
}

/// A failed write. Both reasons ban the host; the difference is only what the
/// log says about why.
fn write_reason(error: &RPCError) -> BanReason {
    match error {
        RPCError::Rhp(inner) if inner.is_timeout() => BanReason::TransferTimeout,
        _ => BanReason::WriteFailed,
    }
}

/// A failed dial. A timeout and a refusal ban identically; only the log word
/// differs, so the message decides it.
fn dial_reason(error: &RPCError) -> BanReason {
    if error.to_string().contains("timeout") {
        BanReason::DialTimeout
    } else {
        BanReason::DialRefused
    }
}

fn short(host: &PublicKey) -> String {
    host.to_string()
        .trim_start_matches("ed25519:")
        .chars()
        .take(8)
        .collect()
}
