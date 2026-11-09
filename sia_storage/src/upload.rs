use std::collections::{HashMap, VecDeque};
use std::io;
#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::app_client::{self, SlabPinParams};
use crate::congestion::{InflightController, SamplePermit};
use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::schedule::SlabId;
use crate::erasure_coding::{self, ErasureCoder, SlabData, SlabReader};
use crate::hosts::{QueueError, RPCError};
#[cfg(test)]
use crate::slabs::SlabVersion;
use crate::time::{Duration, Instant, sleep};
use crate::{
    AppKey, Download, DownloadOptions, Hosts, Object, PackedUploadOptions, Slab, UploadOptions,
};
use bytes::Bytes;
use log::debug;
use sia_core::signing::PublicKey;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Semaphore, oneshot};

pub(crate) mod slab;
mod worker;

/// How many slabs may be encoding parity at once. Two keeps the encoder ahead of
/// the writers while bounding the plaintext it holds to two slabs.
const ENCODERS_IN_FLIGHT: usize = 2;
/// Parity shards produced per pass over a slab. Five holds 20 MiB of output and
/// reads the slab four times, which is the balance measured in
/// docs/upload-bytes.md.
const PARITY_BATCH: usize = 5;
/// How many produced shards may wait for a host before the reader pauses. This is
/// the backpressure the old buffered-slab window provided: without it the queue
/// grows as fast as the encoder runs and every shard of the file is held at once.
const QUEUE_HIGH_WATER: usize = 20;

const INITIAL_INFLIGHT: usize = 8;
const MIN_INFLIGHT: usize = 2;

/// The ceiling the inflight controller may raise to, in shards. It bounds write
/// concurrency, and therefore how many written-but-unacknowledged shards are
/// held. Sixteen keeps the streams that share the uplink few enough that each
/// keeps making progress: with ninety allowed, a 4 MiB write could go six
/// seconds without a byte and the host closed the stream as idle.
const MAX_INFLIGHT: usize = 16;

/// Gates concurrent shard uploads at the [`InflightController`]'s current
/// limit. Replaces a fixed semaphore so the limit can adapt while uploads are
/// in flight.
///
/// Parked workers are served first come, first served. A worker that just
/// finished a shard cannot barge past one that has been waiting, which is what
/// makes "the worker idle longest takes the next shard" true rather than
/// likely. That matters beyond fairness: a host whose session sits unused long
/// enough closes it, and the session is the expensive thing to get back.
struct UploadLimiter {
    state: Mutex<LimiterState>,
    controller: InflightController,
}

#[derive(Default)]
struct LimiterState {
    inflight: usize,
    /// Workers parked in the order they arrived. A slot is handed straight to
    /// the front of this queue, so the queue is the line.
    waiters: VecDeque<oneshot::Sender<UploadPermit>>,
}

impl UploadLimiter {
    fn new(initial: usize, floor: usize, cap: usize) -> Self {
        Self {
            state: Mutex::new(LimiterState::default()),
            // scale 1: the limited unit (a shard upload) is also the sampled unit
            controller: InflightController::new(initial, floor, cap, 1),
        }
    }

    /// Takes a slot, or waits in line for one. The permit is held while the
    /// shard is written, so the caller cannot take work it may not send.
    async fn acquire(self: &Arc<Self>) -> UploadPermit {
        let rx = {
            let mut state = self.state.lock().unwrap();
            if state.waiters.is_empty() && state.inflight < self.controller.limit() {
                state.inflight += 1;
                return UploadPermit {
                    limiter: self.clone(),
                };
            }
            let (tx, rx) = oneshot::channel();
            state.waiters.push_back(tx);
            rx
        };
        // A slot is handed over only to the front of the queue, and only once
        // it has been counted, so this returns a permit that is ready to use.
        rx.await.expect("the limiter outlives its waiters")
    }

    /// Issues a sampling token; capture it at dispatch and hand it back to
    /// [`Self::record`] on completion.
    fn sample(&self) -> SamplePermit {
        self.controller.sample()
    }

    /// Reports a write that hit its deadline. Only lowers the limit, so there
    /// is no slot to hand out.
    fn record_timeout(&self, permit: SamplePermit, host: PublicKey) {
        self.controller.record_timeout(permit, host);
    }

    /// Feeds a completion to the controller and hands any newly opened slots
    /// to the workers that have waited longest.
    fn record(self: &Arc<Self>, permit: SamplePermit, elapsed: Duration, ok: bool) {
        let delta = self.controller.record(permit, elapsed, ok);
        if delta > 0 {
            let mut state = self.state.lock().unwrap();
            self.hand_out(&mut state);
        }
    }

    /// Gives the slot this worker was holding back, then serves the line.
    fn release(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        state.inflight -= 1;
        self.hand_out(&mut state);
    }

    /// Serves parked workers while the gate has room.
    ///
    /// `inflight` counts permits that exist, so the room is always
    /// `limit - inflight`. Counting a grown limit as extra `inflight` instead
    /// would leave the counter above the limit after the controller backs off,
    /// and the gate would never open again. Transfers are not used either: a
    /// permit is only handed over while there is real room, so a shrink takes
    /// effect on the next release.
    fn hand_out(self: &Arc<Self>, state: &mut LimiterState) {
        while state.inflight < self.controller.limit() {
            let Some(tx) = state.waiters.pop_front() else {
                break;
            };
            state.inflight += 1;
            match tx.send(UploadPermit {
                limiter: Arc::clone(self),
            }) {
                Ok(()) => {}
                Err(permit) => {
                    // That worker gave up while we were handing it the slot.
                    // The permit in the `Err` would drop and re-enter
                    // `release` holding this lock, so it is forgotten and the
                    // slot given back before the next worker is offered it.
                    std::mem::forget(permit);
                    state.inflight -= 1;
                }
            }
        }
    }
}

/// Permit for one shard-upload attempt. On drop, including task cancellation,
/// it passes the slot to the worker that has waited longest.
struct UploadPermit {
    limiter: Arc<UploadLimiter>,
}

impl Drop for UploadPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

/// Errors that can occur during an upload.
#[derive(Debug, Error)]
pub enum UploadError {
    /// The upload options are invalid.
    #[error("invalid options {0}")]
    InvalidOptions(String),

    /// An I/O error occurred while reading the data to upload.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// A host RPC error occurred during the upload.
    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

    /// The erasure encoder encountered an error.
    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    /// Not enough shards were successfully uploaded.
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    /// The indexer refused the slab as too old to pin. The shards are gone
    /// from the hosts, and nothing is kept to send them again.
    #[error("indexer rejected slab {0} as too old")]
    SlabTooOld(u64),

    /// The requested range is out of bounds.
    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    /// An error from the host queue.
    #[error("queue error: {0}")]
    QueueError(#[from] QueueError),

    /// An internal task join error.
    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    /// An error from the indexer API.
    #[error("api error: {0}")]
    ApiError(#[from] crate::app_client::Error),

    /// An error downloading existing data while merging an overwrite.
    #[error("download error: {0}")]
    Download(#[from] crate::DownloadError),

    /// The slab ID returned by the indexer does not match the expected value.
    #[error("slab id mismatch")]
    InvalidSlabId,

    /// The upload was cancelled.
    #[error("upload cancelled")]
    Cancelled,
}

/// Maximum number of attempts to pin a single slab — initial request plus
/// retries. The sectors are already on the network by this point, so a
/// transient indexer error should not cost the whole upload.
const MAX_PIN_RETRIES: usize = 3;

/// Delay before the first pin retry. It doubles on each subsequent attempt.
const PIN_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Produces `count` shards starting at `first` from the plaintext data shards.
///
/// This is the encoder helper the coordinator calls: it returns the batch's
/// buffers, so the caller holds only the batch, never the whole slab.
fn encode_batch(
    coder: &ErasureCoder,
    plain: &[Bytes],
    first: usize,
    count: usize,
    size: usize,
) -> Result<Vec<Vec<u8>>, UploadError> {
    let mut out: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; size]).collect();
    {
        let inputs: Vec<&[u8]> = plain.iter().map(|shard| &shard[..]).collect();
        let mut outputs: Vec<&mut [u8]> = out.iter_mut().map(|s| s.as_mut_slice()).collect();
        slab::Encoder::encode_range(coder, &inputs, first, &mut outputs)
            .map_err(UploadError::InvalidOptions)?;
    }
    Ok(out)
}

impl slab::Encoder for ErasureCoder {
    fn encode_range(
        &self,
        data: &[&[u8]],
        first_shard: usize,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        ErasureCoder::encode_range(self, data, first_shard, outputs)
            .map_err(|error| error.to_string())
    }
}

/// Pins a freshly uploaded slab to the indexer, retrying transient errors.
async fn pin_uploaded_slab(
    api_client: &app_client::Client,
    app_key: &AppKey,
    params: SlabPinParams,
) -> Result<(), UploadError> {
    let slab_id = params.digest();
    let params = [params];

    let mut attempt = 0;
    loop {
        match api_client.pin_slabs(&app_key.0, &params).await {
            Ok(ids) => {
                if ids.len() != 1 || ids[0] != slab_id {
                    return Err(UploadError::InvalidSlabId);
                }
                return Ok(());
            }
            Err(e) if attempt + 1 < MAX_PIN_RETRIES && e.is_retryable() => {
                let delay = PIN_RETRY_DELAY * (1 << attempt);
                debug!(
                    "failed to pin slab on attempt {}: {e}; retrying in {delay:?}",
                    attempt + 1,
                );
                sleep(delay).await;
                attempt += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// A single-use streaming upload pipeline. Feed data into it by calling
/// [read](Upload::read) repeatedly, then complete the upload with
/// [finish](Upload::finish) to recover the uploaded slabs.
pub(crate) struct Upload {
    client: Hosts,
    app_key: Arc<AppKey>,
    erasure_coder: Arc<ErasureCoder>,
    total_shards: usize,
    slab_buffer: Option<SlabReader>,
    /// Plaintext of the slabs whose data shards are arriving or being encoded.
    /// Held only until the last parity batch is produced, so memory is bounded by
    /// `ENCODERS_IN_FLIGHT` slabs of data rather than by encoded slabs.
    open: HashMap<SlabId, OpenSlab>,
    /// Slabs encoding parity right now, at most `ENCODERS_IN_FLIGHT`.
    encoders: Arc<Semaphore>,
    /// The worker pool and the request queue. A slab is registered here once it
    /// is encoded, and a connected host pulls its shards.
    state: Arc<worker::WorkerState>,
}

/// A slab whose data shards are arriving or whose parity is being produced.
struct OpenSlab {
    key: EncryptionKey,
    /// The data shards in the clear, which is what the encoder reads.
    plain: Vec<Option<Bytes>>,
    /// Set once the encoder has been started, so the tenth shard cannot start it
    /// twice.
    started: bool,
    /// The encoder slot this slab holds. It is taken when the slab is opened, not
    /// when the encoder task runs, so a slab cannot sit with its plaintext while
    /// its encoder waits for a slot. The underscore says it is held for its drop.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Shard bytes held for as long as it lives, released even when the work that
/// holds them fails part way. Encoding can return early, so the count is kept by
/// a drop rather than by a line at the end of each path.
struct HeldBytes {
    state: Arc<worker::WorkerState>,
    name: String,
    bytes: usize,
}

impl HeldBytes {
    fn new(state: &Arc<worker::WorkerState>, name: String, bytes: usize) -> Self {
        state.held_put(name.clone(), bytes);
        Self {
            state: state.clone(),
            name,
            bytes,
        }
    }

    /// Releases bytes that have moved into the queue.
    fn release(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.state.held_put(self.name.clone(), self.bytes);
    }
}

impl Drop for HeldBytes {
    fn drop(&mut self) {
        self.state.held_remove(&self.name);
    }
}

impl Upload {
    pub(crate) fn new(
        client: Hosts,
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
        options: UploadOptions,
    ) -> Result<Self, UploadError> {
        options.validate()?;
        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        let erasure_coder =
            ErasureCoder::new(options.data_shards as usize, options.parity_shards as usize)
                .map_err(|e| {
                    UploadError::InvalidOptions(format!("failed to create erasure coder: {e}"))
                })?;

        let limiter = Arc::new(UploadLimiter::new(
            INITIAL_INFLIGHT,
            MIN_INFLIGHT,
            MAX_INFLIGHT,
        ));
        let state = Arc::new(worker::WorkerState::new(
            client.clone(),
            api_client.clone(),
            app_key.clone(),
            limiter,
            options.shard_uploaded.clone(),
            options.shard_attempt.clone(),
        ));
        let slab_buffer = SlabReader::new(options.data_shards as usize);
        Ok(Self {
            client,
            app_key,
            slab_buffer: Some(slab_buffer),
            erasure_coder: Arc::new(erasure_coder),
            total_shards,
            open: HashMap::new(),
            encoders: Arc::new(Semaphore::new(ENCODERS_IN_FLIGHT)),
            state,
        })
    }

    /// Errors if the host list can't cover a slab, refreshing it first.
    async fn ensure_hosts(&self) -> Result<(), UploadError> {
        if self.client.ensure_upload_hosts(self.total_shards).await < self.total_shards {
            return Err(QueueError::InsufficientHosts.into());
        }
        Ok(())
    }

    /// Returns the cumulative number of bytes that have landed in the pipeline
    /// across all [read](Self::read) calls, including bytes from reads that
    /// errored part-way. Callers can diff this across a call to recover a
    /// partial count on error and treat the bytes as dead padding.
    /// Encodes and queues a filled slab's shards.
    ///
    /// The data shards go out immediately because they need no arithmetic. Parity
    /// is produced in batches of `PARITY_BATCH` by an encoder task, so the slab is
    /// never held whole: memory is the plaintext of the slabs encoding right now,
    /// which is `ENCODERS_IN_FLIGHT` of them.
    ///
    /// Nothing is assigned to a host here. The schedule holds the shards, and a
    /// connected host pulls the next one it is allowed to write, which is what
    /// lets a host keep working across slabs instead of being spent on one.
    /// Opens a slab for shards that will arrive one at a time, after waiting for
    /// the queue to have room.
    /// A handle that stops this upload from outside.
    pub(crate) fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            state: self.state.clone(),
        }
    }

    pub(crate) async fn open_data_slab(
        &mut self,
        encryption_key: EncryptionKey,
        length: usize,
    ) -> Result<Option<SlabId>, UploadError> {
        // The public per-shard API can be driven without going through `read`,
        // so it gates here too. In the read path the gate has already run and
        // this is a no-op.
        if !self.wait_for_room().await? {
            return Ok(None);
        }
        let min_shards = self.erasure_coder.data_shards();
        debug!(
            "[upload] holding {} shards across {} open slabs",
            self.state.queued(),
            self.open.len(),
        );
        // Hold the encoder slot from here. `wait_for_room` has already checked
        // that one is free, so this does not wait, and taking it now means the
        // reader cannot read a slab whose encoder has no slot.
        let Some(permit) = self.encoders.clone().acquire_owned().await.ok() else {
            return Ok(None);
        };
        let key = encryption_key;
        let seed = crate::schedule::SlabSeed {
            encryption_key: key.clone(),
            length: length as u32,
            min_shards: min_shards as u8,
        };
        let id = self.state.open_slab(seed, self.total_shards);
        self.open.insert(
            id,
            OpenSlab {
                key,
                plain: vec![None; min_shards],
                started: false,
                _permit: Some(permit),
            },
        );
        Ok(Some(id))
    }

    /// Waits while the queue is over its high-water mark. Returns false when the
    /// upload was cancelled while waiting, which means nothing more is opened.
    async fn wait_for_room(&self) -> Result<bool, UploadError> {
        while self.state.queued() > QUEUE_HIGH_WATER
            || self.encoders.available_permits() == 0
        {
            if self.state.is_closed() {
                return Ok(false);
            }
            sleep(Duration::from_millis(50)).await;
        }
        Ok(true)
    }

    /// Queues one data shard, and starts the encoder once the last one is in.
    pub(crate) async fn add_data_shard(
        &mut self,
        id: SlabId,
        index: usize,
        plain: Bytes,
    ) -> Result<(), UploadError> {
        let data_shards = self.erasure_coder.data_shards();
        let Some(open) = self.open.get_mut(&id) else {
            return Err(UploadError::InvalidOptions(format!(
                "slab {} is not open",
                id.0
            )));
        };
        if index >= data_shards || open.plain[index].is_some() {
            return Err(UploadError::InvalidOptions(format!(
                "data shard {index} of slab {} is not expected",
                id.0
            )));
        }
        open.plain[index] = Some(plain.clone());
        let key = open.key.clone();

        // A data shard needs no other shard to be written, so it goes out as it
        // arrives. The slab only has to know that every data shard is in before
        // parity can be produced, which is checked below.
        let mut shard = plain.to_vec();
        encrypt_shard(&key, index as u8, 0, &mut shard);
        if !self
            .state
            .add_shard_waiting(id, index, Bytes::from(shard))
            .await
        {
            // Closed while waiting for room: the shard is dropped with the rest.
            return Ok(());
        }
        worker::ensure_workers(&self.state);
        self.state.notify_work();

        let ready = open.plain.iter().all(Option::is_some)
            && self.state.slab_ready_for_parity(id);
        if ready && !open.started {
            open.started = true;
            // The plaintext moves into the encoder task, which frees it once the
            // last batch is produced.
            if let Some(open) = self.open.remove(&id) {
                self.spawn_encoder(id, open);
            }
        }
        Ok(())
    }

    /// Produces the slab's parity shards in batches, two slabs at a time.
    fn spawn_encoder(&self, id: SlabId, open: OpenSlab) {
        let state = self.state.clone();
        let coder = self.erasure_coder.clone();
        let key = open.key.clone();
        // The slot travels with `open`, which the task owns. Fields drop in
        // declaration order, so the plaintext is released before the slot is,
        // and a slab change cannot double the plaintext.
        let data_shards = self.erasure_coder.data_shards();
        let total = self.total_shards;
        let size = open.plain[0].as_ref().map(|shard| shard.len()).unwrap_or(0);
        maybe_spawn!(async move {
            let encoded: Result<(), UploadError> = async move {
                let started = Instant::now();
                // The plaintext is the encoder's input for every batch; the
                // batches only split its output.
                let inputs: Vec<Bytes> = open.plain.iter().flatten().cloned().collect();
                let plain_bytes: usize = inputs.iter().map(Bytes::len).sum();
                // The reader's entry becomes this slab's plaintext entry.
                state.held_remove("reader");
                let mut plain_held =
                    HeldBytes::new(&state, format!("plain:{}", id.0), plain_bytes);
                for first in (data_shards..total).step_by(PARITY_BATCH) {
                    // Cancelled while encoding: stop before the next batch rather
                    // than finish work whose shards nobody will write.
                    if state.is_closed() {
                        break;
                    }
                    let count = PARITY_BATCH.min(total - first);
                    let batch_coder = coder.clone();
                    // Reference-counted pointers, so a batch costs nothing to hand
                    // to the blocking task.
                    let inputs = inputs.clone();
                    let mut out = maybe_spawn_blocking!({
                        encode_batch(&batch_coder, &inputs, first, count, size)
                    })?;
                    for (offset, shard) in out.iter_mut().enumerate() {
                        encrypt_shard(&key, (first + offset) as u8, 0, shard);
                    }
                    // The batch is held until its shards are queued: it is real
                    // memory at the cap, so the count includes it.
                    let batch_bytes: usize = out.iter().map(Vec::len).sum();
                    let mut batch_held = HeldBytes::new(
                        &state,
                        format!("batch:{}:{}", id.0, first),
                        batch_bytes,
                    );
                    // Parity takes the same queue as data, one shard at a time,
                    // and waits for room rather than overshooting the bound.
                    for (offset, shard) in out.into_iter().enumerate() {
                        #[cfg(test)]
                        state.count_parity();
                        let bytes = shard.len();
                        if !state
                            .add_shard_waiting(id, first + offset, Bytes::from(shard))
                            .await
                        {
                            break;
                        }
                        batch_held.release(bytes);
                    }
                    state.notify_work();
                }
                plain_held.release(plain_bytes);
                debug!("[upload] slab {} encoded in {:?}", id.0, started.elapsed());
                Ok(())
            }
            .await;
            if let Err(error) = encoded {
                debug!("[upload] slab {} could not be encoded: {error}", id.0);
            }
        });
    }

    pub(crate) fn length(&self) -> u64 {
        self.slab_buffer
            .as_ref()
            .map(|b| b.total_length())
            .unwrap_or(0)
    }

    /// Reads up to one slab's worth of data. Returns the bytes consumed and,
    /// when the slab filled, its ten data shards. Waiting for queue room happens
    /// before the read, so nothing is read that cannot be handed on.
    ///
    /// This is the one source of data shards: both `read` and the packed
    /// upload's `add` feed their shards through it.
    pub(crate) async fn next_slab<R: AsyncRead + Unpin>(
        &mut self,
        data_key: EncryptionKey,
        reader: &mut R,
    ) -> Result<(usize, Option<SlabData>), UploadError> {
        if !self.wait_for_room().await? {
            return Ok((0, None));
        }
        let (read, slab) = self
            .slab_buffer
            .as_mut()
            .unwrap()
            .read_shards(data_key, reader)
            .await?;
        if let Some(slab) = &slab {
            // The reader allocated this slab's buffers; the encoder that takes
            // them adopts this entry.
            self.state.held_put("reader".into(), slab.bytes());
        }
        Ok((read, slab))
    }

    /// Reads from the provided reader, buffering data into slabs and spawning
    /// slab-upload tasks as they fill. Returns the number of bytes read.
    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        data_key: EncryptionKey,
        mut reader: R,
    ) -> Result<u64, UploadError> {
        // checked before anything is consumed, so a failure never drops a slab
        self.ensure_hosts().await?;
        let mut total_length: u64 = 0;
        loop {
            let (n, slab) = self.next_slab(data_key.clone(), &mut reader).await?;
            if n == 0 {
                return Ok(total_length);
            }
            total_length += n as u64;

            if let Some(slab) = slab {
                let Some(id) = self.open_data_slab(slab.encryption_key, slab.length).await? else {
                    return Ok(total_length);
                };
                for (index, shard) in slab.shards.into_iter().enumerate() {
                    self.add_data_shard(id, index, Bytes::from(shard)).await?;
                }
            }
        }
    }

    /// Finalizes the pipeline, flushing any trailing partial slab, then waits
    /// for every registered slab to be pinned by a worker.
    pub(crate) async fn finish(mut self) -> Result<Vec<Slab>, UploadError> {
        let last_slab = self.slab_buffer.take().unwrap().finish();
        if let Some(slab) = &last_slab {
            self.state.held_put("reader".into(), slab.bytes());
        }
        if let Some(slab) = last_slab {
            self.ensure_hosts().await?;
            if let Some(id) = self.open_data_slab(slab.encryption_key, slab.length).await? {
                for (index, shard) in slab.shards.into_iter().enumerate() {
                    self.add_data_shard(id, index, Bytes::from(shard)).await?;
                }
            }
        }
        loop {
            if self.state.is_closed() {
                return Err(UploadError::Cancelled);
            }
            let total = self.state.registered();
            if self.state.finished() >= total {
                break;
            }
            if self.state.stalled() {
                let failure = self.state.take_failure();
                self.state.shutdown();
                if let Some(error) = failure {
                    return Err(error);
                }
                return Err(UploadError::NotEnoughShards(0, total.min(u8::MAX as usize) as u8));
            }
            // Registered before the check, so a pin that lands in between is not
            // missed.
            let notified = self.state.done_notify();
            if self.state.finished() >= self.state.registered() {
                break;
            }
            notified.await;
        }
        let slabs = self.state.shutdown();
        if slabs.len() < self.state.registered() {
            return Err(UploadError::NotEnoughShards(
                slabs.len().min(u8::MAX as usize) as u8,
                self.state.registered().min(u8::MAX as usize) as u8,
            ));
        }
        Ok(slabs)
    }

    /// Downloads `[offset, offset + len)` of `object` and feeds it into the
    /// pipeline. A no-op when `len` is 0.
    async fn feed_range(
        &mut self,
        object: &Object,
        data_key: &EncryptionKey,
        offset: u64,
        len: u64,
    ) -> Result<(), UploadError> {
        if len == 0 {
            return Ok(());
        }
        let download = Download::new(
            object,
            self.client.clone(),
            self.app_key.clone(),
            DownloadOptions {
                offset,
                length: Some(len),
                ..Default::default()
            },
        )?;
        self.read(data_key.clone(), download).await?;
        Ok(())
    }

    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    pub(crate) fn remaining(&self) -> usize {
        let slab_buffer = self.slab_buffer.as_ref().unwrap();
        slab_buffer
            .optimal_data_size()
            .saturating_sub(slab_buffer.length())
    }

    /// Returns the optimal size of each slab.
    pub(crate) fn optimal_data_size(&self) -> usize {
        self.slab_buffer.as_ref().unwrap().optimal_data_size()
    }

    /// The slabs pinned so far, indexed by slab id.
    pub(crate) fn pinned_slabs(&self) -> Vec<Option<Slab>> {
        self.state.pinned_slabs()
    }

    /// Shard bytes the upload holds right now.
    pub(crate) fn held_bytes(&self) -> usize {
        self.state.held_bytes()
    }

    /// The highest [`held_bytes`](Self::held_bytes) reached.
    pub(crate) fn peak_held_bytes(&self) -> usize {
        self.state.peak_held_bytes()
    }
}

struct ObjectUpload {
    start: u64,
    end: u64,
    object: Object,
}

/// Dropping an upload is a cancel: the workers stop, the dials are aborted, and
/// an encoder stops at its next batch instead of finishing shards nobody will
/// write.
impl Drop for Upload {
    fn drop(&mut self) {
        self.state.shutdown();
    }
}

/// Stops an upload from outside the task that owns it.
///
/// There is no second signal: this sets the same closed flag the encoder and
/// placement already consult, so every part of the upload stops for the same
/// reason.
#[derive(Clone)]
pub struct CancelHandle {
    state: Arc<worker::WorkerState>,
}

impl CancelHandle {
    /// Stops the upload. Shards stop being queued, the encoder stops before its
    /// next batch, and the dials are aborted.
    pub fn cancel(&self) {
        self.state.shutdown();
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.is_closed()
    }
}

/// A packed upload allows multiple objects to be uploaded together in a single upload. This can be more
/// efficient than uploading each object separately if the size of the object is less than the minimum
/// slab size.
///
/// The caller must call [finalize](Self::finalize) to complete the upload.
pub struct PackedUpload {
    upload: Upload,
    objects: Vec<ObjectUpload>,
    /// One data key for every object in the upload.
    ///
    /// An object made of several of these slabs has to decrypt with one key,
    /// and a caller composing a file that spans slabs takes the key from one
    /// object and the slabs from all of them. Separate keys per added object
    /// would leave every slab after the first undecryptable.
    data_key: EncryptionKey,
}

impl PackedUpload {
    /// A handle that stops this upload from outside, for callers that hold the
    /// upload behind a lock.
    pub fn cancel_handle(&self) -> CancelHandle {
        self.upload.cancel_handle()
    }

    pub(crate) fn new(
        client: Hosts,
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
        options: PackedUploadOptions,
    ) -> Result<Self, UploadError> {
        Ok(Self {
            upload: Upload::new(client, api_client, app_key, options.into())?,
            objects: Vec::new(),
            data_key: EncryptionKey::from(rand::random::<[u8; 32]>()),
        })
    }

    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    /// To minimize padding, prioritize objects that fit within the
    /// remaining size.
    pub fn remaining(&self) -> u64 {
        self.upload.remaining() as u64
    }

    /// Returns the cumulative length of all objects currently in the upload.
    pub fn length(&self) -> u64 {
        self.upload.length()
    }

    /// Returns the optimal size of each slab.
    pub fn optimal_data_size(&self) -> usize {
        self.upload.optimal_data_size()
    }

    /// Shard bytes the upload holds right now: queued shards, the shards a host
    /// is writing, parity being encoded, and the reader's buffer.
    pub fn held_bytes(&self) -> usize {
        self.upload.held_bytes()
    }

    /// The highest [`held_bytes`](Self::held_bytes) reached, so the peak does
    /// not depend on how often a caller samples it.
    pub fn peak_held_bytes(&self) -> usize {
        self.upload.peak_held_bytes()
    }

    /// Returns the number of slabs after the upload is finalized.
    pub fn slabs(&self) -> usize {
        self.length().div_ceil(self.optimal_data_size() as u64) as usize
    }

    /// Adds a new object to the upload. The data is read until EOF and packed into
    /// the current slab. Returns the number of bytes consumed; call
    /// [finalize](Self::finalize) once all objects have been added to get the
    /// resulting objects.
    ///
    /// If the reader errors part-way, it's safe to continue calling
    /// [add](Self::add); no object is registered for the failed call. Or call
    /// [finalize](Self::finalize) to collect the objects added so far. Bytes
    /// the failed read had buffered but not yet committed are dropped, since
    /// no object references them. Whole buffers committed before the error
    /// stay in the slab as padding, counted in [length](Self::length) and
    /// [remaining](Self::remaining).
    pub async fn add<R: AsyncRead + Unpin>(&mut self, mut r: R) -> Result<u64, UploadError> {
        let mut object = Object::new(None);
        object.data_key = self.data_key.clone();
        let start = self.upload.length();
        let key = self.data_key.clone();
        let mut read = 0usize;

        // A thin caller of the per-shard calls: read a slab, register it, then
        // hand over its ten data shards. Nothing here knows how a shard is
        // encoded or queued.
        loop {
            let (n, slab) = self.upload.next_slab(key.clone(), &mut r).await?;
            if n == 0 {
                break;
            }
            read += n;
            let Some(slab) = slab else { continue };
            let id = self
                .register_slab_with(slab.encryption_key, slab.length as u64)
                .await?;
            if id == 0 {
                break;
            }
            for (index, shard) in slab.shards.iter().enumerate() {
                self.add_shard(id, index, shard).await?;
            }
        }

        let end = self.upload.length();
        self.objects.push(ObjectUpload { start, end, object });
        Ok(read as u64)
    }

    /// Adds a new object to the upload by opening the file at `path` and
    /// reading it to EOF. Behaves like [add](Self::add) otherwise.
    #[cfg(feature = "fs")]
    pub async fn add_path<P: AsRef<Path>>(&mut self, path: P) -> Result<u64, UploadError> {
        self.add(tokio::fs::File::open(path).await?).await
    }

    /// Finalizes the upload and returns the resulting objects. This will wait for all readers
    /// to finish and all slabs to be uploaded before returning. The resulting objects will contain the metadata needed to download the objects.
    ///
    /// The slabs are pinned as they are uploaded, but the caller must pin the
    /// resulting objects to the indexer when ready.
    pub async fn finalize(self) -> Result<Vec<Object>, UploadError> {
        let optimal_data_size = self.optimal_data_size() as u64;
        let uploaded_slabs = self.upload.finish().await?;
        self.objects
            .into_iter()
            .map(|upload| {
                if upload.start == upload.end {
                    // empty object: nothing to splice in, leave it with zero slabs
                    return Ok(upload.object);
                }
                let slabs_start = (upload.start / optimal_data_size) as usize;
                let slabs_end = upload.end.div_ceil(optimal_data_size) as usize;
                Ok(splice(
                    &upload.object,
                    upload.start,
                    upload.end,
                    &uploaded_slabs[slabs_start..slabs_end],
                    optimal_data_size,
                ))
            })
            .collect()
    }

    /// The objects whose slabs have all pinned, indexed the same way
    /// [add](Self::add) was called. `None` means that object still has a slab
    /// in flight, so a caller can compose and pin finished files while the
    /// upload keeps running instead of waiting for
    /// [finalize](Self::finalize).
    /// Opens a slab for shards that arrive one at a time, and returns its id.
    /// `0` means the upload was cancelled before a slot was free.
    ///
    /// The caller sends the `data_shards` data shards with
    /// [`add_shard`](Self::add_shard); the encoder produces the parity shards
    /// from them, so nothing here needs a whole encoded slab.
    pub async fn register_slab(&mut self, length: u64) -> Result<u64, UploadError> {
        self.register_slab_with(self.data_key.clone(), length).await
    }

    /// Same registration with the slab's own key, which is what the reader used
    /// to encrypt the object stream for that slab.
    async fn register_slab_with(
        &mut self,
        key: EncryptionKey,
        length: u64,
    ) -> Result<u64, UploadError> {
        Ok(
            match self.upload.open_data_slab(key, length as usize).await? {
                Some(id) => id.0,
                None => 0,
            },
        )
    }

    /// Queues one data shard of a slab opened with
    /// [`register_slab`](Self::register_slab).
    pub async fn add_shard(
        &mut self,
        slab: u64,
        index: usize,
        data: &[u8],
    ) -> Result<(), UploadError> {
        self.upload
            .add_data_shard(
                crate::schedule::SlabId(slab),
                index,
                Bytes::copy_from_slice(data),
            )
            .await
    }

    pub fn ready_objects(&self) -> Vec<Option<Object>> {
        let pinned = self.upload.pinned_slabs();
        let optimal_data_size = self.optimal_data_size() as u64;
        self.objects
            .iter()
            .map(|upload| {
                if upload.start == upload.end {
                    return Some(upload.object.clone());
                }
                let slabs_start = (upload.start / optimal_data_size) as usize;
                let slabs_end = upload.end.div_ceil(optimal_data_size) as usize;
                let slabs: Vec<Slab> = pinned
                    .get(slabs_start..slabs_end)?
                    .iter()
                    .map(|slab| slab.clone())
                    .collect::<Option<Vec<_>>>()?;
                Some(splice(
                    &upload.object,
                    upload.start,
                    upload.end,
                    &slabs,
                    optimal_data_size,
                ))
            })
            .collect()
    }
}

/// Gives `object` the slabs its byte range covers, trimming the first and last
/// to the range. Shared by [`PackedUpload::finalize`] and
/// [`PackedUpload::ready_objects`] so the two cannot disagree.
fn splice(object: &Object, start: u64, end: u64, slabs: &[Slab], optimal: u64) -> Object {
    let mut object = object.clone();
    let count = slabs.len();
    object.slabs.extend_from_slice(slabs);
    object.slabs[0].offset = (start % optimal) as u32;
    if count > 1 {
        // if spanning multiple slabs, adjust first slab's length
        object.slabs[0].length = (optimal - object.slabs[0].offset as u64) as u32;
    }
    let last = count - 1;
    let last_offset = object.slabs[last].offset as u64;
    // Start of the slab that holds the last byte. Using the object's own slab
    // count here instead would be right only for an object that begins in slab
    // zero, and made every later object hundreds of megabytes too long.
    let last_slab_start = (end - 1) / optimal * optimal;
    object.slabs[last].length = (end - last_slab_start - last_offset) as u32;
    object
}

/// Reads until EOF and uploads all slabs. The data will be erasure coded,
/// encrypted, and uploaded. Slabs are pinned to the indexer in batches as they
/// finish uploading.
///
/// Pass [`Object::default()`] for new uploads. To resume a previous upload,
/// pass the object returned from the earlier call. Appending data changes
/// an object's ID. It must be re-pinned afterward and any references to
/// the previous ID must be updated.
pub(crate) async fn upload_object<R: AsyncRead + Unpin>(
    hosts: Hosts,
    api_client: app_client::Client,
    app_key: Arc<AppKey>,
    mut object: Object,
    mut reader: R,
    options: UploadOptions,
) -> Result<Object, UploadError> {
    let object_size = object.size();
    let start_offset = options.start_offset.unwrap_or(object_size);
    if start_offset > object_size {
        return Err(UploadError::OutOfRange(
            start_offset as usize,
            object_size as usize,
        ));
    }

    // Feed the existing head bytes, then the new data, then the existing tail
    // bytes into the pipeline; it re-chunks the whole stream into fresh slabs.
    let data_key = object.data_key.clone();
    let (mut head_index, mut head_start) = slab_at_offset(&object.slabs, start_offset);
    if start_offset == object_size
        && let Some(last_slab) = object.slabs.last()
        && (last_slab.length as usize) < options.optimal_data_size()
    {
        head_index -= 1;
        head_start -= last_slab.length as u64;
    }
    let mut upload = Upload::new(hosts, api_client, app_key, options)?;
    let mut first_byte = [0u8; 1];
    let prefix = if start_offset == object_size {
        if reader.read(&mut first_byte).await? == 0 {
            return Ok(object);
        }
        &first_byte[..]
    } else {
        &[]
    };
    let reader = prefix.chain(reader);
    upload
        .feed_range(&object, &data_key, head_start, start_offset - head_start)
        .await?;
    let n = upload.read(data_key.clone(), reader).await?;
    if n == 0 {
        return Ok(object);
    }
    let end = start_offset + n;
    let (tail_index, tail_start) = slab_at_offset(&object.slabs, end);
    let mut replace_end = tail_index;
    if end < object_size && end > tail_start {
        let tail_end = tail_start + object.slabs[tail_index].length as u64;
        upload
            .feed_range(&object, &data_key, end, tail_end - end)
            .await?;
        replace_end += 1;
    }

    object
        .slabs
        .splice(head_index..replace_end, upload.finish().await?);
    Ok(object)
}

/// Returns the index of the slab containing `offset` and the object byte offset
/// at which that slab begins. If `offset` is at or past the end, returns
/// `(slabs.len(), object_size)`.
fn slab_at_offset(slabs: &[Slab], offset: u64) -> (usize, u64) {
    let mut start = 0u64;
    for (i, slab) in slabs.iter().enumerate() {
        let next = start + slab.length as u64;
        if offset < next {
            return (i, start);
        }
        start = next;
    }
    (slabs.len(), start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::client::Client;
    use crate::rhp4::mock;
    use bytes::BytesMut;
    use rand::Rng;
    use reqwest::StatusCode;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::{NetAddress, Protocol};
    use std::io::Cursor;

    fn opts(data: u8, parity: u8) -> UploadOptions {
        UploadOptions {
            data_shards: data,
            parity_shards: parity,
            ..Default::default()
        }
    }

    fn test_host(public_key: PublicKey) -> Host {
        Host {
            public_key,
            addresses: vec![NetAddress {
                protocol: Protocol::QUIC,
                address: "localhost:1234".to_string(),
            }],
            country_code: "US".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        }
    }

    fn test_slab() -> Slab {
        Slab {
            version: SlabVersion::V1,
            encryption_key: rand::random::<[u8; 32]>().into(),
            min_shards: 1,
            sectors: Vec::new(),
            offset: 0,
            length: 1,
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_splice_sizes_an_object_that_starts_inside_a_later_slab() {
        // One slab per upload meant every object started at slab 0, so the
        // subtraction that sizes the last slab was accidentally right. In a
        // packed batch the second object can start in the middle of a later
        // slab, and then the object's own slab count is not the slab's offset.
        let optimal = 40 * 1024 * 1024u64;
        let mib = 1024 * 1024u64;
        let mut slab = test_slab();
        slab.min_shards = 10;
        slab.length = optimal as u32;

        // A 10 MiB object sitting 50 MiB into the upload, so 10 MiB into slab 1.
        let object = splice(&Object::default(), 50 * mib, 60 * mib, &[slab], optimal);
        assert_eq!(object.slabs.len(), 1);
        assert_eq!(object.slabs[0].offset, 10 * mib as u32, "10 MiB into its slab");
        assert_eq!(object.slabs[0].length, 10 * mib as u32, "and 10 MiB long");
        assert_eq!(object.size(), 10 * mib, "so the object is 10 MiB, not 60");
    }

    #[sia_core_derive::cross_target_test]
    fn test_validate_ec_params() {
        let cases: &[(u8, u8, bool)] = &[
            (0, 6, false),   // zero data shards
            (6, 0, false),   // zero parity shards (total < data)
            (1, 2, false),   // 1-of-3: insufficient recovery probability
            (2, 4, false),   // 2-of-6: insufficient recovery probability
            (4, 4, false),   // 4-of-8: insufficient recovery probability
            (1, 9, false),   // 1-of-10: 10x redundancy is too high
            (60, 15, false), // 60-of-75: 1.25x redundancy is too low
            (10, 20, true),  // 10-of-30
            (40, 40, true),  // 40-of-80
            (30, 30, true),  // 30-of-60
        ];

        for &(data, parity, ok) in cases {
            let total = data as u16 + parity as u16;
            let result = opts(data, parity).validate();
            assert_eq!(
                result.is_ok(),
                ok,
                "{data}-of-{total}: expected ok={ok}, got {:?}",
                result.err()
            );
        }
    }

    /// The next slot goes to the worker that has been waiting longest.
    ///
    /// Three workers park in a known order, then the only permit is dropped.
    /// Polling in reverse order is the point: if the newest arrival had barged
    /// in, it would already hold the slot and the first worker would stay
    /// parked.
    #[sia_core_derive::cross_target_test]
    async fn test_permits_go_to_the_worker_that_waited_longest() {
        use std::task::{Context, Poll, Waker};

        let limiter = Arc::new(UploadLimiter::new(1, 1, 4));
        let held = limiter.acquire().await;

        let mut first = Box::pin(limiter.acquire());
        let mut second = Box::pin(limiter.acquire());
        let mut third = Box::pin(limiter.acquire());
        let mut cx = Context::from_waker(Waker::noop());
        for waiter in [&mut first, &mut second, &mut third] {
            assert!(
                waiter.as_mut().poll(&mut cx).is_pending(),
                "the only slot is held, so every worker must park"
            );
        }

        drop(held);
        assert!(
            third.as_mut().poll(&mut cx).is_pending(),
            "the worker that just arrived must not take the slot"
        );
        assert!(
            second.as_mut().poll(&mut cx).is_pending(),
            "only one slot freed, so only the front of the line is served"
        );
        let permit = match first.as_mut().poll(&mut cx) {
            Poll::Ready(permit) => permit,
            Poll::Pending => panic!("the worker that waited longest must be served first"),
        };

        // And the line keeps moving: each release serves exactly one worker.
        drop(permit);
        let permit = match second.as_mut().poll(&mut cx) {
            Poll::Ready(permit) => permit,
            Poll::Pending => panic!("the second worker is next in line"),
        };
        drop(permit);
        assert!(
            matches!(third.as_mut().poll(&mut cx), Poll::Ready(_)),
            "the last worker is served once the others are done"
        );
    }

    /// The write gate refuses a worker past the limit, and admits it as soon as
    /// one frees up.
    ///
    /// The worker loop asks for this permit before it asks the queue for a
    /// shard, so memory is bounded by the write gate rather than by how many
    /// hosts are connected. The ordering itself is one line in `run_worker` and
    /// is not observable from a test; what is observable, and checked here, is
    /// that the gate really holds a worker out.
    #[sia_core_derive::cross_target_test]
    async fn test_the_write_gate_refuses_a_worker_past_the_limit() {
        use std::task::{Context, Poll, Waker};

        // `UploadLimiter::new` starts at the initial inflight, which is 8, so
        // hold all of them before asking for a ninth.
        let limiter = Arc::new(UploadLimiter::new(2, 1, 4));
        let first = limiter.acquire().await;
        let second = limiter.acquire().await;

        let mut extra = Box::pin(limiter.acquire());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            extra.as_mut().poll(&mut cx).is_pending(),
            "a worker at the write limit must not be given work"
        );

        drop(first);
        assert!(
            matches!(extra.as_mut().poll(&mut cx), Poll::Ready(_)),
            "and it is given one as soon as a permit frees up"
        );
        drop(second);
    }

    /// A gate that shrinks after growing must still admit the next worker.
    ///
    /// The controller raises the limit when writes go well and halves it when
    /// the link sours. If a growth is counted as if the new room were already
    /// in use, a later shrink leaves the counter above the limit, and the gate
    /// never opens again: every worker parks waiting for a slot the counter
    /// says is taken. Nothing in the log says why.
    #[sia_core_derive::cross_target_test]
    async fn test_a_shrunk_write_gate_still_admits_the_next_worker() {
        use std::task::{Context, Poll, Waker};

        let limiter = Arc::new(UploadLimiter::new(2, 1, 30));
        let mut held = Some(limiter.acquire().await);

        // Good writes first, with nobody waiting, so the limit climbs.
        let mut grew = false;
        for _ in 0..200 {
            let sample = limiter.sample();
            limiter.record(sample, Duration::from_millis(20), true);
            if limiter.controller.limit() > 2 {
                grew = true;
                break;
            }
        }
        assert!(grew, "the controller must climb on good completions");

        // Then the link sours and the controller backs all the way down.
        for _ in 0..200 {
            if limiter.controller.limit() <= 1 {
                break;
            }
            let sample = limiter.sample();
            limiter.record(sample, Duration::from_secs(5), false);
        }
        assert_eq!(limiter.controller.limit(), 1, "one write at a time now");

        // One write is running. Stop it, and the one slot the gate allows must
        // be usable again.
        drop(held.take());
        let mut next = Box::pin(limiter.acquire());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(next.as_mut().poll(&mut cx), Poll::Ready(_)),
            "the slot the gate allows must not be counted as already taken",
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_append_object_repacks_last_slab() {
        let options = UploadOptions::default();
        let optimal = options.optimal_data_size();
        const MIB: usize = 1 << 20;

        for (initial_len, append_len, explicit_offset) in [
            (optimal + MIB, MIB, false),
            (optimal + MIB, optimal - MIB, false),
            (optimal + MIB, optimal, false),
            (MIB, 1, false),
            (optimal, MIB, false),
            (0, MIB, false),
            (optimal, 0, false),
            (0, 0, false),
            (optimal + MIB, 0, false),
            (MIB, 0, true),
            (optimal + MIB, MIB, true),
        ] {
            let transport = mock::Client::new();
            let hosts = Hosts::new(Client::from_mock(transport.clone()));
            hosts.update(
                (0..60)
                    .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                    .collect(),
                true,
            );
            let app_key = Arc::new(AppKey::import(rand::random()));
            let api = app_client::mock::Client::new();
            let api_client = app_client::Client::Mock(api.clone());
            let mut expected = vec![0u8; initial_len];
            rand::rng().fill_bytes(&mut expected);
            let base = upload_object(
                hosts.clone(),
                api_client.clone(),
                app_key.clone(),
                Object::default(),
                Cursor::new(&expected),
                options.clone(),
            )
            .await
            .unwrap();
            let pinned_before = api.pinned_slabs();
            if append_len == 0 {
                transport.clear();
            }
            let new = upload_object(
                hosts.clone(),
                api_client,
                app_key.clone(),
                base.clone(),
                Cursor::new(vec![0xA5; append_len]),
                UploadOptions {
                    start_offset: explicit_offset.then_some(initial_len as u64),
                    ..options.clone()
                },
            )
            .await
            .unwrap();

            assert_eq!(new.data_key, base.data_key);
            assert_eq!(new.size(), (initial_len + append_len) as u64);
            assert_eq!(
                new.slabs().len(),
                (initial_len + append_len).div_ceil(optimal)
            );
            let full_slabs = initial_len / optimal;
            assert_eq!(&new.slabs()[..full_slabs], &base.slabs()[..full_slabs]);
            if append_len == 0 {
                assert_eq!(
                    transport.read_requests(),
                    0,
                    "empty appends need no download"
                );
            } else if initial_len.is_multiple_of(optimal) {
                assert_eq!(transport.read_requests(), 0, "full slabs need no download");
            } else {
                assert!(transport.read_requests() > 0, "partial slab is downloaded");
            }
            if append_len == 0 {
                assert_eq!(new, base);
                assert_eq!(api.pinned_slabs(), pinned_before);
                continue;
            } else {
                assert_eq!(
                    api.pinned_slabs() - pinned_before,
                    new.slabs().len() - full_slabs
                );
                if !initial_len.is_multiple_of(optimal) {
                    assert_ne!(
                        new.slabs()[full_slabs].encryption_key,
                        base.slabs()[full_slabs].encryption_key
                    );
                }
                for slab in &new.slabs()[..new.slabs().len() - 1] {
                    assert_eq!(slab.length as usize, optimal);
                }
            }

            expected.resize(initial_len + append_len, 0xA5);
            let mut recovered = Vec::with_capacity(expected.len());
            let mut download =
                Download::new(&new, hosts, app_key, DownloadOptions::default()).unwrap();
            tokio::io::copy(&mut download, &mut recovered)
                .await
                .unwrap();
            assert_eq!(recovered, expected);
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_no_shard_is_queued_after_cancel() {
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..30)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        upload.ensure_hosts().await.unwrap();
        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), 4096)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");

        // The handle the browser layer uses: the same closed flag, no second
        // signal beside it.
        upload.cancel_handle().cancel();
        let before = upload.state.queued();
        for index in 0..10 {
            let _ = upload.add_data_shard(id, index, Bytes::from(vec![0u8; 4096])).await;
        }
        sleep(Duration::from_millis(50)).await;
        assert_eq!(
            upload.state.queued(),
            before,
            "a cancelled upload queues nothing, and the encoder produces no parity"
        );
    }

    /// Held bytes count the reader's buffer and the shards in the queue, and
    /// the peak keeps the highest value seen whether or not anyone samples.
    #[sia_core_derive::cross_target_test]
    async fn test_held_bytes_counts_the_reader_and_the_queue() {
        use sia_core::rhp4::SECTOR_SIZE;
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        // No hosts are added, so a queued shard stays queued instead of being
        // written, which is what makes the count observable.
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();

        // Nothing is held before a slab is read: the reader's buffers are
        // counted when it allocates them for a slab.
        assert_eq!(upload.held_bytes(), 0);
        let size = upload.optimal_data_size();
        let (_, slab) = upload
            .next_slab(
                EncryptionKey::from([3u8; 32]),
                &mut Cursor::new(vec![0u8; size]),
            )
            .await
            .unwrap();
        assert!(slab.is_some(), "a full slab was read");
        assert_eq!(
            upload.held_bytes(),
            10 * SECTOR_SIZE,
            "the slab being read is held"
        );

        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), SECTOR_SIZE)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");
        upload
            .add_data_shard(id, 0, Bytes::from(vec![0u8; SECTOR_SIZE]))
            .await
            .unwrap();

        assert_eq!(
            upload.held_bytes(),
            11 * SECTOR_SIZE,
            "the read slab plus one queued shard"
        );
        assert_eq!(upload.peak_held_bytes(), 11 * SECTOR_SIZE);

        upload.state.shutdown();
        assert_eq!(upload.held_bytes(), 0, "a stopped upload holds nothing");
    }

    /// Shards added one at a time, through the same calls `registerSlab` and
    /// `addShard` use, assemble a slab that pins with all thirty sectors.
    #[sia_core_derive::cross_target_test]
    async fn test_a_slab_can_be_built_from_individual_shards() {
        use sia_core::rhp4::SECTOR_SIZE;

        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..30)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        upload.ensure_hosts().await.unwrap();

        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), SECTOR_SIZE)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");
        for index in 0..10 {
            upload
                .add_data_shard(id, index, Bytes::from(vec![index as u8; SECTOR_SIZE])).await
                .unwrap();
        }

        let slabs = upload.finish().await.unwrap();
        assert_eq!(slabs.len(), 1);
        assert_eq!(
            slabs[0].sectors.len(),
            30,
            "ten data shards and the parity produced from them"
        );
    }

    /// A cancel while a parity batch is being computed stops the encoder: the
    /// rest of the slab is never produced.
    #[sia_core_derive::cross_target_test]
    async fn test_cancel_during_a_parity_batch() {
        use sia_core::rhp4::SECTOR_SIZE;

        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), SECTOR_SIZE)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");
        // Four mebibytes per shard, so the batch is still being computed when
        // the cancel lands rather than finishing first.
        for index in 0..10 {
            upload
                .add_data_shard(id, index, Bytes::from(vec![index as u8; SECTOR_SIZE]))
                .await
                .unwrap();
        }
        sleep(Duration::from_millis(20)).await;

        let handle = upload.cancel_handle();
        handle.cancel();
        sleep(Duration::from_millis(500)).await;

        assert!(handle.is_cancelled());
        assert!(
            upload.state.parity_shards() < 20,
            "the encoder stopped part way: {} of 20 parity shards",
            upload.state.parity_shards()
        );
        assert_eq!(
            upload.encoders.available_permits(),
            ENCODERS_IN_FLIGHT,
            "the encoder released its slot"
        );
    }

    /// A cancel that lands while a parity batch is waiting for room stops the
    /// encoder: the batch is not handed over, and no later batch is produced.
    #[sia_core_derive::cross_target_test]
    async fn test_cancel_while_a_parity_batch_waits_for_room() {
        use sia_core::rhp4::SECTOR_SIZE;

        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        // No hosts write anything, so the queue only grows and the encoder has
        // to wait for room it will never get.
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), SECTOR_SIZE)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");
        for index in 0..10 {
            upload
                .add_data_shard(id, index, Bytes::from(vec![index as u8; SECTOR_SIZE])).await
                .unwrap();
        }

        // The queue reaches the high water and the encoder parks: it has a
        // batch in hand but no room to hand it over.
        let deadline = Instant::now() + Duration::from_secs(20);
        while upload.state.queued() < QUEUE_HIGH_WATER && Instant::now() < deadline {
            sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            upload.state.queued(),
            QUEUE_HIGH_WATER,
            "the queue stops at the high water"
        );
        // With no host to drain it, the queue stays at the bound and the encoder
        // has nowhere to put its next shard.
        sleep(Duration::from_millis(100)).await;
        assert_eq!(
            upload.state.queued(),
            QUEUE_HIGH_WATER,
            "the queue holds at the bound while the encoder has more to hand over"
        );
        let before = upload.state.parity_shards();

        let handle = upload.cancel_handle();
        handle.cancel();
        sleep(Duration::from_millis(100)).await;

        assert!(handle.is_cancelled());
        assert_eq!(
            upload.state.parity_shards(),
            before,
            "no batch is handed over after the cancel"
        );
        assert_eq!(
            upload.encoders.available_permits(),
            ENCODERS_IN_FLIGHT,
            "the encoder stopped and released its permit"
        );
    }

    /// Cancelling after parity has started leaves no shard queued and no
    /// encoder running.
    #[sia_core_derive::cross_target_test]
    async fn test_cancel_after_the_first_parity_batch() {
        use sia_core::rhp4::SECTOR_SIZE;

        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        // No hosts to write to, so the queue keeps what the encoder produced
        // and the test can see how far it got.
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        let id = upload
            .open_data_slab(EncryptionKey::from([3u8; 32]), SECTOR_SIZE)
            .await
            .unwrap()
            .expect("a slab opens while the upload is live");
        for index in 0..10 {
            upload
                .add_data_shard(id, index, Bytes::from(vec![index as u8; SECTOR_SIZE])).await
                .unwrap();
        }

        // Wait until the first parity batch has joined the ten data shards.
        let deadline = Instant::now() + Duration::from_secs(20);
        while upload.state.queued() < 10 + PARITY_BATCH && Instant::now() < deadline {
            sleep(Duration::from_millis(5)).await;
        }
        assert!(
            upload.state.queued() >= 10 + PARITY_BATCH,
            "parity started: {} shards queued",
            upload.state.queued()
        );

        let handle = upload.cancel_handle();
        handle.cancel();
        assert!(handle.is_cancelled());
        assert_eq!(
            upload.state.queued(),
            0,
            "the shards of an abandoned slab are dropped"
        );
        assert!(
            matches!(upload.finish().await, Err(UploadError::Cancelled)),
            "a cancelled upload does not pin"
        );
    }

    /// A pinned slab is reported when the upload is cancelled, which is what a
    /// caller resumes from.
    #[sia_core_derive::cross_target_test]
    async fn test_cancel_reports_the_pinned_slabs() {
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..30)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let mut upload = Upload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            UploadOptions::default(),
        )
        .unwrap();
        // One full slab, so the read flushes it and the workers pin it.
        let size = upload.optimal_data_size();
        upload
            .read(
                rand::random::<[u8; 32]>().into(),
                Cursor::new(vec![1u8; size]),
            )
            .await
            .unwrap();
        while upload.state.finished() < upload.state.registered() {
            let notified = upload.state.done_notify();
            notified.await;
        }

        let pinned = upload.state.shutdown();
        assert_eq!(pinned.len(), 1, "the pinned slab comes back for a resume");
    }

    #[sia_core_derive::cross_target_test]
    async fn test_dropping_an_upload_cancels_it() {
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..30)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let mut packed = PackedUpload::new(
            hosts,
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            PackedUploadOptions::default(),
        )
        .unwrap();
        packed.add(Cursor::new(vec![1u8; 111])).await.unwrap();

        let state = packed.upload.state.clone();
        assert!(!state.is_closed(), "an upload in flight is open");
        drop(packed);
        assert!(state.is_closed(), "dropping the upload cancels it");
    }

    #[sia_core_derive::cross_target_test]
    async fn test_shards_can_be_added_one_at_a_time() {
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..30)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let mut packed = PackedUpload::new(
            hosts.clone(),
            app_client::Client::mock(),
            Arc::new(AppKey::import(rand::random())),
            PackedUploadOptions::default(),
        )
        .unwrap();

        let id = packed.register_slab(4096).await.unwrap();
        assert_ne!(id, 0, "a slab opens and has an id");
        let shard = vec![7u8; 4096];
        for index in 0..10 {
            packed.add_shard(id, index, &shard).await.unwrap();
        }

        // The ten data shards are queued immediately; the encoder adds parity from
        // them. Nothing waits for a whole encoded slab to exist first.
        assert!(
            packed.upload.state.queued() >= 10,
            "the data shards are queued as they arrive"
        );
        drop(packed);
    }

    #[sia_core_derive::cross_target_test]
    async fn test_append_packed_object() {
        let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
        hosts.update(
            (0..60)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let app_key = Arc::new(AppKey::import(rand::random()));
        let api_client = app_client::Client::mock();
        let mut packed = PackedUpload::new(
            hosts.clone(),
            api_client.clone(),
            app_key.clone(),
            PackedUploadOptions::default(),
        )
        .unwrap();
        let inputs = [vec![1; 111], vec![2; 1234], vec![3; 333]];
        for input in &inputs {
            packed.add(Cursor::new(input)).await.unwrap();
        }
        let objects = packed.finalize().await.unwrap();
        assert_eq!(objects[1].slabs()[0].offset, inputs[0].len() as u32);
        let new = upload_object(
            hosts.clone(),
            api_client,
            app_key.clone(),
            objects[1].clone(),
            Cursor::new(vec![4; 4321]),
            UploadOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(new.slabs().len(), 1);
        assert_eq!(new.slabs()[0].offset, 0);
        assert_ne!(
            new.slabs()[0].encryption_key,
            objects[1].slabs()[0].encryption_key
        );

        let mut expected = inputs[1].clone();
        expected.extend(vec![4; 4321]);
        for (object, data) in objects.iter().zip(inputs.iter()).chain([(&new, &expected)]) {
            let mut recovered = Vec::new();
            let mut download = Download::new(
                object,
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            tokio::io::copy(&mut download, &mut recovered)
                .await
                .unwrap();
            assert_eq!(&recovered, data);
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_compose_object_from_existing_slabs() {
        let options = UploadOptions::default();
        let optimal = options.optimal_data_size();
        const MIB: usize = 1 << 20;
        let tail = 3 * MIB;
        let small = MIB;

        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport));
        hosts.update(
            (0..60)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let app_key = Arc::new(AppKey::import(rand::random()));
        let api = app_client::mock::Client::new();
        let api_client = app_client::Client::Mock(api.clone());

        let mut initial = vec![0u8; optimal + tail];
        rand::rng().fill_bytes(&mut initial);
        let base = upload_object(
            hosts.clone(),
            api_client.clone(),
            app_key.clone(),
            Object::default(),
            Cursor::new(&initial),
            options.clone(),
        )
        .await
        .unwrap();
        assert_eq!(base.slabs().len(), 2);

        let pinned_before = api.pinned_slabs();
        let small_bytes = vec![0xA5u8; small];
        let extended = upload_object(
            hosts.clone(),
            api_client,
            app_key.clone(),
            base.clone(),
            Cursor::new(&small_bytes),
            options.clone(),
        )
        .await
        .unwrap();

        // Only the tail slab was repacked and pinned. The head slab is reused.
        assert_eq!(api.pinned_slabs() - pinned_before, 1);
        assert_eq!(extended.slabs().len(), 2);
        assert_eq!(extended.slabs()[0], base.slabs()[0]);
        assert_ne!(
            extended.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );
        assert_eq!(extended.size(), (optimal + tail + small) as u64);

        let large = extended.truncate((optimal + tail) as u64);
        assert_eq!(large.size(), (optimal + tail) as u64);
        assert_eq!(large.slabs()[0], base.slabs()[0]);
        assert_eq!(large.slabs()[1].length, tail as u32);
        assert_ne!(large.id(), base.id());

        // The small file shares the new tail slab at the offset after the large
        // file's tail. The slab and data key are the same, so no bytes move.
        let mut small_slab = large.slabs()[1].clone();
        small_slab.offset = tail as u32;
        small_slab.length = small as u32;
        let mut small_object = large.with_slabs(vec![small_slab]);
        small_object.metadata = b"small".to_vec();
        assert_eq!(small_object.size(), small as u64);
        assert_ne!(small_object.id(), large.id());
        assert_ne!(small_object.id(), base.id());
        let _sealed = small_object.seal(&app_key);

        // Replace-slab builds the same large object from the old head and the
        // new tail.
        let replaced = base.replace_slab(1, large.slabs()[1].clone()).unwrap();
        assert_eq!(replaced.slabs(), large.slabs());
        assert_eq!(replaced.id(), large.id());
        assert!(base.replace_slab(2, large.slabs()[1].clone()).is_none());

        // The large file reads back its original bytes.
        let mut recovered = Vec::new();
        let mut download = Download::new(
            &large,
            hosts.clone(),
            app_key.clone(),
            DownloadOptions::default(),
        )
        .unwrap();
        tokio::io::copy(&mut download, &mut recovered).await.unwrap();
        assert_eq!(recovered, initial);

        // The small file reads back only its bytes from the shared slab.
        let mut recovered_small = Vec::new();
        let mut download = Download::new(
            &small_object,
            hosts,
            app_key,
            DownloadOptions::default(),
        )
        .unwrap();
        tokio::io::copy(&mut download, &mut recovered_small)
            .await
            .unwrap();
        assert_eq!(recovered_small, small_bytes);
    }

    /// Uploads `data`, overwrites `patch_len` bytes of value `patch_byte` at
    /// `offset`, then verifies the result downloads back to the expected bytes.
    /// Returns the (original, overwritten) objects for key assertions. Uses a
    /// fresh transport per call so each case's sectors are freed afterward.
    async fn overwrite_case(
        data: Bytes,
        offset: usize,
        patch_byte: u8,
        patch_len: usize,
    ) -> (Object, Object) {
        let options = UploadOptions::default();
        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport.clone()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );
        let app_key = Arc::new(AppKey::import(rand::random()));

        let base = upload_object(
            hosts.clone(),
            app_client::Client::mock(),
            app_key.clone(),
            Object::default(),
            Cursor::new(data.clone()),
            options.clone(),
        )
        .await
        .unwrap();

        let new = upload_object(
            hosts.clone(),
            app_client::Client::mock(),
            app_key.clone(),
            base.clone(),
            Cursor::new(vec![patch_byte; patch_len]),
            UploadOptions {
                start_offset: Some(offset as u64),
                ..options
            },
        )
        .await
        .unwrap();

        let end = offset + patch_len;
        let mut expected = data.to_vec();
        if end > expected.len() {
            expected.resize(end, 0);
        }
        expected[offset..end]
            .iter_mut()
            .for_each(|b| *b = patch_byte);
        assert_eq!(new.size(), expected.len() as u64, "size");

        let mut recovered = Vec::with_capacity(expected.len());
        let mut download = Download::new(&new, hosts, app_key, DownloadOptions::default()).unwrap();
        tokio::io::copy(&mut download, &mut recovered)
            .await
            .unwrap();
        assert_eq!(expected, recovered, "content");
        (base, new)
    }

    /// Overwriting a byte range rewrites only the slabs it covers — merging the
    /// partial head and tail with existing data and re-keying them — across
    /// one-, two-, and three-slab spans, an aligned head, and an extension past
    /// the end, leaving untouched slabs (and their keys) intact.
    #[sia_core_derive::cross_target_test]
    async fn test_overwrite_object() {
        let optimal = UploadOptions::default().optimal_data_size();
        fn rand_bytes(n: usize) -> Bytes {
            let mut d = BytesMut::zeroed(n);
            rand::rng().fill_bytes(&mut d);
            d.freeze()
        }

        // one-slab span: overwrite inside the second slab; the first is kept.
        let (base, new) =
            overwrite_case(rand_bytes(optimal + 4096), optimal + 1000, 0xA1, 1000).await;
        assert_eq!(new.slabs().len(), 2);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );

        // two-slab span with an aligned head (no head download): start on slab
        // 1's boundary and run through it into slab 2; slab 0 is kept.
        let (base, new) =
            overwrite_case(rand_bytes(optimal * 2 + 4096), optimal, 0xB2, optimal + 100).await;
        assert_eq!(new.slabs().len(), 3);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );

        // three-slab span: head in slab 0, slab 1 fully overwritten (no
        // download), tail in slab 2.
        let (base, new) =
            overwrite_case(rand_bytes(optimal * 2 + 4096), 100, 0xC3, optimal * 2).await;
        assert_eq!(new.slabs().len(), 3);
        assert_ne!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );

        // extend past the end: overwrite from inside the last slab beyond EOF.
        let (base, new) =
            overwrite_case(rand_bytes(optimal + 4096), optimal + 1000, 0xD4, 8192).await;
        assert_eq!(new.size(), (optimal + 1000 + 8192) as u64);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );

        // end on a slab boundary: head in slab 1, overwrite ending exactly at the
        // start of slab 2, which must be left untouched (not re-keyed).
        let (base, new) = overwrite_case(
            rand_bytes(optimal * 2 + 4096),
            optimal + 1000,
            0xE5,
            optimal - 1000,
        )
        .await;
        assert_eq!(new.slabs().len(), 3);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );
        assert_eq!(
            new.slabs()[2].encryption_key,
            base.slabs()[2].encryption_key
        );

        // empty overwrite: a 0-byte patch is a no-op that leaves every slab
        // (and its key) untouched.
        let (base, new) = overwrite_case(rand_bytes(optimal + 4096), 1000, 0x00, 0).await;
        assert_eq!(new.slabs().len(), base.slabs().len());
        for (new_slab, base_slab) in new.slabs().iter().zip(base.slabs()) {
            assert_eq!(new_slab.encryption_key, base_slab.encryption_key);
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_pin_uploaded_slab_retries_transient_errors() {
        let api = app_client::mock::Client::new();
        api.set_pin_slabs_failures(MAX_PIN_RETRIES - 1);
        let client = app_client::Client::Mock(api.clone());
        let app_key = AppKey::import(rand::random());

        let slab = test_slab();
        pin_uploaded_slab(&client, &app_key, SlabPinParams::from(&slab))
            .await
            .unwrap();

        assert_eq!(api.pin_slabs_calls(), MAX_PIN_RETRIES);
        assert_eq!(api.pinned_slabs(), 1);
    }

    #[sia_core_derive::cross_target_test]
    async fn test_pin_uploaded_slab_stops_after_max_attempts() {
        let api = app_client::mock::Client::new();
        api.set_pin_slabs_failures(MAX_PIN_RETRIES);
        let client = app_client::Client::Mock(api.clone());
        let app_key = AppKey::import(rand::random());

        let slab = test_slab();
        let err = pin_uploaded_slab(&client, &app_key, SlabPinParams::from(&slab))
            .await
            .expect_err("pin to fail");

        assert!(matches!(err, UploadError::ApiError(_)));
        assert_eq!(api.pin_slabs_calls(), MAX_PIN_RETRIES);
        assert_eq!(api.pinned_slabs(), 0);
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_does_not_reupload_other_pin_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for (status, message) in [
            (StatusCode::UNAUTHORIZED, "unauthorized"),
            (StatusCode::BAD_REQUEST, "invalid slab pin params"),
            (
                StatusCode::BAD_REQUEST,
                "slab upload time is in the future (max 5m0s ahead)",
            ),
        ] {
            let options = opts(3, 9);
            let total_shards = options.data_shards as usize + options.parity_shards as usize;
            let hosts = Hosts::new(Client::from_mock(mock::Client::new()));
            hosts.update(
                (0..total_shards * 2)
                    .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                    .collect(),
                true,
            );
            let api = app_client::mock::Client::new();
            api.set_pin_slabs_errors([app_client::Error::Api(status, message.into())]);
            let uploads = Arc::new(AtomicUsize::new(0));
            let counter = uploads.clone();
            let result = upload_object(
                hosts,
                app_client::Client::Mock(api.clone()),
                Arc::new(AppKey::import(rand::random())),
                Object::default(),
                Cursor::new(vec![1; 4096]),
                UploadOptions {
                    shard_uploaded: Some(Arc::new(move |_| {
                        counter.fetch_add(1, Ordering::SeqCst);
                    })),
                    ..options
                },
            )
            .await;

            assert!(
                matches!(result, Err(UploadError::ApiError(app_client::Error::Api(s, m))) if s == status && m == message),
                "expected the original pin error: {status}: {message}"
            );
            // One failed slab pin request; every shard uploaded once and
            // no slab pinned.
            assert_eq!(api.pin_slabs_calls(), 1);
            assert_eq!(uploads.load(Ordering::SeqCst), total_shards);
            assert_eq!(api.pinned_slabs(), 0);
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_dials_each_host_once() {
        // The point of the pool: one session per host, reused for every shard it
        // is allowed to write, instead of a fresh dial for each shard of each
        // slab. Sixty hosts, one slab, so thirty of them are used.
        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport.clone()));
        hosts.update(
            (0..60)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let api = app_client::mock::Client::new();
        let options = UploadOptions::default();
        let mut data = BytesMut::zeroed(options.optimal_data_size());
        rand::rng().fill_bytes(&mut data);

        let object = upload_object(
            hosts,
            app_client::Client::Mock(api.clone()),
            Arc::new(AppKey::import(rand::random())),
            Object::default(),
            Cursor::new(data.freeze()),
            options,
        )
        .await
        .unwrap();

        assert_eq!(object.slabs().len(), 1);
        assert_eq!(api.pinned_slabs(), 1);
        assert_eq!(
            transport.connect_requests(),
            transport.connected_hosts(),
            "a host is dialled once and its session reused",
        );
        assert_eq!(
            transport.connected_hosts(),
            60.min(worker::WORKER_TARGET),
            "the pool fills to the target, or to every candidate when there are fewer",
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_pins_every_slab() {
        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport.clone()));
        hosts.update(
            (0..60)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );
        let api = app_client::mock::Client::new();
        let options = UploadOptions::default();
        let mut data = BytesMut::zeroed(options.optimal_data_size() * 2 + 4096);
        rand::rng().fill_bytes(&mut data);

        let object = upload_object(
            hosts,
            app_client::Client::Mock(api.clone()),
            Arc::new(AppKey::import(rand::random())),
            Object::default(),
            Cursor::new(data.freeze()),
            options,
        )
        .await
        .unwrap();

        // each slab is pinned by its own upload task
        assert_eq!(object.slabs().len(), 3);
        assert_eq!(api.pinned_slabs(), 3);
        assert_eq!(api.pin_slabs_calls(), 3);
    }

    /// A slab the indexer rejects as too old fails the upload: the shards are
    /// written once and not kept, so there is nothing to send again.
    #[sia_core_derive::cross_target_test]
    async fn test_upload_fails_when_the_indexer_rejects_slab() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let options = opts(3, 9);
        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport));
        hosts.update(
            (0..total_shards * 2)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );

        let uploads = Arc::new(AtomicUsize::new(0));
        let counter = uploads.clone();
        let api = app_client::mock::Client::new();
        // The first pin fails transiently, so it is retried with the same
        // request. The second says the slab is too old, which ends the upload.
        api.set_pin_slabs_errors([
            app_client::Error::Api(StatusCode::INTERNAL_SERVER_ERROR, "temporary".into()),
            app_client::Error::Api(StatusCode::BAD_REQUEST, "slab upload is too old".into()),
        ]);
        let app_key = Arc::new(AppKey::import(rand::random()));
        let mut upload = Upload::new(
            hosts.clone(),
            app_client::Client::Mock(api.clone()),
            app_key.clone(),
            UploadOptions {
                shard_uploaded: Some(Arc::new(move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                })),
                ..options
            },
        )
        .unwrap();

        let mut data = BytesMut::zeroed(4096);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let object = Object::default();
        upload
            .read(object.data_key.clone(), Cursor::new(data.clone()))
            .await
            .unwrap();
        let error = upload.finish().await.unwrap_err();

        assert!(
            matches!(error, UploadError::SlabTooOld(1)),
            "expected the slab to be reported too old, got {error}"
        );
        assert_eq!(
            uploads.load(Ordering::SeqCst),
            total_shards,
            "the shards are written once and not kept for a reupload"
        );
        assert_eq!(api.pin_slabs_calls(), 2, "one retry, then the refusal");
        assert_eq!(api.pinned_slabs(), 0);
        let requests = api.pin_slabs_requests();
        assert_eq!(requests[0], requests[1], "a retry reuses the same request");
    }

}
