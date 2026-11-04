use std::collections::VecDeque;
use std::io;
#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::app_client::{self, SlabPinParams};
use crate::congestion::{InflightController, SamplePermit};
use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder, ReadSlab, SlabReader};
use crate::hosts::{QueueError, RPCError};
#[cfg(test)]
use crate::slabs::SlabVersion;
use crate::time::{Duration, Instant, sleep};
use crate::{
    AppKey, Download, DownloadOptions, Hosts, Object, PackedUploadOptions, Slab, UploadOptions,
};
#[cfg(test)]
use crate::{ShardProgress, ShardProgressCallback};
use bytes::Bytes;
#[cfg(test)]
use chrono::Utc;
use log::debug;
use sia_core::signing::PublicKey;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::oneshot;

mod worker;

const INITIAL_INFLIGHT: usize = 8;
const MIN_INFLIGHT: usize = 2;

#[cfg(not(target_arch = "wasm32"))]
fn default_slabs_in_memory(slab_size: usize) -> usize {
    (crate::default_memory_budget() / slab_size as u64).max(1) as usize
}

#[cfg(target_arch = "wasm32")]
fn default_slabs_in_memory(_slab_size: usize) -> usize {
    3
}

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
        self.grant(delta.max(0) as usize);
    }

    /// Hands the slot this worker was holding to the front of the queue, or
    /// gives it back to the controller when nobody is waiting.
    fn release(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        while let Some(tx) = state.waiters.pop_front() {
            match tx.send(UploadPermit {
                limiter: Arc::clone(self),
            }) {
                Ok(()) => return,
                // That worker gave up while we were handing it the slot. The
                // permit in the `Err` would drop and re-enter this function
                // holding the lock, so it is forgotten and the slot stays
                // counted while the next waiter is offered it.
                Err(permit) => std::mem::forget(permit),
            }
        }
        state.inflight -= 1;
    }

    /// Grows the budget by `count` and gives what grew to parked workers.
    fn grant(self: &Arc<Self>, count: usize) {
        if count == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.inflight += count;
        let mut handed = 0;
        while handed < count {
            let Some(tx) = state.waiters.pop_front() else {
                break;
            };
            match tx.send(UploadPermit {
                limiter: Arc::clone(self),
            }) {
                Ok(()) => handed += 1,
                Err(permit) => {
                    // Same as `release`: give the slot back and try the next
                    // worker, without dropping the permit under the lock.
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

    /// The indexer rejected every upload of the slab as too old to pin.
    #[error("slab stale after {0} upload attempts")]
    StaleSlab(usize),

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

/// Maximum number of times a slab is uploaded before failing with
/// [`UploadError::StaleSlab`].
const MAX_SLAB_ATTEMPTS: usize = 3;

/// A single-use streaming upload pipeline. Feed data into it by calling
/// [read](Upload::read) repeatedly, then complete the upload with
/// [finish](Upload::finish) to recover the uploaded slabs.
pub(crate) struct Upload {
    client: Hosts,
    app_key: Arc<AppKey>,
    erasure_coder: Arc<ErasureCoder>,
    total_shards: usize,
    slab_buffer: Option<SlabReader>,
    /// The worker pool and the request queue. A slab is registered here once it
    /// is encoded, and a connected host pulls its shards.
    state: Arc<worker::WorkerState>,
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

        let max_buffered_slabs = options
            .max_buffered_slabs
            .unwrap_or_else(|| default_slabs_in_memory(options.slab_size()));
        let limiter = Arc::new(UploadLimiter::new(
            INITIAL_INFLIGHT,
            MIN_INFLIGHT,
            max_buffered_slabs.saturating_mul(total_shards),
        ));
        let state = Arc::new(worker::WorkerState::new(
            client.clone(),
            api_client.clone(),
            app_key.clone(),
            limiter,
            max_buffered_slabs,
            options.shard_uploaded.clone(),
            options.shard_attempt.clone(),
        ));
        Ok(Self {
            client,
            app_key,
            slab_buffer: Some(SlabReader::new(
                options.data_shards as usize,
                options.parity_shards as usize,
            )),
            erasure_coder: Arc::new(erasure_coder),
            total_shards,
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
    /// Encodes and encrypts a filled slab, then hands its shards to the workers.
    ///
    /// Nothing is assigned to a host here. The schedule holds the shards, and a
    /// connected host pulls the next one it is allowed to write, which is what
    /// lets a host keep working across slabs instead of being spent on one.
    async fn register_slab(&mut self, slab: ReadSlab) -> Result<(), UploadError> {
        // Bound how many slabs hold shard memory. The slot comes back when the
        // slab is pinned, so the ceiling is slabs in flight, not shards.
        while !self.state.slack_available() {
            let notified = self.state.slot_notify();
            if self.state.slack_available() {
                break;
            }
            notified.await;
        }
        self.state.take_slot();

        let min_shards = self.erasure_coder.data_shards() as u8;
        let length = slab.length as u32;
        let encryption_key = slab.encryption_key.clone();
        let rs = self.erasure_coder.clone();
        let mut shards = slab.shards;
        let started = Instant::now();
        let shards = maybe_spawn_blocking!({
            rs.encode_shards(&mut shards)?;
            Ok::<_, UploadError>(shards)
        })?;
        debug!("slab encoded in {:?}", started.elapsed());

        let owned_slab_key = Arc::new(encryption_key.clone());
        let mut encrypted: Vec<Bytes> = Vec::with_capacity(shards.len());
        for (index, mut shard) in shards.into_iter().enumerate() {
            let key = owned_slab_key.clone();
            let data = maybe_spawn_blocking!({
                encrypt_shard(&key, index as u8, 0, &mut shard);
                Bytes::from(shard)
            });
            encrypted.push(data);
        }

        self.state.register(
            encrypted,
            crate::schedule::SlabSeed {
                encryption_key,
                length,
                min_shards,
            },
        );
        worker::ensure_workers(&self.state);
        self.state.notify_work();
        Ok(())
    }

    pub(crate) fn length(&self) -> u64 {
        self.slab_buffer
            .as_ref()
            .map(|b| b.total_length())
            .unwrap_or(0)
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
            let (n, slab) = self
                .slab_buffer
                .as_mut()
                .unwrap()
                .read_slab(data_key.clone(), &mut reader)
                .await?;
            if n == 0 {
                return Ok(total_length);
            }
            total_length += n as u64;

            if let Some(slab) = slab {
                self.register_slab(slab).await?;
            }
        }
    }

    /// Finalizes the pipeline, flushing any trailing partial slab, then waits
    /// for every registered slab to be pinned by a worker.
    pub(crate) async fn finish(mut self) -> Result<Vec<Slab>, UploadError> {
        let last_slab = self.slab_buffer.take().unwrap().finish();
        if let Some(slab) = last_slab {
            self.ensure_hosts().await?;
            self.register_slab(slab).await?;
        }
        loop {
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
}

struct ObjectUpload {
    start: u64,
    end: u64,
    object: Object,
}

/// A packed upload allows multiple objects to be uploaded together in a single upload. This can be more
/// efficient than uploading each object separately if the size of the object is less than the minimum
/// slab size.
///
/// The caller must call [finalize](Self::finalize) to complete the upload.
pub struct PackedUpload {
    upload: Upload,
    objects: Vec<ObjectUpload>,
}

impl PackedUpload {
    pub(crate) fn new(
        client: Hosts,
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
        options: PackedUploadOptions,
    ) -> Result<Self, UploadError> {
        Ok(Self {
            upload: Upload::new(client, api_client, app_key, options.into())?,
            objects: Vec::new(),
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
    pub async fn add<R: AsyncRead + Unpin>(&mut self, r: R) -> Result<u64, UploadError> {
        let object = Object::default();
        let start = self.upload.length();
        let n = self.upload.read(object.data_key.clone(), r).await?;
        let end = self.upload.length();
        self.objects.push(ObjectUpload { start, end, object });
        Ok(n)
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
                let mut object = upload.object;
                if upload.start == upload.end {
                    // empty object: nothing to splice in, leave it with zero slabs
                    return Ok(object);
                }
                let slabs_start = (upload.start / optimal_data_size) as usize;
                let slabs_end = upload.end.div_ceil(optimal_data_size) as usize;
                let n = slabs_end - slabs_start;
                object
                    .slabs
                    .extend_from_slice(&uploaded_slabs[slabs_start..slabs_end]);

                object.slabs[0].offset = (upload.start % optimal_data_size) as u32;
                if object.slabs.len() > 1 {
                    // if spanning multiple slabs, adjust first slab's length
                    object.slabs[0].length =
                        (optimal_data_size - object.slabs[0].offset as u64) as u32;
                }
                let last_slab_index = n - 1;
                let last_slab_offset = object.slabs[last_slab_index].offset as u64;
                object.slabs[last_slab_index].length =
                    (upload.end - ((slabs_end as u64 - 1) * optimal_data_size) - last_slab_offset)
                        as u32;

                Ok(object)
            })
            .collect()
    }
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

    /// Number of fast hosts [`racing_setup`] seeds alongside the slow one.
    const FAST_HOSTS: usize = 5;


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
            60,
            "the pool fills to every candidate it can reach",
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

    /// Transient pin errors reuse the same request; the indexer rejecting the
    /// slab as too old reuploads every shard with fresh upload times and
    /// preserves the object's data.
    #[sia_core_derive::cross_target_test]
    async fn test_upload_reuploads_when_indexer_rejects_slab() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let options = opts(3, 9);
        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        let transport = mock::Client::new();
        let hosts = Hosts::new(Client::from_mock(transport));
        // Two host sets let the reupload use previously unsampled hosts.
        hosts.update(
            (0..total_shards * 2)
                .map(|_| test_host(PrivateKey::from_seed(&rand::random()).public_key()))
                .collect(),
            true,
        );

        let uploads = Arc::new(AtomicUsize::new(0));
        let counter = uploads.clone();
        let api = app_client::mock::Client::new();
        api.set_pin_slabs_errors([
            app_client::Error::Api(StatusCode::INTERNAL_SERVER_ERROR, "temporary".into()),
            app_client::Error::Api(StatusCode::BAD_REQUEST, "slab upload is too old".into()),
            app_client::Error::Api(StatusCode::INTERNAL_SERVER_ERROR, "temporary".into()),
        ]);
        let app_key = Arc::new(AppKey::import(rand::random()));
        let before = Utc::now();
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
        let slabs = upload.finish().await.unwrap();

        assert_eq!(slabs.len(), 1);
        assert_eq!(slabs[0].sectors.len(), total_shards);
        let after = Utc::now();
        // every shard uploaded twice; each upload's pin was retried once after
        // a transient error, and only the second upload was pinned
        assert_eq!(uploads.load(Ordering::SeqCst), total_shards * 2);
        assert_eq!(api.pin_slabs_calls(), 4);
        assert_eq!(api.pinned_slabs(), 1);

        let requests = api.pin_slabs_requests();
        assert_eq!(requests.len(), 4, "two pin requests per upload attempt");
        assert_eq!(
            requests[0], requests[1],
            "first pin retry changed the request"
        );
        assert_eq!(
            requests[2], requests[3],
            "second pin retry changed the request"
        );
        for (shard_index, (first, second)) in requests[0][0]
            .sectors
            .iter()
            .zip(&requests[2][0].sectors)
            .enumerate()
        {
            assert_eq!(
                first.sector.root, second.sector.root,
                "shard {shard_index} changed its sector root on reupload"
            );
            // Upload times are UTC metadata, not a monotonic clock. Check
            // that both attempts supply recent times without ordering them.
            for (attempt, params) in [first, second].into_iter().enumerate() {
                let uploaded_at = params.uploaded_at.expect("missing sector upload time");
                assert!(
                    before <= uploaded_at && uploaded_at <= after,
                    "shard {shard_index} upload attempt {attempt}: {uploaded_at} outside {before}..={after}"
                );
            }
        }

        let object = Object { slabs, ..object };
        let mut download =
            Download::new(&object, hosts, app_key, DownloadOptions::default()).unwrap();
        let mut downloaded = Vec::with_capacity(data.len());
        tokio::io::copy(&mut download, &mut downloaded)
            .await
            .unwrap();
        assert_eq!(downloaded, data, "reupload changed the object data");
    }

    /// An upload fails once [`MAX_SLAB_ATTEMPTS`] attempts have all gone
    /// stale.
    #[sia_core_derive::cross_target_test]
    async fn test_upload_fails_after_max_stale_attempts() {
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

        let api = app_client::mock::Client::new();
        api.set_pin_slabs_errors((0..MAX_SLAB_ATTEMPTS).map(|_| {
            app_client::Error::Api(StatusCode::BAD_REQUEST, "slab upload is too old".into())
        }));
        let mut upload = Upload::new(
            hosts,
            app_client::Client::Mock(api.clone()),
            Arc::new(AppKey::import(rand::random())),
            options,
        )
        .unwrap();

        let mut data = BytesMut::zeroed(4096);
        rand::rng().fill_bytes(&mut data);
        upload
            .read(
                rand::random::<[u8; 32]>().into(),
                Cursor::new(data.freeze()),
            )
            .await
            .unwrap();
        let err = upload.finish().await.unwrap_err();
        assert!(matches!(err, UploadError::StaleSlab(attempts) if attempts == MAX_SLAB_ATTEMPTS));
        // the indexer rejected every attempt, so none was pinned
        assert_eq!(api.pin_slabs_calls(), MAX_SLAB_ATTEMPTS);
        assert_eq!(api.pinned_slabs(), 0);
    }
}
