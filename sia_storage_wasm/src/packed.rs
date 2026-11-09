use std::cell::Cell;
use std::rc::Rc;
use tokio::sync::Mutex;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use sia_storage::{CancelHandle, PackedUpload as CorePackedUpload};
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::stream_reader::js_stream_reader;

/// A packed upload handle for efficiently uploading multiple objects
/// together. Objects are packed into shared slabs to avoid wasting storage.
///
/// ```js
/// const packed = sdk.uploadPacked();
/// await packed.add(file1.stream());
/// await packed.add(file2.stream());
/// const objects = await packed.finalize();
/// for (const obj of objects) await sdk.pinObject(obj);
/// ```
#[wasm_bindgen]
pub struct PackedUpload {
    inner: Rc<Mutex<Option<CorePackedUpload>>>,
    cancel: CancelHandle,
    optimal_data_size: f64,
    length: Cell<f64>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        let optimal_data_size = inner.optimal_data_size() as f64;
        let cancel = inner.cancel_handle();
        Self {
            inner: Rc::new(Mutex::new(Some(inner))),
            cancel,
            optimal_data_size,
            length: Cell::new(0.0),
        }
    }
}

#[wasm_bindgen]
impl PackedUpload {
    /// Bytes remaining until the current slab is full. Adding objects that
    /// fit within this size avoids starting a new slab and minimizes padding.
    pub fn remaining(&self) -> f64 {
        remaining(self.length.get(), self.optimal_data_size)
    }

    /// Total bytes added so far across all objects.
    pub fn length(&self) -> f64 {
        self.length.get()
    }

    /// Shard bytes the upload holds right now: queued shards, the shards a host
    /// is writing, parity being encoded, and the reader's buffer.
    #[wasm_bindgen(js_name = "heldBytes")]
    pub async fn held_bytes(&self) -> Result<f64, JsError> {
        let guard = self.inner.lock().await;
        let pu = guard.as_ref().ok_or_else(|| JsError::new("upload closed"))?;
        Ok(pu.held_bytes() as f64)
    }

    /// The highest [`heldBytes`](Self::held_bytes) reached, so the peak does
    /// not depend on how often it is sampled.
    #[wasm_bindgen(js_name = "peakHeldBytes")]
    pub async fn peak_held_bytes(&self) -> Result<f64, JsError> {
        let guard = self.inner.lock().await;
        let pu = guard.as_ref().ok_or_else(|| JsError::new("upload closed"))?;
        Ok(pu.peak_held_bytes() as f64)
    }

    /// Number of slabs in the upload.
    pub fn slabs(&self) -> f64 {
        let length = self.length.get();
        if length == 0.0 {
            0.0
        } else {
            (length / self.optimal_data_size).ceil()
        }
    }

    /// Optimal size of each slab in bytes.
    #[wasm_bindgen(js_name = "optimalDataSize")]
    pub fn optimal_data_size(&self) -> f64 {
        self.optimal_data_size
    }

    /// Adds a new object to the upload. The data is read until EOF and packed into
    /// the current slab. Returns the number of bytes consumed; call
    /// [finalize](Self::finalize) once all objects have been added to get the
    /// resulting objects.
    ///
    /// If the reader errors part-way, it's safe to continue calling
    /// [add](Self::add); no object is registered for the failed call. Or call
    /// [finalize](Self::finalize) to collect the objects added so far. Bytes
    /// read before the error remain in the current slab as padding and stay
    /// counted in [length](Self::length) and [remaining](Self::remaining).
    ///
    /// ```js
    /// const packed = sdk.uploadPacked();
    /// await packed.add(file.stream());
    /// await packed.add(blob.stream());
    /// const objects = await packed.finalize();
    /// ```
    pub async fn add(&self, stream: web_sys::ReadableStream) -> Result<f64, JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let reader = js_stream_reader(stream).compat();
        let mut guard = self.inner.lock().await;
        // Taking the upload out lets a cancel drop it and abort its slab
        // uploads; the core's closed flag is what stops the work itself.
        let mut pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
        let res = pu.add(reader).await.map_err(to_js_err);
        // Mirror pu.length() rather than accumulating the add's returned size,
        // so partial bytes from an errored add stay accounted for.
        let total = pu.length() as f64;
        *guard = Some(pu);
        self.length.set(total);
        Ok(res? as f64)
    }

    /// Opens a slab for shards that arrive one at a time, and returns its id.
    /// `0` means the upload was cancelled. Send its data shards with
    /// [`addShard`](Self::add_shard); the encoder produces parity from them.
    #[wasm_bindgen(js_name = "registerSlab")]
    pub async fn register_slab(&self, length: f64) -> Result<f64, JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let mut guard = self.inner.lock().await;
        let mut pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
        let result = pu.register_slab(length as u64).await.map_err(to_js_err);
        *guard = Some(pu);
        Ok(result? as f64)
    }

    /// Queues one data shard of a slab opened with `registerSlab`.
    #[wasm_bindgen(js_name = "addShard")]
    pub async fn add_shard(&self, slab: f64, index: f64, data: &[u8]) -> Result<(), JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let mut guard = self.inner.lock().await;
        let mut pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
        let result = pu
            .add_shard(slab as u64, index as usize, data)
            .await
            .map_err(to_js_err);
        *guard = Some(pu);
        result
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(&self) -> Result<Vec<PinnedObject>, JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let mut guard = self.inner.lock().await;
        let pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
        let objects = pu.finalize().await.map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// The objects whose slabs have all pinned, indexed the same way
    /// [add](Self::add) was called. `undefined` at an index means that object
    /// still has a slab in flight.
    ///
    /// This is how a caller composes and pins files while the upload keeps
    /// running, instead of waiting for [finalize](Self::finalize).
    #[wasm_bindgen(js_name = "addedObjects")]
    pub async fn added_objects(&self) -> Result<js_sys::Array, JsError> {
        let inner = self.inner.clone();
        let guard = inner.lock().await;
        let Some(pu) = guard.as_ref() else {
            return Err(JsError::new("upload closed"));
        };
        let array = js_sys::Array::new();
        for ready in pu.ready_objects() {
            match ready {
                Some(object) => {
                    array.push(&JsValue::from(PinnedObject(object)));
                }
                None => {
                    array.push(&JsValue::UNDEFINED);
                }
            }
        }
        Ok(array)
    }

    /// Cancels the packed upload. Immediately interrupts any in-flight `add`
    /// and aborts all pending slab uploads.
    pub fn cancel(&self) {
        // The one signal: the core's closed flag. Every task of the upload
        // observes it, and the shards in the queue are dropped with it.
        self.cancel.cancel();
        if let Ok(mut guard) = self.inner.try_lock() {
            guard.take();
        }
    }
}

/// Bytes remaining in the current slab, given what has been added so far.
fn remaining(length: f64, optimal_data_size: f64) -> f64 {
    optimal_data_size - (length % optimal_data_size)
}

#[cfg(test)]
mod packed_remaining_tests {
    use super::remaining;

    #[test]
    fn a_full_slab_reports_a_whole_slab_free() {
        let optimal = (40 << 20) as f64;
        assert_eq!(remaining(0.0, optimal), optimal, "nothing added yet");
        assert_eq!(remaining(optimal / 2.0, optimal), optimal / 2.0);
        // The slab rolled over, so the next one is empty. Reporting 0 here
        // would tell a caller every further add starts a new slab.
        assert_eq!(remaining(optimal, optimal), optimal);
        assert_eq!(remaining(2.0 * optimal, optimal), optimal);
    }
}
