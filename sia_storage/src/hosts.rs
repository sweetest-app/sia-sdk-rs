use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, serde_as};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;

use crate::client::Client;
#[cfg(test)]
use crate::client::metrics::{HostMetric, Transfer};
use crate::rhp4::HostEndpoint;
#[cfg(test)]
use crate::task::AbortOnDropHandle;
use crate::time::{Duration, Instant};
use crate::tokens::AccountTokenSource;
use crate::{AppKey, app_client};

/// How long a sector RPC may go without stream progress before the
/// transport gives up on the host.
pub(crate) const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(6);

/// Represents a host in the Sia network. The
/// addresses can be used to connect to the host.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A storage host on the Sia network.
pub struct Host {
    /// The host's public key.
    pub public_key: PublicKey,
    /// The host's network addresses.
    #[serde_as(as = "DefaultOnNull")]
    pub addresses: Vec<NetAddress>,
    /// The host's ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// The host's latitude coordinate.
    pub latitude: f64,
    /// The host's longitude coordinate.
    pub longitude: f64,
    /// Whether the host is currently suitable for uploading data.
    pub good_for_upload: bool,
}

#[derive(Debug)]
struct HostInfo {
    addresses: Vec<NetAddress>,
    good_for_upload: bool,
    /// Number of upload RPCs currently in flight to this host. The guard is
    /// created when a worker takes a shard and dropped when its write finishes,
    /// so a host that is busy is visible to anything that scores hosts.
    inflight_uploads: Arc<AtomicUsize>,
    /// Number of download RPCs currently in flight to this host. Updated
    /// by an [`InflightGuard`] in `Hosts::read_sector`; read by
    /// `prioritize` so concurrent slab downloads disperse across hosts
    /// instead of all piling onto the same top-N.
    inflight_downloads: Arc<AtomicUsize>,
}

/// RAII guard that increments an `AtomicUsize` on construction and
/// decrements it on drop. Used to track per-host inflight uploads so the
/// host scorer reflects current load and is balanced even on early returns
/// or async cancellations.
pub(crate) struct InflightGuard(Arc<AtomicUsize>);

impl InflightGuard {
    /// Increments `counter` and returns a guard that decrements it on
    /// drop. The increment is part of the selection path so concurrent
    /// pickers see the load on their next scan rather than only after
    /// the RPC starts.
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Where a host list is refreshed from, and when it last was.
struct HostRefresher {
    app_key: Arc<AppKey>,
    api_client: app_client::Client,
    min_time_between_refresh: Duration,
    last_refresh: tokio::sync::Mutex<Option<Instant>>,
}

/// Errors that can occur during host RPCs.
#[derive(Debug, Error)]
pub enum RPCError {
    /// The host is not known to the SDK.
    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    /// No account token is available to pay the host.
    #[error("no account token for host: {0}")]
    NoToken(PublicKey),

    /// An error in the RHP4 protocol.
    #[error("RHP error: {0}")]
    Rhp(#[from] crate::rhp4::Error),
}

/// Manages a list of known hosts and their performance metrics.
///
/// It allows updating the list of hosts, recording performance samples,
/// and prioritizing hosts based on their metrics.
///
/// It can be safely shared across threads and cloned.
#[derive(Clone)]
pub(crate) struct Hosts {
    transport: Client,
    hosts: Arc<RwLock<HashMap<PublicKey, HostInfo>>>,
    refresher: Option<Arc<HostRefresher>>,
}

impl Hosts {
    pub fn new(transport: Client) -> Self {
        Self {
            transport,
            hosts: Arc::default(),
            refresher: None,
        }
    }

    fn addresses(&self, host_key: &PublicKey) -> Option<Vec<NetAddress>> {
        let hosts = self.hosts.read().unwrap();
        hosts.get(host_key).map(|h| h.addresses.clone())
    }

    /// Sorts a list of items by their host's download score (descending).
    /// Score is `throughput / (inflight_downloads + 1)`, lower failure_rate
    /// wins first, and unsampled hosts get discovery priority. Used by the
    /// download path so concurrent slab downloads spread initial picks
    /// across less-busy hosts.
    ///
    /// Hosts this SDK has no address for are dropped rather than sorted to
    /// the back. Reading from one could only ever fail with
    /// [`RPCError::UnknownHost`], so leaving it in hides a shortage that is
    /// already certain behind a run of doomed attempts.
    pub fn prioritize<H, F>(&self, items: &mut Vec<H>, f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        let host_info = self.hosts.read().unwrap();
        items.retain(|item| host_info.contains_key(f(item)));
        // Use `sort_by_cached_key` so each item's score is computed exactly
        // once. The inflight counter is an atomic that other tasks mutate
        // concurrently — recomputing during the sort would let the same
        // host's score change between comparisons, violating total order
        // and crashing the sort.
        items.sort_by_cached_key(|item| {
            let key = f(item);
            let inflight = host_info[key].inflight_downloads.load(Ordering::Relaxed);
            let metric = self.transport.host_metric(key);
            let throughput = metric.combined_throughput();
            // Expected throughput if one more download started here. `to_bits`
            // keeps this a total order: throughput is never negative or NaN,
            // and IEEE754 bit patterns sort with the value in that range.
            let expected = throughput
                .map(|t| (t / (inflight as f64 + 1.0)).to_bits())
                .unwrap_or(0);
            // Ascending key, every component written worst-first:
            // fewer failures, unsampled before sampled (discovery), then the
            // highest expected throughput, then the least busy.
            (
                metric.failure_rate(),
                throughput.is_some(),
                std::cmp::Reverse(expected),
                inflight,
            )
        });
    }

    /// Adds new hosts to the list if they don't already exist.
    ///
    /// If `clear` is true, existing hosts not in the new list are removed, but
    /// their metrics and inflight counters are retained in case they reappear later.
    pub fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        let mut hosts = self.hosts.write().unwrap();
        // Preserve inflight counters across `clear=true` updates so guards
        // currently outstanding still decrement the right counter.
        let old = if clear {
            std::mem::take(&mut *hosts)
        } else {
            HashMap::new()
        };
        for host in new_hosts {
            let existing = hosts
                .get(&host.public_key)
                .or_else(|| old.get(&host.public_key));
            let inflight_uploads = existing
                .map(|h| h.inflight_uploads.clone())
                .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
            let inflight_downloads = existing
                .map(|h| h.inflight_downloads.clone())
                .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
            hosts.insert(
                host.public_key,
                HostInfo {
                    addresses: host.addresses,
                    good_for_upload: host.good_for_upload,
                    inflight_uploads,
                    inflight_downloads,
                },
            );
        }
    }

    /// Returns the number of known hosts that are good for upload.
    pub fn available_for_upload(&self) -> usize {
        self.hosts
            .read()
            .unwrap()
            .iter()
            .filter(|(_, h)| h.good_for_upload)
            .count()
    }

    /// Snapshots the currently upload-eligible host keys. Used to seed the
    /// worker pool, which then decides whom to dial.
    pub(crate) fn upload_eligible_hosts(&self) -> Vec<PublicKey> {        self.hosts
            .read()
            .unwrap()
            .iter()
            .filter_map(|(k, info)| info.good_for_upload.then_some(*k))
            .collect()
    }

    /// Begins tracking an in-flight download from the host. Returns a guard
    /// that increments the host's `inflight_downloads` counter immediately
    /// and decrements it on drop. Returns `None` if the host is unknown.
    pub fn reserve_inflight_download(&self, host_key: &PublicKey) -> Option<InflightGuard> {
        let counter = self
            .hosts
            .read()
            .unwrap()
            .get(host_key)?
            .inflight_downloads
            .clone();
        Some(InflightGuard::new(counter))
    }

    /// A [`Hosts`] that refreshes its list from the indexer, no more often
    /// than `min_time_between_refresh`.
    pub fn with_refresher(
        transport: Client,
        app_key: Arc<AppKey>,
        api_client: app_client::Client,
        min_time_between_refresh: Duration,
    ) -> Self {
        Self {
            refresher: Some(Arc::new(HostRefresher {
                app_key,
                api_client,
                min_time_between_refresh,
                last_refresh: tokio::sync::Mutex::new(None),
            })),
            ..Self::new(transport)
        }
    }

    /// Replaces the host list with the indexer's current one. Does nothing if
    /// there is no refresher or one ran within `min_time_between_refresh`.
    pub async fn refresh(&self) -> Result<(), app_client::Error> {
        let Some(refresher) = self.refresher.as_ref() else {
            return Ok(());
        };
        let mut last_refresh = refresher.last_refresh.lock().await;
        if last_refresh.is_some_and(|at| at.elapsed() < refresher.min_time_between_refresh) {
            return Ok(());
        }
        // recorded after the fetch, so anyone waiting on the lock sees a recent
        // refresh, and on failure too, so a down indexer isn't retried per slab
        let result = refresher.api_client.all_hosts(&refresher.app_key.0).await;
        *last_refresh = Some(Instant::now());
        self.replace(result?);
        Ok(())
    }

    /// Refreshes the list if fewer than `required` hosts are eligible for
    /// upload and returns how many are afterwards. A failed refresh is logged,
    /// not returned.
    pub async fn ensure_upload_hosts(&self, required: usize) -> usize {
        let available = self.available_for_upload();
        if available >= required {
            return available;
        }
        debug!("fewer than {required} hosts available for upload, refreshing");
        if let Err(err) = self.refresh().await {
            warn!("on-demand host refresh failed: {err}");
        }
        self.available_for_upload()
    }

    /// Swaps in a freshly fetched host list and warms the upload-eligible
    /// hosts.
    fn replace(&self, all_hosts: Vec<Host>) {
        debug!(
            "Refreshed hosts: total {}, good for upload {}",
            all_hosts.len(),
            all_hosts.iter().filter(|h| h.good_for_upload).count()
        );
        self.update(all_hosts, true);
    }

    fn host_endpoint(&self, host_key: PublicKey) -> Result<HostEndpoint, RPCError> {
        let addresses = self.addresses(&host_key);
        match addresses {
            Some(addresses) => Ok(HostEndpoint {
                public_key: host_key,
                addresses,
            }),
            None => Err(RPCError::UnknownHost(host_key)),
        }
    }

    /// Opens a session to a host without running an RPC, so the worker pool can
    /// dial a candidate once and reuse it for every shard that follows.
    pub(crate) async fn connect(
        &self,
        host_key: PublicKey,
        idle_timeout: Duration,
    ) -> Result<(), RPCError> {
        let host = self.host_endpoint(host_key)?;
        self.transport.connect(&host, idle_timeout).await?;
        Ok(())
    }

    /// Whether a session to this host is still open in the transport pool.
    ///
    /// A host that hung up on an idle session is not a failure, so the worker
    /// asks this before blaming the host for a write that could not start.
    pub(crate) fn is_connected(&self, host_key: &PublicKey) -> bool {
        self.transport.is_connected(host_key)
    }

    pub fn write_estimate(&self, bytes: u32) -> Duration {
        self.transport.write_estimate(bytes)
    }

    /// Bytes per second this host has written, once any shard has landed on it.
    /// `None` means nothing has been measured yet. The worker pool's dial score
    /// reads this, so a host that has proven slow is dialled after a fast one.
    pub(crate) fn write_throughput(&self, host_key: &PublicKey) -> Option<f64> {
        self.transport
            .host_metric(host_key)
            .write_throughput()
            .map(|rate| *rate)
    }

    pub fn read_estimate(&self, bytes: u32) -> Duration {
        self.transport.read_estimate(bytes)
    }

    /// Performs an upload RPC to the given host. The caller holds the
    /// [`InflightGuard`] for the duration of this call so the host scorer
    /// reflects the load.
    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: bytes::Bytes,
        idle_timeout: Duration,
    ) -> Result<Hash256, RPCError> {
        let host = self.host_endpoint(host_key)?;
        let was_connected = self.transport.is_connected(&host_key);
        let prices_started = Instant::now();
        let prices = self.transport.host_prices(&host, idle_timeout).await?;
        let prices_elapsed = prices_started.elapsed();
        let handshake = if was_connected {
            Duration::ZERO
        } else {
            self.transport.handshake_time(&host_key).unwrap_or_default()
        };
        let ttfb = prices_elapsed.saturating_sub(handshake);
        let write_started = Instant::now();
        let result = self
            .transport
            .write_sector(&host, prices, account_key, sector, idle_timeout)
            .await;
        let transfer = write_started.elapsed();
        match &result {
            Ok(_) => debug!(
                "[RHP] host {host_key} handshake {handshake:?} ttfb {ttfb:?} transfer {transfer:?}"
            ),
            Err(e) => debug!(
                "[RHP] host {host_key} handshake {handshake:?} ttfb {ttfb:?} transfer {transfer:?} failed: {e}"
            ),
        }
        let root = result?;
        Ok(root)
    }

    /// Performs a download RPC from the given host. The caller is
    /// responsible for holding the [`InflightGuard`] returned by
    /// [`Self::reserve_inflight_download`] for the duration of this call so
    /// the host scorer reflects the load.
    pub async fn read_sector(
        &self,
        host_key: PublicKey,
        tokens: &AccountTokenSource,
        root: Hash256,
        offset: usize,
        length: usize,
        idle_timeout: Duration,
    ) -> Result<bytes::Bytes, RPCError> {
        let host = self.host_endpoint(host_key)?;
        let prices = self.transport.host_prices(&host, idle_timeout).await?;
        let data = self
            .transport
            .read_sector(
                &host,
                prices,
                tokens,
                root,
                offset..offset + length,
                idle_timeout,
            )
            .await
            .map_err(|e| match e {
                crate::rhp4::Error::NoToken(host) => RPCError::NoToken(host),
                e => e.into(),
            })?;
        Ok(data)
    }
}

#[cfg(test)]
impl Hosts {
    /// Mutates the per-host metric in place. Used by the sample/failure
    /// recording helpers below.
    fn with_metric<F>(&self, host_key: &PublicKey, f: F)
    where
        F: FnOnce(&mut HostMetric),
    {
        self.transport.seed_metric(*host_key, f);
    }

    /// Adds a failure for the given host, updating its metrics.
    pub fn add_failure(&self, host_key: PublicKey) {
        self.transport.seed_failure(host_key);
    }

    /// Adds a read sample for the given host, updating its metrics.
    fn add_read_sample(&self, host_key: PublicKey, transfer: Transfer) {
        self.with_metric(&host_key, |m| m.add_read_sample(transfer));
    }

    /// Adds a write sample for the given host, updating its metrics.
    fn add_write_sample(&self, host_key: PublicKey, transfer: Transfer) {
        self.with_metric(&host_key, |m| m.add_write_sample(transfer));
    }

    pub fn record_write_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        self.transport.seed_write_sample(host_key, size, elapsed);
    }

    pub fn record_read_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        self.transport.seed_read_sample(host_key, size, elapsed);
    }
}

/// Errors from host selection.
#[derive(Debug, Error)]
pub enum QueueError {
    /// Not enough hosts are available to meet the required shard count.
    #[error("not enough initial hosts")]
    InsufficientHosts,
}

#[cfg(test)]
mod test {
    use crate::client::Client;
    use crate::time::sleep;
    use sia_core::signing::PrivateKey;

    use super::*;

    fn random_pubkey() -> sia_core::signing::PublicKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        PrivateKey::from_seed(&seed).public_key()
    }

    /// A [`Hosts`] with an empty list that refreshes from `api`.
    fn hosts_with_refresher(
        api: &crate::app_client::mock::Client,
        min_time_between_refresh: Duration,
    ) -> Hosts {
        Hosts::with_refresher(
            Client::mock(),
            Arc::new(AppKey::import([1u8; 32])),
            app_client::Client::Mock(api.clone()),
            min_time_between_refresh,
        )
    }

    fn upload_host() -> Host {
        Host {
            public_key: random_pubkey(),
            addresses: vec![],
            country_code: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_ensure_upload_hosts_refetches_when_short() {
        let api = crate::app_client::mock::Client::new();
        api.add_hosts(vec![upload_host(), upload_host()]);
        let hosts = hosts_with_refresher(&api, Duration::from_secs(10));

        assert_eq!(hosts.available_for_upload(), 0);
        assert_eq!(hosts.ensure_upload_hosts(2).await, 2);
    }

    #[sia_core_derive::cross_target_test]
    async fn test_ensure_upload_hosts_is_rate_limited() {
        let api = crate::app_client::mock::Client::new();
        let hosts = hosts_with_refresher(&api, Duration::from_secs(10));
        assert_eq!(hosts.ensure_upload_hosts(1).await, 0);

        api.add_hosts(vec![upload_host()]);
        assert_eq!(
            hosts.ensure_upload_hosts(1).await,
            0,
            "a second refresh within the rate limit should be skipped"
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn shared_client_caches_prices_across_host_lists() {
        let transport = crate::rhp4::mock::Client::new();
        transport.set_price_delay(Duration::from_millis(100));
        let client = Client::from_mock(transport.clone());
        let first = Hosts::new(client.clone());
        let second = Hosts::new(client);
        let mut host = upload_host();
        host.addresses.push(NetAddress {
            protocol: sia_core::types::v2::Protocol::SiaMux,
            address: "localhost:9984".into(),
        });
        let key = host.public_key;
        first.update(vec![host.clone()], true);
        second.update(vec![host.clone()], true);
        let account = PrivateKey::from_seed(&[7; 32]);
        let data = bytes::Bytes::from(vec![1; sia_core::rhp4::SECTOR_SIZE]);
        let (a, b) = tokio::join!(
            first.write_sector(key, &account, data.clone(), RPC_IDLE_TIMEOUT),
            second.write_sector(key, &account, data.clone(), RPC_IDLE_TIMEOUT),
        );
        assert_eq!(a.unwrap(), b.unwrap());
        assert_eq!(transport.price_requests(), 1);

        first.update(vec![], true);
        drop(first);
        second.update(vec![], true);
        second.update(vec![host], true);
        second
            .write_sector(key, &account, data, RPC_IDLE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(transport.price_requests(), 1);

        let independent = Client::from_mock(transport.clone());
        independent
            .host_prices(&second.host_endpoint(key).unwrap(), RPC_IDLE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(transport.price_requests(), 2);
    }

    #[sia_core_derive::cross_target_test]
    async fn shared_client_tracks_rpcs_across_host_lists() {
        let client = Client::mock();
        let first = Hosts::new(client.clone());
        let second = Hosts::new(client.clone());
        let mut host = upload_host();
        host.addresses.push(NetAddress {
            protocol: sia_core::types::v2::Protocol::SiaMux,
            address: "localhost:9984".into(),
        });
        let key = host.public_key;
        first.update(vec![host.clone()], true);
        second.update(vec![host.clone()], true);
        first.add_failure(key);
        let rate = || client.failure_rate(key);
        assert_eq!(rate(), 100);

        let account = PrivateKey::from_seed(&[7; 32]);
        let data = bytes::Bytes::from(vec![1; sia_core::rhp4::SECTOR_SIZE]);
        let root = first
            .write_sector(key, &account, data.clone(), RPC_IDLE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(
            rate(),
            64,
            "settings and write RPCs each record one success"
        );
        assert_eq!(first.write_estimate(1024), second.write_estimate(1024));
        let tokens = AccountTokenSource::from(Arc::new(AppKey::import([7; 32])));
        assert_eq!(
            second
                .read_sector(key, &tokens, root, 0, data.len(), RPC_IDLE_TIMEOUT)
                .await
                .unwrap(),
            data
        );
        assert_eq!(rate(), 51);
        assert_eq!(first.read_estimate(1024), second.read_estimate(1024));

        let write_estimate = first.write_estimate(1024);
        let read_estimate = first.read_estimate(1024);
        first.update(vec![], true);
        assert!(first.host_endpoint(key).is_err());
        assert!(second.host_endpoint(key).is_ok());
        second.update(vec![], true);
        drop(first);
        drop(second);
        let third = Hosts::new(client);
        third.update(vec![host], true);
        assert_eq!(third.transport.failure_rate(key), 51);
        assert_eq!(third.write_estimate(1024), write_estimate);
        assert_eq!(third.read_estimate(1024), read_estimate);
    }

    #[test]
    fn shared_client_failures_affect_other_host_lists() {
        let client = Client::mock();
        let first = Hosts::new(client.clone());
        let second = Hosts::new(client);
        let bad = upload_host();
        let good = upload_host();
        first.update(vec![bad.clone()], true);
        second.update(vec![bad.clone(), good.clone()], true);
        first.add_failure(bad.public_key);
        let mut keys = vec![bad.public_key, good.public_key];
        second.prioritize(&mut keys, |key| key);
        assert_eq!(keys, vec![good.public_key, bad.public_key]);
        assert!(first.host_endpoint(good.public_key).is_err());
    }

    /// A timing out sector RPC must cost the host a failure sample.
    ///
    /// Without one its rate stays 0, and the download ranking puts an
    /// unsampled host above every measured one as a discovery preference, so
    /// the host that just timed out is picked first again.
    ///
    /// Each RPC gets its own host, so each starts unsampled and the assertion
    /// cannot be satisfied by the other RPC's failure.
    #[sia_core_derive::cross_target_test]
    async fn test_sector_rpc_timeout_records_a_host_failure() {
        let write_host = random_pubkey();
        let read_host = random_pubkey();
        let transport = crate::rhp4::mock::Client::new();
        // Far longer than the idle limit the RPCs get, so the idle timeout
        // always fires rather than the test depending on scheduling.
        transport.set_slow_hosts([write_host, read_host], Duration::from_secs(30));

        let entry = |public_key| Host {
            public_key,
            addresses: vec![sia_core::types::v2::NetAddress {
                protocol: sia_core::types::v2::Protocol::QUIC,
                address: "localhost:9984".to_string(),
            }],
            country_code: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        };
        let hosts = Hosts::new(Client::from_mock(transport));
        hosts.update(vec![entry(write_host), entry(read_host)], true);

        let rate = |hk| hosts.transport.failure_rate(hk);
        assert_eq!(rate(write_host), 0, "an unsampled host starts at zero");
        assert_eq!(rate(read_host), 0, "an unsampled host starts at zero");

        let account = PrivateKey::from_seed(&[7u8; 32]);
        let err = hosts
            .write_sector(
                write_host,
                &account,
                bytes::Bytes::from(vec![0u8; 4096]),
                Duration::from_millis(50),
            )
            .await
            .expect_err("a 30 second host cannot answer in 50ms");
        assert!(
            matches!(&err, RPCError::Rhp(e) if e.is_timeout()),
            "expected the idle timeout, got {err:?}"
        );
        assert!(
            rate(write_host) > 0,
            "the write timeout left the host unsampled, so it stays top ranked"
        );

        let err = hosts
            .read_sector(
                read_host,
                &AccountTokenSource::from(Arc::new(AppKey::import([7u8; 32]))),
                Hash256::new([0u8; 32]),
                0,
                4096,
                Duration::from_millis(50),
            )
            .await
            .expect_err("a 30 second host cannot answer in 50ms");
        assert!(
            matches!(&err, RPCError::Rhp(e) if e.is_timeout()),
            "expected the idle timeout, got {err:?}"
        );
        assert!(
            rate(read_host) > 0,
            "the read timeout left the host unsampled, so it stays top ranked"
        );
    }

    /// Concurrent price lookups for one host share a single RPC, success or
    /// failure. A shared failure is sampled once, not per caller.
    #[sia_core_derive::cross_target_test]
    async fn test_price_fetches_serialize_behind_one_rpc() {
        let host_key = random_pubkey();
        let transport = crate::rhp4::mock::Client::new();
        transport.set_price_delay(Duration::from_millis(100));
        let entry = || Host {
            public_key: host_key,
            addresses: vec![],
            country_code: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        };
        let hosts = Hosts::new(Client::from_mock(transport.clone()));
        hosts.update(vec![entry()], true);
        let cache = hosts.transport.clone();
        let host = || HostEndpoint {
            public_key: host_key,
            addresses: vec![],
        };
        let rate = |hosts: &Hosts| hosts.transport.failure_rate(host_key);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let host = host();
            join_set_spawn!(set, async move {
                cache.host_prices(&host, Duration::from_secs(5)).await
            });
        }
        while let Some(result) = set.join_next().await {
            result.unwrap().expect("price fetch failed");
        }
        assert_eq!(transport.price_requests(), 1);

        cache
            .host_prices(&host(), Duration::from_secs(5))
            .await
            .expect("price fetch failed");
        assert_eq!(transport.price_requests(), 1, "a valid table is reused");

        cache.expire_host_prices(host_key);
        cache
            .host_prices(&host(), Duration::from_secs(5))
            .await
            .expect("price fetch failed");
        assert_eq!(
            transport.price_requests(),
            2,
            "an expired table must be fetched again"
        );

        // A failed in-flight fetch is shared with everyone queued behind it
        // rather than each waiter retrying in turn. Seed a success first so
        // the failure rate can tell one failure sample from eight.
        let sample = Transfer::new(1 << 20, Duration::from_secs(1));
        hosts.add_write_sample(host_key, sample);
        transport.set_price_failures(1);
        cache.expire_host_prices(host_key);
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let host = host();
            join_set_spawn!(set, async move {
                cache.host_prices(&host, Duration::from_secs(5)).await
            });
        }
        while let Some(result) = set.join_next().await {
            result
                .unwrap()
                .expect_err("the failure must reach every waiter");
        }
        assert_eq!(transport.price_requests(), 3);

        // Eight callers, one RPC, one failure sample: the rate must match a
        // host that was told about exactly one failure.
        let reference = Hosts::new(Client::mock());
        reference.update(vec![entry()], true);
        reference.add_write_sample(host_key, sample);
        reference.add_failure(host_key);
        assert_eq!(rate(&hosts), rate(&reference));
        assert!(rate(&hosts) > 0, "the failed RPC must be sampled");

        cache
            .host_prices(&host(), Duration::from_secs(5))
            .await
            .expect("a call after the failure must retry");
        assert_eq!(transport.price_requests(), 4);
    }

    /// A price fetch outlives the caller that started it while another
    /// caller waits on it, and stops once nobody does.
    #[sia_core_derive::cross_target_test]
    async fn test_price_fetch_runs_until_done_or_unwanted() {
        let host_key = random_pubkey();
        let transport = crate::rhp4::mock::Client::new();
        transport.set_price_delay(Duration::from_millis(200));
        let hosts = Hosts::new(Client::from_mock(transport.clone()));
        hosts.update(
            vec![Host {
                public_key: host_key,
                addresses: vec![],
                country_code: String::new(),
                latitude: 0.0,
                longitude: 0.0,
                good_for_upload: true,
            }],
            true,
        );
        let cache = hosts.transport.clone();
        let host = || HostEndpoint {
            public_key: host_key,
            addresses: vec![],
        };
        let spawn_fetch = || {
            let cache = cache.clone();
            let host = host();
            AbortOnDropHandle::new(maybe_spawn!(async move {
                cache.host_prices(&host, Duration::from_secs(5)).await
            }))
        };

        // the starter is cancelled; the waiter still gets the result of the
        // same RPC
        let starter = spawn_fetch();
        let waiter = spawn_fetch();
        sleep(Duration::from_millis(20)).await;
        drop(starter);
        waiter
            .await
            .unwrap()
            .expect("the fetch must survive its starter being cancelled");
        assert_eq!(transport.price_requests(), 1);

        // with every waiter gone the RPC is abandoned, so nothing is cached
        // from it and the next call fetches again
        cache.expire_host_prices(host_key);
        let abandoned = spawn_fetch();
        sleep(Duration::from_millis(20)).await;
        drop(abandoned);
        sleep(Duration::from_millis(300)).await;
        cache
            .host_prices(&host(), Duration::from_secs(5))
            .await
            .expect("price fetch failed");
        assert_eq!(
            transport.price_requests(),
            3,
            "an abandoned fetch must not complete and populate the cache"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_prioritize_uses_download_inflight() {
        // Two hosts with identical throughput samples; bumping one host's
        // download inflight counter should push it down in the sorted
        // order. Mirrors the upload-side `next_upload_host` behavior so
        // concurrent slab downloads spread across less-busy hosts.
        let hosts_manager = Hosts::new(Client::mock());
        let hk1 = random_pubkey();
        let hk2 = random_pubkey();
        hosts_manager.update(
            vec![
                Host {
                    public_key: hk1,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
                Host {
                    public_key: hk2,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
            ],
            true,
        );
        // Sample both with the same throughput so the inflight counter is
        // the only differentiator.
        hosts_manager.add_read_sample(hk1, Transfer::new(1_000_000, Duration::from_secs(1)));
        hosts_manager.add_read_sample(hk2, Transfer::new(1_000_000, Duration::from_secs(1)));

        // With both idle, sort order is arbitrary among ties — assert the
        // ranking switches when we add inflight to one of them.
        let mut items = vec![hk1, hk2];
        hosts_manager.prioritize(&mut items, |k| k);
        let initial_first = items[0];
        let initial_second = items[1];

        // Bump inflight on whichever host happened to be first by holding
        // three live guards on it.
        let _guards: Vec<_> = (0..3)
            .map(|_| {
                hosts_manager
                    .reserve_inflight_download(&initial_first)
                    .unwrap()
            })
            .collect();

        let mut items = vec![hk1, hk2];
        hosts_manager.prioritize(&mut items, |k| k);
        assert_eq!(
            items[0], initial_second,
            "host with higher download inflight should sort second",
        );
        assert_eq!(items[1], initial_first);
    }

    /// The download ranking, in the one place that sorts.
    ///
    /// Order: fewest failures, then unsampled hosts (discovery), then the
    /// highest `throughput / (inflight + 1)`.
    #[sia_core_derive::cross_target_test]
    fn prioritize_ranks_failures_then_discovery_then_throughput() {
        let hosts_manager = Hosts::new(Client::mock());
        let failing = upload_host();
        let unsampled = upload_host();
        let slow = upload_host();
        let fast = upload_host();
        let mut entries = vec![
            failing.clone(),
            unsampled.clone(),
            slow.clone(),
            fast.clone(),
        ];
        hosts_manager.update(std::mem::take(&mut entries), true);

        hosts_manager.add_read_sample(failing.public_key, Transfer::new(1_000_000, Duration::from_secs(1)));
        hosts_manager.add_failure(failing.public_key);
        hosts_manager.add_read_sample(slow.public_key, Transfer::new(100, Duration::from_secs(1)));
        hosts_manager.add_read_sample(fast.public_key, Transfer::new(1000, Duration::from_secs(1)));

        let mut items = vec![
            failing.public_key,
            unsampled.public_key,
            slow.public_key,
            fast.public_key,
        ];
        hosts_manager.prioritize(&mut items, |key| key);
        assert_eq!(
            items,
            vec![
                unsampled.public_key,
                fast.public_key,
                slow.public_key,
                failing.public_key,
            ],
            "clean before failing, unsampled before sampled, faster first",
        );

        // A busy host loses to an idle one of the same speed, which is what
        // spreads concurrent downloads across hosts.
        let _guards: Vec<_> = (0..12)
            .map(|_| {
                hosts_manager
                    .reserve_inflight_download(&fast.public_key)
                    .unwrap()
            })
            .collect();
        let mut items = vec![fast.public_key, slow.public_key];
        hosts_manager.prioritize(&mut items, |key| key);
        assert_eq!(
            items,
            vec![slow.public_key, fast.public_key],
            "10x the throughput split 13 ways is less than the idle host",
        );
    }
}
