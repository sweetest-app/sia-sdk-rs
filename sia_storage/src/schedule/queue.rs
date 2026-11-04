use std::collections::HashMap;

use bytes::Bytes;
use sia_core::signing::PublicKey;

use crate::app_client::SectorPinParams;

use super::slab::{FinishedSlab, SlabId, SlabSeed, SlabTracker};

/// One shard waiting for a host that may write it.
#[derive(Clone, Debug)]
pub(crate) struct ShardRequest {
    pub slab: SlabId,
    pub shard: usize,
    /// The encoded sector. `Bytes` is reference counted, so handing one out is
    /// a pointer copy, not a 4 MiB move.
    pub data: Bytes,
}

/// The shards waiting to be written, and the slabs they belong to.
///
/// The queue never chooses a host. A host asks for work and the queue answers
/// with the best shard that host is allowed to write, or nothing. That is the
/// whole inversion: availability assigns work, not a score.
#[derive(Debug, Default)]
pub(crate) struct RequestQueue {
    slabs: HashMap<SlabId, SlabTracker>,
    pending: Vec<ShardRequest>,
    next_slab: u64,
    next_order: u64,
}

impl RequestQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Registers a finished slab's shards and returns its id. Every shard starts
    /// pending, in index order.
    pub(crate) fn add_slab(&mut self, shards: Vec<Bytes>, seed: SlabSeed) -> SlabId {
        self.next_slab += 1;
        let id = SlabId(self.next_slab);
        let order = self.next_order;
        self.next_order += 1;
        self.slabs
            .insert(id, SlabTracker::new(id, order, seed, shards.clone()));
        for (shard, data) in shards.into_iter().enumerate() {
            self.pending.push(ShardRequest { slab: id, shard, data });
        }
        id
    }

    /// Puts a slab back for another upload attempt, keeping its id and order so
    /// the caller's bookkeeping does not move. Used when the indexer rejects a
    /// slab as stale: the same bytes go out again rather than being re-encoded.
    pub(crate) fn readd_slab(&mut self, id: SlabId, order: u64, shards: Vec<Bytes>, seed: SlabSeed) {
        self.slabs
            .insert(id, SlabTracker::new(id, order, seed, shards.clone()));
        for (shard, data) in shards.into_iter().enumerate() {
            self.pending.push(ShardRequest { slab: id, shard, data });
        }
    }

    /// The best shard `host` may write, or `None` so the caller can park.
    ///
    /// Best is the slab with the fewest shards remaining, because an unfinished
    /// slab is never pinned and its placed shards are wasted work. Equally
    /// unfinished slabs are taken oldest first. Slabs this host has already
    /// served are skipped: one shard per host per slab.
    pub(crate) fn take(&mut self, host: &PublicKey) -> Option<ShardRequest> {
        let mut best: Option<(usize, u64, usize)> = None;
        for (index, request) in self.pending.iter().enumerate() {
            let Some(slab) = self.slabs.get(&request.slab) else {
                continue;
            };
            if slab.has_served(host) {
                continue;
            }
            let rank = (slab.remaining(), slab.order());
            let better = match best {
                None => true,
                Some((remaining, order, _)) => {
                    rank.0 < remaining || (rank.0 == remaining && rank.1 < order)
                }
            };
            if better {
                best = Some((rank.0, rank.1, index));
            }
        }
        let (_, _, index) = best?;
        Some(self.pending.swap_remove(index))
    }

    /// Records a placed shard. Returns the finished slab once every shard has
    /// landed, which is the only point at which it can be pinned.
    pub(crate) fn placed(
        &mut self,
        host: &PublicKey,
        request: &ShardRequest,
        sector: SectorPinParams,
    ) -> Option<FinishedSlab> {
        let slab = self.slabs.get_mut(&request.slab)?;
        if !slab.record(request.shard, *host, sector) {
            return None;
        }
        if !slab.is_complete() {
            return None;
        }
        self.slabs.remove(&request.slab).and_then(SlabTracker::finish)
    }

    /// Puts a shard back, for a host that failed. The host is not recorded as
    /// having served the slab, so another host may take the same shard.
    pub(crate) fn failed(&mut self, request: ShardRequest) {
        self.pending.push(request);
    }

    /// Whether any pending shard could be written by one of `hosts`.
    ///
    /// A worker that finds nothing is not evidence of a stall: it may simply have
    /// served that slab already, while another worker has not. This is the
    /// question that decides whether the upload is stuck.
    pub(crate) fn servable_by(&self, hosts: &[PublicKey]) -> bool {
        self.pending.iter().any(|request| {
            match self.slabs.get(&request.slab) {
                Some(slab) => hosts.iter().any(|host| !slab.has_served(host)),
                // A request whose slab is gone is a bug, not work.
                None => false,
            }
        })
    }

    pub(crate) fn pending(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn open_slabs(&self) -> usize {
        self.slabs.len()
    }

    /// A one line summary for the upload log.
    pub(crate) fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .slabs
            .values()
            .map(|slab| format!("{} {}/{}", slab.id().0, slab.placed(), slab.total()))
            .collect();
        parts.sort();
        format!(
            "{} pending across {} slabs [{}]",
            self.pending.len(),
            self.slabs.len(),
            parts.join(", "),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::Sector;
    use sia_core::signing::PrivateKey;
    use sia_core::types::Hash256;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from_seed(&[seed; 32]).public_key()
    }

    fn shards(count: usize) -> Vec<Bytes> {
        (0..count).map(|index| Bytes::from(vec![index as u8; 8])).collect()
    }

    fn seed() -> SlabSeed {
        SlabSeed {
            encryption_key: [1u8; 32].into(),
            length: 4096,
            min_shards: 10,
        }
    }

    fn sector(host: PublicKey) -> SectorPinParams {
        SectorPinParams {
            sector: Sector {
                root: Hash256::new([9u8; 32]),
                host_key: host,
            },
            uploaded_at: Some(Utc::now()),
        }
    }

    /// Adds a slab of `count` shards with the default header.
    fn add(queue: &mut RequestQueue, count: usize) -> SlabId {
        queue.add_slab(shards(count), seed())
    }

    /// Places a shard with the sector the host would have written.
    fn place(queue: &mut RequestQueue, host: PublicKey, request: &ShardRequest) -> Option<SlabId> {
        queue
            .placed(&host, request, sector(host))
            .map(|finished| finished.id)
    }

    #[test]
    fn taking_with_nothing_pending_returns_none_so_a_worker_parks() {
        let mut queue = RequestQueue::new();
        assert!(queue.take(&key(1)).is_none());
    }

    #[test]
    fn a_host_cannot_take_two_shards_of_the_same_slab() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 30);
        let host = key(1);

        let first = queue.take(&host).expect("a shard");
        assert_eq!(first.slab, slab);
        place(&mut queue, host, &first);

        assert!(
            queue.take(&host).is_none(),
            "one shard per host per slab, so the same host gets nothing more here",
        );
        assert!(queue.take(&key(2)).is_some());
    }

    #[test]
    fn a_host_may_serve_a_different_slab() {
        let mut queue = RequestQueue::new();
        let first = add(&mut queue, 2);
        let second = add(&mut queue, 2);
        let host = key(1);

        let request = queue.take(&host).unwrap();
        assert_eq!(request.slab, first);
        place(&mut queue, host, &request);

        let next = queue.take(&host).expect("the other slab is open to this host");
        assert_eq!(next.slab, second);
    }

    #[test]
    fn the_slab_with_the_fewest_shards_remaining_goes_first() {
        let mut queue = RequestQueue::new();
        // 30 shards to place, 29 of them on the older slab, so the older slab
        // is one shard from done while the younger one is untouched.
        let older = add(&mut queue, 30);
        let younger = add(&mut queue, 30);
        for index in 0..29 {
            let host = key(50 + index);
            let request = queue.take(&host).unwrap();
            assert_eq!(request.slab, older, "the unfinished slab is the one to work on");
            place(&mut queue, host, &request);
        }

        // One shard left on the older slab, thirty on the younger. The older
        // is chosen for the reason the rule gives: the fewest shards left.
        let last = queue.take(&key(99)).unwrap();
        assert_eq!(
            last.slab, older,
            "a slab one shard from done is finished before a bigger one starts",
        );
        assert!(place(&mut queue, key(99), &last).is_some(), "that shard finishes it");

        let next = queue.take(&key(98)).unwrap();
        assert_eq!(next.slab, younger, "the younger slab is what is left");
    }

    #[test]
    fn a_small_slab_is_finished_before_an_older_big_one() {
        // Age only breaks a tie. The younger slab here is far closer to done,
        // so it wins even though the other one was added first. Getting this
        // backwards would leave partial slabs, which are never pinned.
        let mut queue = RequestQueue::new();
        let _older = add(&mut queue, 30);
        let younger = add(&mut queue, 2);

        let first = queue.take(&key(1)).unwrap();
        assert_eq!(first.slab, younger, "two shards left beats thirty");
    }

    #[test]
    fn equally_unfinished_slabs_go_oldest_first() {
        let mut queue = RequestQueue::new();
        let older = add(&mut queue, 30);
        let _younger = add(&mut queue, 30);

        for seed in 1..4 {
            let request = queue.take(&key(seed)).expect("a shard");
            assert_eq!(
                request.slab, older,
                "the older slab breaks the tie until it pulls ahead",
            );
        }
    }

    #[test]
    fn hosts_do_not_block_each_other_on_the_same_slab() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 30);
        let first = queue.take(&key(1)).unwrap();
        let second = queue.take(&key(2)).unwrap();
        assert_eq!(first.slab, slab);
        assert_eq!(second.slab, slab);
        assert_ne!(first.shard, second.shard, "two hosts, two shards");
    }

    #[test]
    fn a_failed_shard_is_reported_back_and_taken_by_another_host() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 2);

        let keeps = queue.take(&key(1)).unwrap();
        let fails = queue.take(&key(2)).unwrap();
        assert_eq!(keeps.slab, slab);
        assert_ne!(keeps.shard, fails.shard);
        let shard = fails.shard;

        queue.failed(fails);
        assert_eq!(queue.pending(), 1, "the failed request is pending again");

        let retry = queue.take(&key(3)).unwrap();
        assert_eq!(retry.shard, shard, "the same shard went to another host");
        place(&mut queue, key(3), &retry);
        assert_eq!(queue.pending(), 0);
        assert_eq!(
            place(&mut queue, key(1), &keeps),
            Some(slab),
            "the slab completes when the last shard lands",
        );
    }

    #[test]
    fn a_slab_is_reported_complete_only_on_the_last_shard() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 3);

        for (index, seed) in (10..13).enumerate() {
            let host = key(seed);
            let request = queue.take(&host).unwrap();
            assert_eq!(request.slab, slab);
            let finished = place(&mut queue, host, &request);
            if index < 2 {
                assert_eq!(finished, None, "not done at {index}");
            } else {
                assert_eq!(finished, Some(slab), "done on the last shard");
            }
        }
        assert_eq!(queue.open_slabs(), 0);
        assert_eq!(queue.pending(), 0);
    }

    #[test]
    fn a_completed_slab_accepts_no_more_requests() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 1);
        let host = key(1);
        let request = queue.take(&host).unwrap();
        assert_eq!(place(&mut queue, host, &request), Some(slab));
        assert!(queue.take(&key(2)).is_none());
        assert_eq!(place(&mut queue, host, &request), None, "the slab is gone");
    }

    #[test]
    fn describe_names_every_open_slab() {
        let mut queue = RequestQueue::new();
        add(&mut queue, 2);
        add(&mut queue, 1);
        let line = queue.describe();
        assert!(line.contains("3 pending across 2 slabs"), "{line}");
    }

    #[test]
    fn a_stale_slab_goes_back_with_its_own_id() {
        let mut queue = RequestQueue::new();
        let slab = add(&mut queue, 2);

        // Place both shards so the slab finishes and is handed back.
        let first = queue.take(&key(1)).unwrap();
        place(&mut queue, key(1), &first);
        let second = queue.take(&key(2)).unwrap();
        let finished = queue
            .placed(&key(2), &second, sector(key(2)))
            .expect("the second shard completes it");
        assert_eq!(finished.id, slab);
        assert_eq!(finished.shards.len(), 2, "the bytes come back for the retry");

        // The indexer rejected it as stale, so the same shards go out again and
        // the id does not move, which keeps the caller's slot correct.
        queue.readd_slab(finished.id, finished.order, finished.shards, finished.seed);
        assert_eq!(queue.pending(), 2);
        assert_eq!(queue.open_slabs(), 1);

        let retry_a = queue.take(&key(3)).unwrap();
        assert_eq!(retry_a.slab, slab);
        place(&mut queue, key(3), &retry_a);
        let retry_b = queue.take(&key(4)).unwrap();
        let again = place(&mut queue, key(4), &retry_b);
        assert_eq!(again, Some(slab), "the retry finishes under the same id");
    }
}
