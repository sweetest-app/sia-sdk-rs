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
}

impl RequestQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Opens a slab whose shards will arrive one at a time, and returns its id.
    /// Nothing is queued until [`add_shard`](Self::add_shard).
    pub(crate) fn open_slab(&mut self, seed: SlabSeed, total: usize) -> SlabId {
        self.next_slab += 1;
        let id = SlabId(self.next_slab);
        self.slabs.insert(id, SlabTracker::open(id, seed, total));
        id
    }

    /// Queues one produced shard for a slab opened with
    /// [`open_slab`](Self::open_slab). Returns false when the shard does not
    /// belong to the slab or was already produced.
    pub(crate) fn add_shard(&mut self, id: SlabId, index: usize, data: Bytes) -> bool {
        let Some(slab) = self.slabs.get_mut(&id) else {
            return false;
        };
        if !slab.add_shard(index, data.clone()) {
            return false;
        }
        self.pending.push(ShardRequest {
            slab: id,
            shard: index,
            data,
        });
        true
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
            if slab.state() != crate::upload::slab::SlabState::Open || slab.has_served(host) {
                continue;
            }
            let rank = (slab.remaining(), request.slab.0);
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

    /// Whether every data shard of the slab is in, which is when parity may be
    /// produced.
    pub(crate) fn slab_ready_for_parity(&self, id: SlabId) -> bool {
        self.slabs
            .get(&id)
            .is_some_and(|slab| slab.all_data_shards_ready())
    }

    pub(crate) fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Abandons every slab and drops the work still queued for it. Called when
    /// the upload is cancelled, so nothing is written for a slab nobody wants.
    pub(crate) fn cancel_all(&mut self) {
        self.pending.clear();
        for tracker in self.slabs.values_mut() {
            tracker.cancel();
        }
        self.slabs.clear();
    }

    #[cfg(test)]
    pub(crate) fn open_slabs(&self) -> usize {
        self.slabs.len()
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

    /// Opens a slab of `count` shards with the default header, and adds them.
    fn add(queue: &mut RequestQueue, count: usize) -> SlabId {
        // Every shard is a data shard in these fixtures, so the slab freezes as
        // soon as they are all in and placement can be tested on its own.
        let mut header = seed();
        header.min_shards = count as u8;
        let id = queue.open_slab(header, count);
        for (index, shard) in shards(count).into_iter().enumerate() {
            assert!(queue.add_shard(id, index, shard));
        }
        id
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
    fn every_slab_with_a_shard_is_open_at_once() {
        // Five slabs of thirty is more than the old buffered window allowed, and
        // each one must hand out work without waiting for the others.
        let mut queue = RequestQueue::new();
        let ids: Vec<SlabId> = (0..5).map(|_| add(&mut queue, 30)).collect();
        assert_eq!(queue.open_slabs(), 5);

        for seed in 1..=5u8 {
            let host = key(seed);
            let request = queue.take(&host).expect("work from one of the slabs");
            assert!(ids.contains(&request.slab));
            place(&mut queue, host, &request);
        }
    }

    #[test]
    fn cancelling_drops_queued_work_and_abandons_slabs() {
        let mut queue = RequestQueue::new();
        add(&mut queue, 30);
        add(&mut queue, 30);
        assert!(queue.pending() > 0);

        queue.cancel_all();
        assert_eq!(queue.pending(), 0, "no shard is left to write");
        assert_eq!(queue.open_slabs(), 0, "no slab is left open");
        assert!(queue.take(&key(1)).is_none(), "nothing to hand out");
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


}
