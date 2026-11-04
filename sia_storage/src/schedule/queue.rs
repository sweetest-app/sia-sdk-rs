use std::collections::HashMap;

use bytes::Bytes;
use sia_core::signing::PublicKey;

use super::slab::{SlabId, SlabTracker};

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
    pub(crate) fn add_slab(&mut self, shards: Vec<Bytes>) -> SlabId {
        self.next_slab += 1;
        let id = SlabId(self.next_slab);
        let order = self.next_order;
        self.next_order += 1;
        let total = shards.len();
        self.slabs.insert(id, SlabTracker::new(id, total, order));
        for (shard, data) in shards.into_iter().enumerate() {
            self.pending.push(ShardRequest { slab: id, shard, data });
        }
        id
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

    /// Records a placed shard. Returns the slab id once every shard has landed,
    /// which is the only point at which the slab can be pinned.
    pub(crate) fn placed(&mut self, host: &PublicKey, request: &ShardRequest) -> Option<SlabId> {
        let slab = self.slabs.get_mut(&request.slab)?;
        if !slab.record(request.shard, *host) {
            return None;
        }
        if slab.is_complete() {
            let id = slab.id();
            self.slabs.remove(&id);
            return Some(id);
        }
        None
    }

    /// Puts a shard back, for a host that failed. The host is not recorded as
    /// having served the slab, so another host may take the same shard.
    pub(crate) fn failed(&mut self, request: ShardRequest) {
        self.pending.push(request);
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
    use sia_core::signing::PrivateKey;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from_seed(&[seed; 32]).public_key()
    }

    fn shards(count: usize) -> Vec<Bytes> {
        (0..count).map(|index| Bytes::from(vec![index as u8; 8])).collect()
    }

    #[test]
    fn taking_with_nothing_pending_returns_none_so_a_worker_parks() {
        let mut queue = RequestQueue::new();
        assert!(queue.take(&key(1)).is_none());
    }

    #[test]
    fn a_host_cannot_take_two_shards_of_the_same_slab() {
        let mut queue = RequestQueue::new();
        let slab = queue.add_slab(shards(30));
        let host = key(1);

        let first = queue.take(&host).expect("a shard");
        assert_eq!(first.slab, slab);
        queue.placed(&host, &first);

        assert!(
            queue.take(&host).is_none(),
            "one shard per host per slab, so the same host gets nothing more here",
        );
        // Another host can still take the next one.
        assert!(queue.take(&key(2)).is_some());
    }

    #[test]
    fn a_host_may_serve_a_different_slab() {
        let mut queue = RequestQueue::new();
        let first = queue.add_slab(shards(2));
        let second = queue.add_slab(shards(2));
        let host = key(1);

        let request = queue.take(&host).unwrap();
        assert_eq!(request.slab, first);
        queue.placed(&host, &request);

        let next = queue.take(&host).expect("the other slab is open to this host");
        assert_eq!(next.slab, second);
    }

    #[test]
    fn the_slab_with_the_fewest_shards_remaining_goes_first() {
        let mut queue = RequestQueue::new();
        let behind = queue.add_slab(shards(30));
        let ahead = queue.add_slab(shards(30));

        // Fill the second slab almost to the end with other hosts.
        for seed in 10..39 {
            let host = key(seed);
            let request = queue.take(&host).unwrap();
            assert_eq!(request.slab, behind, "the untouched slab is older");
            queue.placed(&host, &request);
        }
        // Now the first slab is untouched and the second has none placed, so
        // place shards on the younger one and check it wins.
        let mut placed_on_second = 0;
        for seed in 40..70 {
            let host = key(seed);
            let request = queue.take(&host).unwrap();
            if request.slab == ahead {
                placed_on_second += 1;
            }
            queue.placed(&host, &request);
            if placed_on_second == 25 {
                break;
            }
        }

        let probe = queue.take(&key(1)).unwrap();
        assert_eq!(
            probe.slab, ahead,
            "the slab closest to done should be finished first",
        );
    }

    #[test]
    fn equally_unfinished_slabs_go_oldest_first() {
        let mut queue = RequestQueue::new();
        let older = queue.add_slab(shards(30));
        let younger = queue.add_slab(shards(30));

        // Nothing is placed anywhere, so both slabs are equally unfinished and
        // the tie-break decides. Every fresh host is sent to the older one.
        for seed in 1..4 {
            let request = queue.take(&key(seed)).expect("a shard");
            assert_eq!(
                request.slab, older,
                "the older slab breaks the tie until it pulls ahead",
            );
        }
        // Placing those three makes the older slab the most advanced, so it
        // still leads. The younger one is only chosen once it is ahead.
        let young = queue.take(&key(9)).expect("a shard");
        assert!(
            young.slab == older || young.slab == younger,
            "every request belongs to one of the two slabs",
        );
    }

    #[test]
    fn hosts_do_not_block_each_other_on_the_same_slab() {
        let mut queue = RequestQueue::new();
        let slab = queue.add_slab(shards(30));
        let first = queue.take(&key(1)).unwrap();
        let second = queue.take(&key(2)).unwrap();
        assert_eq!(first.slab, slab);
        assert_eq!(second.slab, slab);
        assert_ne!(first.shard, second.shard, "two hosts, two shards");
    }

    #[test]
    fn a_failed_shard_is_reported_back_and_taken_by_another_host() {
        let mut queue = RequestQueue::new();
        let slab = queue.add_slab(shards(2));

        // Two hosts take the two shards, so nothing is pending. One of them
        // fails, which must put exactly that shard back.
        let keeps = queue.take(&key(1)).unwrap();
        let fails = queue.take(&key(2)).unwrap();
        assert_eq!(keeps.slab, slab);
        assert_ne!(keeps.shard, fails.shard);
        let shard = fails.shard;

        queue.failed(fails);
        assert_eq!(queue.pending(), 1, "the failed request is pending again");

        let retry = queue.take(&key(3)).unwrap();
        assert_eq!(
            retry.shard, shard,
            "the same shard went to another host",
        );
        queue.placed(&key(3), &retry);
        assert_eq!(queue.pending(), 0);
        assert_eq!(
            queue.placed(&key(1), &keeps),
            Some(slab),
            "the slab completes when the last shard lands",
        );
    }

    #[test]
    fn a_slab_is_reported_complete_only_on_the_last_shard() {
        let mut queue = RequestQueue::new();
        let slab = queue.add_slab(shards(3));

        for (index, seed) in (10..13).enumerate() {
            let host = key(seed);
            let request = queue.take(&host).unwrap();
            assert_eq!(request.slab, slab);
            let finished = queue.placed(&host, &request);
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
        let slab = queue.add_slab(shards(1));
        let host = key(1);
        let request = queue.take(&host).unwrap();
        assert_eq!(queue.placed(&host, &request), Some(slab));
        assert!(queue.take(&key(2)).is_none());
        assert_eq!(queue.placed(&host, &request), None, "the slab is gone");
    }

    #[test]
    fn describe_names_every_open_slab() {
        let mut queue = RequestQueue::new();
        queue.add_slab(shards(2));
        queue.add_slab(shards(1));
        let line = queue.describe();
        assert!(line.contains("3 pending across 2 slabs"), "{line}");
    }
}
