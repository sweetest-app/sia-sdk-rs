use std::collections::HashSet;

use sia_core::signing::PublicKey;

/// Identifies one slab inside one upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SlabId(pub(crate) u64);

/// What the schedule knows about a slab while its shards are being placed.
///
/// A slab is done only when every shard has landed, because nothing is pinned
/// until then. That is why placement prefers the slab closest to done: the
/// shards of a half finished slab are work that cannot be kept.
#[derive(Debug)]
pub(crate) struct SlabTracker {
    id: SlabId,
    total: usize,
    /// Shard indices that have landed. A set, not a counter, so a shard
    /// reported twice cannot make a slab look complete.
    done: HashSet<usize>,
    /// Hosts that have placed a shard here. One shard per host per slab, so a
    /// single host losing its disk cannot take two shards of the same slab.
    served: HashSet<PublicKey>,
    /// Creation order, for the tie-break between equally unfinished slabs.
    order: u64,
}

impl SlabTracker {
    pub(crate) fn new(id: SlabId, total: usize, order: u64) -> Self {
        Self {
            id,
            total,
            done: HashSet::new(),
            served: HashSet::new(),
            order,
        }
    }

    pub(crate) fn id(&self) -> SlabId {
        self.id
    }

    pub(crate) fn total(&self) -> usize {
        self.total
    }

    pub(crate) fn order(&self) -> u64 {
        self.order
    }

    pub(crate) fn remaining(&self) -> usize {
        self.total.saturating_sub(self.done.len())
    }

    pub(crate) fn placed(&self) -> usize {
        self.done.len()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.done.len() >= self.total
    }

    pub(crate) fn has_served(&self, host: &PublicKey) -> bool {
        self.served.contains(host)
    }

    /// Records a placed shard. Returns false when the shard was already
    /// recorded, so a duplicate report cannot advance the slab.
    pub(crate) fn record(&mut self, shard: usize, host: PublicKey) -> bool {
        if shard >= self.total || !self.done.insert(shard) {
            return false;
        }
        self.served.insert(host);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::signing::PrivateKey;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from_seed(&[seed; 32]).public_key()
    }

    #[test]
    fn a_slab_is_complete_only_when_every_shard_has_landed() {
        let mut slab = SlabTracker::new(SlabId(1), 3, 0);
        assert!(slab.record(0, key(1)));
        assert_eq!(slab.remaining(), 2);
        assert!(!slab.is_complete());
        assert!(slab.record(1, key(2)));
        assert!(!slab.is_complete(), "two of three is not a slab");
        assert!(slab.record(2, key(3)));
        assert!(slab.is_complete());
        assert_eq!(slab.remaining(), 0);
    }

    #[test]
    fn a_shard_reported_twice_does_not_advance_the_slab() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0);
        assert!(slab.record(0, key(1)));
        assert!(!slab.record(0, key(2)), "a duplicate is not progress");
        assert_eq!(slab.placed(), 1);
    }

    #[test]
    fn a_shard_index_outside_the_slab_is_refused() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0);
        assert!(!slab.record(2, key(1)));
        assert_eq!(slab.placed(), 0);
    }

    #[test]
    fn a_host_that_placed_a_shard_is_recorded_as_served() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0);
        assert!(!slab.has_served(&key(1)));
        slab.record(0, key(1));
        assert!(slab.has_served(&key(1)));
        assert!(!slab.has_served(&key(2)));
    }
}
