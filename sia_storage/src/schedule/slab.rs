use std::collections::HashSet;

use sia_core::signing::PublicKey;

use crate::app_client::{SectorPinParams, SlabPinParams};
use crate::encryption::EncryptionKey;
use crate::slabs::SlabVersion;

/// Identifies one slab inside one upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SlabId(pub(crate) u64);

/// Everything a slab needs pinned, before its sectors have arrived.
#[derive(Clone, Debug)]
pub(crate) struct SlabSeed {
    pub encryption_key: EncryptionKey,
    /// Bytes of file data in this slab, for the slab's `length`.
    pub length: u32,
    /// Data shards needed to recover it. Ten for the default 10+20.
    pub min_shards: u8,
}

/// A slab whose every shard has landed, ready to pin.
#[derive(Debug)]
pub(crate) struct FinishedSlab {
    pub id: SlabId,
    pub pin: SlabPinParams,
}

/// What the schedule knows about a slab while its shards are being placed.
///
/// A slab is done only when every shard has landed, because nothing is pinned
/// until then. That is why placement prefers the slab closest to done: the
/// shards of a half finished slab are work that cannot be kept.
#[derive(Debug)]
pub(crate) struct SlabTracker {
    id: SlabId,
    total: usize,
    seed: SlabSeed,
    /// One entry per shard, filled as the shards land. A slot, not a counter,
    /// so a shard reported twice cannot make a slab look complete.
    sectors: Vec<Option<SectorPinParams>>,
    /// Hosts that have placed a shard here. One shard per host per slab, so a
    /// single host losing its disk cannot take two shards of the same slab.
    served: HashSet<PublicKey>,
    /// Creation order, for the tie-break between equally unfinished slabs.
    order: u64,
}

impl SlabTracker {
    pub(crate) fn new(id: SlabId, total: usize, order: u64, seed: SlabSeed) -> Self {
        Self {
            id,
            total,
            seed,
            sectors: vec![None; total],
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
        self.sectors.iter().filter(|slot| slot.is_none()).count()
    }

    pub(crate) fn placed(&self) -> usize {
        self.sectors.iter().filter(|slot| slot.is_some()).count()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn has_served(&self, host: &PublicKey) -> bool {
        self.served.contains(host)
    }

    /// Records a placed shard. Returns false when the shard was already
    /// recorded, so a duplicate report cannot advance the slab.
    pub(crate) fn record(
        &mut self,
        shard: usize,
        host: PublicKey,
        sector: SectorPinParams,
    ) -> bool {
        if shard >= self.total || self.sectors[shard].is_some() {
            return false;
        }
        self.sectors[shard] = Some(sector);
        self.served.insert(host);
        true
    }

    /// The pin request for a complete slab, or None when a shard is missing.
    pub(crate) fn finish(self) -> Option<FinishedSlab> {
        let sectors: Option<Vec<SectorPinParams>> = self.sectors.into_iter().collect();
        Some(FinishedSlab {
            id: self.id,
            pin: SlabPinParams {
                version: SlabVersion::V1,
                encryption_key: self.seed.encryption_key,
                min_shards: self.seed.min_shards,
                sectors: sectors?,
            },
        })
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
                root: Hash256::new([7u8; 32]),
                host_key: host,
            },
            uploaded_at: Some(Utc::now()),
        }
    }

    #[test]
    fn a_slab_is_complete_only_when_every_shard_has_landed() {
        let mut slab = SlabTracker::new(SlabId(1), 3, 0, seed());
        assert!(slab.record(0, key(1), sector(key(1))));
        assert_eq!(slab.remaining(), 2);
        assert!(!slab.is_complete());
        assert!(slab.record(1, key(2), sector(key(2))));
        assert!(!slab.is_complete(), "two of three is not a slab");
        assert!(slab.record(2, key(3), sector(key(3))));
        assert!(slab.is_complete());
        assert_eq!(slab.remaining(), 0);
    }

    #[test]
    fn a_shard_reported_twice_does_not_advance_the_slab() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0, seed());
        assert!(slab.record(0, key(1), sector(key(1))));
        assert!(!slab.record(0, key(2), sector(key(2))), "a duplicate is not progress");
        assert_eq!(slab.placed(), 1);
    }

    #[test]
    fn a_shard_index_outside_the_slab_is_refused() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0, seed());
        assert!(!slab.record(2, key(1), sector(key(1))));
        assert_eq!(slab.placed(), 0);
    }

    #[test]
    fn a_host_that_placed_a_shard_is_recorded_as_served() {
        let mut slab = SlabTracker::new(SlabId(1), 2, 0, seed());
        assert!(!slab.has_served(&key(1)));
        slab.record(0, key(1), sector(key(1)));
        assert!(slab.has_served(&key(1)));
        assert!(!slab.has_served(&key(2)));
    }

    #[test]
    fn finishing_carries_every_sector_and_the_slab_header() {
        let mut slab = SlabTracker::new(SlabId(9), 2, 0, seed());
        slab.record(1, key(2), sector(key(2)));
        slab.record(0, key(1), sector(key(1)));
        let finished = slab.finish().expect("every shard is in");
        assert_eq!(finished.id, SlabId(9));
        assert_eq!(finished.pin.min_shards, 10);
        assert_eq!(finished.pin.sectors.len(), 2);
        assert_eq!(finished.pin.sectors[0].sector.host_key, key(1));
        assert_eq!(finished.pin.sectors[1].sector.host_key, key(2));
    }
}
