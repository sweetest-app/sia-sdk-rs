use std::collections::HashSet;

use bytes::Bytes;
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
///
/// It carries its shards because the indexer can reject a slab as stale, and the
/// retry re-uploads the same bytes rather than encoding them again. The shards
/// are reference counted, so this is pointers, not another copy of the data.
#[derive(Debug)]
pub(crate) struct FinishedSlab {
    pub id: SlabId,
    pub order: u64,
    pub seed: SlabSeed,
    pub shards: Vec<Bytes>,
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
    /// The shards that have arrived, kept until the slab is pinned so a stale
    /// retry can send the same bytes again. `None` until the shard is produced:
    /// data shards arrive from the caller, parity from the encoder.
    shards: Vec<Option<Bytes>>,
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
    pub(crate) fn new(
        id: SlabId,
        order: u64,
        seed: SlabSeed,
        shards: Vec<Bytes>,
    ) -> Self {
        let total = shards.len();
        Self {
            id,
            total,
            seed,
            shards: shards.into_iter().map(Some).collect(),
            sectors: vec![None; total],
            served: HashSet::new(),
            order,
        }
    }

    /// Opens a slab whose shards are produced one at a time.
    pub(crate) fn open(id: SlabId, order: u64, seed: SlabSeed, total: usize) -> Self {
        Self {
            id,
            total,
            seed,
            shards: vec![None; total],
            sectors: vec![None; total],
            served: HashSet::new(),
            order,
        }
    }

    /// Records one produced shard. Returns false when the index is outside the
    /// slab or the shard is already there, so a duplicate cannot make the slab
    /// look complete.
    pub(crate) fn push(&mut self, index: usize, data: Bytes) -> bool {
        if index >= self.total || self.shards[index].is_some() {
            return false;
        }
        self.shards[index] = Some(data);
        true
    }

    /// Whether every shard has been produced, which is when encoding is done.
    pub(crate) fn all_produced(&self) -> bool {
        self.shards.iter().all(Option::is_some)
    }

    pub(crate) fn order(&self) -> u64 {
        self.order
    }

    pub(crate) fn remaining(&self) -> usize {
        self.sectors.iter().filter(|slot| slot.is_none()).count()
    }

    #[cfg(test)]
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
        let shards: Option<Vec<Bytes>> = self.shards.into_iter().collect();
        Some(FinishedSlab {
            id: self.id,
            order: self.order,
            seed: self.seed.clone(),
            shards: shards?,
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

    fn shards(count: usize) -> Vec<Bytes> {
        (0..count).map(|index| Bytes::from(vec![index as u8; 8])).collect()
    }

    #[test]
    fn a_slab_is_complete_only_when_every_shard_has_landed() {
        let mut slab = SlabTracker::new(SlabId(1), 0, seed(), shards(3));
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
        let mut slab = SlabTracker::new(SlabId(1), 0, seed(), shards(2));
        assert!(slab.record(0, key(1), sector(key(1))));
        assert!(!slab.record(0, key(2), sector(key(2))), "a duplicate is not progress");
        assert_eq!(slab.placed(), 1);
    }

    #[test]
    fn a_shard_index_outside_the_slab_is_refused() {
        let mut slab = SlabTracker::new(SlabId(1), 0, seed(), shards(2));
        assert!(!slab.record(2, key(1), sector(key(1))));
        assert_eq!(slab.placed(), 0);
    }

    #[test]
    fn a_host_that_placed_a_shard_is_recorded_as_served() {
        let mut slab = SlabTracker::new(SlabId(1), 0, seed(), shards(2));
        assert!(!slab.has_served(&key(1)));
        slab.record(0, key(1), sector(key(1)));
        assert!(slab.has_served(&key(1)));
        assert!(!slab.has_served(&key(2)));
    }

    #[test]
    fn finishing_carries_every_sector_and_the_slab_header() {
        let mut slab = SlabTracker::new(SlabId(9), 0, seed(), shards(2));
        slab.record(1, key(2), sector(key(2)));
        slab.record(0, key(1), sector(key(1)));
        let finished = slab.finish().expect("every shard is in");
        assert_eq!(finished.id, SlabId(9));
        assert_eq!(finished.shards.len(), 2, "the shards come back for a retry");
        assert_eq!(finished.pin.min_shards, 10);
        assert_eq!(finished.pin.sectors.len(), 2);
        assert_eq!(finished.pin.sectors[0].sector.host_key, key(1));
        assert_eq!(finished.pin.sectors[1].sector.host_key, key(2));
    }
}
