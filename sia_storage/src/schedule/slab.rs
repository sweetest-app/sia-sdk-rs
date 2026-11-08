use std::collections::HashSet;

use bytes::Bytes;
use sia_core::signing::PublicKey;

use crate::app_client::{SectorPinParams, SlabPinParams};
use crate::encryption::EncryptionKey;
use crate::slabs::SlabVersion;
use crate::upload::slab::{Slab, SlabState};

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
/// It carries the sectors and the header, not the shard bytes. Those left with
/// the hosts, which is what keeps memory proportional to the shards in flight
/// instead of to the slabs that happen to be open.
#[derive(Debug)]
pub(crate) struct FinishedSlab {
    pub id: SlabId,
    pub seed: SlabSeed,
    pub pin: SlabPinParams,
    /// The lifecycle that produced it, so the pin result is recorded on the same
    /// slab rather than on a copy of its counters.
    pub slab: Slab,
}

/// What the schedule knows about a slab while its shards are being placed.
///
/// A slab is done only when every shard has landed, because nothing is pinned
/// until then. That is why placement prefers the slab closest to done: the
/// shards of a half finished slab are work that cannot be kept.
#[derive(Debug)]
pub(crate) struct SlabTracker {
    /// The lifecycle: which data shards are in, which shards have landed, and
    /// whether it is pinned or abandoned.
    slab: Slab,
    seed: SlabSeed,
    /// One entry per shard, filled as the shards land. A slot, not a counter,
    /// so a shard reported twice cannot make a slab look complete.
    sectors: Vec<Option<SectorPinParams>>,
    /// Hosts that have placed a shard here. One shard per host per slab, so a
    /// single host losing its disk cannot take two shards of the same slab.
    served: HashSet<PublicKey>,
}

impl SlabTracker {
    /// Opens a slab and sets its seed. Its shards are produced one at a time.
    pub(crate) fn open(id: SlabId, seed: SlabSeed, total: usize) -> Self {
        let data_shards = seed.min_shards as usize;
        Self {
            slab: Slab::open(id, data_shards, total),
            seed,
            sectors: vec![None; total],
            served: HashSet::new(),
        }
    }

    pub(crate) fn state(&self) -> SlabState {
        self.slab.state()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.slab.total() - self.slab.placed_count()
    }

    #[cfg(test)]
    pub(crate) fn placed(&self) -> usize {
        self.slab.placed_count()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.slab.all_placed()
    }

    /// Every data shard is in, so parity may be produced.
    pub(crate) fn all_data_shards_ready(&self) -> bool {
        self.slab.all_data_shards_ready()
    }

    /// Abandons the slab whatever state it is in. A pinned slab refuses,
    /// because its shards are already paid for.
    pub(crate) fn cancel(&mut self) -> bool {
        self.slab.cancel().is_ok()
    }

    pub(crate) fn has_served(&self, host: &PublicKey) -> bool {
        self.served.contains(host)
    }

    /// Records one produced shard. A data shard also marks the slab's input, so
    /// the encoder's trigger is a fact about the slab rather than a count kept
    /// beside it. A parity shard has no input fact to record.
    pub(crate) fn add_shard(&mut self, index: usize, data: Bytes) -> bool {
        if index >= self.sectors.len() {
            return false;
        }
        if index < self.seed.min_shards as usize {
            return self.slab.add_data_shard(index, data).is_ok();
        }
        self.slab.state() == SlabState::Open
    }

    /// Records a placed shard. Data and parity land here alike. Returns false
    /// when the shard was already recorded, so a duplicate report cannot advance
    /// the slab.
    pub(crate) fn record(
        &mut self,
        shard: usize,
        host: PublicKey,
        sector: SectorPinParams,
    ) -> bool {
        if shard >= self.sectors.len() || self.sectors[shard].is_some() {
            return false;
        }
        if self.slab.shard_placed(shard).is_err() {
            return false;
        }
        self.sectors[shard] = Some(sector);
        self.served.insert(host);
        true
    }

    /// The pin request for a complete slab, or None when a shard is missing.
    pub(crate) fn finish(self) -> Option<FinishedSlab> {
        if !self.slab.all_placed() {
            return None;
        }
        let sectors: Option<Vec<SectorPinParams>> = self.sectors.into_iter().collect();
        Some(FinishedSlab {
            id: self.slab.id(),
            seed: self.seed.clone(),
            pin: SlabPinParams {
                version: SlabVersion::V1,
                encryption_key: self.seed.encryption_key,
                min_shards: self.seed.min_shards,
                sectors: sectors?,
            },
            slab: self.slab,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sector;
    use chrono::Utc;
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

    /// A slab with every shard already produced, so placement can be tested on
    /// its own.
    fn produced(count: usize) -> SlabTracker {
        let id = SlabId(1);
        // Every shard is a data shard here, so the slab is ready for parity as
        // soon as they are all in and the test can go straight to placement.
        let mut header = seed();
        header.min_shards = count as u8;
        let mut tracker = SlabTracker::open(id, header, count);
        for index in 0..count {
            assert!(tracker.add_shard(index, Bytes::from(vec![index as u8; 8])));
        }
        tracker
    }

    #[test]
    fn a_slab_is_complete_only_when_every_shard_has_landed() {
        let mut slab = produced(3);
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
        let mut slab = produced(2);
        assert!(slab.record(0, key(1), sector(key(1))));
        assert!(
            !slab.record(0, key(2), sector(key(2))),
            "a duplicate is not progress"
        );
        assert_eq!(slab.placed(), 1);
    }

    #[test]
    fn a_shard_index_outside_the_slab_is_refused() {
        let mut slab = produced(2);
        assert!(!slab.record(2, key(1), sector(key(1))));
        assert_eq!(slab.placed(), 0);
    }

    #[test]
    fn a_produced_shard_twice_is_refused() {
        let mut slab = SlabTracker::open(SlabId(1), seed(), 30);
        assert!(slab.add_shard(0, Bytes::from_static(b"one")));
        assert!(
            !slab.add_shard(0, Bytes::from_static(b"two")),
            "duplicate"
        );
        assert!(
            !slab.add_shard(30, Bytes::from_static(b"far")),
            "not a data shard"
        );
    }

    #[test]
    fn parity_is_ready_once_the_data_shards_are_in() {
        let mut slab = SlabTracker::open(SlabId(1), seed(), 30);
        for index in 0..9 {
            assert!(slab.add_shard(index, Bytes::from(vec![index as u8; 8])));
            assert!(!slab.all_data_shards_ready(), "nine of ten is not data");
        }
        assert!(slab.add_shard(9, Bytes::from(vec![9u8; 8])));
        assert!(slab.all_data_shards_ready(), "ten of ten is ready");
        assert!(
            slab.record(9, key(1), sector(key(1))),
            "a shard that exists is placed without waiting for parity"
        );
    }

    #[test]
    fn a_host_that_placed_a_shard_is_recorded_as_served() {
        let mut slab = produced(2);
        assert!(!slab.has_served(&key(1)));
        slab.record(0, key(1), sector(key(1)));
        assert!(slab.has_served(&key(1)));
        assert!(!slab.has_served(&key(2)));
    }

    #[test]
    fn finishing_carries_every_sector_and_the_slab_header() {
        let mut slab = produced(2);
        slab.record(1, key(2), sector(key(2)));
        slab.record(0, key(1), sector(key(1)));
        let finished = slab.finish().expect("every shard is in");
        assert_eq!(finished.id, SlabId(1));
        assert_eq!(finished.pin.min_shards, 2, "every shard is data in this fixture");
        assert_eq!(finished.pin.sectors.len(), 2);
        assert_eq!(finished.pin.sectors[0].sector.host_key, key(1));
        assert_eq!(finished.pin.sectors[1].sector.host_key, key(2));
        assert_eq!(finished.slab.state(), SlabState::Open);
    }

    #[test]
    fn a_slab_missing_a_shard_does_not_finish() {
        let mut slab = produced(2);
        slab.record(0, key(1), sector(key(1)));
        assert!(slab.finish().is_none());
    }

    #[test]
    fn the_pin_result_is_recorded_on_the_slab() {
        let mut slab = produced(2);
        slab.record(0, key(1), sector(key(1)));
        slab.record(1, key(2), sector(key(2)));
        let mut finished = slab.finish().expect("every shard is in");
        finished.slab.pin_ok().expect("pin accepted");
        assert_eq!(finished.slab.state(), SlabState::Pinned);
    }
}
