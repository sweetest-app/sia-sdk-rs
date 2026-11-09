//! One slab's life, from the first data shard to the pin.
//!
//! A shard is a slab, an index, and 4 MiB of bytes. Data shards come from the
//! file read and parity shards from the encoder, but once a shard exists the
//! slab does not care where it came from: it is placed the same way, and every
//! event below treats it the same.
//!
//! Two facts are tracked separately, because they move independently:
//!
//! * whether every data shard is in, which is the encoder's only trigger, and
//! * how many of the slab's shards have been placed, which is what a pin needs.
//!
//! Placement does not wait for the data to be complete. A shard that exists can
//! be given to a host immediately.

use bytes::Bytes;

use crate::schedule::SlabId;

/// Where a slab is. Only the pin gates anything, so there are three states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlabState {
    /// Taking shards, data and parity alike. This is the whole life of the slab
    /// up to its pin.
    Open,
    /// Every shard landed and the indexer accepted the pin.
    Pinned,
    /// Cancelled, or the pin failed for good. Its shards are wasted.
    Abandoned,
}

/// An event that does not fit the slab's current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlabError {
    /// The slab is pinned or abandoned and takes no more events.
    Closed { state: SlabState },
    DataShardOutOfRange,
    DataShardAlreadyAdded,
    ShardOutOfRange,
    ShardAlreadyPlaced,
    ShardNotPlaced,
}

impl SlabError {
    fn closed(state: SlabState) -> Self {
        Self::Closed { state }
    }
}

/// One slab's lifecycle.
#[derive(Debug)]
pub(crate) struct Slab {
    id: SlabId,
    state: SlabState,
    /// One slot per data shard, marked as the shard is produced. A slot rather
    /// than a counter, so a data shard reported twice cannot make the slab look
    /// ready for parity.
    data: Vec<bool>,
    data_count: usize,
    /// One entry per shard of the slab, data and parity.
    placed: Vec<bool>,
    placed_count: usize,
}

impl Slab {
    /// A slab waiting for its data shards. `data_shards` of them, `total`
    /// shards once parity is included.
    pub(crate) fn open(id: SlabId, data_shards: usize, total: usize) -> Self {
        Self {
            id,
            state: SlabState::Open,
            data: vec![false; data_shards],
            data_count: 0,
            placed: vec![false; total],
            placed_count: 0,
        }
    }

    pub(crate) fn id(&self) -> SlabId {
        self.id
    }

    pub(crate) fn state(&self) -> SlabState {
        self.state
    }

    pub(crate) fn total(&self) -> usize {
        self.placed.len()
    }

    pub(crate) fn placed_count(&self) -> usize {
        self.placed_count
    }

    /// Takes one data shard. Allowed at any point before the pin, and only once
    /// per index.
    pub(crate) fn add_data_shard(&mut self, index: usize, _data: Bytes) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::closed(self.state));
        }
        let slot = self
            .data
            .get_mut(index)
            .ok_or(SlabError::DataShardOutOfRange)?;
        if *slot {
            return Err(SlabError::DataShardAlreadyAdded);
        }
        *slot = true;
        self.data_count += 1;
        Ok(())
    }

    /// Every data shard is in, so parity may be produced.
    pub(crate) fn data_complete(&self) -> bool {
        self.data_count == self.data.len()
    }

    /// The encoder's trigger. Named for what the encoder asks, so a reader of
    /// the encoder cannot mistake it for a gate on shards.
    pub(crate) fn ready_for_parity(&self) -> bool {
        self.data_complete()
    }

    /// Records a shard that landed. Data and parity are recorded the same way;
    /// the index decides which shard it is, not the producer.
    pub(crate) fn shard_placed(&mut self, index: usize) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::closed(self.state));
        }
        let slot = self
            .placed
            .get_mut(index)
            .ok_or(SlabError::ShardOutOfRange)?;
        if *slot {
            return Err(SlabError::ShardAlreadyPlaced);
        }
        *slot = true;
        self.placed_count += 1;
        Ok(())
    }

    pub(crate) fn all_placed(&self) -> bool {
        self.placed_count == self.placed.len()
    }

    /// The indexer accepted the pin. Only a slab with every shard placed can be
    /// pinned.
    pub(crate) fn pin_ok(&mut self) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::closed(self.state));
        }
        if !self.all_placed() {
            return Err(SlabError::ShardNotPlaced);
        }
        self.state = SlabState::Pinned;
        Ok(())
    }

    /// The indexer refused the pin for good.
    pub(crate) fn pin_failed(&mut self) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::closed(self.state));
        }
        self.state = SlabState::Abandoned;
        Ok(())
    }

    /// Cancels the slab whatever it was doing. Pinned slabs are already paid
    /// for, so they stay pinned.
    pub(crate) fn cancel(&mut self) -> Result<(), SlabError> {
        match self.state {
            SlabState::Pinned => Err(SlabError::closed(SlabState::Pinned)),
            SlabState::Abandoned => Ok(()),
            SlabState::Open => {
                self.state = SlabState::Abandoned;
                Ok(())
            }
        }
    }
}

/// Produces a range of a slab's shards from its data shards.
///
/// The real implementation is the erasure coder; tests use a fake so the
/// lifecycle can be exercised without the arithmetic.
pub(crate) trait Encoder {
    fn encode_range(
        &self,
        data: &[&[u8]],
        first_shard: usize,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String>;
}

/// Where produced shards go. The real implementation is the request queue.
pub(crate) trait Placement {
    fn enqueue(&self, slab: SlabId, index: usize, data: Bytes) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn byte(value: u8) -> Bytes {
        Bytes::from(vec![value; 8])
    }

    fn open() -> Slab {
        Slab::open(SlabId(1), 10, 30)
    }

    fn with_data() -> Slab {
        let mut slab = open();
        for index in 0..10 {
            slab.add_data_shard(index, byte(index as u8)).unwrap();
        }
        slab
    }

    #[test]
    fn data_shards_are_taken_only_once() {
        let mut slab = open();
        slab.add_data_shard(0, byte(1)).unwrap();
        assert_eq!(
            slab.add_data_shard(0, byte(1)),
            Err(SlabError::DataShardAlreadyAdded)
        );
        assert_eq!(
            slab.add_data_shard(10, byte(1)),
            Err(SlabError::DataShardOutOfRange)
        );
    }

    #[test]
    fn data_complete_needs_every_data_shard() {
        let mut slab = open();
        for index in 0..9 {
            slab.add_data_shard(index, byte(index as u8)).unwrap();
            assert!(!slab.data_complete(), "{index} of ten is not all");
        }
        slab.add_data_shard(9, byte(9)).unwrap();
        assert!(slab.data_complete());
        assert!(slab.ready_for_parity(), "the encoder sees the same fact");
    }

    #[test]
    fn a_shard_is_placed_before_the_data_is_complete() {
        let mut slab = open();
        slab.add_data_shard(0, byte(0)).unwrap();
        assert!(!slab.ready_for_parity(), "nine data shards are missing");
        slab.shard_placed(0).expect("a shard that exists can be placed");
        assert_eq!(slab.placed_count(), 1);
    }

    #[test]
    fn a_parity_shard_is_placed_the_same_way() {
        let mut slab = with_data();
        slab.shard_placed(25).expect("a parity shard is a shard");
        assert_eq!(slab.placed_count(), 1);
    }

    #[test]
    fn a_shard_placed_twice_is_refused() {
        let mut slab = with_data();
        slab.shard_placed(3).unwrap();
        assert_eq!(slab.shard_placed(3), Err(SlabError::ShardAlreadyPlaced));
        assert_eq!(slab.placed_count(), 1);
    }

    #[test]
    fn a_slab_pins_only_with_every_shard() {
        let mut slab = with_data();
        for index in 0..29 {
            slab.shard_placed(index).unwrap();
        }
        assert_eq!(slab.pin_ok(), Err(SlabError::ShardNotPlaced));
        slab.shard_placed(29).unwrap();
        slab.pin_ok().unwrap();
        assert_eq!(slab.state(), SlabState::Pinned);
    }

    #[test]
    fn a_pin_failure_abandons_the_slab() {
        let mut slab = with_data();
        slab.pin_failed().unwrap();
        assert_eq!(slab.state(), SlabState::Abandoned);
        assert_eq!(
            slab.shard_placed(0),
            Err(SlabError::closed(SlabState::Abandoned))
        );
    }

    #[test]
    fn cancel_abandons_anything_not_pinned() {
        let mut fresh = open();
        fresh.cancel().unwrap();
        assert_eq!(fresh.state(), SlabState::Abandoned, "from no data");

        let mut mid = open();
        mid.add_data_shard(0, byte(0)).unwrap();
        mid.shard_placed(0).unwrap();
        mid.cancel().unwrap();
        assert_eq!(mid.state(), SlabState::Abandoned, "from a placed shard");

        let mut abandoned = open();
        abandoned.cancel().unwrap();
        abandoned.cancel().expect("cancelling twice is not an error");
        assert_eq!(abandoned.state(), SlabState::Abandoned);

        let mut pinned = with_data();
        for index in 0..30 {
            pinned.shard_placed(index).unwrap();
        }
        pinned.pin_ok().unwrap();
        assert!(
            pinned.cancel().is_err(),
            "a pinned slab is already paid for"
        );
        assert_eq!(pinned.state(), SlabState::Pinned);
    }

    #[test]
    fn cancel_between_parity_shards_refuses_the_rest() {
        // Parity arrives in batches while data shards are already placed, so a
        // cancel lands part way through the slab rather than before it starts.
        let mut slab = with_data();
        for index in 0..15 {
            slab.shard_placed(index).unwrap();
        }
        slab.cancel().unwrap();
        assert_eq!(slab.state(), SlabState::Abandoned);
        assert_eq!(
            slab.shard_placed(15),
            Err(SlabError::closed(SlabState::Abandoned)),
            "the shard after the cancel is refused"
        );
        assert_eq!(slab.placed_count(), 15);
    }

    #[test]
    fn a_closed_slab_takes_no_events() {
        for state in [SlabState::Pinned, SlabState::Abandoned] {
            let mut slab = with_data();
            for index in 0..30 {
                slab.shard_placed(index).unwrap();
            }
            if state == SlabState::Pinned {
                slab.pin_ok().unwrap();
            } else {
                slab.pin_failed().unwrap();
            }
            assert_eq!(slab.state(), state);

            assert_eq!(
                slab.add_data_shard(0, byte(0)),
                Err(SlabError::closed(state)),
                "data shard into {state:?}"
            );
            assert_eq!(
                slab.shard_placed(0),
                Err(SlabError::closed(state)),
                "placed shard into {state:?}"
            );
            assert_eq!(slab.pin_ok(), Err(SlabError::closed(state)));
            assert_eq!(slab.pin_failed(), Err(SlabError::closed(state)));
        }
    }
}
