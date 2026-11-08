//! One slab's life, from the first data shard to the pin.
//!
//! The state is here and nowhere else. Shards arrive from the caller as the file
//! is sliced, parity is produced from them, workers place them one at a time, and
//! the slab is pinned when the last one lands. Every one of those is an event on
//! this type, and an event that does not fit the current state is refused rather
//! than ignored.

use bytes::Bytes;

use crate::schedule::SlabId;

/// Where a slab is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlabState {
    /// Data shards are arriving. Nothing has been encoded or placed.
    Open,
    /// Every data shard is in. Parity may be produced from here.
    Frozen,
    /// Shards are queued and being placed.
    Placing,
    /// Every shard landed and the indexer accepted the pin.
    Pinned,
    /// Cancelled, or the pin failed for good. Its shards are wasted.
    Abandoned,
}

/// An event that does not fit the slab's current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlabError {
    WrongState {
        expected: SlabState,
        actual: SlabState,
    },
    DataShardOutOfRange,
    DataShardAlreadyAdded,
    ShardOutOfRange,
    ShardAlreadyPlaced,
    ShardNotPlaced,
}

/// One slab's lifecycle.
#[derive(Debug)]
pub(crate) struct Slab {
    id: SlabId,
    state: SlabState,
    /// The data shards, filled as they arrive. These are the source the encoder
    /// reads from.
    data: Vec<Option<Bytes>>,
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
            data: vec![None; data_shards],
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

    /// Takes one data shard. Only while the slab is open, and only once per
    /// index.
    pub(crate) fn add_data_shard(&mut self, index: usize, data: Bytes) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::WrongState {
                expected: SlabState::Open,
                actual: self.state,
            });
        }
        let slot = self
            .data
            .get_mut(index)
            .ok_or(SlabError::DataShardOutOfRange)?;
        if slot.is_some() {
            return Err(SlabError::DataShardAlreadyAdded);
        }
        *slot = Some(data);
        Ok(())
    }

    /// Every data shard has arrived, so the slab's bytes are fixed.
    pub(crate) fn all_data(&self) -> bool {
        self.data.iter().all(Option::is_some)
    }

    /// Freezes the slab: its data is complete and parity may be produced.
    pub(crate) fn freeze(&mut self) -> Result<(), SlabError> {
        if self.state != SlabState::Open {
            return Err(SlabError::WrongState {
                expected: SlabState::Open,
                actual: self.state,
            });
        }
        if !self.all_data() {
            return Err(SlabError::WrongState {
                expected: SlabState::Frozen,
                actual: self.state,
            });
        }
        self.state = SlabState::Frozen;
        Ok(())
    }

    /// Placing begins once at least one shard has been queued.
    pub(crate) fn begin_placing(&mut self) -> Result<(), SlabError> {
        match self.state {
            SlabState::Frozen => {
                self.state = SlabState::Placing;
                Ok(())
            }
            SlabState::Placing => Ok(()),
            actual => Err(SlabError::WrongState {
                expected: SlabState::Frozen,
                actual,
            }),
        }
    }

    /// Records a shard that landed. Refused outside placing, out of range, or
    /// for a shard that already landed.
    pub(crate) fn shard_placed(&mut self, index: usize) -> Result<(), SlabError> {
        if self.state != SlabState::Placing {
            return Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: self.state,
            });
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
        if self.state != SlabState::Placing {
            return Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: self.state,
            });
        }
        if !self.all_placed() {
            return Err(SlabError::ShardNotPlaced);
        }
        self.state = SlabState::Pinned;
        Ok(())
    }

    /// The indexer refused the pin for good.
    pub(crate) fn pin_failed(&mut self) -> Result<(), SlabError> {
        if self.state != SlabState::Placing {
            return Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: self.state,
            });
        }
        self.state = SlabState::Abandoned;
        Ok(())
    }

    /// Cancels the slab whatever it was doing. Pinned slabs are already paid
    /// for, so they stay pinned.
    pub(crate) fn cancel(&mut self) -> Result<(), SlabError> {
        match self.state {
            SlabState::Pinned => Err(SlabError::WrongState {
                expected: SlabState::Abandoned,
                actual: SlabState::Pinned,
            }),
            SlabState::Abandoned => Ok(()),
            _ => {
                self.state = SlabState::Abandoned;
                Ok(())
            }
        }
    }
}

/// The slab's data shards, which is what the encoder reads. The source helper:
/// the coordinator never reaches into a slab for its bytes itself.
/// Clones are pointer copies: `Bytes` is reference counted.
pub(crate) trait ShardSource {
    fn data_shards(&self) -> Vec<Bytes>;
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
    fn data_shards_are_taken_only_while_open_and_only_once() {
        let mut slab = open();
        assert_eq!(slab.state(), SlabState::Open);
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
    fn a_slab_freezes_only_with_every_data_shard() {
        let mut slab = open();
        slab.add_data_shard(0, byte(0)).unwrap();
        assert!(slab.freeze().is_err(), "one of ten is not the data");
        for index in 1..10 {
            slab.add_data_shard(index, byte(index as u8)).unwrap();
        }
        slab.freeze().unwrap();
        assert_eq!(slab.state(), SlabState::Frozen);
        assert_eq!(
            slab.add_data_shard(0, byte(9)),
            Err(SlabError::WrongState {
                expected: SlabState::Open,
                actual: SlabState::Frozen,
            })
        );
    }

    #[test]
    fn a_shard_cannot_be_placed_before_the_slab_is_placed() {
        let mut slab = with_data();
        assert_eq!(
            slab.shard_placed(0),
            Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: SlabState::Open,
            })
        );
        slab.freeze().unwrap();
        assert_eq!(
            slab.shard_placed(0),
            Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: SlabState::Frozen,
            })
        );
        slab.begin_placing().unwrap();
        slab.shard_placed(0).unwrap();
    }

    #[test]
    fn a_shard_placed_twice_is_refused() {
        let mut slab = with_data();
        slab.freeze().unwrap();
        slab.begin_placing().unwrap();
        slab.shard_placed(3).unwrap();
        assert_eq!(slab.shard_placed(3), Err(SlabError::ShardAlreadyPlaced));
        assert_eq!(slab.placed_count(), 1);
    }

    #[test]
    fn a_slab_pins_only_with_every_shard() {
        let mut slab = with_data();
        slab.freeze().unwrap();
        slab.begin_placing().unwrap();
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
        slab.freeze().unwrap();
        slab.begin_placing().unwrap();
        slab.pin_failed().unwrap();
        assert_eq!(slab.state(), SlabState::Abandoned);
        assert_eq!(
            slab.shard_placed(0),
            Err(SlabError::WrongState {
                expected: SlabState::Placing,
                actual: SlabState::Abandoned,
            })
        );
    }

    #[test]
    fn cancel_abandons_anything_not_pinned() {
        for stop in [SlabState::Open, SlabState::Frozen, SlabState::Placing] {
            let mut slab = with_data();
            match stop {
                SlabState::Open => {}
                SlabState::Frozen => slab.freeze().unwrap(),
                SlabState::Placing => {
                    slab.freeze().unwrap();
                    slab.begin_placing().unwrap();
                }
                _ => unreachable!(),
            }
            slab.cancel().unwrap();
            assert_eq!(slab.state(), SlabState::Abandoned, "from {stop:?}");
        }

        let mut pinned = with_data();
        pinned.freeze().unwrap();
        pinned.begin_placing().unwrap();
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
    fn every_event_out_of_state_is_refused() {
        // The four states a slab can be cancelled from, crossed with the events
        // that must not be accepted there. A refused event leaves the state
        // alone, which is what makes the machine safe to drive from callbacks.
        let states = [
            SlabState::Open,
            SlabState::Frozen,
            SlabState::Placing,
            SlabState::Pinned,
            SlabState::Abandoned,
        ];
        for state in states {
            let mut slab = if state == SlabState::Open {
                open()
            } else {
                with_data()
            };
            if matches!(state, SlabState::Frozen | SlabState::Placing | SlabState::Pinned) {
                slab.freeze().unwrap();
            }
            if matches!(state, SlabState::Placing | SlabState::Pinned) {
                slab.begin_placing().unwrap();
            }
            if state == SlabState::Pinned {
                for index in 0..30 {
                    slab.shard_placed(index).unwrap();
                }
                slab.pin_ok().unwrap();
            }
            if state == SlabState::Abandoned {
                slab.cancel().unwrap();
            }
            assert_eq!(slab.state(), state, "setup for {state:?}");

            let expects_open = slab.add_data_shard(0, byte(0));
            let expects_freeze = slab.freeze();
            let expects_place = slab.shard_placed(0);
            let expects_pin = slab.pin_ok();
            let expects_fail = slab.pin_failed();

            match state {
                SlabState::Open => {
                    assert!(expects_open.is_ok(), "open takes data");
                    assert!(expects_freeze.is_err(), "data was added twice");
                    assert!(expects_place.is_err());
                    assert!(expects_pin.is_err());
                    assert!(expects_fail.is_err());
                }
                SlabState::Frozen => {
                    assert!(expects_open.is_err(), "frozen takes no data");
                    assert!(expects_freeze.is_err(), "already frozen");
                    assert!(expects_place.is_err(), "not placing yet");
                    assert!(expects_pin.is_err());
                    assert!(expects_fail.is_err());
                }
                SlabState::Placing => {
                    assert!(expects_open.is_err());
                    assert!(expects_freeze.is_err());
                    assert!(expects_place.is_ok(), "placing takes shards");
                    assert!(expects_pin.is_err(), "not every shard landed");
                    assert!(expects_fail.is_ok(), "a pin can fail while placing");
                }
                SlabState::Pinned => {
                    assert!(expects_open.is_err());
                    assert!(expects_freeze.is_err());
                    assert!(expects_place.is_err());
                    assert!(expects_pin.is_err());
                    assert!(expects_fail.is_err());
                }
                SlabState::Abandoned => {
                    assert!(expects_open.is_err());
                    assert!(expects_freeze.is_err());
                    assert!(expects_place.is_err());
                    assert!(expects_pin.is_err());
                    assert!(expects_fail.is_err());
                }
            }
        }
    }
}
