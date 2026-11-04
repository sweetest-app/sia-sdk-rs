//! Pending shards and the slabs they belong to.
//!
//! The schedule answers one question: given this host, which shard should it
//! write next. It never chooses a host, which is what makes the assignment
//! pull-based instead of a queue handing out work.
//!
//! Nothing calls this yet. The wiring into `Upload` is the task after next, and
//! this allow goes with it.
#![allow(dead_code, unused_imports)]

mod queue;
mod slab;

pub(crate) use queue::{RequestQueue, ShardRequest};
pub(crate) use slab::{FinishedSlab, SlabId, SlabSeed, SlabTracker};
