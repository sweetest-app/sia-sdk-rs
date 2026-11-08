//! Pending shards and the slabs they belong to.
//!
//! The schedule answers one question: given this host, which shard should it
//! write next. It never chooses a host, which is what makes the assignment
//! pull-based instead of a queue handing out work.
//!
//! The upload registers each slab here and a connected host pulls the next shard
//! it is allowed to write. Nothing chooses a host for a shard.

mod queue;
mod slab;

pub(crate) use queue::RequestQueue;
pub(crate) use slab::{FinishedSlab, SlabId, SlabSeed};
