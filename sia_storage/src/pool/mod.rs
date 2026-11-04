//! A pool of connected hosts that pull work.
//!
//! The pool decides who to dial and who to ban. It knows nothing about shards,
//! slabs or the transport, which is what makes every rule in it a unit test.
#![allow(dead_code, unused_imports)]

mod bans;
mod pool;
mod score;

pub(crate) use bans::{page_bans, BanReason, SharedBans};
pub(crate) use pool::{HostPool, LeaveReason};
pub(crate) use score::{HostStats, HostView};
