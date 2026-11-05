use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use sia_core::signing::PublicKey;

/// Why a host was banned. Kept for the one log line that explains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BanReason {
    /// The connect budget ran out before the session opened.
    DialTimeout,
    /// The browser or the host refused the handshake.
    DialRefused,
    /// The host took the session and then failed to store a shard.
    WriteFailed,
    /// The shard was accepted but the transfer ran past its cap.
    TransferTimeout,
}

impl BanReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DialTimeout => "connect timeout",
            Self::DialRefused => "handshake refused",
            Self::WriteFailed => "write failed",
            Self::TransferTimeout => "transfer timeout",
        }
    }
}

/// Hosts that failed once, for the life of the page.
///
/// There is no cooldown, no ladder and no retry. A host that failed is never
/// dialled again until the page reloads, which keeps the rule small enough to
/// reason about and stops a bad pool from being walked twice.
#[derive(Debug, Default)]
pub(crate) struct BanSet {
    hosts: HashSet<PublicKey>,
}

impl BanSet {
    /// Bans a host. Returns false when it was already banned. The reason is
    /// logged by the caller at the moment of the ban, so nothing is kept.
    pub(crate) fn ban(&mut self, host: PublicKey) -> bool {
        self.hosts.insert(host)
    }

    pub(crate) fn contains(&self, host: &PublicKey) -> bool {
        self.hosts.contains(host)
    }

    pub(crate) fn len(&self) -> usize {
        self.hosts.len()
    }
}

/// The bans, shareable between pools.
///
/// Every upload in a page shares one of these, so a host that failed in one
/// upload is not dialled again by the next. Only a reload clears it.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedBans(Arc<Mutex<BanSet>>);

impl SharedBans {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn contains(&self, host: &PublicKey) -> bool {
        self.0.lock().unwrap().contains(host)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub(crate) fn ban(&self, host: PublicKey) -> bool {
        self.0.lock().unwrap().ban(host)
    }
}

/// The one ban set for this page.
///
/// A host that failed is never dialled again until the page reloads, whatever
/// upload it failed in. This is the reason the pool is not per upload.
pub(crate) fn page_bans() -> SharedBans {
    static BANS: OnceLock<SharedBans> = OnceLock::new();
    BANS.get_or_init(SharedBans::new).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::signing::PrivateKey;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from_seed(&[seed; 32]).public_key()
    }

    #[test]
    fn a_banned_host_stays_banned() {
        let mut bans = BanSet::default();
        assert!(!bans.contains(&key(1)));

        assert!(bans.ban(key(1)), "first ban is new");
        assert!(bans.contains(&key(1)));
        assert!(!bans.ban(key(1)), "already banned");
        assert_eq!(bans.len(), 1);
    }

    #[test]
    fn banning_one_host_does_not_ban_another() {
        let mut bans = BanSet::default();
        bans.ban(key(1));
        assert!(!bans.contains(&key(2)));
        assert_eq!(bans.len(), 1);
    }

    #[test]
    fn a_shared_set_sees_a_ban_from_any_clone() {
        let bans = SharedBans::new();
        let other = bans.clone();
        assert!(!other.contains(&key(1)));
        bans.ban(key(1));
        assert!(
            other.contains(&key(1)),
            "every upload shares one set, so a ban from one is a ban for the next",
        );
    }
}
