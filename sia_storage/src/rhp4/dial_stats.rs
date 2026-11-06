#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::collections::HashMap;

/// Counts dials per address, and nothing else.
///
/// This used to bench an address for five minutes after the browser refused its
/// handshake. That is gone: the worker pool bans a host for the life of the page
/// on any failure, so there is nothing left for an address list to decide. The
/// counts stay because they are the only way to see whether the pool ever dials
/// the same address twice, which is worth knowing before adding a bench back.
#[derive(Debug, Default)]
pub(crate) struct DialStats {
    dials: HashMap<String, usize>,
}

impl DialStats {
    /// Counts a dial of `address` and returns how many times it has been dialed,
    /// this one included.
    pub(crate) fn note_dial(&mut self, address: &str) -> usize {
        let count = self.dials.entry(address.to_string()).or_default();
        *count += 1;
        *count
    }

    /// How many times `address` has been dialled, without counting this look.
    #[cfg(test)]
    pub(crate) fn dials(&self, address: &str) -> usize {
        self.dials.get(address).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dials_are_counted_per_address() {
        let mut stats = DialStats::default();

        assert_eq!(stats.note_dial("a:9984"), 1);
        assert_eq!(stats.note_dial("a:9984"), 2);
        assert_eq!(stats.note_dial("b:9984"), 1);
        assert_eq!(stats.note_dial("a:9984"), 3);
        assert_eq!(stats.note_dial("a:9984"), 4, "the count keeps climbing");
        assert_eq!(stats.note_dial("c:9984"), 1, "a new address starts at one");
    }
}
