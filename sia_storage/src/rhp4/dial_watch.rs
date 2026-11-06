//! When to give up on a dial that is waiting in the browser's queue.
//!
//! Chromium holds WebTransport handshakes in one queue and starts one per gap,
//! where the gap is `10ms * 2^(n-1)`, capped at a minute, and `n` counts the
//! handshakes it is running plus the failures it still remembers. Nothing in the
//! page says when a dial is released, so a dial cannot tell waiting from a
//! silent host by itself.
//!
//! This type supplies what a caller needs to tell them apart: how many entries
//! the browser is holding, and how many dials of ours are still ahead of a given
//! dial. A dial is only given up on once nothing of ours is ahead of it and it
//! has then been silent for the handshake allowance.

use std::collections::VecDeque;

use crate::time::{Duration, Instant};

/// A failure the browser counts stays on its list for five minutes.
const FORGIVENESS: Duration = Duration::from_secs(300);
/// The first entry makes the next dial wait this long.
const BASE_GAP_MS: f64 = 10.0;
/// The browser stops doubling here and holds a minute per dial.
const MAX_GAP: Duration = Duration::from_secs(60);
/// Each gap is multiplied by a random number between 0.5 and 1.5. Plan for the
/// top of that range, so a gap that comes out long cannot turn into a kill.
const JITTER: f64 = 1.5;
/// Above this many entries the browser's gap is at the cap.
const CAP_ENTRIES: usize = 14;
/// A dial that fails in less than this was refused before the browser counted
/// anything: a full queue, or an address it would not dial. It adds nothing.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const REFUSAL_WINDOW: Duration = Duration::from_millis(25);

/// The dials in flight, the failures the browser still remembers, and the
/// allowance a dial gets once it is at the front.
pub(crate) struct DialWatch {
    failures: VecDeque<Instant>,
    dials: VecDeque<u64>,
    next_id: u64,
    handshake: Duration,
}

impl DialWatch {
    pub(crate) fn new(handshake: Duration) -> Self {
        Self {
            failures: VecDeque::new(),
            dials: VecDeque::new(),
            next_id: 0,
            handshake,
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn set_handshake(&mut self, handshake: Duration) {
        self.handshake = handshake;
    }

    /// Registers a dial and returns its id. Dials are ordered by registration,
    /// which is the order the browser starts them in.
    pub(crate) fn start(&mut self, now: Instant) -> u64 {
        self.prune(now);
        let id = self.next_id;
        self.next_id += 1;
        self.dials.push_back(id);
        id
    }

    pub(crate) fn settle(&mut self, id: u64) {
        self.dials.retain(|dial| *dial != id);
    }

    /// Notes a failure the browser counts. A refusal does not come here.
    pub(crate) fn note_failure(&mut self, now: Instant) {
        self.prune(now);
        self.failures.push_back(now);
    }

    /// How many dials of ours, this one included, are still unsettled in front
    /// of it. `None` once the dial has settled.
    pub(crate) fn ahead(&self, id: u64) -> Option<usize> {
        self.dials.iter().position(|dial| *dial == id)
    }

    /// Every dial the browser is holding, ours and the failures it remembers.
    pub(crate) fn count(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.failures.len() + self.dials.len()
    }

    /// How long the browser waits before starting the next dial.
    pub(crate) fn gap(&mut self, now: Instant) -> Duration {
        let count = self.count(now).max(1);
        let gap_ms = if count >= CAP_ENTRIES {
            MAX_GAP.as_millis() as f64
        } else {
            BASE_GAP_MS * 2f64.powi(count as i32 - 1)
        };
        Duration::from_millis((gap_ms * JITTER) as u64)
    }

    /// The moment this dial is given up on. `previous` is the deadline it had
    /// last, and `front_since` is when it last had another dial ahead of it, or
    /// when it started.
    ///
    /// The deadline only ever moves later. While something is ahead, the
    /// estimate is pushed out by a whole gap, and a gap is never zero, so a dial
    /// that is waiting cannot be killed.
    ///
    /// Being at the front of our own dials is not the same as being started:
    /// Chromium waits one gap before it starts the next request even when
    /// nothing else of ours is queued, because the gap is set by the failures it
    /// remembers. So the front dial also gets one whole gap before its allowance
    /// begins, and that gap is read from the window as it stands.
    pub(crate) fn deadline(
        &mut self,
        id: u64,
        now: Instant,
        previous: Instant,
        front_since: Instant,
    ) -> Instant {
        match self.ahead(id) {
            Some(0) => previous.max(front_since + self.gap(now) + self.handshake),
            Some(ahead) => {
                let wait = self.gap(now).mul_f64(ahead as f64);
                previous.max(now + wait + self.handshake)
            }
            None => previous,
        }
    }

    /// Whether a failed attempt is a failure the browser counts.
    ///
    /// A dial that dies within [`REFUSAL_WINDOW`] was refused before a packet
    /// went out: the queue was full, or the address was refused outright. The
    /// browser counts nothing for those, so neither do we. Anything slower failed
    /// as a handshake, and the browser is holding an entry for it.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn counts_as_failure(elapsed: Duration) -> bool {
        elapsed > REFUSAL_WINDOW
    }

    fn prune(&mut self, now: Instant) {
        while let Some(at) = self.failures.front() {
            if now.duration_since(*at) <= FORGIVENESS {
                break;
            }
            self.failures.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> DialWatch {
        DialWatch::new(Duration::from_secs(10))
    }

    #[test]
    fn a_failure_is_forgotten_after_five_minutes() {
        let mut watch = watch();
        let start = Instant::now();
        watch.note_failure(start);
        assert_eq!(watch.count(start), 1);

        assert_eq!(watch.count(start + Duration::from_secs(299)), 1, "still held");
        assert_eq!(watch.count(start + Duration::from_secs(301)), 0, "aged out");
    }

    #[test]
    fn a_refused_dial_adds_nothing() {
        let mut watch = watch();
        let now = Instant::now();
        let id = watch.start(now);
        watch.settle(id);
        assert_eq!(watch.count(now), 0, "no dial and no failure to remember");
    }

    #[test]
    fn the_gap_doubles_until_it_is_capped() {
        let now = Instant::now();
        assert_eq!(watch().gap(now).as_millis(), 15, "no entries, 10ms, jitter");

        assert_eq!(holding(1, now).gap(now).as_millis(), 15);
        assert_eq!(holding(2, now).gap(now).as_millis(), 30);
        assert_eq!(holding(9, now).gap(now).as_millis(), 3840, "2560ms times jitter");

        let mut full = holding(CAP_ENTRIES, now);
        assert_eq!(full.gap(now).as_millis(), 90_000, "the cap, then jitter");
    }

    #[test]
    fn the_deadline_never_moves_earlier() {
        let now = Instant::now();
        let mut watch = holding(8, now);
        let mine = watch.start(now);
        let first = watch.deadline(mine, now, now, now);

        watch.settle(*watch.dials.front().unwrap());
        let later = now + Duration::from_secs(1);
        let second = watch.deadline(mine, later, first, later);
        assert!(second >= first, "a better position never pulls it back");
    }

    #[test]
    fn a_dial_with_someone_ahead_cannot_be_killed() {
        let now = Instant::now();
        let mut watch = holding(6, now);
        for _ in 0..8 {
            watch.note_failure(now);
        }
        let mine = watch.start(now);
        assert_eq!(watch.ahead(mine), Some(6));

        // Ten minutes of waiting later, still not killed: the estimate pushes
        // out by a whole gap for each dial ahead, and the window is full.
        let much_later = now + Duration::from_secs(600);
        let deadline = watch.deadline(mine, much_later, now, now);
        assert!(deadline > much_later, "the deadline is still in the future");
    }

    #[test]
    fn the_front_dial_still_waits_a_gap_before_its_allowance() {
        let now = Instant::now();
        let mut watch = holding(1, now);
        let mine = *watch.dials.front().unwrap();
        for _ in 0..12 {
            watch.note_failure(now);
        }
        let gap = watch.gap(now);
        assert!(
            gap >= Duration::from_secs(20),
            "twelve failures mean a long gap, got {gap:?}"
        );

        let deadline = watch.deadline(mine, now, now, now);
        assert_eq!(
            deadline,
            now + gap + Duration::from_secs(10),
            "the front dial cannot be killed before the gap plus its allowance"
        );
    }

    #[test]
    fn a_refusal_is_not_a_counted_failure_but_a_slow_failure_is() {
        assert!(!DialWatch::counts_as_failure(Duration::from_millis(1)));
        assert!(!DialWatch::counts_as_failure(REFUSAL_WINDOW));
        assert!(DialWatch::counts_as_failure(Duration::from_millis(26)));
        assert!(DialWatch::counts_as_failure(Duration::from_secs(10)));
    }

    #[test]
    fn at_the_front_the_allowance_runs_from_that_moment() {
        let now = Instant::now();
        let mut watch = holding(3, now);
        let mine = watch.start(now);
        for id in watch.dials.iter().copied().collect::<Vec<_>>() {
            if id != mine {
                watch.settle(id);
            }
        }
        assert_eq!(watch.ahead(mine), Some(0));

        let alone_at = now + Duration::from_secs(4);
        let gap = watch.gap(alone_at);
        let deadline = watch.deadline(mine, alone_at, now, alone_at);
        assert_eq!(
            deadline,
            alone_at + gap + Duration::from_secs(10),
            "one gap for its turn, then ten seconds of silence"
        );
    }

    /// A watch with this many dials started and no failures.
    fn holding(dials: usize, now: Instant) -> DialWatch {
        let mut watch = watch();
        for _ in 0..dials {
            watch.start(now);
        }
        watch
    }
}
