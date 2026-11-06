use std::collections::{HashMap, HashSet};

use log::debug;
use sia_core::signing::PublicKey;

use super::bans::{BanReason, SharedBans};
use super::score::{dial_score, HostView};
#[cfg(test)]
use super::score::HostStats;

/// Why a worker left the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaveReason {
    /// The far end hung up on a session nobody was using. Normal housekeeping,
    /// so the host goes back to the candidates instead of being banned.
    Closed,
    /// The worker failed at something, so the host is banned.
    Failed(BanReason),
}

/// A pool of hosts, of which a target number should be connected at any time.
///
/// The pool owns three facts and nothing else: who is a candidate, who is
/// banned, and who is connected. It does not know about shards, slabs or the
/// transport. The caller asks [`HostPool::plan`] for the hosts to dial, dials
/// them however that target allows, and reports back with [`HostPool::settle`].
/// That keeps the decisions synchronous, so every rule here is a unit test.
pub(crate) struct HostPool<V: HostView> {
    view: V,
    candidates: Vec<PublicKey>,
    banned: SharedBans,
    connected: HashSet<PublicKey>,
    /// Candidates whose dial is in flight. Reserved so two callers cannot dial
    /// the same host, and released by `settle` or `release`.
    dialling: HashSet<PublicKey>,
    target: usize,
    /// Dials the pool has started, and how many of those opened a session.
    /// Together they are the chance a dial to a host nobody has tried will work.
    attempts: usize,
    successes: usize,
    /// Attempts and successes per host, for the host's own chance.
    per_host: HashMap<PublicKey, Record>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Record {
    attempts: usize,
    successes: usize,
}

impl<V: HostView> HostPool<V> {
    #[cfg(test)]
    pub(crate) fn new(view: V, candidates: Vec<PublicKey>, target: usize) -> Self {
        Self::with_bans(view, candidates, target, SharedBans::new())
    }

    /// A pool that shares its ban set with everything else in the page.
    pub(crate) fn with_bans(
        view: V,
        candidates: Vec<PublicKey>,
        target: usize,
        banned: SharedBans,
    ) -> Self {
        let candidates = candidates.into_iter().collect::<HashSet<_>>().into_iter().collect();
        Self {
            view,
            candidates,
            banned,
            connected: HashSet::new(),
            dialling: HashSet::new(),
            target,
            attempts: 0,
            successes: 0,
            per_host: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn connected(&self) -> usize {
        self.connected.len()
    }

    #[cfg(test)]
    pub(crate) fn banned(&self) -> usize {
        self.banned.len()
    }

    #[cfg(test)]
    pub(crate) fn is_banned(&self, host: &PublicKey) -> bool {
        self.banned.contains(host)
    }

    /// The connected hosts, so the caller can start a worker for each one.
    pub(crate) fn workers(&self) -> impl Iterator<Item = &PublicKey> {
        self.connected.iter()
    }

    /// The hosts to dial now: as many as the target is short by, best first.
    /// Every host returned is marked as dialling, so the caller must finish it
    /// with [`HostPool::settle`] or [`HostPool::cancel_dial`].
    pub(crate) fn plan(&mut self) -> Vec<PublicKey> {
        let shortfall = self.target.saturating_sub(self.connected.len() + self.dialling.len());
        if shortfall == 0 {
            return Vec::new();
        }
        let mut ranked: Vec<(f64, PublicKey)> = self
            .candidates
            .iter()
            .filter(|host| {
                !self.banned.contains(host)
                    && !self.connected.contains(host)
                    && !self.dialling.contains(host)
            })
            .map(|host| (self.score(host), *host))
            .collect();
        ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
        let chosen: Vec<PublicKey> = ranked
            .into_iter()
            .take(shortfall)
            .map(|(_, host)| host)
            .collect();
        for host in &chosen {
            self.dialling.insert(*host);
            self.attempts += 1;
            self.per_host.entry(*host).or_default().attempts += 1;
            debug!("[pool] mark {}, {} dialling", short(host), self.dialling.len());
        }
        chosen
    }

    /// Dials the pool has asked for and not settled yet. They may be waiting for
    /// a permit in the transport, so this is not the number of open handshakes.
    pub(crate) fn dialling(&self) -> usize {
        self.dialling.len()
    }

    /// Records the outcome of a planned dial. `None` means a session opened;
    /// `Some(reason)` means the host is banned.
    ///
    /// A dial the pool did not plan is still counted as an attempt, so a caller
    /// that opens a session on its own does not leave a host looking untried.
    pub(crate) fn settle(&mut self, host: PublicKey, outcome: Option<BanReason>) {
        if !self.dialling.remove(&host) {
            self.attempts += 1;
            self.per_host.entry(host).or_default().attempts += 1;
        }
        match outcome {
            None => {
                self.successes += 1;
                self.per_host.entry(host).or_default().successes += 1;
                self.connected.insert(host);
                debug!(
                    "[pool] connected {}: {} of {} target, {} banned",
                    short(&host),
                    self.connected.len(),
                    self.target,
                    self.banned.len(),
                );
            }
            Some(reason) => self.ban(host, reason),
        }
    }

    /// Releases a reservation without judging the host, for a dial that was
    /// abandoned before it finished.
    pub(crate) fn release(&mut self, host: PublicKey) {
        if self.dialling.remove(&host) {
            debug!("[pool] release {}, {} dialling", short(&host), self.dialling.len());
        }
    }

    /// A worker left. A closed session puts the host back in the running; a
    /// failure bans it for the life of the page.
    pub(crate) fn leave(&mut self, host: PublicKey, reason: LeaveReason) {
        self.connected.remove(&host);
        match reason {
            LeaveReason::Closed => {
                debug!(
                    "[pool] {} closed its session, back to the candidates",
                    short(&host)
                );
            }
            LeaveReason::Failed(why) => self.ban(host, why),
        }
    }

    /// True when the pool cannot reach its target and has nothing left to dial.
    #[cfg(test)]
    pub(crate) fn exhausted(&self) -> bool {
        self.connected.len() + self.dialling.len() < self.target
            && self.candidates.iter().all(|host| {
                self.banned.contains(host)
                    || self.connected.contains(host)
                    || self.dialling.contains(host)
            })
    }

    /// A one line summary for the upload log.
    pub(crate) fn describe(&self) -> String {
        format!(
            "{} of {} workers, {} banned of {} candidates, {} dialling",
            self.connected.len(),
            self.target,
            self.banned.len(),
            self.candidates.len(),
            self.dialling.len(),
        )
    }

    fn ban(&mut self, host: PublicKey, reason: BanReason) {
        if self.banned.ban(host) {
            debug!(
                "[pool] banned {}: {} ({} banned of {} candidates)",
                short(&host),
                reason.as_str(),
                self.banned.len(),
                self.candidates.len(),
            );
        }
    }

    /// The chance a dial to `host` opens a session: its own record if it has
    /// one, otherwise how dialling has gone for the pool so far.
    fn p_ok(&self, host: &PublicKey) -> f64 {
        let record = self.per_host.get(host).copied().unwrap_or_default();
        if record.attempts == 0 {
            self.prior_p_ok()
        } else {
            smoothed(record.successes, record.attempts)
        }
    }

    fn prior_p_ok(&self) -> f64 {
        smoothed(self.successes, self.attempts)
    }

    fn score(&self, host: &PublicKey) -> f64 {
        let record = self.per_host.get(host).copied().unwrap_or_default();
        let rate = self
            .view
            .stats(host)
            .write_bps
            .unwrap_or_else(|| self.median_rate());
        dial_score(self.p_ok(host), rate, record.attempts, self.attempts)
    }

    /// A rate for a host nobody has measured, so an untried candidate is
    /// compared on the same scale as a proven one.
    fn median_rate(&self) -> f64 {
        let mut rates: Vec<f64> = self
            .connected
            .iter()
            .filter_map(|host| self.view.stats(host).write_bps)
            .collect();
        if rates.is_empty() {
            return FALLBACK_RATE;
        }
        rates.sort_by(f64::total_cmp);
        rates[rates.len() / 2]
    }
}

/// Laplace smoothing, so one success out of one attempt does not read as
/// certainty and no attempts at all reads as even odds.
fn smoothed(successes: usize, attempts: usize) -> f64 {
    (successes as f64 + 1.0) / (attempts as f64 + 2.0)
}

/// Used before anything has been measured, so every candidate starts level.
const FALLBACK_RATE: f64 = 1.0;

fn short(host: &PublicKey) -> String {
    let text = host.to_string();
    text.trim_start_matches("ed25519:").chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::signing::PrivateKey;

    struct FakeView {
        rates: HashMap<PublicKey, f64>,
    }

    impl FakeView {
        fn new() -> Self {
            Self {
                rates: HashMap::new(),
            }
        }

        fn with_rate(mut self, host: PublicKey, rate: f64) -> Self {
            self.rates.insert(host, rate);
            self
        }
    }

    impl HostView for FakeView {
        fn stats(&self, host: &PublicKey) -> HostStats {
            match self.rates.get(host) {
                Some(rate) => HostStats::with_write_rate(*rate),
                None => HostStats::unsampled(),
            }
        }
    }

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from_seed(&[seed; 32]).public_key()
    }

    fn keys(count: u8) -> Vec<PublicKey> {
        (0..count).map(key).collect()
    }

    #[test]
    fn plan_fills_to_the_target_and_not_the_whole_list() {
        let mut pool = HostPool::new(FakeView::new(), keys(10), 4);
        let first = pool.plan();
        assert_eq!(first.len(), 4, "dial only what the target is short by");
        assert!(pool.plan().is_empty(), "reserved dials count against the target");
    }

    #[test]
    fn a_failed_dial_bans_the_host_and_frees_its_place() {
        let list = keys(4);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 1);
        let planned = pool.plan();
        assert_eq!(planned.len(), 1);
        let bad = planned[0];

        pool.settle(bad, Some(BanReason::DialTimeout));
        assert!(pool.is_banned(&bad));
        assert_eq!(pool.connected(), 0);

        let next = pool.plan();
        assert_eq!(next.len(), 1, "the pool replaces what it lost");
        assert_ne!(next[0], bad, "a banned host is never dialled again");
    }

    #[test]
    fn a_banned_host_never_comes_back_while_others_remain() {
        let list = keys(3);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 3);
        for host in pool.plan() {
            pool.settle(host, Some(BanReason::DialRefused));
        }
        assert_eq!(pool.banned(), 3);
        assert!(pool.plan().is_empty());
        assert!(pool.exhausted(), "nothing left to dial and short of target");
    }

    #[test]
    fn a_closed_session_returns_the_host_to_the_candidates() {
        let list = keys(1);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 1);
        let host = pool.plan()[0];
        pool.settle(host, None);
        assert_eq!(pool.connected(), 1);

        pool.leave(host, LeaveReason::Closed);
        assert_eq!(pool.connected(), 0);
        assert!(!pool.is_banned(&host), "hanging up is not a failure");

        assert_eq!(pool.plan(), vec![host], "the only candidate comes back");
    }

    #[test]
    fn a_failed_worker_is_banned_and_replaced() {
        let list = keys(3);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 2);
        for host in pool.plan() {
            pool.settle(host, None);
        }
        assert_eq!(pool.connected(), 2);

        let victim = *pool.workers().next().unwrap();
        pool.leave(victim, LeaveReason::Failed(BanReason::TransferTimeout));
        assert!(pool.is_banned(&victim));
        assert_eq!(pool.connected(), 1);

        let replacement = pool.plan();
        assert_eq!(replacement.len(), 1);
        assert_ne!(replacement[0], victim);
    }

    #[test]
    fn a_ban_through_a_shared_set_is_visible_to_a_new_pool() {
        // The page keeps one ban set. A new upload builds a new pool over the
        // same set, so a host banned last time must not be dialled again.
        let list = keys(2);
        let bans = SharedBans::new();
        let mut first = HostPool::with_bans(FakeView::new(), list.clone(), 1, bans.clone());
        let bad = first.plan()[0];
        first.settle(bad, Some(BanReason::DialTimeout));
        drop(first);

        let mut second = HostPool::with_bans(FakeView::new(), list.clone(), 1, bans);
        assert!(second.is_banned(&bad), "the new pool must see the ban");
        assert_eq!(
            second.plan(),
            vec![list.iter().copied().find(|host| *host != bad).unwrap()],
            "and dial the host that is left",
        );
    }

    #[test]
    fn a_worker_that_writes_faster_is_dialled_first() {
        let list = keys(2);
        let view = FakeView::new()
            .with_rate(list[0], 1_000.0)
            .with_rate(list[1], 100_000.0);
        let mut pool = HostPool::new(view, list.clone(), 1);
        assert_eq!(pool.plan(), vec![list[1]], "the faster host goes first");
    }

    #[test]
    fn a_known_host_is_preferred_over_an_unknown_one_when_dials_usually_fail() {
        let known = key(1);
        let unknown = key(2);
        let view = FakeView::new()
            .with_rate(known, 10_000.0)
            .with_rate(unknown, 10_000.0);
        let mut pool = HostPool::new(view, vec![known, unknown], 1);

        // Dial the known host and let it close, so it has a record.
        pool.settle(known, None);
        pool.leave(known, LeaveReason::Closed);

        // Most dials have failed for this pool.
        for seed in 10..80 {
            let host = key(seed);
            pool.settle(host, Some(BanReason::DialTimeout));
        }

        assert_eq!(
            pool.plan(),
            vec![known],
            "with a bad dial record, the host that worked is the better bet",
        );
    }

    #[test]
    fn an_unknown_host_is_worth_trying_when_dials_usually_work() {
        let known = key(1);
        let unknown = key(2);
        let view = FakeView::new()
            .with_rate(known, 10_000.0)
            .with_rate(unknown, 10_000.0);
        let mut pool = HostPool::new(view, vec![known, unknown], 1);

        pool.settle(known, None);
        pool.leave(known, LeaveReason::Closed);

        // Most dials have worked for this pool.
        for seed in 10..80 {
            pool.settle(key(seed), None);
            pool.leave(key(seed), LeaveReason::Closed);
        }

        assert_eq!(
            pool.plan(),
            vec![unknown],
            "when dials work, a host nobody has tried is worth a look",
        );
    }

    #[test]
    fn cancelling_a_dial_frees_the_reservation() {
        let list = keys(1);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 1);
        let host = pool.plan()[0];
        pool.release(host);
        assert_eq!(pool.plan(), vec![host], "an abandoned dial may be retried");
    }

    #[test]
    fn the_pool_is_not_exhausted_while_a_candidate_is_left() {
        let list = keys(2);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 2);
        pool.settle(list[0], Some(BanReason::DialTimeout));
        assert!(!pool.exhausted(), "one candidate is still untried");
        pool.settle(list[1], Some(BanReason::DialTimeout));
        assert!(pool.exhausted());
    }

    #[test]
    fn a_zero_target_never_dials() {
        let mut pool = HostPool::new(FakeView::new(), keys(2), 0);
        assert!(pool.plan().is_empty());
        assert_eq!(pool.connected(), 0);
    }

    #[test]
    fn describe_counts_every_side() {
        let list = keys(3);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 2);
        pool.settle(list[0], None);
        pool.settle(list[1], Some(BanReason::WriteFailed));
        let line = pool.describe();
        assert!(line.contains("1 of 2 workers"), "{line}");
        assert!(line.contains("1 banned of 3 candidates"), "{line}");
    }

    #[test]
    fn one_plan_never_returns_the_same_host_twice() {
        let mut pool = HostPool::new(FakeView::new(), keys(6), 6);
        let planned = pool.plan();
        let distinct: HashSet<_> = planned.iter().collect();
        assert_eq!(planned.len(), 6);
        assert_eq!(distinct.len(), 6);
    }

    #[test]
    fn the_pool_never_dials_past_its_target() {
        let list = keys(4);
        let mut pool = HostPool::new(FakeView::new(), list.clone(), 2);
        for host in pool.plan() {
            pool.settle(host, None);
        }
        assert_eq!(pool.connected(), 2);
        assert!(
            pool.plan().is_empty(),
            "the target is met, so nothing is dialled",
        );
        assert_eq!(pool.dialling(), 0, "and nothing is left in flight");
    }
}
