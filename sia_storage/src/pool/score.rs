use sia_core::signing::PublicKey;

/// What the pool knows about one host when it decides whom to dial.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HostStats {
    /// Bytes per second this host has written, once it has finished a shard.
    /// None means nobody has ever moved data through it.
    pub write_bps: Option<f64>,
}

impl HostStats {
    pub(crate) fn unsampled() -> Self {
        Self { write_bps: None }
    }

    pub(crate) fn with_write_rate(bytes_per_second: f64) -> Self {
        Self {
            write_bps: Some(bytes_per_second),
        }
    }
}

/// Where candidate statistics come from. The pool only ever reads, so the
/// transport and the host metrics stay the owner of the numbers.
pub(crate) trait HostView {
    fn stats(&self, host: &PublicKey) -> HostStats;
}

/// One host's score as a dial candidate.
///
/// `p_ok` is the chance a dial to this host opens a session: the host's own
/// record once it has been tried, and the pool's observed dial success rate
/// before that. `rate` is the expected write throughput, and `attempts` is how
/// many times the pool has dialled this host.
///
/// The second term is a bounded bonus, so a host nobody has dialled is worth a
/// try while dialling is cheap. It shrinks with every attempt and is scaled by
/// `p_ok`, so on a link where most dials fail it never outranks a host with a
/// record.
pub(crate) fn dial_score(p_ok: f64, rate: f64, attempts: usize, total_attempts: usize) -> f64 {
    let p_ok = p_ok.clamp(0.0, 1.0);
    let expected = p_ok * rate;
    let bonus = expected * (((total_attempts + 1) as f64).ln() / (attempts as f64 + 1.0)).sqrt();
    expected + bonus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untried_host_is_worth_a_bet_only_when_dials_usually_work() {
        let rate = 1_000_000.0;
        // A link where one dial in ten opens a session: the host with a record wins.
        let unhealthy_untried = dial_score(0.1, rate, 0, 100);
        let proven = dial_score(1.0, rate * 0.8, 1, 100);
        assert!(
            unhealthy_untried < proven,
            "an untried host must not outrank a proven one when 90% of dials fail",
        );

        // A link where most dials work: trying something new is cheap.
        let healthy_untried = dial_score(0.9, rate, 0, 100);
        assert!(
            healthy_untried > proven,
            "an untried host should be worth trying when dials usually work",
        );
    }

    #[test]
    fn the_bonus_shrinks_with_attempts() {
        let first = dial_score(0.5, 1_000.0, 0, 50);
        let second = dial_score(0.5, 1_000.0, 1, 50);
        let tenth = dial_score(0.5, 1_000.0, 10, 50);
        assert!(first > second && second > tenth, "the bonus must decay");
    }

    #[test]
    fn a_faster_host_scores_higher_at_the_same_probability() {
        let slow = dial_score(1.0, 1_000.0, 1, 10);
        let fast = dial_score(1.0, 10_000.0, 1, 10);
        assert!(fast > slow);
    }

    #[test]
    fn the_explore_bonus_does_not_outrun_an_impossible_prior() {
        // Nothing has ever answered, so no amount of curiosity should win.
        assert_eq!(dial_score(0.0, 1_000_000.0, 0, 10_000), 0.0);
    }
}
