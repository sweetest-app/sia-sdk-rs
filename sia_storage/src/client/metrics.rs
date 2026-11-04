use std::fmt::Display;
use std::ops::Deref;

use crate::time::{Duration, Instant};

#[derive(Debug, Default, Clone)]
pub(crate) struct RPCAverage(Option<TransferRate>); // exponential moving average of throughput in bytes/sec

impl RPCAverage {
    const ALPHA: f64 = 0.2;

    pub(crate) fn add_sample(&mut self, rate: TransferRate) {
        match self.0 {
            Some(avg) => {
                self.0 = Some(Self::ALPHA * rate + (1.0 - Self::ALPHA) * avg);
            }
            None => {
                self.0 = Some(rate);
            }
        }
    }

    /// Returns the current average in bytes/sec, or `None` if no samples have
    /// been recorded yet. Callers decide how to treat unsampled hosts.
    pub(crate) fn avg(&self) -> Option<TransferRate> {
        self.0
    }
}

impl Display for RPCAverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.avg() {
            Some(v) => Display::fmt(&v, f),
            None => f.write_str("unsampled"),
        }
    }
}

impl PartialEq for RPCAverage {
    fn eq(&self, other: &Self) -> bool {
        self.avg() == other.avg()
    }
}

impl Eq for RPCAverage {}

/// Exponential moving average of failure rate, halved once per
/// [`Self::HALF_LIFE`] of wall clock.
#[derive(Debug, Default, Clone)]
pub(crate) struct FailureRate {
    /// The average as it stood at `updated_at`.
    value: Option<f64>,
    /// When `value` was written, advanced by whole half lives as it decays.
    /// `None` exactly when `value` is, since `Instant` has no zero.
    updated_at: Option<Instant>,
}

impl FailureRate {
    const ALPHA: f64 = 0.2;

    /// The rate halves once per half life whether or not samples arrive.
    const HALF_LIFE: Duration = Duration::from_secs(60);

    /// Rates below this read as failure free, so a decayed host rejoins the
    /// unsampled bucket instead of sitting just above zero forever.
    const ZERO_THRESHOLD: f64 = 0.01;

    pub(super) fn add_sample(&mut self, success: bool) {
        // A success against a rate already under the threshold leaves it
        // under, however much time has passed, and `rate` reports both as
        // zero. Returning here keeps the clock off the path every successful
        // sector RPC takes.
        if success && self.value.is_some_and(|v| v < Self::ZERO_THRESHOLD) {
            return;
        }
        let sample = if success { 0.0 } else { 1.0 };
        let now = Instant::now();
        match (self.value, self.updated_at) {
            (Some(value), Some(updated_at)) => {
                let (decayed, stamp) = Self::decay(value, updated_at, now);
                self.value = Some(Self::ALPHA * sample + (1.0 - Self::ALPHA) * decayed);
                self.updated_at = Some(stamp);
            }
            _ => {
                self.value = Some(sample);
                self.updated_at = Some(now);
            }
        }
    }

    /// Halves `value` once per whole half life between `updated_at` and `now`,
    /// returning the decayed value and the stamp advanced by exactly those
    /// half lives, so the remainder carries rather than being discarded.
    fn decay(value: f64, updated_at: Instant, now: Instant) -> (f64, Instant) {
        let elapsed = now.saturating_duration_since(updated_at);
        let half_lives = elapsed.as_nanos() / Self::HALF_LIFE.as_nanos();
        match u32::try_from(half_lives) {
            Ok(n) if n <= 1024 => (
                value * 2f64.powi(-(n as i32)),
                updated_at + Self::HALF_LIFE * n,
            ),
            // Past a thousand half lives the value is zero to f64 precision,
            // and the exponent would overflow i32.
            _ => (0.0, now),
        }
    }

    /// Computes the failure rate as an integer percentage (0-100), decayed for
    /// the time since the last sample.
    ///
    /// Takes `&self` because host selection reads it under a read guard and so
    /// cannot write the decay back; the stored value is only ever advanced by
    /// [`Self::add_sample`].
    pub(crate) fn rate(&self) -> i64 {
        let (Some(value), Some(updated_at)) = (self.value, self.updated_at) else {
            return 0; // presume no failures if no samples
        };
        // Decay only shrinks the value, so one already under the threshold
        // cannot come back over it. Host selection scores every candidate on
        // every pick, so this keeps the clock out of that loop too.
        if value < Self::ZERO_THRESHOLD {
            return 0;
        }
        let (decayed, _) = Self::decay(value, updated_at, Instant::now());
        if decayed < Self::ZERO_THRESHOLD {
            0
        } else {
            (decayed * 100.0).round() as i64
        }
    }
}

impl Display for FailureRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%", self.rate())
    }
}

impl PartialEq for FailureRate {
    fn eq(&self, other: &Self) -> bool {
        self.rate() == other.rate()
    }
}

impl Eq for FailureRate {}

impl PartialOrd for FailureRate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FailureRate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rate().cmp(&other.rate())
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HostMetric {
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    failure_rate: FailureRate,
}

impl HostMetric {
    #[cfg(test)]
    pub(crate) fn add_write_sample(&mut self, transfer: Transfer) {
        self.add_write_throughput(transfer.rate());
        self.failure_rate.add_sample(true);
    }

    pub(crate) fn add_write_throughput(&mut self, rate: TransferRate) {
        self.rpc_write_avg.add_sample(rate);
    }

    #[cfg(test)]
    pub(crate) fn add_read_sample(&mut self, transfer: Transfer) {
        self.add_read_throughput(transfer.rate());
        self.failure_rate.add_sample(true);
    }

    pub(crate) fn add_read_throughput(&mut self, rate: TransferRate) {
        self.rpc_read_avg.add_sample(rate);
    }

    pub(crate) fn add_success(&mut self) {
        self.failure_rate.add_sample(true);
    }

    pub(crate) fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
    }

    /// The failure rate as an integer percentage. Zero for an unsampled host,
    /// which the download ranking deliberately treats as good.
    pub(crate) fn failure_rate(&self) -> i64 {
        self.failure_rate.rate()
    }

    /// Combined read + write throughput average. `None` only when neither side
    /// has been sampled. `Hosts::prioritize` reads this for its discovery
    /// preference (unsampled before sampled).
    pub(crate) fn combined_throughput(&self) -> Option<TransferRate> {
        match (self.rpc_write_avg.avg(), self.rpc_read_avg.avg()) {
            (None, None) => None,
            (Some(w), Some(r)) => Some((w + r) / 2.0),
            (Some(v), None) | (None, Some(v)) => Some(v),
        }
    }

    /// Write throughput average, which is what the worker pool ranks dial
    /// candidates by. `None` until a shard has landed on the host.
    pub(crate) fn write_throughput(&self) -> Option<TransferRate> {
        self.rpc_write_avg.avg()
    }
}

/// A successful transfer observation: `size` bytes in `elapsed`. Validated
/// once at construction; [`Self::rate`] and [`Self::pace`] are views.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Transfer {
    size: u32,
    elapsed: Duration,
}

impl Transfer {
    pub const fn new(size: u32, elapsed: Duration) -> Self {
        Self::try_new(size, elapsed).expect("size and elapsed cannot be zero")
    }

    pub const fn try_new(size: u32, elapsed: Duration) -> Option<Self> {
        if size == 0 || elapsed.is_zero() {
            return None;
        }
        Some(Self { size, elapsed })
    }

    /// Returns the rate of the transfer in bytes per second.
    #[cfg(test)]
    pub const fn rate(&self) -> TransferRate {
        TransferRate(self.size as f64 / self.elapsed.as_secs_f64())
    }

    /// Returns the per-byte latency of the transfer in seconds per byte.
    pub const fn pace(&self) -> TransferPace {
        TransferPace(self.elapsed.as_secs_f64() / self.size as f64)
    }

    /// Returns an estimate of the time it will take to transfer
    /// `size` bytes.
    pub fn estimate_duration(&self, size: u32) -> Duration {
        self.pace().estimate_duration(size)
    }
}

impl TransferRate {
    pub(crate) fn try_new(bytes: u64, elapsed: Duration) -> Option<Self> {
        (!elapsed.is_zero()).then(|| Self(bytes as f64 / elapsed.as_secs_f64()))
    }

    pub fn pace(self) -> Option<TransferPace> {
        (self.0 > 0.0).then(|| TransferPace(1.0 / self.0))
    }
}

impl TransferPace {
    /// Returns an estimate of the time it will take to transfer
    /// `size` bytes at this pace.
    pub fn estimate_duration(&self, size: u32) -> Duration {
        Duration::from_secs_f64(self.0 * size as f64)
    }
}

/// The rate of a transfer in bytes per second.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub(crate) struct TransferRate(f64);

/// The per-byte latency of a transfer in seconds per byte.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub(crate) struct TransferPace(f64);

// macro for common implementations between pace and rate
macro_rules! impl_transfer {
    ($($t:ident),*) => {$(
        impl Deref for $t {
            type Target = f64;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::ops::Add for $t {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                Self(self.0 + rhs.0)
            }
        }

        impl std::ops::Sub for $t {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 - rhs.0)
            }
        }

        impl std::ops::Add<f64> for $t {
            type Output = Self;
            fn add(self, rhs: f64) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl std::ops::Sub<f64> for $t {
            type Output = Self;
            fn sub(self, rhs: f64) -> Self {
                Self(self.0 - rhs)
            }
        }

        impl std::ops::Mul<f64> for $t {
            type Output = Self;
            fn mul(self, rhs: f64) -> Self {
                Self(self.0 * rhs)
            }
        }

        impl std::ops::Div<f64> for $t {
            type Output = Self;
            fn div(self, rhs: f64) -> Self {
                Self(self.0 / rhs)
            }
        }

        impl std::ops::Add<$t> for f64 {
            type Output = $t;
            fn add(self, rhs: $t) -> $t {
                $t(self + rhs.0)
            }
        }

        impl std::ops::Sub<$t> for f64 {
            type Output = $t;
            fn sub(self, rhs: $t) -> $t {
                $t(self - rhs.0)
            }
        }

        impl std::ops::Mul<$t> for f64 {
            type Output = $t;
            fn mul(self, rhs: $t) -> $t {
                $t(self * rhs.0)
            }
        }

        impl std::ops::Div<$t> for f64 {
            type Output = $t;
            fn div(self, rhs: $t) -> $t {
                $t(self / rhs.0)
            }
        }
    )*};
}

impl_transfer!(TransferRate, TransferPace);

#[cfg(test)]
mod test {
    use super::*;

    /// The decay is what lets a host demoted out of the selection set recover,
    /// since not being selected is why it stops being sampled.
    ///
    /// Instants are built by adding to a base rather than subtracting from
    /// now: on wasm the clock starts near zero at page load, so subtracting
    /// minutes from it is not safe.
    #[sia_core_derive::cross_target_test]
    fn test_failure_rate_decays_over_time() {
        let base = Instant::now();
        let half_life = FailureRate::HALF_LIFE;

        let (value, _) = FailureRate::decay(1.0, base, base);
        assert_eq!(value, 1.0, "no elapsed time leaves the value alone");

        let (value, _) = FailureRate::decay(1.0, base, base + half_life);
        assert_eq!(value, 0.5, "one half life halves the value");

        let (value, _) = FailureRate::decay(1.0, base, base + half_life * 3);
        assert_eq!(value, 0.125, "three half lives halve it three times");

        let (value, _) = FailureRate::decay(1.0, base, base + half_life / 2);
        assert_eq!(value, 1.0, "a partial half life does not decay at all");

        // The stamp advances by whole half lives only, so the leftover is
        // carried into the next call instead of being thrown away.
        let (_, stamp) = FailureRate::decay(1.0, base, base + half_life * 2 + half_life / 2);
        assert_eq!(stamp, base + half_life * 2, "the remainder carries");
    }

    /// A rate that has decayed to near zero must read as exactly zero, so the
    /// host rejoins the unsampled bucket rather than sitting just above it.
    #[sia_core_derive::cross_target_test]
    fn test_failure_rate_zero_threshold() {
        let below = FailureRate {
            value: Some(FailureRate::ZERO_THRESHOLD / 2.0),
            updated_at: Some(Instant::now()),
        };
        assert_eq!(below.rate(), 0, "below the threshold reads as failure free");

        let above = FailureRate {
            value: Some(0.5),
            updated_at: Some(Instant::now()),
        };
        assert_eq!(above.rate(), 50, "above it reports the percentage");
    }

    #[sia_core_derive::cross_target_test]
    fn test_failure_rate() {
        let mut fr = FailureRate::default();
        assert_eq!(fr.rate(), 0, "initial failure rate should be 0%");
        fr.add_sample(false);
        assert_eq!(fr.rate(), 100, "initial failure should be 100%");

        for _ in 0..5 {
            fr.add_sample(true);
        }
        assert!(
            fr.rate() < 100,
            "failure rate should decrease after successes"
        );

        let mut fr2 = FailureRate::default();
        for _ in 0..5 {
            fr2.add_sample(true);
        }
        assert_eq!(
            fr2.rate(),
            0,
            "failure rate should be 0% after only successes"
        );
        assert_eq!(
            fr.cmp(&fr2),
            std::cmp::Ordering::Greater,
            "higher failure rate should be greater"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_rpc_average() {
        let mut avg = RPCAverage::default();
        assert_eq!(
            avg.avg(),
            None,
            "unsampled average should be None (no 1 Gbps default)"
        );

        avg.add_sample(Transfer::new(100, Duration::from_secs(1)).rate());
        assert_eq!(
            avg.avg(),
            Some(Transfer::new(100, Duration::from_secs(1)).rate()),
            "initial average should be first sample"
        );

        avg.add_sample(Transfer::new(200, Duration::from_secs(1)).rate());
        assert!(
            avg.avg() > Some(Transfer::new(100, Duration::from_secs(1)).rate()),
            "average should increase after higher sample"
        );

        avg.add_sample(Transfer::new(50, Duration::from_secs(1)).rate());
        assert!(
            avg.avg() < Some(Transfer::new(200, Duration::from_secs(1)).rate()),
            "average should decrease after lower sample"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_metric_ranking_inputs() {
        // The download ranking itself lives in `Hosts::prioritize`. This
        // checks the two numbers it reads off a metric, so a change here
        // cannot quietly change that order.
        let unsampled = HostMetric::default();
        assert_eq!(unsampled.failure_rate(), 0);
        assert_eq!(unsampled.combined_throughput(), None);

        let mut sampled = HostMetric::default();
        sampled.add_write_sample(Transfer::new(100, Duration::from_secs(1)));
        assert_eq!(sampled.failure_rate(), 0);
        assert_eq!(
            sampled.combined_throughput(),
            Some(Transfer::new(100, Duration::from_secs(1)).rate())
        );

        // Read and write averages are combined, so a host that only serves
        // reads is not ranked as unsampled.
        let mut read_only = HostMetric::default();
        read_only.add_read_sample(Transfer::new(400, Duration::from_secs(1)));
        assert_eq!(
            read_only.combined_throughput(),
            Some(Transfer::new(400, Duration::from_secs(1)).rate())
        );

        // A failure with no throughput still reads as unsampled, and carries
        // its rate, which is what puts it behind every clean host.
        let mut failed = HostMetric::default();
        failed.add_failure();
        assert_eq!(failed.combined_throughput(), None);
        assert_eq!(failed.failure_rate(), 100);
    }
}
