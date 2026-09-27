//! Loss-tolerant BBR: quinn's BBRv1 minus loss-driven recovery, bounded by a
//! congestion ceiling that ignores random loss.
//!
//! quinn's BBR (a port of Chromium's BBRv1) caps cwnd with a recovery window
//! that shrinks by every lost byte and is only lifted after a whole round
//! without loss. On the local->exit path loss is ~20% and random, so it would
//! stay in recovery forever. Non-persistent loss is therefore not reported to
//! it; lost packets are still retransmitted by QUIC as usual. Persistent
//! congestion (a real outage) is still passed through.
//!
//! Without loss feedback BBR's window runs away: its bandwidth estimate is
//! inflated by ACK compression (ACKs are lost on the lossy return path too),
//! and quinn paces at `1.25 * window / srtt` rather than at BBR's rate. The
//! result was seconds of queue at the bottleneck, or -- behind a policer that
//! drops instead of queueing -- sending at twice the policed rate with half
//! the packets lost. `WindowCap` bounds the window using two signals that
//! random loss does not trigger:
//! - queueing delay: the round's minimum RTT sample well above the path's min RTT;
//! - excess loss: the round's loss rate clearly above the recent norm (75th
//!   percentile of per-round loss, so bimodal random loss is not mistaken
//!   for congestion).

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// Queueing delay tolerated before backing off: max(min_rtt / 2, this).
const QUEUE_FLOOR: Duration = Duration::from_millis(30);
/// How long a min-RTT observation stays valid before it is re-measured.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(30);
/// Rounds of per-round loss rates kept for the loss baseline.
const LOSS_HISTORY: usize = 60;
/// A round needs this many packets' worth of sends for its loss rate to count.
const LOSS_MIN_PACKETS: u64 = 20;
const MIN_CAP_PACKETS: u64 = 16;

#[derive(Debug, Default)]
pub struct LossTolerantBbrConfig {
    pub bbr: BbrConfig,
}

impl ControllerFactory for LossTolerantBbrConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let inner = Arc::new(self.bbr.clone()).build(now, current_mtu);
        let cap = WindowCap::new(inner.initial_window(), current_mtu);
        Box::new(LossTolerantBbr { inner, cap })
    }
}

/// Ceiling on the congestion window, evaluated once per round (≈ one SRTT).
///
/// Backs off by 20% when the round shows queueing or excess loss; otherwise,
/// while the ceiling is what limits sending, grows by 25% per round -- or by
/// 5% when close to where it last had to back off, to avoid overshooting a
/// policer again and again.
#[derive(Debug, Clone)]
struct WindowCap {
    cap: u64,
    min_cap: u64,
    mtu: u64,
    /// Ceiling in effect when congestion was last detected.
    last_backoff: u64,
    min_rtt: Option<(Duration, Instant)>,
    round_start: Option<Instant>,
    round_min_rtt: Option<Duration>,
    round_sent: u64,
    round_lost: u64,
    loss_history: VecDeque<f64>,
    in_flight: u64,
}

impl WindowCap {
    fn new(initial: u64, mtu: u16) -> Self {
        let min_cap = MIN_CAP_PACKETS * u64::from(mtu);
        WindowCap {
            cap: initial.max(min_cap),
            min_cap,
            mtu: u64::from(mtu),
            last_backoff: u64::MAX,
            min_rtt: None,
            round_start: None,
            round_min_rtt: None,
            round_sent: 0,
            round_lost: 0,
            loss_history: VecDeque::with_capacity(LOSS_HISTORY + 1),
            in_flight: 0,
        }
    }

    /// 75th percentile of recent per-round loss rates, once there is enough
    /// history. Random loss on these paths switches between levels (e.g. 3%
    /// and 20%); a median would sit on the low level and flag every high round.
    fn baseline_loss(&self) -> Option<f64> {
        if self.loss_history.len() < 5 {
            return None;
        }
        let mut v: Vec<f64> = self.loss_history.iter().copied().collect();
        v.sort_by(f64::total_cmp);
        Some(v[v.len() * 3 / 4])
    }

    /// Feeds one RTT sample. `srtt` sets the round length; the cap never grows
    /// past `limit` (the inner controller's window).
    fn on_sample(&mut self, now: Instant, sample: Duration, srtt: Duration, limit: u64) {
        match self.min_rtt {
            Some((m, at)) if sample >= m && now.duration_since(at) < MIN_RTT_WINDOW => {}
            _ => self.min_rtt = Some((sample, now)),
        }
        self.round_min_rtt = Some(self.round_min_rtt.map_or(sample, |m| m.min(sample)));
        let start = *self.round_start.get_or_insert(now);
        if now.duration_since(start) < srtt.max(Duration::from_millis(20)) {
            return;
        }

        let (min_rtt, _) = self.min_rtt.unwrap();
        let queueing = self.round_min_rtt.unwrap().saturating_sub(min_rtt) > (min_rtt / 2).max(QUEUE_FLOOR);
        let loss = (self.round_sent >= LOSS_MIN_PACKETS * self.mtu)
            .then(|| self.round_lost.min(self.round_sent) as f64 / self.round_sent as f64);
        let excess_loss = match (loss, self.baseline_loss()) {
            (Some(l), Some(base)) => {
                // Small rounds give noisy loss rates (25 packets at 15% loss is ±7%),
                // so add two binomial standard deviations for this round's size.
                let n = (self.round_sent / self.mtu).max(1) as f64;
                let p = base.max(0.05);
                let noise = 2.0 * (p * (1.0 - p) / n).sqrt();
                l > base + (base / 2.0).max(0.08) + noise
            }
            _ => false,
        };
        if let Some(l) = loss {
            self.loss_history.push_back(l);
            if self.loss_history.len() > LOSS_HISTORY {
                self.loss_history.pop_front();
            }
        }

        if queueing || excess_loss {
            self.last_backoff = self.cap;
            self.cap = (self.cap - self.cap / 5).max(self.min_cap);
        } else if self.in_flight >= self.cap - self.cap / 5 {
            // Only grow while the cap is what limits sending.
            let near_last_backoff = self.cap >= self.last_backoff - self.last_backoff / 5;
            let step = if near_last_backoff { self.cap / 20 } else { self.cap / 4 };
            self.cap = (self.cap + step.max(self.mtu)).min(limit.max(self.cap));
        }
        self.round_start = Some(now);
        self.round_min_rtt = None;
        self.round_sent = 0;
        self.round_lost = 0;
    }
}

struct LossTolerantBbr {
    inner: Box<dyn Controller>,
    cap: WindowCap,
}

impl Controller for LossTolerantBbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.cap.round_sent += bytes;
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
        let limit = self.inner.window();
        self.cap
            .on_sample(now, now.saturating_duration_since(sent), rtt.get(), limit);
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
        self.cap.in_flight = in_flight;
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64) {
        self.cap.round_lost += lost_bytes;
        if is_persistent_congestion {
            self.cap.cap = self.cap.min_cap;
            self.inner.on_congestion_event(now, sent, true, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.cap.mtu = u64::from(new_mtu);
        self.cap.min_cap = MIN_CAP_PACKETS * u64::from(new_mtu);
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window().min(self.cap.cap)
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut m = self.inner.metrics();
        m.congestion_window = self.window();
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(LossTolerantBbr {
            inner: self.inner.clone_box(),
            cap: self.cap.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1200;
    const MS: Duration = Duration::from_millis(1);

    struct Round {
        rtt: Duration,
        jitter: Duration,
        busy: bool,
        /// Fraction of the round's sends reported lost.
        loss: f64,
    }

    impl Round {
        fn clean() -> Self {
            Round {
                rtt: 100 * MS,
                jitter: Duration::ZERO,
                busy: true,
                loss: 0.0,
            }
        }
    }

    /// Runs `rounds` rounds of 100 ms with 10 samples each.
    fn drive(c: &mut WindowCap, t: &mut Instant, rounds: u32, r: &Round) {
        for _ in 0..rounds {
            // About one window is sent per round.
            let sent = c.cap / 10;
            for i in 0..10u32 {
                *t += 10 * MS;
                c.round_sent += sent;
                c.round_lost += (sent as f64 * r.loss) as u64;
                c.in_flight = if r.busy { c.cap } else { 0 };
                c.on_sample(*t, r.rtt + r.jitter * i / 10, 100 * MS, 64 << 20);
            }
        }
    }

    #[test]
    fn grows_without_congestion_when_window_limited() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        let r = Round {
            jitter: 40 * MS,
            ..Round::clean()
        };
        drive(&mut c, &mut t, 20, &r);
        assert!(c.cap > 1_000_000, "cap {}", c.cap);
    }

    #[test]
    fn holds_when_app_limited() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        drive(
            &mut c,
            &mut t,
            20,
            &Round {
                busy: false,
                ..Round::clean()
            },
        );
        assert_eq!(c.cap, 100_000);
    }

    #[test]
    fn backs_off_on_standing_queue() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        drive(&mut c, &mut t, 20, &Round::clean());
        let grown = c.cap;
        // Queue builds: every sample of a round is 300 ms above the 100 ms base.
        let queued = Round {
            rtt: 400 * MS,
            ..Round::clean()
        };
        drive(&mut c, &mut t, 10, &queued);
        assert!(c.cap < grown / 5, "cap {} vs {grown}", c.cap);
        drive(&mut c, &mut t, 100, &queued);
        assert_eq!(c.cap, c.min_cap);
    }

    #[test]
    fn jitter_spikes_do_not_trigger_backoff() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        // Most samples spike to +200 ms, but each round still has one near the base.
        drive(
            &mut c,
            &mut t,
            10,
            &Round {
                jitter: 200 * MS,
                ..Round::clean()
            },
        );
        assert!(c.cap > 100_000);
    }

    #[test]
    fn steady_random_loss_is_ignored() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        drive(
            &mut c,
            &mut t,
            20,
            &Round {
                loss: 0.2,
                ..Round::clean()
            },
        );
        assert!(c.cap > 1_000_000, "cap {}", c.cap);
    }

    #[test]
    fn excess_loss_backs_off_and_probes_gently() {
        let (mut c, mut t) = (WindowCap::new(100_000, MTU), Instant::now());
        let base = Round {
            loss: 0.2,
            ..Round::clean()
        };
        drive(&mut c, &mut t, 10, &base);
        let before = c.cap;
        // A policer kicks in: loss jumps from 20% to 45%.
        let policed = Round {
            loss: 0.45,
            ..Round::clean()
        };
        drive(&mut c, &mut t, 3, &policed);
        assert!(c.cap < before, "no backoff: {} vs {before}", c.cap);
        // Back at baseline loss (after one round that still holds policed sends),
        // growth near the backoff point is 5%/round, not 25%.
        drive(&mut c, &mut t, 2, &base);
        let settled = c.cap;
        drive(&mut c, &mut t, 4, &base);
        assert!(c.cap > settled, "no probing: {} vs {settled}", c.cap);
        assert!(c.cap < settled * 13 / 10, "probing too fast: {} vs {settled}", c.cap);
    }

    #[test]
    fn noisy_loss_in_small_rounds_does_not_pin_the_cap() {
        // ~25 packets per round with loss alternating 5%/27% (mean 16%): pure noise.
        let (mut c, mut t) = (WindowCap::new(0, MTU), Instant::now());
        c.cap = 25 * c.mtu;
        let start = c.cap;
        for i in 0..60 {
            let loss = if i % 2 == 0 { 0.05 } else { 0.27 };
            drive(&mut c, &mut t, 1, &Round { loss, ..Round::clean() });
        }
        assert!(c.cap > 3 * start, "cap pinned: {} vs start {start}", c.cap);
    }
}
