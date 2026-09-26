//! Loss-tolerant BBR: quinn's BBRv1 minus loss-driven recovery.
//!
//! quinn's BBR (a port of Chromium's BBRv1) caps cwnd with a recovery window
//! that shrinks by every lost byte and is only lifted after a whole round
//! without loss. On the local->exit path loss is ~20% and random, so it would
//! stay in recovery forever. BBR's bandwidth/min-RTT model already sees that
//! loss through the delivery rate, so here non-persistent loss is not reported
//! to it; lost packets are still retransmitted by QUIC as usual. Persistent
//! congestion (a real outage) is still passed through.

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

#[derive(Debug, Default)]
pub struct LossTolerantBbrConfig {
    pub bbr: BbrConfig,
}

impl ControllerFactory for LossTolerantBbrConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(LossTolerantBbr {
            inner: Arc::new(self.bbr.clone()).build(now, current_mtu),
        })
    }
}

struct LossTolerantBbr {
    inner: Box<dyn Controller>,
}

impl Controller for LossTolerantBbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64) {
        if is_persistent_congestion {
            self.inner.on_congestion_event(now, sent, true, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(LossTolerantBbr {
            inner: self.inner.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
