use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use crate::types::{Detection, PiiType};

/// Number of log2 latency buckets. Bucket 0 holds latencies below 1 us,
/// bucket `i` holds `[2^(i-1), 2^i)` us; the last bucket is open-ended.
pub const LATENCY_BUCKETS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallKind {
    Detect,
    Redact,
}

/// Lock-free, process-wide engine counters. Individual counters are exact;
/// a snapshot taken under concurrent load is not a single atomic cut.
#[derive(Debug)]
pub struct EngineMetrics {
    detect_calls: AtomicU64,
    redact_calls: AtomicU64,
    bytes_processed: AtomicU64,
    chars_processed: AtomicU64,
    busy_time_ns: AtomicU64,
    last_latency_ns: AtomicU64,
    min_latency_ns: AtomicU64,
    max_latency_ns: AtomicU64,
    detections: [AtomicU64; PiiType::COUNT],
    histogram: [AtomicU64; LATENCY_BUCKETS],
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineMetrics {
    pub const fn new() -> Self {
        Self {
            detect_calls: AtomicU64::new(0),
            redact_calls: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            chars_processed: AtomicU64::new(0),
            busy_time_ns: AtomicU64::new(0),
            last_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
            max_latency_ns: AtomicU64::new(0),
            detections: [const { AtomicU64::new(0) }; PiiType::COUNT],
            histogram: [const { AtomicU64::new(0) }; LATENCY_BUCKETS],
        }
    }

    pub(crate) fn record(
        &self,
        kind: CallKind,
        latency: Duration,
        bytes: usize,
        chars: usize,
        detections: &[Detection],
    ) {
        let ns = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        match kind {
            CallKind::Detect => self.detect_calls.fetch_add(1, Relaxed),
            CallKind::Redact => self.redact_calls.fetch_add(1, Relaxed),
        };
        self.bytes_processed.fetch_add(bytes as u64, Relaxed);
        self.chars_processed.fetch_add(chars as u64, Relaxed);
        self.busy_time_ns.fetch_add(ns, Relaxed);
        self.last_latency_ns.store(ns, Relaxed);
        self.min_latency_ns.fetch_min(ns, Relaxed);
        self.max_latency_ns.fetch_max(ns, Relaxed);
        self.histogram[bucket_for(ns / 1_000)].fetch_add(1, Relaxed);

        let mut counts = [0u64; PiiType::COUNT];
        for d in detections {
            counts[d.pii_type.index()] += 1;
        }
        for (slot, n) in self.detections.iter().zip(counts) {
            if n > 0 {
                slot.fetch_add(n, Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let detect_calls = self.detect_calls.load(Relaxed);
        let redact_calls = self.redact_calls.load(Relaxed);
        let requests = detect_calls + redact_calls;
        let bytes_processed = self.bytes_processed.load(Relaxed);
        let chars_processed = self.chars_processed.load(Relaxed);
        let busy_ns = self.busy_time_ns.load(Relaxed);
        let min_ns = self.min_latency_ns.load(Relaxed);
        let histogram = self.histogram.each_ref().map(|h| h.load(Relaxed));
        let detections = self.detections.each_ref().map(|d| d.load(Relaxed));

        let busy_secs = busy_ns as f64 / 1e9;
        let per_sec = |n: u64| {
            if busy_ns == 0 {
                0.0
            } else {
                n as f64 / busy_secs
            }
        };

        MetricsSnapshot {
            requests,
            detect_calls,
            redact_calls,
            bytes_processed,
            chars_processed,
            busy_time_us: ns_to_us(busy_ns),
            last_latency_us: ns_to_us(self.last_latency_ns.load(Relaxed)),
            min_latency_us: if requests == 0 { 0.0 } else { ns_to_us(min_ns) },
            max_latency_us: ns_to_us(self.max_latency_ns.load(Relaxed)),
            avg_latency_us: if requests == 0 {
                0.0
            } else {
                ns_to_us(busy_ns) / requests as f64
            },
            p50_latency_us: percentile_us(&histogram, 0.50),
            p99_latency_us: percentile_us(&histogram, 0.99),
            throughput_chars_per_sec: per_sec(chars_processed),
            throughput_bytes_per_sec: per_sec(bytes_processed),
            detections,
            latency_histogram: histogram,
        }
    }

    pub fn reset(&self) {
        for c in [
            &self.detect_calls,
            &self.redact_calls,
            &self.bytes_processed,
            &self.chars_processed,
            &self.busy_time_ns,
            &self.last_latency_ns,
            &self.max_latency_ns,
        ] {
            c.store(0, Relaxed);
        }
        self.min_latency_ns.store(u64::MAX, Relaxed);
        for c in self.detections.iter().chain(&self.histogram) {
            c.store(0, Relaxed);
        }
    }
}

#[inline]
fn bucket_for(us: u64) -> usize {
    ((u64::BITS - us.leading_zeros()) as usize).min(LATENCY_BUCKETS - 1)
}

/// Upper bound (exclusive) in microseconds of histogram bucket `i`.
#[inline]
pub const fn bucket_upper_bound_us(i: usize) -> u64 {
    1u64 << i
}

#[inline]
fn ns_to_us(ns: u64) -> f64 {
    ns as f64 / 1_000.0
}

fn percentile_us(histogram: &[u64; LATENCY_BUCKETS], q: f64) -> f64 {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let rank = ((q * total as f64).ceil() as u64).max(1);
    let mut seen = 0u64;
    for (i, &n) in histogram.iter().enumerate() {
        seen += n;
        if seen >= rank {
            return bucket_upper_bound_us(i) as f64;
        }
    }
    bucket_upper_bound_us(LATENCY_BUCKETS - 1) as f64
}

/// Point-in-time copy of [`EngineMetrics`]. Latencies are in microseconds;
/// percentiles are histogram bucket upper bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub detect_calls: u64,
    pub redact_calls: u64,
    pub bytes_processed: u64,
    pub chars_processed: u64,
    pub busy_time_us: f64,
    pub last_latency_us: f64,
    pub min_latency_us: f64,
    pub max_latency_us: f64,
    pub avg_latency_us: f64,
    pub p50_latency_us: f64,
    pub p99_latency_us: f64,
    pub throughput_chars_per_sec: f64,
    pub throughput_bytes_per_sec: f64,
    pub detections: [u64; PiiType::COUNT],
    pub latency_histogram: [u64; LATENCY_BUCKETS],
}

impl MetricsSnapshot {
    pub fn detections_by_type(&self) -> [(PiiType, u64); PiiType::COUNT] {
        PiiType::ALL.map(|t| (t, self.detections[t.index()]))
    }

    pub fn detections_for(&self, pii_type: PiiType) -> u64 {
        self.detections[pii_type.index()]
    }

    pub fn total_detections(&self) -> u64 {
        self.detections.iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(pii_type: PiiType) -> Detection {
        Detection {
            pii_type,
            start: 0,
            end: 1,
        }
    }

    #[test]
    fn empty_snapshot_is_zeroed() {
        let s = EngineMetrics::new().snapshot();
        assert_eq!(s.requests, 0);
        assert_eq!(s.min_latency_us, 0.0);
        assert_eq!(s.p99_latency_us, 0.0);
        assert_eq!(s.throughput_chars_per_sec, 0.0);
    }

    #[test]
    fn records_and_aggregates() {
        let m = EngineMetrics::new();
        m.record(
            CallKind::Detect,
            Duration::from_micros(10),
            100,
            90,
            &[
                det(PiiType::Iban),
                det(PiiType::Iban),
                det(PiiType::CreditCard),
            ],
        );
        m.record(CallKind::Redact, Duration::from_micros(30), 100, 90, &[]);
        let s = m.snapshot();
        assert_eq!((s.requests, s.detect_calls, s.redact_calls), (2, 1, 1));
        assert_eq!(s.bytes_processed, 200);
        assert_eq!(s.chars_processed, 180);
        assert_eq!(s.detections_for(PiiType::Iban), 2);
        assert_eq!(s.detections_for(PiiType::CreditCard), 1);
        assert_eq!(s.total_detections(), 3);
        assert_eq!(s.min_latency_us, 10.0);
        assert_eq!(s.max_latency_us, 30.0);
        assert_eq!(s.last_latency_us, 30.0);
        assert_eq!(s.avg_latency_us, 20.0);
        assert_eq!(s.p50_latency_us, 16.0);
        assert_eq!(s.p99_latency_us, 32.0);
        assert!((s.throughput_chars_per_sec - 180.0 / 40e-6).abs() < 1.0);

        m.reset();
        assert_eq!(m.snapshot(), EngineMetrics::new().snapshot());
    }

    #[test]
    fn bucket_boundaries() {
        assert_eq!(bucket_for(0), 0);
        assert_eq!(bucket_for(1), 1);
        assert_eq!(bucket_for(2), 2);
        assert_eq!(bucket_for(3), 2);
        assert_eq!(bucket_for(1_000), 10);
        assert_eq!(bucket_for(u64::MAX), LATENCY_BUCKETS - 1);
    }
}
