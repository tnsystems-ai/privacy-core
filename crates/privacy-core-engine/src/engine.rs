use std::sync::Arc;
use std::time::Instant;

use crate::error::EngineError;
use crate::metrics::{CallKind, EngineMetrics, MetricsSnapshot};
use crate::ruleset::Ruleset;
use crate::scanner::{self, ScanOutput};
use crate::types::{Detection, RedactionResult};

#[derive(Debug, Default)]
pub struct PIIEngine {
    ruleset: Ruleset,
    metrics: Arc<EngineMetrics>,
}

impl PIIEngine {
    pub fn new(ruleset: Ruleset) -> Self {
        Self {
            ruleset,
            metrics: Arc::new(EngineMetrics::new()),
        }
    }

    pub fn with_preset(name: &str) -> Result<Self, EngineError> {
        Ruleset::preset(name).map(Self::new)
    }

    pub fn detect(&self, text: &str) -> Result<Vec<Detection>, EngineError> {
        let started = Instant::now();
        let out = self.scan(text)?;
        self.metrics.record(
            CallKind::Detect,
            started.elapsed(),
            text.len(),
            out.chars,
            &out.detections,
        );
        Ok(out.detections)
    }

    pub fn redact(&self, text: &str) -> Result<RedactionResult, EngineError> {
        let started = Instant::now();
        let out = self.scan(text)?;
        let redacted = self.apply(text, &out.detections);
        self.metrics.record(
            CallKind::Redact,
            started.elapsed(),
            text.len(),
            out.chars,
            &out.detections,
        );
        Ok(RedactionResult {
            text: redacted,
            detections: out.detections,
        })
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn metrics_handle(&self) -> Arc<EngineMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    #[inline]
    fn scan(&self, text: &str) -> Result<ScanOutput, EngineError> {
        let max = self.ruleset.max_input_bytes();
        if text.len() > max {
            return Err(EngineError::InputTooLarge {
                len: text.len(),
                max,
            });
        }
        Ok(scanner::scan(text, self.ruleset.enabled_mask()))
    }

    fn apply(&self, text: &str, detections: &[Detection]) -> String {
        if detections.is_empty() {
            return text.to_owned();
        }
        let capacity = detections.iter().fold(text.len(), |acc, d| {
            acc - d.len() + self.ruleset.replacement(d.pii_type).len()
        });
        let mut out = String::with_capacity(capacity);
        let mut cursor = 0;
        for d in detections {
            out.push_str(&text[cursor..d.start]);
            out.push_str(self.ruleset.replacement(d.pii_type));
            cursor = d.end;
        }
        out.push_str(&text[cursor..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PiiType;

    const SAMPLE: &str = "Please transfer funds to IBAN FR7630006000011234567890189 \
                          and charge card 4111 1111 1111 1111 for Jürgen.";

    #[test]
    fn redacts_with_default_tags() {
        let engine = PIIEngine::with_preset("eu_fintech").unwrap();
        let res = engine.redact(SAMPLE).unwrap();
        assert_eq!(
            res.text,
            "Please transfer funds to IBAN [IBAN_REDACTED] \
             and charge card [CREDIT_CARD_REDACTED] for Jürgen."
        );
        assert_eq!(res.detections.len(), 2);
    }

    #[test]
    fn custom_tags_and_disabled_types() {
        let engine = PIIEngine::new(
            Ruleset::default()
                .disable(PiiType::CreditCard)
                .with_replacement(PiiType::Iban, "***"),
        );
        let res = engine.redact(SAMPLE).unwrap();
        assert!(res.text.contains("IBAN *** and"));
        assert!(res.text.contains("4111 1111 1111 1111"));
    }

    #[test]
    fn no_detections_returns_input() {
        let engine = PIIEngine::default();
        let res = engine.redact("nothing to see here").unwrap();
        assert_eq!(res.text, "nothing to see here");
        assert!(res.detections.is_empty());
    }

    #[test]
    fn enforces_input_limit() {
        let engine = PIIEngine::new(Ruleset::default().with_max_input_bytes(8));
        assert_eq!(
            engine.detect("123456789"),
            Err(EngineError::InputTooLarge { len: 9, max: 8 })
        );
        assert_eq!(engine.metrics().requests, 0);
    }

    #[test]
    fn records_metrics_per_call() {
        let engine = PIIEngine::default();
        engine.detect(SAMPLE).unwrap();
        engine.redact(SAMPLE).unwrap();
        let s = engine.metrics();
        assert_eq!((s.requests, s.detect_calls, s.redact_calls), (2, 1, 1));
        assert_eq!(s.bytes_processed, 2 * SAMPLE.len() as u64);
        assert_eq!(s.chars_processed, 2 * SAMPLE.chars().count() as u64);
        assert_eq!(s.detections_for(PiiType::Iban), 2);
        assert_eq!(s.detections_for(PiiType::CreditCard), 2);
        assert!(s.max_latency_us >= s.min_latency_us);
    }

    #[test]
    fn metrics_are_consistent_across_threads() {
        const THREADS: usize = 8;
        const ITERS: usize = 500;
        let engine = PIIEngine::default();
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let engine = &engine;
                s.spawn(move || {
                    for _ in 0..ITERS {
                        if t % 2 == 0 {
                            engine.detect(SAMPLE).unwrap();
                        } else {
                            engine.redact(SAMPLE).unwrap();
                        }
                    }
                });
            }
        });
        let total = (THREADS * ITERS) as u64;
        let s = engine.metrics();
        assert_eq!(s.requests, total);
        assert_eq!(s.detect_calls, total / 2);
        assert_eq!(s.total_detections(), 2 * total);
        assert_eq!(s.latency_histogram.iter().sum::<u64>(), total);
        assert_eq!(s.bytes_processed, total * SAMPLE.len() as u64);
    }

    #[test]
    fn engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PIIEngine>();
    }
}
