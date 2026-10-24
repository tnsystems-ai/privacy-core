//! Deterministic, low-latency PII detection and redaction engine.

mod engine;
mod error;
mod metrics;
mod ruleset;
mod scanner;
mod types;
pub mod validators;

pub use engine::PIIEngine;
pub use error::EngineError;
pub use metrics::{EngineMetrics, LATENCY_BUCKETS, MetricsSnapshot, bucket_upper_bound_us};
pub use ruleset::{DEFAULT_MAX_INPUT_BYTES, Ruleset};
pub use types::{Detection, PiiType, RedactionResult};
