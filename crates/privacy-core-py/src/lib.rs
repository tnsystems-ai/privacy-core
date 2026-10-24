use privacy_core_engine::{
    Detection, EngineError, LATENCY_BUCKETS, MetricsSnapshot, PIIEngine, bucket_upper_bound_us,
};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Inputs at or above this size are processed with the GIL released.
const DETACH_THRESHOLD_BYTES: usize = 16 * 1024;

create_exception!(
    privacy_core,
    PrivacyCoreError,
    PyValueError,
    "Base class for all privacy_core errors."
);
create_exception!(
    privacy_core,
    UnknownPresetError,
    PrivacyCoreError,
    "Raised when an unknown ruleset preset name is given."
);
create_exception!(
    privacy_core,
    InputTooLargeError,
    PrivacyCoreError,
    "Raised when the input exceeds the engine's maximum input size."
);

fn to_py_err(err: EngineError) -> PyErr {
    let msg = err.to_string();
    match err {
        EngineError::UnknownPreset(_) => UnknownPresetError::new_err(msg),
        EngineError::InputTooLarge { .. } => InputTooLargeError::new_err(msg),
        _ => PrivacyCoreError::new_err(msg),
    }
}

/// Converts byte offsets of sorted, non-overlapping detections into
/// code-point offsets (Python `str` indices) in a single forward walk.
fn char_offsets(text: &str, detections: &[Detection]) -> Vec<(usize, usize)> {
    if text.is_ascii() {
        return detections.iter().map(|d| (d.start, d.end)).collect();
    }
    let bytes = text.as_bytes();
    let count = |from: usize, to: usize| {
        bytes[from..to]
            .iter()
            .filter(|&&b| b & 0xC0 != 0x80)
            .count()
    };
    let mut byte_pos = 0;
    let mut char_pos = 0;
    detections
        .iter()
        .map(|d| {
            char_pos += count(byte_pos, d.start);
            let start = char_pos;
            char_pos += count(d.start, d.end);
            byte_pos = d.end;
            (start, char_pos)
        })
        .collect()
}

#[pyclass(frozen, name = "PIIEngine", module = "privacy_core")]
struct PyPIIEngine {
    inner: PIIEngine,
    preset: String,
}

impl PyPIIEngine {
    fn run<T: Send>(
        &self,
        py: Python<'_>,
        text: &str,
        f: impl FnOnce(&PIIEngine, &str) -> T + Send,
    ) -> T {
        if text.len() >= DETACH_THRESHOLD_BYTES {
            py.detach(|| f(&self.inner, text))
        } else {
            f(&self.inner, text)
        }
    }
}

#[pymethods]
impl PyPIIEngine {
    #[new]
    #[pyo3(signature = (preset = "eu_fintech"))]
    fn new(preset: &str) -> PyResult<Self> {
        let inner = PIIEngine::with_preset(preset).map_err(to_py_err)?;
        Ok(Self {
            inner,
            preset: preset.to_owned(),
        })
    }

    #[getter]
    fn preset(&self) -> &str {
        &self.preset
    }

    fn redact(&self, py: Python<'_>, text: &str) -> PyResult<String> {
        self.run(py, text, |e, t| e.redact(t))
            .map(|r| r.text)
            .map_err(to_py_err)
    }

    fn detect<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let detections = self.run(py, text, |e, t| e.detect(t)).map_err(to_py_err)?;
        let offsets = char_offsets(text, &detections);
        detections
            .iter()
            .zip(offsets)
            .map(|(d, (start, end))| {
                let dict = PyDict::new(py);
                dict.set_item("type", d.pii_type.as_str())?;
                dict.set_item("start", start)?;
                dict.set_item("end", end)?;
                Ok(dict)
            })
            .collect()
    }

    fn metrics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        metrics_dict(py, &self.inner.metrics())
    }

    fn reset_metrics(&self) {
        self.inner.metrics_handle().reset();
    }

    fn __repr__(&self) -> String {
        format!("PIIEngine(preset='{}')", self.preset)
    }
}

fn metrics_dict<'py>(py: Python<'py>, s: &MetricsSnapshot) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("requests", s.requests)?;
    d.set_item("detect_calls", s.detect_calls)?;
    d.set_item("redact_calls", s.redact_calls)?;
    d.set_item("bytes_processed", s.bytes_processed)?;
    d.set_item("chars_processed", s.chars_processed)?;
    d.set_item("busy_time_us", s.busy_time_us)?;
    d.set_item("last_latency_us", s.last_latency_us)?;
    d.set_item("min_latency_us", s.min_latency_us)?;
    d.set_item("max_latency_us", s.max_latency_us)?;
    d.set_item("avg_latency_us", s.avg_latency_us)?;
    d.set_item("p50_latency_us", s.p50_latency_us)?;
    d.set_item("p99_latency_us", s.p99_latency_us)?;
    d.set_item("throughput_chars_per_sec", s.throughput_chars_per_sec)?;
    d.set_item("throughput_bytes_per_sec", s.throughput_bytes_per_sec)?;

    let detections = PyDict::new(py);
    for (pii_type, n) in s.detections_by_type() {
        detections.set_item(pii_type.as_str(), n)?;
    }
    d.set_item("detections", detections)?;
    d.set_item("total_detections", s.total_detections())?;

    let histogram: Vec<(u64, u64)> = (0..LATENCY_BUCKETS)
        .map(|i| (bucket_upper_bound_us(i), s.latency_histogram[i]))
        .collect();
    d.set_item("latency_histogram", histogram)?;
    Ok(d)
}

#[pymodule(gil_used = false)]
fn _privacy_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<PyPIIEngine>()?;
    m.add("PrivacyCoreError", py.get_type::<PrivacyCoreError>())?;
    m.add("UnknownPresetError", py.get_type::<UnknownPresetError>())?;
    m.add("InputTooLargeError", py.get_type::<InputTooLargeError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
