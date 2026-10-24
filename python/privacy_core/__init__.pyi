from typing import Final, Literal, TypedDict, final

__version__: Final[str]

Preset = Literal["default", "eu_fintech"]
PiiTypeName = Literal["IBAN", "CREDIT_CARD"]

class Detection(TypedDict):
    type: PiiTypeName
    start: int
    end: int

class DetectionCounts(TypedDict):
    IBAN: int
    CREDIT_CARD: int

class Metrics(TypedDict):
    requests: int
    detect_calls: int
    redact_calls: int
    bytes_processed: int
    chars_processed: int
    busy_time_us: float
    last_latency_us: float
    min_latency_us: float
    max_latency_us: float
    avg_latency_us: float
    p50_latency_us: float
    p99_latency_us: float
    throughput_chars_per_sec: float
    throughput_bytes_per_sec: float
    detections: DetectionCounts
    total_detections: int
    latency_histogram: list[tuple[int, int]]

@final
class PIIEngine:
    """Thread-safe PII detection and redaction engine.

    Inputs of 16 KiB or more are processed with the GIL released.
    """

    def __init__(self, preset: Preset = "eu_fintech") -> None:
        """Create an engine from a ruleset preset.

        Raises:
            UnknownPresetError: If ``preset`` is not a known preset name.
        """

    @property
    def preset(self) -> str: ...
    def redact(self, text: str) -> str:
        """Return ``text`` with every detected entity replaced by its tag.

        Raises:
            InputTooLargeError: If ``text`` exceeds the engine's input limit.
        """

    def detect(self, text: str) -> list[Detection]:
        """Return detected entities in order of appearance.

        ``start``/``end`` are ``str`` indices, so ``text[start:end]`` is the match.

        Raises:
            InputTooLargeError: If ``text`` exceeds the engine's input limit.
        """

    def metrics(self) -> Metrics:
        """Return a snapshot of engine telemetry since creation or last reset.

        Latencies are in microseconds; percentiles are log2 histogram bucket
        upper bounds. ``latency_histogram`` is a list of
        ``(upper_bound_us, count)`` pairs.
        """

    def reset_metrics(self) -> None: ...

class PrivacyCoreError(ValueError):
    """Base class for all privacy_core errors."""

class UnknownPresetError(PrivacyCoreError):
    """Raised when an unknown ruleset preset name is given."""

class InputTooLargeError(PrivacyCoreError):
    """Raised when the input exceeds the engine's maximum input size."""

__all__ = [
    "InputTooLargeError",
    "PIIEngine",
    "PrivacyCoreError",
    "UnknownPresetError",
    "__version__",
]
