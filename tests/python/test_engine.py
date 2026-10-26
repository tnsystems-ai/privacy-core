from concurrent.futures import ThreadPoolExecutor

import pytest

import privacy_core
from privacy_core import (
    InputTooLargeError,
    PIIEngine,
    PrivacyCoreError,
    UnknownPresetError,
)

IBAN = "FR7630006000011234567890189"
CARD = "4111 1111 1111 1111"
SAMPLE = f"Please transfer funds to IBAN {IBAN} and charge card {CARD}."


def test_version() -> None:
    assert isinstance(privacy_core.__version__, str)
    assert privacy_core.__version__


@pytest.mark.parametrize("preset", ["default", "eu_fintech"])
def test_redact(preset: str) -> None:
    engine = PIIEngine(preset)
    assert engine.redact(SAMPLE) == (
        "Please transfer funds to IBAN [IBAN_REDACTED] and charge card [CREDIT_CARD_REDACTED]."
    )


def test_default_preset_and_repr() -> None:
    engine = PIIEngine()
    assert engine.preset == "eu_fintech"
    assert repr(engine) == "PIIEngine(preset='eu_fintech')"


def test_redact_without_pii_is_identity() -> None:
    text = "Grüße aus Köln, nichts zu sehen."
    assert PIIEngine().redact(text) == text


def test_detect_returns_codepoint_offsets() -> None:
    text = f"Überweisung → {IBAN} für Jürgen 🙂, Karte: {CARD} ✓"
    detections = PIIEngine().detect(text)
    assert [d["type"] for d in detections] == ["IBAN", "CREDIT_CARD"]
    assert [text[d["start"] : d["end"]] for d in detections] == [IBAN, CARD]


def test_lowercase_and_no_break_space_iban() -> None:
    engine = PIIEngine()
    assert engine.redact("iban fr76 3000 6000 0112 3456 7890 189") == "iban [IBAN_REDACTED]"
    grouped = "FR76 3000 6000 0112 3456 7890 189"
    text = f"IBAN : {grouped}, merci"
    detections = engine.detect(text)
    assert [text[d["start"] : d["end"]] for d in detections] == [grouped]
    assert engine.redact(text) == "IBAN : [IBAN_REDACTED], merci"


def test_detect_ascii_offsets() -> None:
    detections = PIIEngine().detect(SAMPLE)
    assert detections[0] == {
        "type": "IBAN",
        "start": SAMPLE.index(IBAN),
        "end": SAMPLE.index(IBAN) + len(IBAN),
    }


def test_unknown_preset() -> None:
    with pytest.raises(UnknownPresetError, match="nope"):
        PIIEngine("nope")
    with pytest.raises(ValueError):
        PIIEngine("nope")
    with pytest.raises(PrivacyCoreError):
        PIIEngine("nope")


def test_input_too_large() -> None:
    engine = PIIEngine()
    big = "a" * (1024 * 1024 + 1)
    with pytest.raises(InputTooLargeError):
        engine.redact(big)
    with pytest.raises(InputTooLargeError):
        engine.detect(big)
    assert engine.metrics()["requests"] == 0


def test_large_input_releases_gil_and_still_works() -> None:
    text = (SAMPLE + " ") * 400
    assert len(text.encode()) >= 16 * 1024
    engine = PIIEngine()
    assert len(engine.detect(text)) == 800
    assert "4111" not in engine.redact(text)


def test_metrics_and_reset() -> None:
    engine = PIIEngine()
    engine.detect(SAMPLE)
    engine.redact(SAMPLE)
    m = engine.metrics()
    assert m["requests"] == 2
    assert m["detect_calls"] == 1
    assert m["redact_calls"] == 1
    assert m["bytes_processed"] == 2 * len(SAMPLE.encode())
    assert m["chars_processed"] == 2 * len(SAMPLE)
    assert m["detections"] == {"IBAN": 2, "CREDIT_CARD": 2}
    assert m["total_detections"] == 4
    assert m["max_latency_us"] >= m["min_latency_us"] > 0
    assert m["throughput_chars_per_sec"] > 0
    assert sum(count for _, count in m["latency_histogram"]) == 2
    assert m["latency_histogram"][0][0] == 1

    engine.reset_metrics()
    m = engine.metrics()
    assert m["requests"] == 0
    assert m["total_detections"] == 0


def test_concurrent_use() -> None:
    engine = PIIEngine()
    workers, per_worker = 8, 250

    def work(_: int) -> None:
        for _ in range(per_worker):
            assert engine.redact(SAMPLE).count("_REDACTED]") == 2

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, range(workers)))

    m = engine.metrics()
    assert m["requests"] == workers * per_worker
    assert m["total_detections"] == 2 * workers * per_worker
