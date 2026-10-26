# privacy-core

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](Cargo.toml)
[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](pyproject.toml)

Fast, deterministic redaction of IBANs and payment card numbers, written in Rust, with Python bindings.

Use it to strip bank details from free text before the text is logged, stored or sent to an external LLM. It runs inside your process: no model, no network calls, no dependencies in the core crate. Every match must pass a checksum: ISO 13616 mod-97 for IBANs, Luhn for card numbers.

**Status: early alpha (0.1.0).** It detects two entity types. It is a building block, not a complete PII solution: names, addresses, emails, phone numbers and national IDs are not detected yet (see [Limitations](#limitations)).

## What it detects

| Type | Default tag | Rules |
|---|---|---|
| `IBAN` | `[IBAN_REDACTED]` | 50 European country codes, each with its registry length; any letter case; compact or grouped by single spaces, including no-break spaces (U+00A0, U+202F) common in French text; check digits 02–98 and mod-97 |
| `CREDIT_CARD` | `[CREDIT_CARD_REDACTED]` | 13–19 digits; compact or grouped with one separator kind (spaces, including no-break spaces, or hyphens); Luhn; numbers made of one repeated digit are rejected |

A match must start and end at a word boundary: an ASCII letter or digit right before or after it blocks the match.

## Python

Not on PyPI yet. Build from source (needs a Rust toolchain):

```bash
git clone https://github.com/tnsystems-ai/privacy-core
cd privacy-core
uv sync          # or: pip install .
```

```python
import privacy_core

engine = privacy_core.PIIEngine()  # preset "eu_fintech"

text = "Refund to IBAN FR76 3000 6000 0112 3456 7890 189, card 4111 1111 1111 1111, for John Doe."

print(engine.redact(text))
# Refund to IBAN [IBAN_REDACTED], card [CREDIT_CARD_REDACTED], for John Doe.
# The name is not redacted: names are not supported yet.

for d in engine.detect(text):
    print(d["type"], text[d["start"]:d["end"]])
# IBAN FR76 3000 6000 0112 3456 7890 189
# CREDIT_CARD 4111 1111 1111 1111
```

- `detect()` returns `str` indices, so `text[start:end]` is the match, also in non-ASCII text.
- `metrics()` returns counters since creation or the last `reset_metrics()`: calls, bytes, detections per type, min, max and average latency, and p50 and p99 as log2 histogram bucket upper bounds.
- Errors: `UnknownPresetError` and `InputTooLargeError` (default limit 1 MiB of UTF-8), both subclasses of `PrivacyCoreError(ValueError)`.
- The engine is thread-safe. Inputs of 16 KiB or more are processed with the GIL released, and the extension supports free-threaded Python 3.14t.
- Presets `"default"` and `"eu_fintech"` are currently identical: both enable IBANs and cards. Custom tags and turning types on or off are available in the Rust API only for now.

## Rust

Not on crates.io yet. Use a git dependency:

```toml
[dependencies]
privacy-core-engine = { git = "https://github.com/tnsystems-ai/privacy-core" }
```

```rust
use privacy_core_engine::{PIIEngine, PiiType, Ruleset};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = PIIEngine::new(
        Ruleset::default()
            .disable(PiiType::CreditCard)
            .with_replacement(PiiType::Iban, "<IBAN>"),
    );
    let out = engine.redact("Pay DE89370400440532013000 today.")?;
    assert_eq!(out.text, "Pay <IBAN> today.");
    // out.detections holds byte ranges into the original input.
    Ok(())
}
```

## Performance

`redact()` on one thread, release build, Apple M3 Pro, three runs. The synthetic text has an IBAN or a card number about every 85 bytes, which is denser than most real text.

| Input size | p50 | p99 |
|---|---|---|
| 263 bytes | 0.5 µs | 0.6–1.0 µs |
| 2 KB | 2.9–3.4 µs | 3.4–7.2 µs |
| 20 KB | 27–31 µs | 32–160 µs |
| 1 MB (just under the default input limit) | 1.3–1.4 ms | 1.4–1.8 ms |

Throughput was 440–770 MB/s. Through the Python binding, p50 on the 263-byte text was about 0.1 µs higher.

Reproduce with `cargo run --release -p privacy-core-engine --example latency`. Numbers depend on hardware and text, so measure on your own data.

## Limitations

- Only IBANs and payment card numbers. Names, addresses, emails, phone numbers, national IDs (such as the French NIR) and company IDs are not detected.
- IBANs grouped with hyphens or dots are missed.
- IBANs outside the 50 supported European country codes are not detected.
- There is no card-network (IIN) check: any Luhn-valid number of 13–19 digits is tagged `CREDIT_CARD`. French SIRET numbers (14 digits, Luhn-valid by design) and IMEI numbers (15 digits) are tagged as cards.
- A missed entity is a leak. Test recall on your own data before you rely on it.
- This library is one technical control. Using it does not make a system GDPR-compliant by itself.

## Roadmap

Planned, no dates:

- card-network (IIN) check;
- French identifiers: NIR, RIB, SIREN and SIRET, BIC;
- an optional local model for names and addresses;
- wheels for older Python versions, CI, PyPI and crates.io releases.

## Development

```bash
cargo test -p privacy-core-engine
uv run --extra test pytest
```

## About

Built by [TN Systems](https://tnsystems.ai), Paris. We build private, domain-specific models for regulated fintech; this repository holds only the deterministic layer.

- Email: info@tnsystems.ai
- Issues: [GitHub Issues](https://github.com/tnsystems-ai/privacy-core/issues)

Licensed under [Apache 2.0](LICENSE).
