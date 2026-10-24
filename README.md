# Privacy Core (`privacy-core`)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust Core](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)](crates/privacy-core-engine)
[![Python SDK](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](python/)

> **Ultra-fast, deterministic & ONNX-powered PII detection engine built in Rust for enterprise LLM and Fintech pipelines.**

`privacy-core` bridges the 2% safety gap left by general-purpose LLMs while eliminating API latency. It acts as an on-premise / edge security proxy, redacting European PII (IBANs, Credit Cards, Tax IDs, Passports, Names) in **< 2ms** before prompts leave your secure infrastructure.

---

## Why `privacy-core`?

* **< 2ms p99 Latency:** High-performance Rust core with zero-copy regex and SIMD acceleration.
* **EU GDPR & AI Act Sovereign:** Deterministic check-sum validation for European IBANs, PANs, and regional IDs.
* **Hybrid Engine:** Combines zero-latency deterministic matchers with lightweight local ONNX Token Classification models.
* **1-Line Integration:** Seamless Python bindings via PyO3 / Maturin.

---

## Quick Start (Python)

```python
import privacy_core

# Initialize engine with EU GDPR ruleset
engine = privacy_core.PIIEngine(preset="eu_fintech")

text = "Please transfer funds to IBAN FR7630006000011234567890189 for John Doe."
redacted_text = engine.redact(text)

print(redacted_text)
# Output: "Please transfer funds to IBAN [IBAN_REDACTED] for [PERSON_REDACTED]."
```
