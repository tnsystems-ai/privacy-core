//! Single-thread `redact()` latency on synthetic text.
//!
//! Run: `cargo run --release -p privacy-core-engine --example latency`
//! The text has an IBAN or a card number about every 85 bytes, so it is denser
//! in PII than most real text. Measure on your own data before relying on the numbers.

use std::hint::black_box;
use std::time::Instant;

use privacy_core_engine::PIIEngine;

const CHUNKS: [&str; 4] = [
    "Bonjour, merci de virer le solde sur le compte FR7630006000011234567890189 avant vendredi. ",
    "Customer reports a charge on card 4111 1111 1111 1111 that they do not recognise. ",
    "Überweisung bitte an DE89370400440532013000, Rechnung Nr. 2024-118, Betrag 1.250,00 EUR. ",
    "The client asked us to close the account and send the final statement by email. ",
];

fn make_text(target_bytes: usize) -> String {
    let mut s = String::new();
    for chunk in CHUNKS.iter().cycle() {
        if s.len() >= target_bytes {
            break;
        }
        s.push_str(chunk);
    }
    s
}

fn main() {
    let engine = PIIEngine::with_preset("eu_fintech").expect("known preset");
    for size in [200, 2_000, 20_000, 1_000_000] {
        let text = make_text(size);
        let iters = (50_000_000 / text.len()).clamp(200, 200_000);
        for _ in 0..iters / 10 {
            black_box(engine.redact(black_box(&text)).unwrap());
        }
        let mut lat = Vec::with_capacity(iters);
        let started = Instant::now();
        for _ in 0..iters {
            let t = Instant::now();
            black_box(engine.redact(black_box(&text)).unwrap());
            lat.push(t.elapsed().as_nanos() as u64);
        }
        let total = started.elapsed().as_secs_f64();
        lat.sort_unstable();
        let pct = |q: f64| lat[((q * lat.len() as f64) as usize).min(lat.len() - 1)] as f64 / 1e3;
        println!(
            "bytes={:>8} detections={:>5} p50={:>9.2}us p99={:>9.2}us throughput={:>5.0} MB/s",
            text.len(),
            engine.detect(&text).unwrap().len(),
            pct(0.50),
            pct(0.99),
            text.len() as f64 * iters as f64 / total / 1e6,
        );
    }
}
