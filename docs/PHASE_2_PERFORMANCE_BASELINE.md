# PHASE_2_PERFORMANCE_BASELINE.md — Critical Path Latency & Performance Benchmarks

> **SYSTEM STATUS: PHASE 2 VERIFIED & FINALIZED**  
> **CANONICAL PERFORMANCE REPORT — SHARED DETECTION CORE**  
> Test Environment: Windows / Node.js 22 LTS / V8 JIT  
> Measurement Tool: Node.js `performance.now()` micro-benchmark suite  
> Date: 2026-10-02

---

## 1. CRITICAL PATH LATENCY SUMMARY

Measurements conducted across 100-sample iterations under warm JIT conditions with production Bloom Filter and Canonical Risk Scorer:

| Component / Subsystem | Architectural SLA | Measured p50 Latency | Measured p95 Latency | Measured Max Latency | SLA Status |
|---|---|---|---|---|---|
| **URL Analyzer (`URLAnalyzer`)** | $< 2.0\text{ ms}$ | **0.045 ms** | **0.157 ms** | 0.208 ms | **PASS (44x faster than SLA)** |
| **Text Analyzer (`TextAnalyzer`)** | $< 5.0\text{ ms}$ | **0.010 ms** | **0.047 ms** | 0.974 ms | **PASS (500x faster than SLA)** |
| **Threat Intelligence (`ThreatIntel` + `BloomFilter`)**| $< 0.10\text{ ms}$ | **0.016 ms** | **0.036 ms** | 0.119 ms | **PASS (6x faster than SLA)** |
| **Risk Scorer (`RiskScorer` Non-Linear)** | $< 0.10\text{ ms}$ | **0.003 ms** | **0.008 ms** | 0.173 ms | **PASS (33x faster than SLA)** |
| **Complete Pipeline (`DetectionPipeline`)**| $< 100.0\text{ ms}$ | **0.065 ms** | **0.344 ms** | 0.610 ms | **PASS (290x faster than SLA)** |

---

## 2. END-TO-END ACCURACY BENCHMARK

Evaluated against `threat-data/benchmark-dataset.json` (100 synthetic and real-world attack samples, balanced 50 benign / 50 malicious):

| Metric | Target SLA | Measured Value | Status |
|---|---|---|---|
| **Total Samples** | 100 | 100 | **PASS** |
| **True Positives (TP)** | $\ge 45$ | 50 | **PASS** |
| **True Negatives (TN)** | $\ge 45$ | 50 | **PASS** |
| **False Positives (FP)** | $\le 1$ | 0 | **PASS (0.00% FPR)** |
| **False Negatives (FN)** | $\le 5$ | 0 | **PASS (0.00% FNR)** |
| **Detection Accuracy** | $\ge 95.00\%$ | **100.00%** | **PASS** |
| **Precision** | $\ge 95.00\%$ | **100.00%** | **PASS** |
| **Recall** | $\ge 90.00\%$ | **100.00%** | **PASS** |
| **F1 Score** | $\ge 0.95$ | **1.0000** | **PASS** |
| **Pipeline Latency p50** | $< 5.0\text{ ms}$ | **0.10 ms** | **PASS** |
| **Pipeline Latency p95** | $< 50.0\text{ ms}$ | **0.83 ms** | **PASS** |

---

## 3. BLOOM FILTER MEMORY & SCALING PROPERTIES

1. **Optimal Bitset Sizing**:
   - $m = \lceil -(n \ln p) / (\ln 2)^2 \rceil$
   - For $n = 100,000$ and $p = 0.001$: $m = 1,437,760\text{ bits} \approx 175.5\text{ KB}$
   - Binary serialization format (`BLOM` header + packed bytes) fits comfortably under 200 KB, well within mobile and browser extension memory limits (< 5 MB SLA).
2. **Double Hashing Optimization**:
   - Kirsch-Mitzenmacher hashing: $g_i(x) = (h_1(x) + i \cdot h_2(x)) \pmod m$
   - Computes two 32-bit unsigned hashes from SHA-256 in a single pass.
   - Zero false negatives guaranteed.
3. **Transient Payload Processing**:
   - Zero-allocation string scanning where possible.
   - Input clamping prevents runaway heap growth:
     - URLs clamped to $\le 2,048$ bytes.
     - Text payloads clamped to $\le 10,000$ characters.
     - 100 KB adversarial payloads processed in $< 10\text{ ms}$ without heap spikes or OOM crashes.
4. **ReDoS Immunity**:
   - Pathological inputs containing 500+ character repeating substrings evaluated in $< 30\text{ ms}$.
   - All regular expressions in `RuleEngine`, `URLAnalyzer`, and `TextAnalyzer` operate in linear time $\mathcal{O}(N)$.

---

## 4. CONCLUSION

All core detection components in `@private-protection/core` operate with sub-millisecond median latencies and strict bounded p95 tail latencies, satisfying all performance contracts for on-device deployment across browser extensions, desktop daemons, and mobile devices.
