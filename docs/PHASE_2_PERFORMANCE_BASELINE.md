# PHASE_2_PERFORMANCE_BASELINE.md — Critical Path Latency & Performance Benchmarks

> **SYSTEM STATUS: PHASE 2 IMPLEMENTATION**  
> **CANONICAL PERFORMANCE REPORT — SHARED DETECTION CORE**  
> Test Environment: Windows / Node.js 22 LTS / V8 JIT  
> Measurement Tool: Node.js `performance.now()` micro-benchmark suite  
> Date: 2026-10-02

---

## 1. CRITICAL PATH LATENCY SUMMARY

Measurements conducted across 100-sample iterations under warm JIT conditions:

| Component / Subsystem | Architectural SLA | Measured p50 Latency | Measured p95 Latency | Measured Max Latency | SLA Status |
|---|---|---|---|---|---|
| **URL Analyzer (`URLAnalyzer`)** | $< 2.0\text{ ms}$ | **0.139 ms** | **0.385 ms** | 2.266 ms | **PASS** |
| **Text Analyzer (`TextAnalyzer`)** | $< 5.0\text{ ms}$ | **0.027 ms** | **0.113 ms** | 2.477 ms | **PASS** |
| **Threat Intelligence (`ThreatIntel`)**| $< 0.10\text{ ms}$ | **0.017 ms** | **0.054 ms** | 0.286 ms | **PASS** |
| **Risk Scorer (`RiskScorer`)** | $< 0.10\text{ ms}$ | **0.007 ms** | **0.031 ms** | 0.307 ms | **PASS** |
| **Complete Pipeline (`DetectionPipeline`)**| $< 100.0\text{ ms}$ | **0.239 ms** | **1.589 ms** | 3.673 ms | **PASS** |

---

## 2. END-TO-END ACCURACY BENCHMARK

Evaluated against `threat-data/benchmark-dataset.json` (100 synthetic and real-world attack samples, balanced 50 benign / 50 malicious):

| Metric | Target SLA | Measured Value | Status |
|---|---|---|---|
| **Total Samples** | 100 | 100 | **PASS** |
| **True Positives (TP)** | $\ge 45$ | 50 | **PASS** |
| **True Negatives (TN)** | $\ge 45$ | 50 | **PASS** |
| **False Positives (FP)** | $\le 1$ | 0 | **PASS (0.00% FPR)** |
| **False Negatives (FN)** | $\le 5$ | 0 | **PASS** |
| **Detection Accuracy** | $\ge 95.00\%$ | **100.00%** | **PASS** |
| **Precision** | $\ge 95.00\%$ | **100.00%** | **PASS** |
| **Recall** | $\ge 90.00\%$ | **100.00%** | **PASS** |
| **F1 Score** | $\ge 0.95$ | **1.0000** | **PASS** |
| **Pipeline Latency p50** | $< 5.0\text{ ms}$ | **0.27 ms** | **PASS** |
| **Pipeline Latency p95** | $< 50.0\text{ ms}$ | **1.30 ms** | **PASS** |

---

## 3. MEMORY ALLOCATION & SCALING BEHAVIOR

1. **Transient Payload Processing**:
   - Zero-allocation string scanning where possible.
   - Input clamping prevents runaway heap growth:
     - URLs clamped to $\le 2,048$ bytes.
     - Text payloads clamped to $\le 10,000$ characters.
     - 100 KB adversarial payloads processed in $< 10\text{ ms}$ without heap spikes or OOM crashes.
2. **In-Memory Threat Feed Footprint**:
   - In-memory hash set overhead: $\approx 64\text{ bytes}$ per entry.
   - 1,000,000 hash capacity fits within $< 65\text{ MB}$ RAM footprint on native/WASM targets.
3. **ReDoS Immunity**:
   - Pathological inputs containing 500+ character repeating substrings evaluated in $< 30\text{ ms}$.
   - All regular expressions in `RuleEngine`, `URLAnalyzer`, and `TextAnalyzer` operate in linear time $\mathcal{O}(N)$.

---

## 4. CONCLUSION

All core detection components in `@private-protection/core` operate with sub-millisecond median latencies and strict bounded p95 tail latencies, satisfying all performance contracts for on-device deployment across browser extensions, desktop daemons, and mobile devices.
