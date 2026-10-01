# Performance Requirements - PRIVATE PROTECTION

This document defines the performance targets, budgets, and testing methodologies for the PRIVATE PROTECTION on-device AI security assistant.

## Performance Targets

| Analysis Type | Target Latency | Platform | Notes |
|---|---|---|---|
| URL analysis (local) | <100ms | All | Rule + heuristic check |
| URL analysis (with ML) | <300ms | All | Including model inference |
| Message/text analysis | <200ms | Mobile, Web | NLP classification |
| Screenshot analysis | <500ms | Mobile | OCR + analysis |
| QR code scan + analysis | <300ms | Mobile | Decode + URL analysis |
| Browser page analysis | <200ms | Extension | DOM/content signals |
| File scan (small <1MB) | <500ms | Desktop | Signature + heuristic |
| File scan (large >100MB) | <10s | Desktop | Progressive scanning |
| Local AI inference | <500ms | All | Quantized model |
| Warning display | <50ms | All | After decision made |
| App startup | <2s | Mobile, Desktop | Cold start |
| Extension load | <500ms | Browser | Background ready |

## Measurement Methodology

*   **Percentiles:** Latency targets represent the **p95** (95th percentile) under normal operating conditions.
*   **Hardware Baseline:** Targets assume a mid-range device from the last 3-4 years (e.g., iPhone 12, Snapdragon 7-series, Intel Core i5 10th Gen).
*   **Testing Environments:** Benchmarks will be run across controlled, isolated environments simulating various network conditions (including complete offline mode) and system loads.

## Resource Budgets

### Mobile (iOS/Android)
*   **Memory:** < 150MB active, < 50MB background.
*   **CPU:** Spike to max during inference, < 2% sustained in background.
*   **Battery:** < 3% impact per 24 hours of standard usage.
*   **Storage (Model Size):** < 50MB (Quantized INT8/INT4 models).

### Desktop (Windows/macOS)
*   **Memory:** < 300MB active.
*   **CPU:** < 5% sustained during active scanning.
*   **Storage (Model Size):** < 200MB (Allows for slightly larger/more accurate models).

### Browser Extension
*   **Memory:** < 100MB per worker.
*   **Storage (Model Size):** < 20MB (WebAssembly/ONNX optimized).

## Background Processing Limits

*   Background tasks (e.g., background message scanning, passive file system monitoring) must yield to foreground applications.
*   Intensive background tasks (e.g., model updates, full system scans) should only occur when the device is charging or on unmetered Wi-Fi.

## Benchmarking & Regression Testing

*   **Automated Benchmarks:** CI/CD pipeline will include automated performance tests on every PR using standard test datasets.
*   **Thresholds:** Any commit causing a >5% regression in p95 latency on critical paths (URL analysis, extension load) will block deployment.
*   **Telemetry:** Anonymous, opt-in telemetry will monitor real-world p50 and p95 latencies to identify hardware-specific issues.

## Degradation Strategy

*   **Low Battery/Power Saving Mode:** System falls back to rule-based heuristics only; heavy ML models are suspended.
*   **High Thermal/CPU Load:** System queues non-critical analyses (e.g., background message scans) until load normalizes; real-time browser protection prioritizes speed over deep analysis.
*   **Offline State:** System relies entirely on local models and cached signatures, displaying an "Offline Mode" indicator on any warnings.
