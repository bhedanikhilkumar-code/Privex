# Performance Contract & Latency Budgets: PRIVEX

## 1. Overview & Performance Doctrine

Cybersecurity software that degrades host system performance, freezes user input, or drains battery will inevitably be disabled by users.

PRIVEX treats performance as a foundational security feature. Every critical path must conform to strict, measurable latency budgets validated on target hardware.

---

## 2. Measurable Performance Target Matrix

| Critical Operation | Target Latency (SLA) | Measurement Method | Target Hardware / Platform | Acceptable Degradation Limits |
|---|---|---|---|---|
| **URL Detection (Fast-Path Rules)** | **$p50 < 0.2\text{ms}$**<br>**$p95 < 1.0\text{ms}$**<br>*(Hard SLA: $<100\text{ms}$)* | High-resolution wall-clock timer (`performance.now()`) on parsed URL | Mid-tier mobile (Snapdragon 7-series) & Desktop (x86_64 / ARM64) | Under high CPU contention (80%+ load), maximum allowed latency is $10.0\text{ms}$. |
| **URL Detection (Full Heuristic + Bloom Filter)** | **$p50 < 1.0\text{ms}$**<br>**$p95 < 5.0\text{ms}$** | Wall-clock timer over entropy + Levenshtein + Bloom filter check | All supported client platforms (Chromium, Firefox, Mobile, Desktop) | On low-end mobile devices (4GB RAM), maximum allowed latency is $25.0\text{ms}$. |
| **Message / Text Scan (Regex + Lexical)** | **$p50 < 0.5\text{ms}$**<br>**$p95 < 2.0\text{ms}$**<br>*(Hard SLA: $<200\text{ms}$)* | Wall-clock execution time on 1,000-character test SMS payload | Android background service & iOS extension | On payloads approaching the 10,000-character ceiling, maximum latency is $50.0\text{ms}$. |
| **Browser Pre-Navigation Warning Rendering** | **$p50 < 20.0\text{ms}$**<br>**$p95 < 50.0\text{ms}$** | Time from `webNavigation.onBeforeNavigate` event to Shadow DOM paint | Chromium / Firefox extension hosts | In low-memory worker cold-start conditions, maximum allowed paint latency is $100.0\text{ms}$. |
| **Local AI Inference (Intent Classification)** | **$p50 < 30.0\text{ms}$**<br>**$p95 < 80.0\text{ms}$** | Inference forward pass duration on quantized INT8 ONNX/TFLite model | Desktop (CPU/GPU) & Mobile (NPU/NNAPI/CoreML) | On pure CPU fallback without hardware acceleration, maximum allowed latency is $250.0\text{ms}$. |
| **Local AI Assistant (SLM First Token)** | **$p50 < 200.0\text{ms}$**<br>**$p95 < 400.0\text{ms}$** | Time-to-First-Token (TTFT) on 1–3B INT4 quantized model | Desktop & Flagship Mobile (Apple A16+, Snapdragon 8 Gen 2+) | On constrained devices, gracefully degrades to deterministic template engine ($<1.0\text{ms}$). |
| **Local File Inspection (Header + Entropy)** | **$p50 < 5.0\text{ms}$**<br>**$p95 < 20.0\text{ms}$** | Time to read first 4KB, compute SHA-256 and header entropy | Windows Service / macOS launchd daemon on NVMe SSD | Under mechanical HDD storage, maximum allowed read latency is $100.0\text{ms}$. |
| **Application Cold Startup** | **$p50 < 300\text{ms}$**<br>**$p95 < 800\text{ms}$** | Process launch time to main UI interactive / background hook active | All desktop and mobile client platforms | Cold start on budget devices must never exceed $1,500\text{ms}$. |

---

## 3. Platform Resource Ceilings

To preserve device battery and responsiveness, client processes must strictly observe these resource caps:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           PLATFORM RESOURCE CEILINGS                            │
│                                                                                 │
│   MOBILE APP (Android / iOS):                                                   │
│   • Background RAM: < 50 MB                                                     │
│   • Active Foreground RAM: < 150 MB (excluding optional local SLM)              │
│   • Sustained Battery Drain: < 3.0% of daily battery consumption                │
│                                                                                 │
│   DESKTOP SECURITY SOFTWARE (Windows / macOS):                                  │
│   • Idle Background Service RAM: < 80 MB                                        │
│   • Active Scanning RAM: < 300 MB                                               │
│   • Sustained CPU Utilization: < 1.0% idle; < 5.0% during background scanning   │
│                                                                                 │
│   BROWSER EXTENSION (Chrome / Edge / Firefox):                                  │
│   • Background Service Worker RAM: < 100 MB                                     │
│   • Injected Content Script RAM Overhead: < 5 MB per tab                        │
│   • WASM Compiled Memory Allocation: Fixed 16 MB heap cap                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Performance Degradation & Fallback Strategy

When a host device enters resource-constrained states:
1. **Battery Saver Mode Active**: Suspension of background model warming; deferral of OTA update checks; detection engine switches entirely to the sub-millisecond deterministic rule engine.
2. **Low Memory Warning (OS `onLowMemory` / OOM pressure)**: Eviction of cached inference sessions from RAM; immediate fallback to template-based explanation synthesis; Bloom filter retainment via read-only memory mapping (`mmap`).
3. **Slow Storage / Disk Throttling**: File scanner restricts analysis to the first 4KB header buffer rather than traversing deep archive contents.
