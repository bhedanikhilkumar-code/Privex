# PHASE A — EMPIRICAL PERFORMANCE BASELINE (`docs/PHASE_A_PERFORMANCE_BASELINE.md`)

> **Phase:** Phase A — Antivirus Baseline + Security Core Hardening  
> **Document Type:** Empirical Performance Baseline & Resource Budget Verification  
> **Benchmark Suite:** `apps/desktop/src/__tests__/benchmarks/phase-a-baseline.test.ts`  
> **Status:** VERIFIED WITH REAL HARDWARE MEASUREMENTS

---

## 1. Benchmark Execution Environment

All measurements in this document were captured empirically on the local Windows endpoint via `apps/desktop/src/__tests__/benchmarks/phase-a-baseline.test.ts` using `node:perf_hooks` (`performance.now()`, `monitorEventLoopDelay({ resolution: 10 })`), `process.memoryUsage()`, and `process.cpuUsage()`:

| Environment Attribute | Value |
|---|---|
| **Operating System** | Windows 11 Home 64-bit (`Windows_NT 10.0.26300`, `win32 x64`) |
| **CPU** | 13th Gen Intel® Core™ i5-13420H (8 Physical Cores / 12 Logical Threads, 2.10 GHz base) |
| **System Memory** | 15.64 GB Physical RAM |
| **Runtime** | Node.js `v24.8.0` / V8, TypeScript `5.4.5`, Vitest `v4.1.3` |
| **Storage Subsystem** | Local NVMe SSD (`os.tmpdir()` isolated benchmark directory) |
| **Network State** | 100% Local / Offline Execution (Zero external socket calls) |

---

## 2. Measured Performance Baseline Summary

The table below records the real measured latency distributions (`min`, `p50`, `p95`, `max`, `avg`) across all 8 required Phase A performance metrics:

| # | Metric Category | Workload Specification | Min | Median (`p50`) | `p95` | Max | Mean (`avg`) | Phase A SLA Target | Status |
|---|---|---|---|---|---|---|---|---|---|
| **1a** | **Core Engine Startup (Cold)** | Cold `new DetectionPipeline()` initialization (rules, lexical, Bloom filter, file analyzer, risk scorer) | `2.870 ms` | `2.870 ms` | `2.870 ms` | `2.870 ms` | `2.870 ms` | `< 50.0 ms` | **PASS** |
| **1b** | **Core Engine Startup (Warm)** | Subsequent `new DetectionPipeline()` instantiations ($N=10$) | `0.420 ms` | `0.505 ms` | `0.772 ms` | `0.772 ms` | `0.531 ms` | `< 10.0 ms` | **PASS** |
| **1c** | **Desktop Service Graph Startup** | Full `new IpcHandler()` initialization (`SecureStorageService` PBKDF2 + AES-GCM state load + `QuarantineService` vault init + `ScannerService` + `DesktopSecurityAdapter`, $N=5$) | `45.363 ms` | `46.345 ms` | `58.141 ms` | `58.141 ms` | `48.004 ms` | `< 250.0 ms` | **PASS** |
| **2** | **Scanner Startup Overhead** | `new ScannerService()` instantiation + empty directory traversal startup ($N=20$) | `0.012 ms` | `0.016 ms` | `0.387 ms` | `0.387 ms` | `0.038 ms` | `< 15.0 ms` | **PASS** |
| **3** | **Small-File Scan (`1 KB`)** | Full on-disk `analyzeFile()` on `1,024 B` file (single `fd` open/stat, 64 KB bounded header read, Shannon entropy, streaming SHA-256, Core pipeline evaluation, $N=30$) | `1.120 ms` | `1.418 ms` | `2.369 ms` | `2.384 ms` | `1.542 ms` | `< 25.0 ms` | **PASS** |
| **4** | **Medium-File Scan (`1 MB`)** | Full on-disk `analyzeFile()` on `1,048,576 B` file (64 KB header inspection + full 1 MB streaming SHA-256 + Core pipeline evaluation, $N=15$) | `5.644 ms` | `6.282 ms` | `12.557 ms` | `12.557 ms` | `7.209 ms` | `< 100.0 ms` | **PASS** |
| **5** | **Large-File Scan (`25 MB`)** | Full on-disk `analyzeFile()` on `26,214,400 B` pseudo-random binary (`~255 MB/s` streaming SHA-256 + bounded 64 KB header read, $N=5$) | `83.484 ms` | `102.157 ms` | `116.855 ms` | `116.855 ms` | `98.039 ms` | `< 1,000.0 ms` | **PASS** |
| **6** | **Directory Scan (`100 files`)** | Recursive `ScannerService.scanDirectories()` across `100 files` in `10 nested subdirectories` (`95` clean files + `5` synthetic threat files: EICAR, disguised PE-in-PDF, double-extension `.pdf.exe`, $N=5$) | `187.782 ms` | `279.535 ms` | `340.336 ms` | `340.336 ms` | `264.894 ms` (`2.65 ms/file`) | `< 2,500.0 ms` | **PASS** |

---

## 3. Memory Usage Baseline

Memory telemetry was captured via `process.memoryUsage()` before, during, and after the full benchmark suite execution:

| Memory Measurement Point | Resident Set Size (`RSS`) | V8 `heapUsed` | Delta vs. Baseline | Architectural Verification |
|---|---|---|---|---|
| **Baseline (Pre-Scan)** | `81.54 MB` | `13.46 MB` | — | Well below the `< 150 MB` idle RSS ceiling (`AV-PERF-02`). |
| **25 MB Large-File Scan Heap Delta** | `89.40 MB` | `12.82 MB` | `-0.64 MB` (`< 25 MB` limit) | Confirms `DesktopFileAnalyzer` reads only a bounded `64 KB` header slice (`HEADER_SLICE_BYTES = 65,536`) and computes SHA-256 via `64 KB` streaming chunks (`createReadStream`) rather than buffering entire files in RAM. |
| **Post-Suite Final State (After 100-File Dir Scans)** | `91.71 MB` | `15.37 MB` | `+1.91 MB` Heap / `+10.17 MB` RSS | Confirms zero unbounded memory accumulation across repeated file and directory scans. |

---

## 4. CPU Usage & Event Loop Responsiveness Baseline

CPU time (`process.cpuUsage()`) and Node.js event loop delay (`monitorEventLoopDelay`) were measured continuously across the entire benchmark execution window:

| Metric | Measured Value | Target / Budget | Interpretation |
|---|---|---|---|
| **User CPU Time** | `375.0 ms` | — | User-space hashing, entropy calculation, and rule evaluation. |
| **System CPU Time** | `281.0 ms` | — | Kernel VFS descriptor open/stat/read operations on Windows NTFS. |
| **Active Single-Core CPU Utilization** | `49.53%` | `< 100%` (1 thread) | Single worker thread utilization during continuous back-to-back I/O + SHA-256 benchmarking. |
| **System-Normalized CPU Utilization (12 Logical Cores)** | `4.13%` | `< 25%` (`AV-PERF-03`) | Leaves `> 95%` total system CPU capacity free for foreground user applications. |
| **Event Loop Delay (`p50`)** | `10.10 ms` | `< 25.0 ms` | Non-blocking async I/O maintains responsive IPC handling during active scans. |
| **Event Loop Delay (`p95`)** | `11.67 ms` | `< 50.0 ms` | Zero UI/IPC starvation under 25 MB file + 100-file directory scan load. |
| **Event Loop Delay (`max`)** | `12.82 ms` | `< 100.0 ms` | Peak event loop tick remained under `13 ms`. |

---

## 5. Key Baseline Takeaways for Future Phases (`Phase B` – `Phase O`)

1. **Bounded Memory Confirmed:** Scanning a `25 MB` file incurs `-0.64 MB` net V8 heap delta because `DesktopFileAnalyzer` strictly bounds in-memory header inspection to `64 KB` and streams SHA-256 in `64 KB` chunks.
2. **Fast Per-File Throughput:** Small files (`1 KB`) scan in `1.42 ms` (`p50`), and `100` mixed files across `10` subdirectories scan in `279.5 ms` (`2.65 ms/file`), detecting all `5/5` seeded threats with `0` false positives.
3. **Phase O Optimization Targets Identified:**
   - Full-file streaming SHA-256 dominates `25 MB` scan time (`~102 ms`). Introducing the `CleanFileCache` keyed by `(volume_serial, file_id, file_size, mtime_ns, db_version)` in **Phase B / Phase O** will reduce repeat scans of unmodified files from `1.42 ms–102 ms` down to `< 0.05 ms`.
   - Offloading synchronous `PBKDF2` (`100,000` iterations, `~42 ms` during cold `SecureStorageService` startup) and batch directory hashing to the dedicated worker pool in **Phase O** will reduce main-thread startup time below `10 ms`.
