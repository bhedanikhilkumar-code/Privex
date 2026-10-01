# Offline-First Architecture

## Overview
PRIVATE PROTECTION is fundamentally designed to operate with zero internet connectivity. All critical threat detection occurs locally on the device to guarantee absolute privacy and zero-latency analysis. 

## ONLINE vs OFFLINE Capabilities

| Feature | Online Behavior | Offline Behavior |
| :--- | :--- | :--- |
| **URL/Phishing Detection** | Local check + optional Cloud validation (if low confidence) | 100% Local (Regex, Heuristics, Bloom Filter) |
| **SMS/Message Scanning** | Local ML inference | Local ML inference (Fully available) |
| **File Scanning** | Local heuristics + Cloud Hash Lookup | Local heuristics & YARA rules only |
| **Security AI Chat** | Local SLM or Cloud LLM fallback | Quantized Local SLM only |
| **Threat Intel** | Auto-fetches latest signatures hourly | Uses last cached signatures |

## 1. Storage and Execution

### ML Models
- **Mobile:** Uses Int8 quantized models (TFLite/CoreML) optimized for size (<50MB). Loaded into RAM on service startup.
- **Desktop:** Can utilize larger, more accurate fp16 ONNX models (<500MB).
- **Browser Ext:** Tiny WASM-compatible models (<10MB) focusing strictly on DOM/URL analysis.

### Detection Rules & Threat Intel
- Stored using **Bloom Filters** for extreme space efficiency (millions of malicious URLs fit in a few Megabytes).
- Exact match databases (hashes) are stored in an encrypted local SQLite database.

## 2. Update Mechanism

### Fetching & Applying Updates
1. **Delta Updates:** To conserve bandwidth, the backend generates binary diffs (using tools like `bsdiff`) of Bloom filters and SQLite databases.
2. **Polling:** The Configuration & Update System polls the API Gateway periodically.
3. **Application:** Updates are downloaded to a temporary partition, verified, and then swapped atomically into production to prevent corruption.

### Verification & Integrity
- All updates (models, rules, threat intel) are cryptographically signed using Ed25519.
- The client verifies the signature against a public key pinned in the application binary before applying.

## 3. Staleness & Graceful Degradation

### Staleness Handling
- **< 24 Hours:** Normal operation.
- **> 7 Days:** The UI surfaces a yellow warning: "Threat definitions are outdated. Please connect to the internet to update."
- **> 30 Days:** The UI surfaces a red warning. Detection engine increases reliance on behavioral/ML heuristics since exact-match signatures are stale.

### Graceful Degradation
When offline, features that strictly require cloud compute (like querying a multi-billion parameter LLM for advanced phishing analysis) gracefully degrade to local Small Language Models (SLMs). If the SLM confidence is low, the system errs on the side of caution (warning the user of uncertainty).

### Sync Strategy When Online
Upon detecting network restoration:
1. **Prioritize Intel:** Immediately fetch the latest threat intel Bloom filter.
2. **Telemetry (Opt-in):** Flush any queued anonymous telemetry metrics.
3. **Background Updates:** Silently update ML models if significant architectural upgrades are available (respecting metered connections).

## 4. Storage Budgets

| Platform | Threat Intel (Rules/Hashes) | ML Models | App Core |
| :--- | :--- | :--- | :--- |
| **Mobile** | < 20 MB (Aggressive pruning) | < 50 MB | < 30 MB |
| **Desktop** | < 100 MB | < 500 MB | < 100 MB |
| **Browser Ext** | < 5 MB (Bloom filters only) | < 10 MB | < 5 MB |

*Mobile uses aggressive pruning, removing signatures of domains inactive for >30 days, while Desktop retains longer historical data.*
