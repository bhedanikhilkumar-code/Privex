# System Architecture

## High-Level Architecture Overview

PRIVATE PROTECTION employs a localized, privacy-first, edge-computing architecture. The core logic relies on a **Shared Detection Engine** deployed across multiple front-end clients, backed by an optional backend for threat intelligence updates.

```mermaid
flowchart TD
    subgraph Clients
        Mobile[Mobile App (Android/iOS)]
        Desktop[Desktop Client (Electron/Native)]
        Ext[Browser Extension (Manifest V3)]
        Web[Web Application]
    end

    subgraph Core["Shared Detection Engine (C++/Rust/WASM)"]
        RuleEngine[Rule Engine]
        ML[ML/AI Inference Layer]
        ThreatIntel[Threat Intelligence Layer]
        
        subgraph Analyzers
            URL[URL Analyzer]
            Msg[Message Analyzer]
            File[File Analyzer]
            Content[Content Analyzer]
        end
        
        RiskScore[Risk Scoring Engine]
        Explanation[Explanation Engine]
    end
    
    subgraph LocalSystem["Local Device Services"]
        Storage[Local Storage / SQLite]
        Alerts[Alert & Notification System]
        ModelMgmt[Model Management System]
        Config[Configuration & Update]
    end

    subgraph Cloud["Backend (Optional / Minimal)"]
        API[API Gateway]
        ThreatFeeds[Threat Feed Aggregation]
        Telemetry[Anonymous Telemetry]
        ModelRegistry[Model & Rule Registry]
    end

    Clients <--> Core
    Core <--> LocalSystem
    LocalSystem <-- "Update Sync (HTTPS)" --> Cloud
```

## Component Details

### 1. Client Applications
- **Mobile Client (Kotlin/Swift):** Integrates the Shared Detection Engine via JNI/C-Interop. Handles OS-specific APIs for SMS, Notifications, and Camera.
- **Desktop Client (Tauri/Electron + Rust/C++):** Interfaces natively with the engine. Hooks into OS file systems for continuous monitoring.
- **Browser Extension (Manifest V3 - Chrome/Firefox/Edge):** Uses WebAssembly (WASM) to run the Shared Engine directly in the browser. Uses Service Workers to intercept URLs and inject warning banners.
- **Web Application (React/Next.js):** Provides user portal and account settings.

### 2. Shared Detection Engine
Compiled to native code for Desktop/Mobile and WASM for the Browser.
- **Rule Engine:** Executes deterministic Yara/Snort-style rules and regex for immediate, low-cost matching.
- **ML/AI Inference Layer:** Runs quantized models (e.g., TFLite, ONNX) for NLP and image analysis.
- **Threat Intelligence Layer:** Fast lookups against local Bloom filters or SQLite caches of known malicious hashes.
- **Analyzers:** Specialized modules parsing raw inputs (URLs, text, bytes, images).
- **Risk Scoring Engine:** Aggregates outputs from the Rule Engine, ML Layer, and Analyzers to produce a final confidence score (0.0 to 1.0).
- **Explanation Engine:** Translates raw scores and activated rules into human-readable warnings (e.g., "This URL mimics your bank").

### 3. Local Device Services
- **Local Storage Layer:** Encrypted SQLite for logs, history, and user settings.
- **Alert/Notification System:** Bridges the engine to OS-native notification APIs.
- **Model Management System:** Handles versioning and loading of ML weights into memory.
- **Configuration & Update System:** Periodically polls the Backend for delta updates to rules and threat intel.

### 4. Optional Backend
- **Threat Feed Aggregation:** Pulls data from PhishTank, VirusTotal, etc., and compiles highly compressed Bloom filters.
- **API Gateway:** Secure HTTPS endpoints for update polling.
- **Anonymous Telemetry:** (Opt-in only) Collects aggregated metrics on false positives/negatives without PII.

## Data Flow (Suspicious URL Example)
1. **Intercept:** Browser Extension detects a navigation event.
2. **Rule Check:** URL is passed to the WASM Shared Engine -> Rule Engine.
3. **ML Check:** If rules miss, ML Inference analyzes the domain structure and page content.
4. **Scoring:** Risk Scoring Engine calculates high risk.
5. **Action:** Extension injects an overlay blocking the page and rendering an explanation via the Explanation Engine.
