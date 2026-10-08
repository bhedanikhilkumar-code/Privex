# Backend Architecture: Privex

The PRIVEX backend is strictly **OPTIONAL**. The core product operates entirely on-device with zero reliance on cloud connectivity. The backend exists solely to improve detection quality over time, distribute updates, and provide a web dashboard for manual analysis.

## 1. Core Principles
- **Optionality:** Client apps must function 100% offline.
- **Data Minimization:** Only collect what is absolutely necessary.
- **Zero-Trust:** Do not trust client payloads; sanitize and validate strictly.

## 2. Services Overview

### 2.1. Threat Intelligence Feed Service
Aggregates known-bad URLs, domains, and patterns from third-party APIs and internal analysis, distributing them to clients as optimized, compressed files (e.g., Bloom filters, SQLite diffs).
- **API Boundary:** `GET /api/v1/feeds/latest`
- **Auth:** API Key (for rate limiting, not user identity)
- **Rate Limiting:** 1 request per hour per client IP.
- **Offline Fallback:** Client uses last downloaded cache.

### 2.2. Model & Rule Distribution Service
Provides OTA (Over-The-Air) updates for on-device ML models and deterministic rules.
- **API Boundary:** `GET /api/v1/models/{platform}/latest`
- **Security:** Artifacts are signed with Ed25519; clients verify signatures before loading.

### 2.3. Anonymous Telemetry Service (Opt-in)
Collects aggregated, non-identifiable data on threat trends (e.g., "Rule X fired 1000 times today").
- **API Boundary:** `POST /api/v1/telemetry/report`
- **Data Minimization:** No IP logging. No raw URLs. Only hashes and rule IDs.
- **Auth:** Anonymous. Uses a Proof-of-Work challenge to prevent spam/DDoS.

### 2.4. Manual Scan API (Web Dashboard)
Allows users to manually paste URLs/text into a web dashboard for cloud-based deep analysis (using heavier models not suitable for on-device).
- **API Boundary:** `POST /api/v1/scan/deep`
- **Input Validation:** Strict length limits, malicious payload stripping.
- **Privacy:** Data processed in memory and immediately discarded. No logging.

### 2.5. User Account Service (Web Dashboard Only)
Manages optional premium subscriptions and syncs allowlists (E2E encrypted).
- **Auth:** OAuth2 / OIDC.
- **Data:** User identities are isolated from telemetry and threat reports.

## 3. Infrastructure & Security Controls
- **API Gateway:** Handles rate limiting, WAF, and SSL termination.
- **Stateless Services:** All services run as scalable containers (e.g., Kubernetes or Serverless).
- **Error Handling:** Standardized RFC 7807 problem details. Always return 200 OK for telemetry (fire-and-forget) to prevent information leakage.
- **API Versioning:** URI-based versioning (`/api/v1/`).
