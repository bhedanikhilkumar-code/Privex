# Data Architecture: Privex

The PRIVEX system is designed with a privacy-first, offline-first architecture. This document defines the data models used across local clients, optional backend services, and the formats for threat intelligence and detection results.

## 1. Data Classification Principles

To ensure privacy, all data is strictly categorized:
- **Sensitive User Content (Local Only):** Raw SMS messages, emails, clipboard text, browsing history, private URLs, QR code content. **NEVER** transmitted to any backend, stored beyond immediate memory processing, or logged to disk, except explicitly authorized caching by the user (which remains encrypted locally).
- **Security Metadata (Can be Reported/Stored):** Computed risk scores, anonymized domain names (e.g., hashed or sanitized), matched rule IDs, telemetry counters, time-to-process. Can be sent to the optional backend if the user explicitly opts in.

## 2. Local Data Models (Per Platform)
Stored locally on the user's device (IndexedDB for Web/Extension, SQLite/CoreData for Mobile/Desktop).

### 2.1. Security History & Scan Results
- `id`: UUID
- `timestamp`: ISO8601 DateTime
- `input_type`: Enum (URL, TEXT, FILE, QR)
- `risk_score`: Float (0.0 to 1.0)
- `action_taken`: Enum (BLOCKED, WARNED, ALLOWED, IGNORED)
- `rule_matches`: Array of Rule IDs
- *Note: Raw input is scrubbed after analysis and not stored here.*

### 2.2. User Preferences
- `auto_block_threshold`: Float (default 0.8)
- `telemetry_opt_in`: Boolean (default false)
- `custom_allowlist`: Array of strings (Domains/Patterns)
- `custom_denylist`: Array of strings

### 2.3. Cached Threat Intelligence
- `feed_version`: String
- `last_updated`: ISO8601 DateTime
- `signatures`: Blob/Local Table representation of known-bad patterns.

### 2.4. Model Metadata
- `model_id`: String
- `version`: String
- `architecture`: String
- `quantization`: String (e.g., INT8)
- `last_updated`: ISO8601 DateTime

## 3. Detection Results Schema
Generated in-memory by the shared detection engine.

```json
{
  "scan_id": "uuid-v4",
  "timestamp": "2023-10-24T12:00:00Z",
  "input_type": "URL",
  "risk_score": 0.95,
  "confidence": 0.88,
  "evidence": [
    {
      "type": "HEURISTIC",
      "name": "typosquatting",
      "description": "Domain mimics 'paypal.com'"
    },
    {
      "type": "ML_MODEL",
      "name": "phishing_classifier_v2",
      "description": "High probability of credential harvesting layout"
    }
  ],
  "explanation": "This link appears to be imitating PayPal to steal your login credentials.",
  "recommended_action": "BLOCK"
}
```

## 4. Threat Intelligence Representation
Used for local matching. Distributed as compressed, optimized databases (e.g., Bloom filters, optimized SQLite).

- **URL Reputation Entries:**
  - `domain_hash`: SHA256 of the domain
  - `risk_category`: Enum (PHISHING, MALWARE, SCAM)
  - `ttl`: Integer (seconds to live)
- **Known-Bad Patterns (Rules):**
  - `rule_id`: String
  - `regex_pattern`: String (Optimized RE2 compatible)
  - `severity`: Integer (1-10)

## 5. Optional Backend Data Models
Stored in the cloud backend for telemetry and threat intelligence distribution.

- **Anonymous Threat Reports:**
  - `report_id`: UUID
  - `anonymized_domain_hash`: String
  - `matched_rules`: Array of Strings
  - `country_code`: String (for regional threat tracking)
- **Aggregated Statistics:**
  - `date`: Date
  - `total_blocks`: Integer
  - `active_users`: Integer (Estimated via anonymous pings)
- **User Accounts (Optional for Web Dashboard only):**
  - `user_id`: UUID
  - `email_hash`: String
  - `subscription_tier`: String
