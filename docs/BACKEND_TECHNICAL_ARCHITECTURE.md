# BACKEND_TECHNICAL_ARCHITECTURE.md — Stateless Cloud Edge & Privacy Relay

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION BACKEND ARCHITECTURE**  
> This document specifies the optional, stateless cloud edge infrastructure of PRIVATE PROTECTION. It defines the strict operational boundaries, Oblivious HTTP relays, update distribution endpoints, rate limiting, and constitutional data prohibitions.

---

## 1. THE FOUNDATIONAL BACKEND PRINCIPLES

1. **Stateless by Design**: The backend maintains **ZERO USER DATABASES**, zero persistent user accounts, zero session trackers, and zero browsing history logs.
2. **Distribution & Relay Only**: The backend serves exactly two legitimate functions:
   - *Function 1*: Distributing static, Ed25519-signed threat intelligence Bloom filter delta files and software releases via a global CDN.
   - *Function 2*: Decoupling client IP addresses from opt-in anonymous statistical telemetry via an Oblivious HTTP (OHTTP RFC 9458) relay.
3. **Zero-Knowledge Architecture**: The backend is architected so that even if it is completely subpoenaed, seized, or compromised by an adversary, it contains zero private user communications or browsing histories.

---

## 2. STRICT ARCHITECTURAL PROHIBITIONS

The backend is **CONSTITUTIONALLY FORBIDDEN** from ever receiving, accepting, or logging:
- ❌ Raw, unhashed user URLs or browsing navigation paths.
- ❌ Raw user text messages, chat transcripts, or emails.
- ❌ Uploaded user files, document bytes, or binary attachments.
- ❌ Client IP addresses paired with decrypted telemetry payloads.
- ❌ Persistent device hardware identifiers (IMEI, MAC, Advertising IDs).
- ❌ User identity tokens or third-party authentication tokens.

Any pull request or architectural change attempting to introduce an API endpoint accepting raw user payloads will be automatically rejected.

---

## 3. BACKEND SERVICE TOPOLOGY

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     GLOBAL EDGE INFRASTRUCTURE                                         │
│                                                                                                        │
│   ┌──────────────────────────────────────────────┐    ┌────────────────────────────────────────────┐   │
│   │ SERVICE 1: STATIC UPDATE CDN                 │    │ SERVICE 2: OBLIVIOUS HTTP (OHTTP) RELAY    │   │
│   │ (Cloudflare R2 / AWS CloudFront / Fastly)    │    │ (Independent Edge Worker / RFC 9458)       │   │
│   │ • Serves /manifest.json                      │    │ • Terminates Client TLS Connection         │   │
│   │ • Serves /patches/*.bf.patch                 │    │ • Strips Client IP & User-Agent            │   │
│   │ • Serves /rules/*.json.enc                   │    │ • Forwards Opaque HPKE Blob to Aggregator  │   │
│   │ • 100% Static GET requests                   │    │ • Cannot decrypt payload contents          │   │
│   └──────────────────────────────────────────────┘    └─────────────────────┬──────────────────────┘   │
│                                                                             │                          │
│                                                                             │ Forward Encrypted Blob   │
│                                                                             ▼                          │
│                                                       ┌────────────────────────────────────────────┐   │
│                                                       │ SERVICE 3: TELEMETRY AGGREGATOR COLLECTOR  │   │
│                                                       │ (Isolated Private Edge Target)             │   │
│                                                       │ • Holds HPKE Private Key                   │   │
│                                                       │ • Decrypts anonymous rule counters         │   │
│                                                       │ • ZERO IP VISIBILITY (Sees only relay IP)  │   │
│                                                       │ • Applies Differential Privacy filters     │   │
│                                                       └────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. API CONTRACTS & ENDPOINT SPECIFICATIONS

All endpoints enforce API versioning under the `/v1/` route prefix:

---

### Endpoint 1: `GET /v1/updates/manifest.json`
- **Purpose**: Returns the latest cryptographic manifest describing available Bloom filter and rule updates.
- **Request Headers**:
  - `Accept: application/json`
  - `If-None-Match: "<version_etag>"` (Optional cache header)
- **Response Structure (200 OK)**:
  ```json
  {
    "version": 105,
    "timestampEpoch": 1775088000,
    "minEngineVersion": 1,
    "artifacts": {
      "bloomFilter": {
        "fullHash": "a1b2c3d4e5...",
        "fullUrl": "https://cdn.private-protection.org/v1/bloom/full_105.bf",
        "fullSizeBytes": 3450000,
        "deltaPatches": [
          {
            "fromVersion": 104,
            "patchHash": "f8e7d6...",
            "patchUrl": "https://cdn.private-protection.org/v1/bloom/diff_104_to_105.bf.patch",
            "patchSizeBytes": 420000
          }
        ]
      }
    },
    "ed25519Signature": "9a8b7c6d5e4f..."
  }
  ```
- **Rate Limiting**: Cached aggressively at CDN edge; 60 requests per minute per IP.
- **Data Logged**: Standard CDN access logs (IP, timestamp, byte count) with 48-hour automated deletion.

---

### Endpoint 2: `POST /v1/telemetry/relay` (Oblivious HTTP Relay)
- **Purpose**: RFC 9458 Oblivious HTTP entry point. Receives Hybrid Public Key Encrypted (HPKE) payloads.
- **Request Body**: Binary `application/ohttp-req` blob.
- **Relay Processing**:
  1. Validates encapsulation header.
  2. Strips client IP address and all client HTTP headers.
  3. Re-encapsulates request and forwards to private Telemetry Aggregator.
- **Response Body**: Binary `application/ohttp-res` response returned to client.
- **Security & Privacy**: The Relay cannot read the inner payload because it lacks the Collector's private HPKE key. The Collector cannot learn the Client IP because all requests arrive from the Relay's internal IP.

---

## 5. RATE LIMITING, ABUSE PREVENTION & INFRASTRUCTURE MONITORING

1. **Edge Rate Limiting**:
   - Implemented via Cloudflare Edge Rules: 120 requests / minute per IP on update endpoints; 10 requests / minute on telemetry relay.
   - Excessive requests return `HTTP 429 Too Many Requests` with a `Retry-After: 300` header.
2. **DDoS Protection**:
   - Managed CDN Layer 3/4/7 DDoS mitigation.
   - Any volumetric attack is absorbed at edge nodes without impacting availability of cached local client software.
3. **Zero Persistent PII Logging**:
   - Web server logs disable logging of Query Strings, Referrer headers, and full User-Agent strings.
   - Logs are rotated every 24 hours and permanently purged within 48 hours.
