# Phase T9 Architecture: Mobile Threat Intelligence (.ppdb)

## 1. Architectural Mission & Invariants

Phase T9 establishes the on-device **Mobile Threat Intelligence** subsystem for Private Protection (Privex).

### Core Invariants:
1. **100% Offline Parity**: Local threat indicators (SHA-256 malware hashes, malicious domains, and typed rules) are stored and evaluated entirely on-device via `.ppdb` SQLite and in-memory hash sets.
2. **Cryptographic Rigor**: All threat database delta updates require Ed25519 signatures and SHA-256 payload digest verification. The signature commits to canonical string: `targetSequence:formatVersion:sha256`.
3. **Fail-Closed Trust Anchor**: An all-zero placeholder key (`0000...`) or unconfigured key MUST fail closed with `UNCONFIGURED_TRUST_KEY`. Test-only keys are strictly segregated and rejected in production mode (`TEST_KEY_REJECTED`).
4. **Strict Monotonic Anti-Downgrade**: Replay attacks and sequence downgrades (`targetSequence <= currentSequence`) are unconditionally blocked with `DOWNGRADE_OR_REPLAY_REJECTED`.
5. **Zero-Knowledge Privacy**: User browsing history, URLs, and file payloads never leave the device. Only indicators and local hashes are compared in memory.
6. **Atomic Staging & Rollback**: Updates are staged in isolated SQLite transactions. Any validation or integrity check failure triggers a rollback to the Last Known Good (LKG) or immutable Factory Seed.

---

## 2. Subsystem Topology & Integration Points

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ANDROID MOBILE PLATFORM                         │
│                                                                        │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │   WebShieldService    │             │ UniversalFileShieldService │  │
│  │ (DNS & URL Screening) │             │ (Download & Archive Audit) │  │
│  └───────────┬───────────┘             └─────────────┬──────────────┘  │
│              │                                       │                 │
│              │                                       │                 │
│              ▼                                       ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │           MobileThreatDatabase (@privateprotection/shield)       │  │
│  │                                                                  │  │
│  │  • Fast volatile memory lookup (<0.05 ms):                       │  │
│  │      - inMemoryBadHashes (ConcurrentHashMap)                     │  │
│  │      - inMemoryBadDomains (ConcurrentHashMap)                    │  │
│  │  • Persistent SQLite storage:                                    │  │
│  │      - threat_records (indicator, type, name, severity, etc.)    │  │
│  │      - threat_metadata (version, sequence, feed, digest)         │  │
│  │  • Factory Seed (EICAR, Synthetic trojan/ransomware, Phish seeds)│  │
│  │  • Ed25519 Native Java Signature & SHA-256 Digest Verification   │  │
│  │  • DatabaseChangeListener -> Invalidate Web/File Caches          │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      MainActivity JS Bridge                      │  │
│  │  • getThreatDatabaseMetadata()                                   │  │
│  │  • applyThreatDatabaseSignedUpdate(bundleJson, keyOverride)      │  │
│  │  • rollbackThreatDatabaseToFactorySeed()                         │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
└─────────────────────────────────────┼──────────────────────────────────┘
                                      │ IPC Bridge
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     TYPESCRIPT UI / WEBVIEW LAYER                      │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │               MobileThreatIntelService (Singleton)               │  │
│  │  • inspectDatabaseHealth() (Calculates freshness & staleness)    │  │
│  │  • applySignedUpdate()                                           │  │
│  │  • rollbackToFactorySeed()                                       │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │      ProtectionStatusScreen & Diagnostics UI                     │  │
│  │  • Live indicator count, sequence number, feed source           │  │
│  │  • Staleness indicator (FRESH <= 7d, AGED <= 30d, STALE > 30d)   │  │
│  │  • Factory Seed status and one-click Safe Rollback               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Bundle Protocol Specification

### Format: `PPDB_V1`
```json
{
  "manifest": {
    "targetSequence": 105,
    "targetVersion": "1.0.5",
    "formatVersion": "PPDB_V1",
    "publishedAt": 1728000000000,
    "recordsCount": 2,
    "sha256": "4b5d6e...",
    "ed25519Signature": "1a2b3c...",
    "sourceFeed": "OFFICIAL_PRIVEX_INTEL"
  },
  "payload": {
    "addRecords": [
      {
        "indicator": "malicious-domain.com",
        "type": "DOMAIN",
        "threatName": "PHISH_SAMPLE",
        "category": "PHISHING",
        "severity": "HIGH",
        "isCritical": false
      }
    ],
    "removeIndicators": []
  }
}
```

### Verification Pipeline:
1. Check bundle format and mandatory JSON fields.
2. Check trust anchor key against `PLACEHOLDER_ZERO_KEY` and segregated test keys.
3. Verify monotonic sequence: `targetSequence > activeSequence`.
4. Check Ed25519 signature on canonical message string: `${targetSequence}:${formatVersion}:${sha256}`.
5. Verify SHA-256 payload digest matches `manifest.sha256`.
6. Enforce payload record count limit (max 20,000 items).
7. Apply updates atomically inside SQLite transaction.
8. Re-warm fast in-memory concurrent lookup maps.
9. Dispatch `DatabaseChangeListener` notifications to invalidate cached DNS / file verdicts.
