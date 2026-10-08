# Phase I — Automatic Response Ladder & False-Positive Exclusion Management Architecture

## 1. Executive Summary

Phase I establishes the autonomous threat mitigation policy and user-governed false-positive resolution system for the Privex Windows Desktop Antivirus. It solves two critical operational requirements:
1. **Deterministic, Non-Dilutable Response Ladder**: Transforming multi-factor threat detection telemetry into proportional, automated security interventions without user fatigue or unsafe mitigation dilution.
2. **Hardened 3-Tier False-Positive Exclusion Management**: Providing granular, secure user overrides (`HASH`, `PATH`, `DOMAIN`) shielded by cryptographic persistence, anti-abuse guardrails, mandatory domain TTLs, and cryptographic non-bypassability during ransomware or canary trip events.

---

## 2. Five-Tier Automatic Response Ladder (`ResponsePolicyEngine`)

### 2.1 Ladder Mapping & Deterministic Policy Invariants

The `ResponsePolicyEngine` strictly maps threat posture attributes `(riskScore, severity, verdict, confidence, isProtectedSystemBinary)` to the five discrete response tiers:

```
┌──────────────────────┬────────────┬─────────────┬───────────┬─────────────────────────┬──────────────────────────┐
│ Tier                 │ Risk Score │ Severity    │ Verdict   │ Action                  │ Execution Behavior       │
├──────────────────────┼────────────┼─────────────┼───────────┼─────────────────────────┼──────────────────────────┤
│ LOW                  │ 0 – 34     │ safe / low  │ ALLOW     │ LOG_ONLY                │ Silent local audit log   │
│ MEDIUM               │ 35 – 69    │ medium      │ SUSPICIOUS│ WARN_USER               │ Non-modal advisory toast │
│ HIGH                 │ 70 – 89    │ high        │ SUSP/WARN │ HOLD_QUARANTINE         │ Quarantine staging + modal│
│ CRITICAL             │ 90 – 100   │ critical    │ BLOCK     │ AUTO_QUARANTINE         │ Immediate PPVAULT2 lock  │
│ RANSOMWARE_BEHAVIOR  │ 90 – 100   │ critical    │ BLOCK     │ CONTAIN_AND_ROLLBACK    │ Process Kill + Rollback  │
└──────────────────────┴────────────┴─────────────┴───────────┴─────────────────────────┴──────────────────────────┘
```

### 2.2 Response Ladder Invariants
1. **Ransomware Inviolability**: If `isRansomwareIncident` or `isCanaryTamper` is detected, the ladder evaluates directly to `RANSOMWARE_BEHAVIOR` (`action: CONTAIN_AND_ROLLBACK`). User exclusions or allowlists CANNOT suppress or downgrade this tier under any circumstance.
2. **System Binary Protection (RULE-09)**: If `isProtectedSystemBinary` is flagged, process containment is prohibited (`containProcess: false`, `requiresConfirmation: true`), preventing OS instability from rogue termination of critical Windows binaries (`csrss.exe`, `lsass.exe`, `services.exe`).
3. **Deterministic Evaluation**: Policy decisions are pure functions executed in $<0.01\text{ ms}$, ensuring zero impact on real-time event loops.

---

## 3. Three-Tier False-Positive Exclusion Manager (`ExclusionManagerService`)

### 3.1 Exclusion Types & Scopes

```
┌──────────┬──────────────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Type     │ Canonical Format                         │ Validation & Anti-Abuse Guardrails                     │
├──────────┼──────────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ HASH     │ 64-char lowercase hexadecimal SHA-256    │ Exact hash match; immune to path renaming / symlinks   │
│ PATH     │ Canonical resolved Windows path (no wild)│ Path prefix/exact match; forbidden system folder blocks│
│ DOMAIN   │ Lowercase FQDN (RFC 1123, no wildcards)  │ Hostname check; mandatory TTL (default 7 days)         │
└──────────┴──────────────────────────────────────────┴────────────────────────────────────────────────────────┘
```

### 3.2 Anti-Abuse Guardrails (Forbidden Exclusion Targets)
To prevent malware or adversaries from blinding the antivirus via broad exclusions, `ExclusionManagerService` enforces:
- **Wildcard Prohibition**: Wildcard characters (`*`, `?`) in paths and domains are rejected outright.
- **Forbidden System Roots**: Exclusions targeting entire root drives (`C:\`), Windows system directories (`C:\Windows`, `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Program Files`, `C:\Program Files (x86)`), user profiles (`C:\Users\username`), browser/user temp directories (`%TEMP%`, `%APPDATA%`), or user Downloads folders (`C:\Users\username\Downloads`) are blocked with `SECURITY_VIOLATION`.
- **Domain Guardrails**: IP addresses, `localhost`, `.local`, `.internal`, URL schemes (`http://`), paths, and directional override Unicode control characters (`\u202E`) are rejected.
- **Mandatory Domain TTL**: Domain exclusions cannot be permanent; they default to 7 days (maximum 365 days) and are automatically pruned on boot and access.

---

## 4. Cryptographic Storage & Crash Recovery

### 4.1 AES-256-GCM Encrypted Persistence
- **Storage Target**: `exclusions.enc` located in encrypted local config storage.
- **Key Derivation**: PBKDF2-SHA256 (100,000 iterations) salted with unique per-machine entropy (`.storage.salt`).
- **Atomic Writes & Backup**: Staged through temporary `.tmp` files with `fsync`, accompanied by `.bak` backup copies for crash resilience.

### 4.2 Quarantine "Restore & Trust SHA-256" Integration
When a user restores a false-positive file from the Quarantine Vault with the `trustSha256: true` option:
1. The exact plaintext SHA-256 hash is verified against the quarantined blob.
2. An exact `HASH` exclusion (`createdBy: RESTORE_AND_TRUST`) is atomically registered in `ExclusionManagerService`.
3. `ThreatIntel` and `CleanFileCache` are seeded with the trusted hash.
4. `RealtimeMonitorService` allows the restored file immediately upon ingress without triggering duplicate alerts or re-quarantining.

---

## 5. Security & Invariant Verification Matrix

| Invariant | Implementation Mechanism | Test Verification Suite | Status |
|---|---|---|---|
| **INV-I-01: Deterministic Ladder Mapping** | `ResponsePolicyEngine.evaluate()` | `response-policy-engine.test.ts` | **PASS** |
| **INV-I-02: Ransomware Non-Dilution** | Hardcoded priority bypass in ladder & exclusions | `phase-i-security.test.ts` (SEC-I-A) | **PASS** |
| **INV-I-03: Forbidden Path Blocking** | `canonicalizePath` system folder boundary list | `exclusion-manager.test.ts` | **PASS** |
| **INV-I-04: Domain Mandatory TTL** | `canonicalizeDomain` + 7d expiry clamp | `exclusion-manager.test.ts` | **PASS** |
| **INV-I-05: AES-256-GCM Persistence** | PBKDF2 + AES-256-GCM + atomic `.bak` staging | `exclusion-manager.test.ts` | **PASS** |
| **INV-I-06: Restore & Trust Integration** | Quarantine restoration hash injection | `phase-i-exclusion.integration.test.ts` | **PASS** |
| **INV-I-07: Microsecond Throughput** | $O(1)$ Hash Set & Map Lookups ($<0.01\text{ ms}$) | `phase-i-performance.test.ts` | **PASS** |
