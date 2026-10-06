# PHASE K: PRACTICAL EMAIL (.EML/.MSG) & NETWORK SOCKET PROTECTION
## Technical Architecture & Security Specification

### 1. Executive Summary & Problem Scope
Email communications remain the dominant initial access vector for ransomware droppers, credential phishing, and financial extortion. Concurrently, malicious implants, reverse shells, and RATs communicate over active TCP/UDP network sockets to Command and Control (C2) servers.

**Phase K** integrates:
1. **Practical Email Protection (`.eml` and bounded `.msg`)**: Safe, bounded RFC 5322 MIME extraction, sender spoofing detection, SPF/DMARC authentication analysis, body URL & text heuristic scanning, and sandboxed attachment analysis through the 10-layer `FileAnalyzer`.
2. **Real Windows Network Posture Monitoring**: Active socket inspection (`netstat -ano`), remote IP threat intelligence correlation against local blocklists, suspicious C2 port detection, and real Windows Defender Firewall profile state auditing (`netsh advfirewall show allprofiles`).

Everything operates **100% offline**, **local-first**, with **zero cloud dependencies**.

---

### 2. Email MIME Architecture & Threat Pipeline

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                EMAIL INGRESS HOOK                                      │
│                 (.eml / .msg via RealtimeMonitorService / FileAnalyzer)                │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                             EmailMimeParser (apps/desktop)                             │
│                                                                                        │
│   ┌───────────────────────────┐      ┌───────────────────────────┐                     │
│   │   RFC 5322 Headers Parser │ ───► │  Authentication Analyzer  │                     │
│   │  • Unfolding & domain ext │      │  • SPF (pass/fail/soft)   │                     │
│   │  • From vs Reply-To match │      │  • DMARC verification     │                     │
│   │  • Brand spoofing (+85)   │      │  • DKIM signature check   │                     │
│   └─────────────┬─────────────┘      └─────────────┬─────────────┘                     │
│                 │                                  │                                   │
│                 └─────────────────┬────────────────┘                                   │
│                                   ▼                                                    │
│   ┌──────────────────────────────────────────────────────────────┐                     │
│   │                       Body & URL Scanning                    │                     │
│   │  • Decodes quoted-printable & HTML bodies                    │                     │
│   │  • TextAnalyzer text heuristic evaluation                    │                     │
│   │  • URLAnalyzer & ThreatIntel correlation for extracted links │                     │
│   └───────────────────────────────┬──────────────────────────────┘                     │
│                                   │                                                    │
│                                   ▼                                                    │
│   ┌──────────────────────────────────────────────────────────────┐                     │
│   │               Sandboxed Attachment Extractor                 │                     │
│   │  • Filename sanitization (RTLO, NUL, traversal cleansing)    │                     │
│   │  • Isolated temporary sandbox (os.tmpdir()/pp-email-stage-*) │                     │
│   │  • SHA-256 ThreatIntel hash match + 10-layer FileAnalyzer    │                     │
│   │  • Guaranteed sandbox cleanup in finally block               │                     │
│   └──────────────────────────────────────────────────────────────┘                     │
└────────────────────────────────────────────────────┬───────────────────────────────────┘
                                                     │
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   Canonical Decision Pipeline & ResponsePolicyEngine                   │
│                                                                                        │
│   • Malicious EICAR / Executable Attachment: BLOCK (Auto-Quarantine to PPVAULT2)       │
│   • Phishing URL / Brand Impersonation: BLOCK (Friction-Gated Warning Banner)          │
│   • Suspicious Mismatch / Softfail: WARN / CAUTION                                     │
│   • Clean Email: ALLOW (0 risk contribution)                                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. Network Socket & Firewall Auditing Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          NetworkMonitorService (apps/desktop)                          │
│                                                                                        │
│   ┌───────────────────────────┐      ┌───────────────────────────┐                     │
│   │   Socket Inspector        │      │   Firewall Profile Audit  │                     │
│   │  • netstat -ano -p TCP    │      │  • netsh advfirewall show │                     │
│   │  • netstat -ano -p UDP    │      │    allprofiles            │                     │
│   │  • Owning PID extraction  │      │  • Domain, Private, Public│                     │
│   │  • IP/Port normalization  │      │    profile state (ON/OFF) │                     │
│   └─────────────┬─────────────┘      └─────────────┬─────────────┘                     │
│                 │                                  │                                   │
│                 └─────────────────┬────────────────┘                                   │
│                                   ▼                                                    │
│   ┌──────────────────────────────────────────────────────────────┐                     │
│   │             Local Threat Intelligence Correlation            │                     │
│   │  • $O(1)$ Bloom filter lookup of remote IP                   │                     │
│   │  • High-risk C2 port detection (4444, 1337, 6667, 31337)     │                     │
│   │  • Zero network lookups or external telemetry                │                     │
│   └──────────────────────────────────────────────────────────────┘                     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4. Adversarial & Security Defenses

1. **MIME Recursion & Expansion Bombs**: Recursion depth strictly clamped to $\le 10$; attachment memory clamped to $\le 15\text{ MB}$; email file limit bounded to $\le 25\text{ MB}$.
2. **Filename Sanitization**: Directory traversal (`../`, `..\\`), NUL bytes, ASCII control characters, and Unicode RTLO bidi overrides (`\u202E`, `\u2066`–`\u2069`) are cleanly stripped.
3. **Air-Gap Guarantee**: 100% offline execution; zero external network requests (`fetch`, `XMLHttpRequest`, TCP sockets) during email scanning or network posture audits.
4. **Fail-Closed Safety**: Malformed inputs produce structured diagnostic warnings without crashing or defaulting to `ALLOW`.
