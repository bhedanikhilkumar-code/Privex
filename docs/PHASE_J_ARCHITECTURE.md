# PHASE J: WEB & DOWNLOAD MARK-OF-THE-WEB (MOTW) PROTECTION
## Technical Architecture & Security Specification

### 1. Executive Summary & Problem Scope
When users download files from the web, modern web browsers attach an NTFS Alternate Data Stream (ADS) named `:Zone.Identifier` to the downloaded file. This stream contains the Windows Security Zone (`ZoneId`), the originating download URL (`HostUrl`), and the referring webpage URL (`ReferrerUrl`).

Attackers leverage diverse evasion techniques—such as bundling malicious binaries in ISO/VHD/ZIP archives (MOTW bypass), registering typosquatted or IDN punycode domains, or hosting payloads on raw IP C2 nodes.

**Phase J** integrates production-grade, local-first Mark-of-the-Web (MOTW) extraction and download origin security into Privex's Windows Antivirus engine.

---

### 2. Core Architectural Components

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 FILE INGRESS HOOK                                      │
│                (RealtimeMonitorService / On-Demand FileAnalyzer)                       │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              MotwAnalyzer (apps/desktop)                               │
│                                                                                        │
│   ┌───────────────────────────┐      ┌───────────────────────────┐                     │
│   │   readRawAds (NTFS ADS)   │ ───► │  parseZoneIdentifier()    │                     │
│   │  • Win32 stream path      │      │  • Safe INI lexer         │                     │
│   │  • Companion test fallback│      │  • 4 KB bounded input     │                     │
│   │  • Zero shell execution   │      │  • RTLO & bidi scrubbing  │                     │
│   └───────────────────────────┘      └─────────────┬─────────────┘                     │
│                                                    │                                   │
│                                                    ▼                                   │
│                                      ┌───────────────────────────┐                     │
│                                      │     analyzeUrl()          │                     │
│                                      │  • ThreatIntel blocklists │                     │
│                                      │  • URLAnalyzer heuristics │                     │
│                                      │  • Brand typosquatting    │                     │
│                                      │  • Punycode homographs    │                     │
│                                      └─────────────┬─────────────┘                     │
└────────────────────────────────────────────────────┼───────────────────────────────────┘
                                                     │
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      Origin Risk Contribution Math (+35 to +85)                        │
│                                                                                        │
│   • Clean Origin (e.g., github.com, nodejs.org, ZoneId=3): +0 (Clean, No-Op)           │
│   • Suspicious TLD / Abnormal Port Origin: +45                                         │
│   • Raw IP Download Origin (e.g., 185.x.x.x:8080): +65                                │
│   • IDN / Punycode Homograph Origin (xn--): +80                                        │
│   • Typosquatted Major Brand Origin (paypa1, micros0ft): +85                           │
│   • Known Malicious C2 URL in ThreatIntel Blocklist: +100                              │
│   • Restricted Zone (ZoneId=4): +60                                                    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. NTFS Alternate Data Stream (ADS) Extraction

#### 3.1 Stream Path Resolution
- On Windows (`win32`), `MotwAnalyzer.readRawAds` targets `<canonicalFilePath>:Zone.Identifier`.
- Bounded to `MAX_ADS_READ_BYTES = 4096` (4 KB) using low-level synchronous file descriptors (`fs.openSync`, `fs.readSync`, `fs.closeSync`).
- Companion test fixtures (`.zone.identifier`) provide deterministic cross-platform execution in CI environments.

#### 3.2 INI Parser & Sanitization
- **Strict Bounds**: Input clamped to 4,096 bytes.
- **Section Parsing**: Handles `[ZoneTransfer]` sections and property lines.
- **Duplicate Key Invariant**: First occurrence wins; subsequent duplicate keys are ignored.
- **RTLO & Control Character Scrubbing**: Regex cleanses Unicode Right-to-Left Override (`\u202E`, `\u2066`-\`\u2069\`) and ASCII control characters (`\x00-\x1F\x7F`).
- **No Shell Execution**: ADS extraction strictly utilizes file descriptor reads; zero child processes (`cmd.exe`, `powershell.exe`, or `more.exe`) are executed.

---

### 4. Canonical URL & Threat Intelligence Correlation

`MotwAnalyzer` does **not** duplicate or split security decision logic. It leverages `@private-protection/core`:
1. `ThreatIntel.getSharedInstance().checkUrl()`: Immediate $O(1)$ Bloom filter and cryptographic hash check against local threat intelligence databases.
2. `URLAnalyzer.analyze()`: Full lexical heuristic engine evaluating entropy, subdomain depth, TLD reputation, and brand spoof distance.
3. Sub-token brand distance inspection across top consumer and financial brands (`paypal`, `google`, `microsoft`, `apple`, `amazon`, `chase`, etc.).

---

### 5. False Positive Prevention & Zone Preservation
- **Clean Internet Downloads**: A file originating from a verified clean domain (e.g., `https://nodejs.org/...` or `https://github.com/...`) with `ZoneId=3` receives `originRiskScore: 0` and `isOriginMalicious: false`.
- Only deceptive, typosquatted, homographic, raw-IP, or blocklisted origins trigger risk elevation.
