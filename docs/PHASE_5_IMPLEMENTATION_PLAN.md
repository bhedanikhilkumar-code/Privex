# PHASE_5_IMPLEMENTATION_PLAN.md — Browser Extension (Manifest V3) Real-Time Web Protection

> **SYSTEM STATUS: PHASE 5 ACTIVE IMPLEMENTATION**  
> **CANONICAL IMPLEMENTATION PLAN — `apps/extension`**  
> Governed by: `AGENTS.md`, `docs/BROWSER_TECHNICAL_ARCHITECTURE.md`, `docs/SECURITY_ARCHITECTURE.md`, `docs/PRIVACY_ARCHITECTURE.md`, `docs/OFFLINE_ARCHITECTURE.md`.

---

## 1. EXECUTIVE MISSION & PURPOSE

Phase 5 implements `apps/extension`: a privacy-first Chromium browser extension operating under Manifest V3 (MV3). It provides real-time, on-device protection while the user browses the web, intercepting dangerous URLs, phishing forms, and scam redirects before damage occurs.

### Cardinal Extension Invariant
```
USER BROWSING / NAVIGATION
            │
            ▼
MV3 BACKGROUND SERVICE WORKER (webNavigation.onBeforeNavigate)
            │
            ▼
URL & STRUCTURAL PAGE SIGNAL EXTRACTION
            │
      ┌─────┴─────────────────────────────────────────────┐
      ▼                                                   ▼
@private-protection/core (Plane 3)              @private-protection/ml (Plane 4)
• Lexical Analysis (< 0.2 ms)                   • URL Semantic Classifier (< 0.5 ms)
• Offline Bloom Filter (< 0.05 ms)              • Prompt Sanitizer (< 0.02 ms)
• Levenshtein Typosquatting (< 0.3 ms)          • Read-Only AI Security Assistant
• Risk Scorer Math Aggregation (< 0.02 ms)      • Grade 6 Threat Explanation Synthesis
      │                                                   │
      └─────────────────────┬─────────────────────────────┘
                            ▼
              SECURITY DECISION & ACTION
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
       ALLOW               WARN              BLOCK
   (Navigate ok)    (Shadow DOM Banner) (Redirect to Interstitial)
```

**ABSOLUTE CONSTITUTIONAL DIRECTIVE**:
1. **Zero Cloud Exfiltration**: Visited URLs, web page content, and browsing histories are **NEVER** transmitted to any remote server or API.
2. **Reuse Existing Engines**: Core detection (`@private-protection/core`) and AI security assistant (`@private-protection/ml`) must be directly reused without duplicating algorithms or inventing parallel risk thresholds.
3. **No Keystroke / Credential Inspection**: Content scripts inspect only DOM structure (`input.type === 'password'` within an insecure `http://` form action). Keystrokes, cookies, and passwords are never read or stored.

---

## 2. MANIFEST V3 DIRECTORY STRUCTURE

```
apps/extension/
├── manifest.json                            # Manifest V3 specification
├── package.json                             # @private-protection/extension
├── tsconfig.json                            # Strict ES2022 TypeScript configuration
├── vite.config.ts                           # Multi-entry Vite bundler (background, content, popup, options, warning)
├── vitest.config.ts                         # Vitest runner with JSDOM
├── src/
│   ├── background/
│   │   ├── background.ts                    # Ephemeral Service Worker entry point
│   │   ├── navigation-interceptor.ts        # webNavigation listener & fast-path URL filter
│   │   ├── session-store.ts                 # chrome.storage.session state manager & rehydration
│   │   └── message-router.ts                # Schema-validated background message dispatcher
│   ├── content/
│   │   ├── content.ts                       # DOM structural signal extractor
│   │   ├── dom-analyzer.ts                  # Form action & password field structural inspector
│   │   └── shadow-banner.ts                 # Tamper-proof closed mode Shadow DOM warning
│   ├── popup/
│   │   ├── popup.html                       # Popup UI shell
│   │   ├── popup.tsx                        # Status display, risk meter, AI briefing, quick scanner
│   │   └── styles.css                       # Accessible high-contrast styling
│   ├── options/
│   │   ├── options.html                     # Extension settings shell
│   │   ├── options.tsx                      # Protection toggle, sensitivity, allowlists, audit logs
│   │   └── styles.css
│   ├── warning/
│   │   ├── interstitial.html                # Isolated full-page warning blocking malicious navigation
│   │   ├── interstitial.tsx                 # 5-second friction gate, evidence display, user override
│   │   └── styles.css
│   ├── shared/
│   │   ├── types.ts                         # Extension contracts, tab states, and preferences
│   │   ├── messages.ts                      # Strict typed message schemas
│   │   ├── storage.ts                       # chrome.storage wrapper with crypto-shredding
│   │   ├── formatters.ts                    # Visual risk helpers & HTML escaping
│   │   └── shims/
│   │       ├── buffer-shim.ts               # Browser Node Buffer shim
│   │       └── crypto-shim.ts               # Browser Node crypto shim
│   └── __tests__/
│       ├── background/navigation.test.ts    # URL interception & canonical verdict mapping
│       ├── background/lifecycle.test.ts     # Service worker restart & session state recovery
│       ├── content/dom-analyzer.test.ts     # Structural password/form analysis (keystroke-free)
│       ├── popup/popup.test.tsx             # Tab status rendering & restricted URL handling
│       ├── warning/interstitial.test.tsx    # Friction countdown & safe user override workflow
│       ├── security/message-security.test.ts # Schema validation, origin check & spoof rejection
│       ├── security/prompt-injection.test.ts # Adversarial prompt containment in page signals
│       ├── privacy/network-isolation.test.ts # 0 outbound HTTP/XHR/Beacon spy verification
│       └── offline/offline-parity.test.ts   # 100% detection parity air-gapped
```

---

## 3. PERMISSIONS JUSTIFICATION (LEAST PRIVILEGE)

| Permission | Technical Justification | Data Accessed | Transmission Vector |
|---|---|---|---|
| `"webNavigation"` | Required to intercept target URLs on `onBeforeNavigate` before network sockets connect. | Target URL of top-level navigation. | Local RAM only (0 bytes transmitted). |
| `"storage"` | Stores local user preferences and temporary session verdicts across Service Worker lifecycles. | Extension preferences, allowlisted domains. | Local browser disk/RAM only. |
| `"activeTab"` | Permits popup to query current active tab URL and display threat briefing. | Current active tab URL upon user clicking icon. | Local RAM only. |
| `"tabs"` | Allows background worker to redirect active tab to local `interstitial.html` when threat is blocked. | Tab ID only for `chrome.tabs.update`. | Local browser API only. |
| `<all_urls>` (Host) | Needed for `webNavigation` to inspect arbitrary web destinations before loading. | Top-level navigation URL. | Local RAM only. |

*Explicitly Excluded*: `"cookies"`, `"webRequestBlocking"`, `"management"`, `"history"`, `"identity"`.

---

## 4. PRE-NAVIGATION & VERDICT POLICY

| Core Verdict | Overall Score | Extension Action | UI Presentation |
|---|---|---|---|
| `ALLOW` | $0 - 29$ | Permit navigation immediately. | Neutral/Green badge in toolbar. |
| `INFORM` | $30 - 49$ | Permit navigation; notify in popup. | Informational icon in toolbar. |
| `CAUTION` | $50 - 69$ | Permit navigation; inject subtle warning if structural flaw. | Amber warning badge. |
| `SUSPICIOUS` | $70 - 84$ | Trigger Shadow DOM warning banner or interstitial. | Amber/Orange warning interstitial. |
| `DANGEROUS` | $85 - 100$ | **BLOCK navigation immediately** (`chrome.tabs.update` to `interstitial.html`). | Red full-page interstitial with 5s friction gate. |

---

## 5. USER OVERRIDE & FRICTION PROTOCOL

1. When a user is stopped at `interstitial.html`, navigation to the dangerous destination is halted.
2. The user is presented with the root threat evidence and AI assistant briefing.
3. A 5-second countdown friction gate disables the proceed button.
4. If the user deliberately clicks "I Understand the Risks (Proceed Anyway)":
   - The override is registered in `chrome.storage.session` for that specific tab and origin only.
   - It is **temporary** (cleared on browser/tab close).
   - Webpage JavaScript has **zero access** to trigger or simulate an override.

---

## 6. DEFINITION OF DONE & AUDIT CRITERIA
- 100% Manifest V3 compliance.
- Zero outbound network requests verified via automated test spies.
- All core and ML features reused without duplication.
- Comprehensive unit and integration test suite passing.
- Security and privacy audit sign-offs completed.
