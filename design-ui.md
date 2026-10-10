# design-ui.md — PRIVEX Canonical Web UI Specification & Design System Architecture

> **DOCUMENT STATUS:** CANONICAL SPECIFICATION & SYSTEM CONTRACT  
> **SCOPE:** Complete User Interface, Visual Hierarchy, Theme Variables, Logic State Machines, Component Interfaces, Event Handling, and Behavioral Integrity for the PRIVEX Web Application.  
> **GOAL:** This single specification document captures all UI functions, layout components, design tokens, responsive breakpoints, state machines, and business logics so that any implementation or migration across environments renders an identical, pixel-precise, tamper-proof, and fully functional interface.

---

## 1. DESIGN PHILOSOPHY & CORE PRINCIPLES

1. **Brutalist Cyber-Defense Aesthetic:** Heavy solid borders (`2px solid var(--border-dark)`), high-contrast hard geometric drop-shadows (`var(--shadow-brutal)`), uppercase typography tags, high-density monospace telemetry, and vibrant functional status badges.
2. **Deterministic UI State Consistency:** All views, inputs, buttons, sliders, modals, and friction gates derive deterministically from explicit state contracts. No transient styling or unexpected layout shifts.
3. **Calm Authority & Zero Alarmism:** Warnings are unmistakable, plain-language (cognitive reading grade $\le 8$), color-coded, and provide immediate friction-gated safety.
4. **Local-First & Offline Resilience:** UI explicitly displays real-time connection state (`online` / `offline` air-gapped parity banner) and operates 100% locally with zero external network dependencies for detection.
5. **Universal Accessibility (WCAG 2.1 AA/AAA):** High contrast ratios across all 3 themes, semantic HTML5 landmarks (`banner`, `nav`, `main`, `contentinfo`, `article`, `section`), ARIA keyboard navigation for tab switching, and explicit screen-reader notifications.

---

## 2. DESIGN TOKENS & CSS VARIABLE REGISTRY

The UI appearance is strictly controlled through CSS custom properties defined on the root element. When implementing the UI anywhere, these exact token definitions ensure 100% visual fidelity.

### 2.1 Theme Definitions

```css
:root, [data-theme="light"] {
  /* Surfaces & Backgrounds */
  --bg-primary: #F7F3EB;
  --bg-secondary: #EBE7DE;
  --bg-card: #FFFFFF;

  /* Typography & Foreground */
  --text-primary: #111111;
  --text-muted: #555555;

  /* Borders & Shadows */
  --border-color: #111111;
  --border-dark: #111111;
  --border-width: 2px;
  --shadow-brutal-sm: 2px 2px 0px #111111;
  --shadow-brutal: 4px 4px 0px #111111;
  --shadow-brutal-lg: 6px 6px 0px #111111;
  --shadow-brutal-xl: 8px 8px 0px #111111;

  /* Semantic Status Palettes */
  --color-safe: #1DB954;
  --color-safe-bg: #E7F9EE;
  --color-caution: #FFB800;
  --color-caution-bg: #FFF9E6;
  --color-danger: #FF5A36;
  --color-danger-bg: #FFECE8;
  --color-brand: #2457FF;
  --color-brand-hover: #1844DD;
  --color-accent: #D7FF3F;

  /* Typography Font Stacks */
  --font-serif: 'Playfair Display', Georgia, 'Times New Roman', serif;
  --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  --font-mono: 'Space Grotesk', 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
}

[data-theme="dark"] {
  --bg-primary: #0b1120;
  --bg-secondary: #1e293b;
  --bg-card: #151f32;
  --text-primary: #f8fafc;
  --text-muted: #94a3b8;
  --border-color: #334155;
  --border-dark: #334155;
  --border-width: 2px;
  --shadow-brutal-sm: 2px 2px 0px #020617;
  --shadow-brutal: 4px 4px 0px #020617;
  --shadow-brutal-lg: 6px 6px 0px #020617;
  --shadow-brutal-xl: 8px 8px 0px #020617;
  --color-safe: #22c55e;
  --color-safe-bg: #052e16;
  --color-caution: #f59e0b;
  --color-caution-bg: #451a03;
  --color-danger: #ef4444;
  --color-danger-bg: #450a0a;
  --color-brand: #3b82f6;
  --color-brand-hover: #2563eb;
  --color-accent: #a3e635;
}

[data-theme="night"] {
  --bg-primary: #000000;
  --bg-secondary: #0c0c0e;
  --bg-card: #141416;
  --text-primary: #ffffff;
  --text-muted: #a1a1aa;
  --border-color: #27272a;
  --border-dark: #27272a;
  --border-width: 2px;
  --shadow-brutal-sm: 2px 2px 0px #000000;
  --shadow-brutal: 4px 4px 0px #000000;
  --shadow-brutal-lg: 6px 6px 0px #000000;
  --shadow-brutal-xl: 8px 8px 0px #000000;
  --color-safe: #10b981;
  --color-safe-bg: #022c22;
  --color-caution: #eab308;
  --color-caution-bg: #422006;
  --color-danger: #f43f5e;
  --color-danger-bg: #4c0519;
  --color-brand: #60a5fa;
  --color-brand-hover: #3b82f6;
  --color-accent: #ccff00;
}
```

### 2.2 Global CSS Utility Classes

```css
.brutal-card {
  background-color: var(--bg-card);
  border: 2px solid var(--border-dark);
  box-shadow: var(--shadow-brutal);
}

.brutal-card-lg {
  background-color: var(--bg-card);
  border: 2px solid var(--border-dark);
  box-shadow: var(--shadow-brutal-lg);
}

.brutal-btn-primary {
  background-color: var(--color-brand);
  color: #FFFFFF;
  border: 2px solid var(--border-dark);
  box-shadow: var(--shadow-brutal-sm);
  font-weight: 700;
  cursor: pointer;
  transition: transform 0.1s ease, box-shadow 0.1s ease;
}

.brutal-btn-primary:hover:not(:disabled) {
  transform: translate(-1px, -1px);
  box-shadow: var(--shadow-brutal);
}

.brutal-btn-primary:active:not(:disabled) {
  transform: translate(2px, 2px);
  box-shadow: 0px 0px 0px #111111;
}
```

---

## 3. CORE APPLICATION ARCHITECTURE & NAVIGATION SHELL

### 3.1 Application Shell Top-Level Layout
The top-level shell coordinates global themes, offline status, introduction overlays, and active screen panels:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ HEADER (Logo, Brand Title, Air-gap Tag, Theme Switcher, PWA Install CTA)         │
├──────────────────────────────────────────────────────────────────────────────────┤
│ NAVIGATION BAR (7 Tabs: HOME, URL_SCAN, TEXT_SCAN, ASSISTANT, MONITOR, PRIVACY,  │
│                SETTINGS) with horizontal keyboard ARROW keys navigation          │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [CONDITIONAL] AIR-GAPPED OFFLINE ALERT BANNER (Active when navigator.onLine=false│
├──────────────────────────────────────────────────────────────────────────────────┤
│ MAIN CONTENT CANVAS (Max-width: 1200px, padding: 2.5rem 2rem, centered)         │
│                                                                                  │
│   Active Tab Panel rendered based on current ActiveTab state                     │
│                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│ FOOTER (Privacy Guarantee, Version, Zero Cloud Ingestion badge, Replay Intro)    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Canonical State Types (`types.ts`)

```typescript
export type ActiveTab = 
  | 'HOME' 
  | 'URL_SCAN' 
  | 'TEXT_SCAN' 
  | 'ASSISTANT' 
  | 'SECURITY_MONITOR' 
  | 'PRIVACY' 
  | 'SETTINGS';

export type AppTheme = 'light' | 'dark' | 'night';

export type ScanType = 'URL' | 'TEXT';
export type ScanStatus = 'IDLE' | 'SCANNING' | 'COMPLETED' | 'ERROR';

export interface UserPreferences {
  cognitiveReadingGrade: 6 | 8;
  enableWorkerOffloading: boolean;
  allowlistDomains: string[];
  theme?: AppTheme;
}

export interface ScanResultViewData {
  readonly id: string;
  readonly targetPreview: string;
  readonly scanType: ScanType;
  readonly verdict: 'ALLOW' | 'SUSPICIOUS' | 'DANGEROUS';
  readonly overallScore: number;
  readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  readonly confidence: number;
  readonly evidence: Array<{
    detectorId: string;
    description: string;
    score: number;
    weight: number;
    severity: string;
  }>;
  readonly recommendation: {
    action: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';
    summary: string;
    actionLabel?: string;
  };
  readonly executionTimeMs: number;
  readonly timestamp: number;
  readonly isModelBacked: boolean;
  readonly isAllowlisted?: boolean;
  readonly privacyGuarantee: string;
}
```

---

## 4. UI VIEWS & DETAILED FUNCTIONAL LOGIC

---

### 4.1 Header & Theme Switcher Component (`Header.tsx` & `ThemeToggle.tsx`)

#### Purpose
Renders project identity, dynamic PWA installation triggers, and 3-way instant theme switching (`Light`, `Dark`, `Night`).

#### Layout & Styling
- **Container:** `display: flex`, `justify-content: space-between`, `align-items: center`, `padding: 1rem 2rem`, `background: var(--bg-card)`, `borderBottom: 2px solid var(--border-dark)`.
- **Branding:** 
  - Logo Box: `2.5rem x 2.5rem`, `#090d16` background, `border: 2px solid var(--border-dark)`, contains SVG shield logo.
  - Title: `var(--font-serif)`, `1.4rem`, bold `800`.
  - Subtitle: `var(--font-mono)`, `0.725rem`, uppercase, `color: var(--text-muted)`.
- **PWA Install Button:**
  - Hidden by default.
  - Automatically surfaces if browser fires `beforeinstallprompt` event.
  - Style: Neon accent background `var(--color-accent)`, `border: 2px solid var(--border-dark)`, text `Install App ↓`.
- **Theme Selector (`ThemeToggle`):**
  - Segmented 3-button control group: `☀️ Light`, `🌙 Dark`, `🌌 Night`.
  - Active button: `background: var(--color-brand)`, `color: #FFFFFF`, `boxShadow: var(--shadow-brutal-sm)`.
  - Updates `document.documentElement.setAttribute('data-theme', newTheme)` and persists via `localStorage.setItem('privex_theme', newTheme)`.

---

### 4.2 Navigation Tabs (`Navigation.tsx`)

#### Purpose
Persistent tab strip with zero-latency tab switching and full keyboard accessibility.

#### Navigation Items
1. **`HOME`** (`🏠 Overview`)
2. **`URL_SCAN`** (`🔗 URL Scanner`)
3. **`TEXT_SCAN`** (`💬 Message Scanner`)
4. **`ASSISTANT`** (`🤖 AI Security Assistant`)
5. **`SECURITY_MONITOR`** (`🛡️ Password & Network`)
6. **`PRIVACY`** (`🔒 Privacy & Architecture`)
7. **`SETTINGS`** (`⚙️ Settings`)

#### Layout & Accessibility Logic
- **Container:** `role="tablist"`, `background: var(--bg-secondary)`, `borderBottom: 2px solid var(--border-dark)`, `overflow-x: auto`.
- **Buttons:**
  - Semantic `role="tab"`, `aria-selected={isActive}`, `aria-controls={`panel-${key.toLowerCase()}`}`.
  - Style (Active): `background: var(--color-brand)`, `color: #FFFFFF`, `boxShadow: 3px 3px 0px var(--border-dark)`.
  - Style (Inactive): `background: var(--bg-card)`, `color: var(--text-primary)`, `boxShadow: 1px 1px 0px var(--border-dark)`.
- **Keyboard Handling:**
  - `ArrowRight`: Focuses and selects next tab (wrapping to first).
  - `ArrowLeft`: Focuses and selects previous tab (wrapping to last).

---

### 4.3 Screen 1: Home / Overview View (`App.tsx` Home Section)

#### Purpose
Serves as the high-impact landing dashboard with real-world threat previews, architectural value badges, quick-launch scanner cards, and system status metrics.

#### Layout Specification
1. **Hero Header:**
   - Pill Badge: `🚀 ZERO-INSTALL • LOCAL-FIRST • PRIVACY-FIRST` (Neon accent `#D7FF3F` background with hard brutalist shadow).
   - Headline: `Neutralize digital threats before they reach your data.` (`font-family: var(--font-serif)`, `3rem`, weight `800`).
   - Subtitle: `On-Device Threat & Scam Protection` (`var(--font-mono)`, `var(--color-brand)`).
   - Value Text: Plain-language explanation of volatile RAM processing and zero cloud logging.
2. **Featured Safe Sample Card:**
   - Displays sample verified safe target `amazon.com/order-history`.
   - Safe verification pill (`SAFE / VERIFIED` in `#1DB954`).
   - Quick action CTA button: `Launch Scanner →` directly triggers `setActiveTab('URL_SCAN')`.
3. **Quick-Action Scanner Cards (3-Column Grid):**
   - **Card 1: URL Scanner:** Icon `🔗`, title `Scan Any URL`, subtitle `Punycode, homographs, brand typosquatting, Bloom filter reputation`. Direct button `Open URL Scanner`.
   - **Card 2: Message Scanner:** Icon `💬`, title `Analyze Messages`, subtitle `Detect urgent extortion, scam SMS, advance-fee fraud, and phishing lure patterns`. Direct button `Open Message Scanner`.
   - **Card 3: AI Assistant:** Icon `🤖`, title `Security Explanations`, subtitle `Jargon-free, Grade ≤8 plain explanations directly on-device`. Direct button `Open AI Assistant`.
4. **Value & Security Proof Grid:**
   - 4-card matrix detailing:
     - `100% On-Device Processing` (Zero cloud API payloads).
     - `<1.0 ms Fast Path Latency` (Sub-millisecond Bloom and heuristic execution).
     - `Air-Gapped Parity` (Identical threat engine functionality when offline).
     - `Zero-Knowledge Telemetry` (Raw data mathematically impossible to extract).

---

### 4.4 Screen 2: URL Threat Scanner (`UrlScannerView.tsx`)

#### Purpose
Provides real-time, interactive link scanning with instant local detection, sample threat test presets, custom allowlist bypass checks, and detailed threat evidence breakdowns.

#### State Machine & Logic
```
[IDLE] ─── User enters URL or clicks Sample Preset ───> [VALIDATING]
                                                               │
                                                       Valid URL Syntax
                                                               │
                                                               ▼
                                                          [SCANNING]
                                                     (Web Worker Bridge)
                                                               │
                                                               ▼
                                                         [COMPLETED]
                                                               │
                                            ┌──────────────────┴──────────────────┐
                                            ▼                                     ▼
                                      SAFE (Score < 30)                DANGEROUS (Score >= 70)
                                    Green Alert Banner                5-Second Friction Gate Modal
```

#### Layout & Interactive Elements
- **Input Field:**
  - Input `type="url"`, large font (`1.05rem`), border `2px solid var(--border-dark)`, placeholder `https://example.com/login`.
  - Clear button `✕` visible when text is entered.
- **Action Controls:**
  - Primary button: `Analyze URL Now` (`var(--color-brand)` with `boxShadow: var(--shadow-brutal)`).
  - Disabled during scan with spinner/animated text `Scanning Locally...`.
- **Preset Test Chips (Instant One-Click Testing):**
  - Preset 1: `Safe: google.com`
  - Preset 2: `Homograph: paypa1.com` (Typosquatting)
  - Preset 3: `IP Host: http://192.168.1.1/admin`
  - Preset 4: `Deceptive: secure-login.account-update.xyz`
  - Clicking any chip populates the input and auto-triggers `handleScan()`.
- **Allowlist Indicator:**
  - Checks domain against `preferences.allowlistDomains`.
  - If allowlisted, displays yellow badge `ALLOWED BY USER POLICY` and skips blocking.

---

### 4.5 Screen 3: Message / SMS Scanner (`TextScannerView.tsx`)

#### Purpose
Deep text parsing for suspicious communications, cryptocurrency extortion, urgent delivery scams, and financial impersonation.

#### State Machine & Logic
- **Input Area:** Expandable textarea (`minHeight: 140px`), character counter (`${len} / 10,000 max bytes`), and clear button.
- **Preset Threat Buttons:**
  - `Cryptocurrency Blackmail`: *"Send 0.5 BTC within 24 hours or your private videos will be leaked."*
  - `Fake Postal Fee`: *"USPS: Your package is detained due to unpaid $2.49 delivery fee. Visit link to verify."*
  - `Urgent Bank Alert`: *"ALERT: Chase account suspended due to unauthorized login. Verify credentials immediately."*
  - `Safe Meeting Message`: *"Hi John, let's catch up at 3 PM today to discuss the quarterly project review."*
- **Execution Path:**
  - Respects `preferences.enableWorkerOffloading`. If true, offloads regex and heuristic tokenization to `WorkerBridge`; otherwise runs on main thread.
- **Evidence Rendering:**
  - Displays identified urgency words, extortion triggers, threat categories, and Bayesian aggregate score.

---

### 4.6 Threat Result Card & 5-Second Friction Gate (`ResultCard.tsx`)

#### Purpose
Universal result display used across all scanners. Communicates threat verdict with high visual contrast and imposes safety friction on hazardous actions.

#### Visual Hierarchy & Token Mapping
| Verdict | Banner Color | Text Color | Icon | Label |
|---|---|---|---|---|
| **`ALLOW`** | `var(--color-safe)` (`#1DB954`) | `#FFFFFF` | 🛡️ | `SAFE / NO IMMEDIATE THREAT DETECTED` |
| **`SUSPICIOUS`** | `var(--color-caution)` (`#FFB800`) | `#111111` | ⚠️ | `POTENTIAL RISK DETECTED` |
| **`DANGEROUS`** | `var(--color-danger)` (`#FF5A36`) | `#FFFFFF` | 🚨 | `ACCESS BLOCKED / DANGEROUS THREAT` |

#### Friction Gate Logic for Dangerous Verdicts
1. When `result.verdict === 'DANGEROUS'`, direct bypass button is disabled.
2. Countdown timer starts at **5 seconds**: `[Proceed Anyway (5s)]`.
3. Every 1,000 ms, countdown ticks: $5 \rightarrow 4 \rightarrow 3 \rightarrow 2 \rightarrow 1 \rightarrow 0$.
4. At $0\text{ s}$, button unlocks: `[Proceed Anyway (Not Recommended)]`.
5. User clicking proceed reveals explicit security warning acknowledgment modal.
6. Resetting or submitting a new scan resets friction timer back to 5 seconds.

#### Explanatory Evidence Grid
- **The 4 Plain-Language Pillars:**
  1. **What Happened:** Plain-language summary (Grade $\le 8$).
  2. **Why It Matters:** Concrete risk explanation (e.g., credentials or funds at risk).
  3. **What Privex Did:** Local blocking/quarantine action executed in RAM.
  4. **Recommended Action:** Step-by-step guidance (`Do not enter passwords`, `Delete message`).
- **Telemetry Breakdown:**
  - Score meter: $0 - 100$ scale with color gradient.
  - Execution time: e.g., `0.38 ms` (illustrating local speed).
  - Privacy Guarantee Badge: `Zero telemetry transmitted off-device`.

---

### 4.7 Screen 4: AI Security Assistant (`AssistantView.tsx`)

#### Purpose
Demonstrates local Small Language Model (SLM) / deterministic template synthesis. Translates technical threat telemetry into jargon-free explanations.

#### Security & Injection Containment Boundary
- **Constitutional Rule:** Untrusted user input is **NEVER** concatenated into prompt instructions.
- The assistant receives strictly tokenized, sanitized `Evidence` structures.
- The assistant has **ZERO AUTHORITY** to alter or reverse the risk score.

#### Interactive Controls
- **Topic Selectors:** Preset simulation topics (`Phishing Credentials`, `Cryptocurrency Extortion`, `Fake Tech Support Invoice`, `Postal Delivery Scam`).
- **Custom Scenario Input:** Allows testing how the assistant formats technical evidence tokens into plain explanations.
- **Reading Level Complexity Selector:**
  - Toggle between `Grade 6 (Plain Language)` and `Grade 8 (Technical Details)`.
- **Output Card:**
  - Structured into: *Executive Summary*, *Threat Mechanics*, *Immediate Action*, *Defensive Advice*.

---

### 4.8 Screen 5: Password & Network Security Monitor (`SecurityDashboardView.tsx`)

#### Purpose
Comprehensive client-side security monitoring with interactive sub-tabs:

#### Sub-Components
1. **Password Checker (`PasswordChecker.tsx`):**
   - Instant client-side entropy calculation without sending password anywhere.
   - Evaluates: Length, character variety, common pattern dictionary, time to crack.
   - Color-coded strength bar: Weak (`#FF5A36`), Fair (`#FFB800`), Strong (`#1DB954`).
2. **Password Generator (`PasswordGenerator.tsx`):**
   - Cryptographically secure random password generation via `window.crypto.getRandomValues()`.
   - Configurable length slider ($12 - 64$ characters), toggles for symbols, numbers, uppercase, lowercase.
   - One-click copy to clipboard with 2-second visual copied checkmark.
3. **Network Monitor (`NetworkMonitor.tsx`):**
   - Monitors client-side outbound destinations, classifying requests into `FIRST_PARTY`, `THIRD_PARTY`, and `UNKNOWN_SUSPICIOUS`.
   - Live telemetry list with simulated request injection to test alert triggers.
4. **Security Alert Banner (`SecurityAlertBanner.tsx`):**
   - Displays real-time security posture status:
     - `🟢 Protected`
     - `🟡 Warning` (e.g., high third-party request volume)
     - `🔴 Attention Required` (suspicious destinations detected)

---

### 4.9 Screen 6: Privacy & Architecture Guarantee (`PrivacyView.tsx`)

#### Purpose
Auditable proof of Privex's privacy-first architecture for technical auditors and end-users.

#### Content & Visual Modules
- **Interactive Data Boundary Diagram:**
  - Tier 1: Sensitive Data (RAM Only, Zero Persistence).
  - Tier 2: Local Encrypted State (AES-256-GCM / SQLCipher).
  - Tier 3: Opt-in Differential Privacy Telemetry.
- **Zero-Cloud Code Verification:**
  - Demonstrates client-side pure function execution via WebAssembly / Web Workers.
- **Local Storage Inspector:**
  - Allows user to view all data stored locally by Privex.
  - One-click **Crypto-Shredding** button: Completely purges all local storage and state keys.

---

### 4.10 Screen 7: User Settings & Policy Management (`SettingsView.tsx`)

#### Purpose
Local persistence configuration and security rule customization.

#### Settings Options
1. **Visual Theme:** Light / Dark / Night radio selector.
2. **Cognitive Reading Grade:** Grade 6 (Simplest) vs. Grade 8 (Technical) radio selector.
3. **Web Worker Offloading:** Toggle switch between background Web Worker thread and direct main-thread execution.
4. **Custom Domain Allowlist:**
   - Input field to add trusted domains (e.g., `internal.company.corp`).
   - Interactive list of allowlisted domains with individual `[Remove]` buttons.
   - Instant validation preventing empty or duplicate domain entries.
5. **Onboarding Intro Tour:**
   - Button `Replay Introduction Tour` triggers `IntroOverlay` to re-run animated product tour.
6. **Factory Reset / Wipe All Data:**
   - Destructive action button with confirmation dialog. Wipes all settings and resets to factory defaults.

---

### 4.11 Onboarding Tour Overlay (`IntroOverlay.tsx`)

#### Purpose
High-engagement 3-scene animated intro for first-time visitors or on-demand replay.

#### Architecture & Scenes
- **Persistence:** Stored in `localStorage.getItem('privex_intro_seen')`.
- **Scene 1: Brand & Doctrine:** Introducing Privex's zero-knowledge on-device mandate.
- **Scene 2: Network & Threat Isolation:** Visualizing threats blocked at the device perimeter.
- **Scene 3: Shield Activation & Readiness:** Interactive `[Enter Shield Dashboard]` completion CTA.
- **Navigation Controls:** `[Skip Tour]`, `[Next Step →]`, and scene progress indicator dots.

---

## 5. COMPLETE RE-USE & IMPLEMENTATION CONTRACT

To guarantee that the UI **never changes and remains 100% identical** whenever and wherever implemented, all implementations MUST adhere to these strict invariants:

### 5.1 Layout & DOM Invariants
1. **Root Element Theme Attribute:** The `<html>` element must always have `data-theme="light"`, `data-theme="dark"`, or `data-theme="night"`.
2. **Brutalist Border Standards:** All card containers must use `border: 2px solid var(--border-dark)`. Rounded pill tags must use `border: 1px solid var(--border-dark)`.
3. **Hard Drop Shadows:** Cards must use `box-shadow: var(--shadow-brutal)` (`4px 4px 0px #111111`) or `var(--shadow-brutal-lg)` (`6px 6px 0px #111111`). No soft blurred Gaussian shadows.
4. **Font Declarations:**
   - Serif headings: `'Playfair Display', Georgia, serif`
   - Sans body: `'Plus Jakarta Sans', -apple-system, sans-serif`
   - Monospace telemetry: `'Space Grotesk', Consolas, monospace`

### 5.2 Behavioral & Logic Invariants
1. **5-Second Friction Gate:** Any threat identified as `DANGEROUS` must enforce a strictly timed 5-second countdown before enabling the override/proceed option.
2. **Fail-Closed Default:** If a scan cannot complete or throws an unhandled error, the UI must render an error/caution state—never a silent `SAFE` pass.
3. **Air-Gap Parity Banner:** If `window.navigator.onLine === false`, the offline status banner must render immediately above `<main>`.
4. **Zero Cloud Payload Guarantee:** The UI form inputs (`URL`, `Message`) must only communicate with local Web Workers or local WebAssembly instances. No HTTP POST or fetch call may ever contain user scan input.

---

## 6. VERIFICATION CHECKLIST FOR UI CONFORMANCE

| Verification Item | Required Behavior | Conformance Status |
|---|---|---|
| **Theme Switching** | Instant palette change across Light, Dark, Night without page reload | **MANDATORY** |
| **Tab Switching** | Instant panel render via state without full page refresh | **MANDATORY** |
| **Keyboard Nav** | Arrow Left/Right navigates between active tab buttons | **MANDATORY** |
| **Friction Timer** | 5s countdown on high-risk threats before override unlock | **MANDATORY** |
| **Offline Mode** | Alert banner displays with air-gapped protection notice | **MANDATORY** |
| **Allowlist Rules** | Added domain immediately overrides warning verdict to ALLOW | **MANDATORY** |
| **Password Entropy** | Cryptographic strength calculated 100% locally in browser | **MANDATORY** |
| **Brutalist Shadows** | Sharp, unblurred 2px, 4px, 6px, and 8px geometric offsets | **MANDATORY** |
