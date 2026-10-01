# PHASE_4_IMPLEMENTATION_PLAN.md — Web Application Dashboard & Zero-Install Client-Side Security Scanner

> **SYSTEM STATUS: PHASE 4 ACTIVE IMPLEMENTATION**  
> **CANONICAL IMPLEMENTATION PLAN — `apps/web`**  
> Governed by: `AGENTS.md`, `docs/WEB_TECHNICAL_ARCHITECTURE.md`, `docs/SECURITY_ARCHITECTURE.md`, `docs/PRIVACY_ARCHITECTURE.md`, `docs/OFFLINE_ARCHITECTURE.md`.

---

## 1. EXECUTIVE MISSION & PURPOSE

Phase 4 implements `apps/web`: a zero-install, privacy-first web application dashboard providing local-first cyber-threat detection and AI security assistant explanations.

### Cardinal Web Doctrine
```
USER PAYLOAD (URL, Message Text)
      │
      ▼
BROWSER ENVIRONMENT
      │
      ▼
LOCAL IN-MEMORY PROCESSING (Web Worker / Main Thread)
      │
  ┌───┴─────────────────────────────────────────┐
  ▼                                             ▼
@private-protection/core              @private-protection/ml
(Deterministic Engine)                (AI Assistant Runtime)
  │                                             │
  └───┬─────────────────────────────────────────┘
      ▼
STRUCTURED RESULT & EXPLANATION (Purely Client-Side UI)
```

**ABSOLUTE DIRECTIVE**: **ZERO HTTP TRANSMISSION OF USER DATA**.
No user message, URL, file, or credential is ever transmitted over network sockets to any web server, cloud endpoint, or external API.

---

## 2. WEB APPLICATION ARCHITECTURE & DIRECTORY STRUCTURE

```
apps/web/
├── package.json                   # @private-protection/web; depends on @private-protection/core, @private-protection/ml
├── tsconfig.json                  # Strict ES2022 TypeScript configuration
├── vitest.config.ts               # Component and integration testing setup with jsdom
├── public/
│   ├── manifest.json              # PWA manifest
│   ├── sw.js                      # Progressive Web App offline Service Worker (Cache-First app shell)
│   ├── favicon.ico
│   └── icons/
├── src/
│   ├── index.html                 # Shell HTML with strict CSP meta tag
│   ├── main.tsx                   # Client entry point
│   ├── app/                       # Routing & main dashboard views
│   │   ├── App.tsx                # Main container with tab-based navigation
│   │   └── routes.ts              # Navigation items (Home, URL Scan, Message Scan, Assistant, Privacy, Settings)
│   ├── components/                # Accessible, reusable UI components
│   │   ├── layout/
│   │   │   ├── Header.tsx         # App bar with local privacy badge
│   │   │   ├── Navigation.tsx     # Responsive tab navigation bar
│   │   │   └── Footer.tsx         # WCAG compliant status footer
│   │   ├── scanner/
│   │   │   ├── UrlScannerView.tsx # Interactive URL input and fast-path inspection
│   │   │   ├── TextScannerView.tsx# Multiline suspicious communication analyzer
│   │   │   └── ResultCard.tsx     # Color-coded verdict, risk meter, evidence list
│   │   ├── assistant/
│   │   │   └── AssistantView.tsx  # Interactive AI Security Assistant explanation panel
│   │   ├── privacy/
│   │   │   └── PrivacyView.tsx    # Transparent privacy information, network isolation proof
│   │   └── settings/
│   │       └── SettingsView.tsx   # Offline cache status, allowlist overrides, local state reset
│   ├── lib/                       # Utility libraries and state adapters
│   │   ├── formatters.ts          # Score badges, accessible color maps, date formats
│   │   └── storage.ts             # Non-sensitive client preferences (zero user payload retention)
│   ├── scanner/                   # Client-side scanner integration orchestration
│   │   ├── client-scanner.ts      # Direct integration with @private-protection/core & ml
│   │   └── types.ts               # UI state models and scan history interfaces
│   ├── workers/                   # Background execution
│   │   ├── detection-worker.ts    # Dedicated Web Worker for non-blocking intensive scans
│   │   └── worker-bridge.ts       # Type-safe worker client with main-thread fallback
│   └── __tests__/                 # Comprehensive test suite
│       ├── unit/                  # Scanner orchestration, formatting, storage tests
│       ├── components/            # UI rendering, accessibility, and form validation tests
│       ├── privacy/               # Network isolation tests (0 external requests during scans)
│       └── integration/           # End-to-end scanner pipeline simulation tests
```

---

## 3. CORE SUBAGENTS & ROLES

1. **WEB ARCHITECT AGENT**: Package structure, module exports, build configuration, TypeScript types.
2. **UI/UX AGENT**: Dashboard components, URL/text scanner views, result cards, responsive mobile/desktop layouts.
3. **SECURITY & PRIVACY AGENT**: XSS prevention, closed Shadow DOM/safe string escapes, strict CSP, network isolation tests.
4. **PWA & OFFLINE AGENT**: Service Worker cache strategy, PWA manifest, air-gapped execution verification.
5. **ACCESSIBILITY AGENT**: WCAG 2.1 AA keyboard navigation, ARIA attributes, focus states, color contrast compliance.
6. **QA & PERFORMANCE AGENT**: Automated test suites, micro-latency benchmarks, network spying tests.

---

## 4. BROWSER EXECUTION & WASM/TS DECISION

- **Engine Implementation**: `@private-protection/core` and `@private-protection/ml` are written in pure ES2022 TypeScript with zero native C/C++ bindings.
- **Architectural Decision**: Running compiled TypeScript directly in the browser JavaScript engine (V8 / SpiderMonkey / JavaScriptCore) achieves sub-millisecond execution ($p50 < 0.2\text{ ms}$ for core detection pipeline and $< 0.01\text{ ms}$ for ML assistant).
- **Zero Fake WASM**: Per Master Prompt Rule #13, we do NOT manufacture fake WASM glue layers. The direct client-side execution model is authentic, zero-overhead, and 100% compliant.

---

## 5. NETWORK PRIVACY ASSURANCE PROTOCOL

The test suite will enforce network spying on all scanning operations:
- Intercepts `window.fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, and `navigator.sendBeacon`.
- Verifies that zero bytes of user data leave the browser during:
  1. URL scanning
  2. Text / Message scanning
  3. AI Security Assistant explanation synthesis
  4. Error / Malformed payload handling
