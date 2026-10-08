# @private-protection/web

> Zero-install, local-first web application for on-device phishing detection, message scam analysis, and password & network security protection.

## Core Capabilities

1. **On-Device URL Security Scanner:** Deterministic rules, Shannon entropy, brand typosquatting, Punycode homographs, and high-risk TLD checks executed 100% locally in browser memory.
2. **Message & Scam Analyzer:** Natural language heuristics detecting urgency pressure, invoice fraud, advance fee scams, and extortion demands.
3. **AI Security Assistant:** Read-only plain-language threat explanations translated directly on the user's device.
4. **Password Security Checker:**
   - Evaluates password length, uppercase, lowercase, numbers, special characters.
   - Detects repeated characters, sequential patterns ("1234", "qwerty"), and common breach dictionary passwords.
   - Computes Shannon entropy and displays a real-time color-coded strength meter.
   - Zero transmission guarantee: evaluated entirely client-side; never sent over network or logged.
5. **Strong Password Generator:**
   - Generates high-entropy passwords using `window.crypto.getRandomValues()` (never `Math.random()`).
   - Customizable character classes: Uppercase, Lowercase, Numbers, Symbols.
   - Excludes ambiguous symbols and similar characters (e.g., `l`, `1`, `I`, `0`, `O`) on demand.
   - Automatic copy-to-clipboard with instant strength evaluation.
6. **URL & Network Request Monitor:**
   - Observes application-level outbound traffic in volatile RAM.
   - Categorizes requests as First-Party, Third-Party, or Unknown/Suspicious (e.g., numeric IPs, high-abuse TLDs).
   - Sanitizes all request URLs to redact query tokens, session IDs, passwords, and API keys.
7. **Request Overload Detection:**
   - Sliding-window frequency tracking per domain.
   - Configurable thresholds (`requestOverloadThreshold = 50`, `timeWindowMs = 10000ms`).
   - Flags `HIGH_REQUEST_ACTIVITY` alerts when anomalous burst patterns occur.
8. **Security Alerts & Account Notifications:**
   - Reusable `SecurityEvent` dispatch mechanism.
   - Visual alert banner prompting users to review activity or update account passwords upon threat detection.

## Privacy & Security Guarantees

- **100% Client-Side Processing:** All evaluations occur in volatile browser RAM.
- **Zero Logging of Sensitive Inputs:** Passwords and credential inputs are never saved in `localStorage`, `sessionStorage`, or backend databases.
- **Sanitized URL Telemetry:** Query parameters matching authentication keywords are masked with `[REDACTED]`.
- **Browser Sandbox Limitations:** Monitoring observes application fetch/XHR network interactions; cannot inspect external OS sockets or other browser tabs.

## Development & Testing

```bash
# Run tests
npm run test

# Run type check
npm run typecheck

# Build for production
npm run build
```
