# EXTENSION_PERMISSION_JUSTIFICATION.md — Manifest V3 Permission Minimization

> **CANONICAL SPECIFICATION — PRIVACY & PERMISSIONS AUDIT**  
> Evaluated under Chrome Web Store Least Privilege Guidelines & `AGENTS.md`.

---

## 1. PRINCIPLE OF LEAST PRIVILEGE

PRIVATE PROTECTION enforces strict privilege minimization. Every permission requested in `manifest.json` is audited, technically bounded, and constrained so that the extension cannot exceed its operational necessity.

```
┌────────────────────────────────────────────────────────────────────────┐
│ EXTENSION MANIFEST V3 PERMISSIONS MATRIX                               │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ Permission        │ Classification    │ Technical Purpose              │
├───────────────────┼───────────────────┼────────────────────────────────┤
│ "webNavigation"   │ Sensitive         │ Pre-navigation URL intercept   │
│ "storage"         │ Standard          │ Local preferences & session    │
│ "activeTab"       │ Minimal / Ephemeral│ User-initiated popup check     │
│ "tabs"            │ Standard          │ Redirect tab to warning page   │
│ "<all_urls>"      │ Host Match Pattern│ Intercept any inbound URL      │
└───────────────────┴───────────────────┴────────────────────────────────┘
```

---

## 2. DETAILED PERMISSION BREAKDOWNS

### A. `"webNavigation"`
- **Why Required**: To catch phishing, typosquatting, and malicious IP hosts **before** the browser dispatches HTTP requests or executes remote JavaScript.
- **Data Accessed**: Target navigation URL (`details.url`), navigation transition type (`details.transitionType`), and tab ID (`details.tabId`).
- **Data Privacy Guarantee**: The URL string is parsed exclusively in volatile local RAM. Zero bytes of navigation telemetry are logged to disk or transmitted over the network.
- **Why Unavoidable**: Declarative blocking alone cannot perform advanced brand typosquatting Levenshtein math or Shannon entropy analysis on dynamic subdomains.

### B. `"storage"`
- **Why Required**:
  1. `chrome.storage.local`: Persists user settings (protection toggle, cognitive reading grade, user allowlists).
  2. `chrome.storage.session`: Retains ephemeral scan verdicts and temporary user override tokens across Service Worker idle terminations.
- **Data Accessed**: Extension-specific preference records. Does **not** access website storage, cookies, or other extensions' data.
- **Why Unavoidable**: Manifest V3 Service Workers terminate after 30 seconds of inactivity; session storage is the standard browser mechanism for persistent in-memory state.

### C. `"activeTab"`
- **Why Required**: When the user opens the toolbar popup, allows the popup to inspect the URL of the focused tab to render the threat breakdown without requiring permanent cross-tab permissions.
- **Data Accessed**: Current active tab URL and tab ID.
- **Why Unavoidable**: Ensures users can view real-time safety assessments on-demand.

### D. `"tabs"`
- **Why Required**: When a URL is evaluated as `DANGEROUS` (risk score $\ge 85$), the extension calls `chrome.tabs.update(tabId, { url: interstitialUrl })` to replace the dangerous destination with the local security warning page.
- **Data Accessed**: Tab ID and target redirect URL. Does **not** read tab history or capture screenshots.
- **Why Unavoidable**: Modern browsers do not allow blocking and redirecting navigation in `webNavigation.onBeforeNavigate` without redirecting the tab via the tabs API or DeclarativeNetRequest.

### E. Host Permission (`"<all_urls>"`)
- **Why Required**: Cyber threats emerge from unknown domains, newly registered TLDs (`.buzz`, `.xyz`, `.top`), IP hosts, and typo-squatted variations across the entire internet. To shield users, the extension must inspect arbitrary destination URLs upon navigation.
- **Data Privacy Guarantee**: 100% of inspections occur locally inside `@private-protection/core`. Zero browsing data leaves the device.

---

## 3. PROHIBITED PERMISSIONS AUDIT

The following permissions are strictly **PROHIBITED** from `manifest.json`:

| Prohibited Permission | Risk Prevented | Constitutional Mandate |
|---|---|---|
| `cookies` | Session hijacking / cookie theft | Zero access to user auth tokens. |
| `webRequestBlocking` | Deprecated in MV3 / excessive privilege | Replaced by safe `webNavigation` + local redirect. |
| `history` | Browsing tracking | Extension never inspects past browsing history. |
| `management` | Cross-extension interference | Prohibited; isolated operation only. |
| `identity` | PII leakage | No account sign-in or cloud identity required. |
| `geolocation` | Physical location tracking | Zero location access. |
| `debugger` | Deep process manipulation | Prohibited. |

---

## 4. PERMISSION REVIEW CONCLUSION

The permission set is minimal, safe, transparent, and completely traceable to the functional requirements of PS-05.
