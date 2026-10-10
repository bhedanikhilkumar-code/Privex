# Privex v0.1.2 (Release 1.2)

### 🌐 Live Web Application (On-Device Zero-Install PWA)
- **Primary Cloudflare Pages URL:** [https://privex.pages.dev/](https://privex.pages.dev/)
- **GitHub Pages Mirror:** [https://bhedanikhilkumar-code.github.io/Privex/](https://bhedanikhilkumar-code.github.io/Privex/)
- **100% Client-Side On-Device Security Engine:** Instant phishing detection, URL lexical analysis, scam SMS evaluation, password strength auditor, and website exposed entry point / port auditor running directly inside your browser without cloud data transmission.

## What's New in v0.1.2
- **🛡️ Offline Website Open Points & Port Auditor (All Platforms):**
  - Identifies open and exposed entry points where threat actors can compromise a website or origin server (Port 21 FTP, Port 22 SSH, Port 80 HTTP, Port 3306 MySQL, Port 3389 RDP, Port 5432 Postgres, Port 6379 Redis, Port 8080 dev, etc.).
  - Detects exposed sensitive paths (`/.env`, `/.git`, `/actuator`, `/admin`, `/xmlrpc.php`, `/wp-content/uploads/`).
  - Provides clear, jargon-free explanations of how hackers exploit each weak point (brute force, credential stuffing, MITM, remote code execution).
  - Supplies actionable step-by-step remediation blueprints and copyable server configuration snippets (Nginx, Apache, UFW).
- **📱 Background Phone Guardian (Continuous Auto-Scan on Mobile):**
  - Runs periodic background security posture audits, app permission checks, and threat intel validations.
  - 100% on-device local RAM processing without sending user browsing or app data to the cloud.
  - Native push notification alerts on threat anomaly detection.
- **🏫 University & Educational Portal Presets:**
  - Integrated quick audit presets for `https://atmiyauni.ac.in/` across Desktop, Mobile, and Web.

## Verification
- **Full Test Suite:** PASS across Core, UI, Desktop, Extension, Mobile, and Web workspaces.
- **Air-Gapped Parity:** 100% local-first on-device execution; zero Tier-1 payload exfiltration.
- **Binary Integrity:** All release binaries verified with cryptographic SHA-256 hashes.

## Release Artifacts
| Filename | Platform | SHA-256 |
|---|---|---|
| `PrivateProtection-0.1.2-win-x64.exe` | Windows 10/11 x64 (Portable) | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` |
| `PrivateProtection-Setup-0.1.2.exe` | Windows 10/11 x64 (Installer) | `0b9a894a992f5f43e3c964c69e3b1ec60d2d2b9cc7f3c899eaeafb5b3ab9ebe9` |
| `private-protection-mobile-0.1.2.apk` | Android 8.0+ Direct Distribution APK | `be48757f791f287136d8725c4e8cf2faf4eda9f4f340da84f1661b793fe137bd` |
| `private-protection-mobile-0.1.2.aab` | Android App Bundle (AAB) | `8340e3cfa7a55b1d9a89685d5920260af7804edd9e9fd55ba8aecc1e97228ffb` |
| `private-protection-web-0.1.2.zip` | Web Application Client Bundle | `53d691018616d756faf82013ef2f30627ecd4184bd19231315b1944ac94a2e63` |
| `private-protection-extension-0.1.2.zip` | Chromium MV3 Browser Extension | `167aa2c212781a1a5cc21194fe1d9ef6c8948ff063c8932a9a7b432ec8a4a2cc` |
