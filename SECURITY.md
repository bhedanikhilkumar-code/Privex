# SECURITY POLICY & VULNERABILITY DISCLOSURE
## PRIVATE PROTECTION

> **POLICY STATUS:** ACTIVE  
> **CANONICAL VERSION SUPPORTED:** `>= 0.1.0`  

Private Protection takes security and privacy vulnerabilities with utmost seriousness. As a privacy-first cybersecurity platform operating on user endpoints, maintaining the highest standard of defensive engineering is our constitutional imperative.

---

## 1. SUPPORTED VERSIONS

Only the latest active minor release receives official security patches and threat intelligence updates:

| Version | Supported | Security Update Status |
|---|---|---|
| `0.1.x` | :white_check_mark: Yes | Current Active Release (Fully Supported) |
| `< 0.1.0` | :x: No | Unsupported Development Pre-releases |

---

## 2. REPORTING A VULNERABILITY

If you discover a security vulnerability, privacy leak, or flaw in Private Protection, **please do NOT open a public GitHub issue.** Public disclosure puts users at risk.

Instead, report vulnerabilities via one of our private channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Navigate to the repository **Security** tab and click **"Report a vulnerability"** to open a confidential advisory.
2. **Encrypted Security Email:**  
   Send an email to `security@private-protection.local` (or our PGP-signed maintainer contact).

---

## 3. WHAT INFORMATION TO PROVIDE

To help us triage and verify your finding promptly, please include:
- **Description:** A clear explanation of the potential vulnerability and its real-world impact.
- **Affected Subsystem:** Core engine (`@private-protection/core`), ML assistant (`@private-protection/ml`), Web app, Browser extension, Mobile client, or Desktop software.
- **Proof of Concept / Reproduction Steps:** Exact inputs, step-by-step instructions, or automated script demonstrating the behavior.
- **Environment Details:** Operating System (Windows, Android, Linux, macOS), browser version, Node.js version.
- **Proposed Remediation (Optional):** Suggested patch or architectural mitigation.

> [!WARNING]
> **DO NOT** attach live exploit payloads, malicious binaries, private signing keys, or personal credentials to your report.

---

## 4. OUR DISCLOSURE TIMELINE & COMMITMENT

- **Initial Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Severity Assessment:** Within **5 business days**, utilizing CVSS v3.1 scoring.
- **Remediation & Patch Target:** Within **30 days** for Critical/High vulnerabilities; within **90 days** for Medium/Low issues.
- **Public Advisory & Credit:** Upon release of the patch, an advisory will be published and the reporting researcher credited (unless anonymity is requested).

---

## 5. CORE SECURITY & PRIVACY INVARIANTS

Every security review adheres to our foundational project constitution (`AGENTS.md`):
1. **Local-First Processing:** User URLs, message contents, and file bytes must NEVER leave volatile RAM.
2. **Defense-in-Depth:** The AI Security Assistant is strictly an explanatory layer and possesses ZERO AUTHORITY to alter or downgrade deterministic threat verdicts.
3. **Fail-Closed Architecture:** If an input parser encounters malformed or corrupted inputs, it must fail safely to `CAUTION` or `SUSPICIOUS`, never to silent `ALLOW`.
