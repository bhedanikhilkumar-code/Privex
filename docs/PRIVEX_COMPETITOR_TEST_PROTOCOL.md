# PRIVEX — Competitor Evaluation & Testing Protocol (Phase 3 Supplement)

> **Document Status:** CANONICAL TESTING PROTOCOL  
> **Target Scope:** Reproducible, Isolated Mobile Security Benchmarking  
> **Standard:** AV-Comparatives / AMTSO Compliant Synthetic Testing  

---

## 1. Principles of Fair Mobile Security Testing

To ensure fair, accurate, and non-biased benchmarking across Android security products, all tests must follow these five rules:

1. **Isolation Guarantee (Zero Cross-Contamination):**
   - Security applications must NEVER be tested simultaneously on the same device. Multiple running VPN services, accessibility listeners, or file monitors will intercept each other's traffic and cause false latency spikes or crashes.
   - Each product must be installed, evaluated, and completely uninstalled on a clean device profile before testing the next product.

2. **Synthetic, Safe Test Fixtures (Zero Live Malware):**
   - Strictly forbidden to execute or handle active live malware.
   - Use standardized test vectors:
     - **EICAR Standard Anti-Virus Test File** (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`).
     - **Deceptive Double Extensions** (e.g. `urgent_invoice.pdf.exe` with MZ header).
     - **Synthesized Phishing URLs** (Punycode homographs, IP-literal hosts, known test patterns).
     - **Synthesized Social Engineering SMS** (Crypto ransom demands, advance-fee fraud, urgent credential resets).

3. **Air-Gapped & Offline Testing Protocol:**
   - Put the device into Airplane Mode with Wi-Fi and Cellular disabled.
   - Execute file and URL inspection tests to measure offline degradation.

4. **Resource Footprint Measurement:**
   - Measure Cold Startup time using `adb shell am start -W`.
   - Measure Resident Memory using `adb shell dumpsys meminfo <package>`.
   - Measure Battery & CPU impact over 60 minutes of background idle.

5. **Transparency of Evidence:**
   - Clearly label every datapoint as `[DOC]` (vendor docs), `[LAB]` (independent test labs), `[OBS]` (directly observed on device), or `[UNV]` (unverified).

---

## 2. Standardized Test Cases & Test Suite

| Test ID | Category | Scenario / Vector | Expected Security Behavior |
|---|---|---|---|
| **TC-BENCH-01** | URL / Phishing | IP-literal URL (`http://192.168.1.1/login.php`) | Warning triggered immediately before user enters credentials. |
| **TC-BENCH-02** | URL / IDN | Homograph attack (`https://xn--pple-43d.com`) | Punycode decoded, brand spoof detected, warning modal shown. |
| **TC-BENCH-03** | SMS / Text | Social engineering crypto demand ("Send 0.5 BTC or data leak") | Analyzed as extortion / scam with risk score > 90. |
| **TC-BENCH-04** | File / Header | Double extension with PE header (`receipt.pdf.exe`) | Flagged as deceptive executable, quarantined or blocked. |
| **TC-BENCH-05** | Offline | Flight mode URL & file inspection | Engine maintains 100% detection capability without internet. |
| **TC-BENCH-06** | Privacy | Network packet capture during scan | Zero outbound HTTP/DNS requests containing scanned target content. |
| **TC-BENCH-07** | Performance | Memory usage under active scan | RAM consumption stays below 65 MB. |

---

## 3. Protocol Execution Summary

This protocol governs all comparative tests and guarantees that Privex's evaluations are scientifically repeatable, objective, and compliant with privacy and ethical standards.
