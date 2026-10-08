# PRIVEX: Product Scope Specification

## 1. Product Vision & Overview
PRIVEX is a multi-platform security ecosystem designed to provide an intelligent, conversational AI Security Assistant. Its primary directive is to detect phishing, scams, and malicious content purely on-device, prioritizing user privacy, low latency, and offline availability.

---

## 2. Platform Scope and Value Propositions

### 2.1 Shared Detection Engine (Core)
* **Scope:** In-Scope. The foundational C++/Rust/C library encapsulating the on-device ML models, NLP pipelines, and threat heuristics.
* **Target Users:** Internal engineering teams (used across all downstream platforms).
* **Use Cases:** URL analysis, text scam evaluation, content parsing.
* **Value Proposition:** Write-once, deploy-anywhere architecture ensuring consistent detection logic and resource-efficient performance across mobile, desktop, and browsers.

### 2.2 Mobile Application (Android / iOS)
* **Scope:** In-Scope.
* **Target Users:** Everyday consumers, elderly users prone to SMS/email scams.
* **Use Cases:** Background scanning of SMS messages, parsing links shared via messaging apps (WhatsApp, Telegram), clipboard scanning (opt-in).
* **Value Proposition:** Constant, invisible protection on the user's most personal and frequently targeted device, acting instantly before a malicious link is tapped.

### 2.3 Desktop Security Software (Windows / macOS)
* **Scope:** In-Scope.
* **Target Users:** Remote workers, students, general consumers.
* **Use Cases:** User-space recursive filesystem scanning (Quick Scan, Full Scan, Custom Folder/File Scan), real-time ingress directory monitoring (`Downloads` and `Temp`), executable magic-byte/entropy/double-extension inspection via `@private-protection/core`, and AES-256-GCM (`PPVAULT1`) quarantine isolation and restoration.
* **Value Proposition:** Comprehensive local-first protection against malicious downloads, deceptive executables, spear-phishing, and social engineering targeting desktop environments, operating 100% offline.

### 2.4 Browser Extension (Chrome / Firefox / Edge)
* **Scope:** In-Scope.
* **Target Users:** Heavy web users, online shoppers, enterprise employees.
* **Use Cases:** Real-time DOM scanning for malicious content, URL analysis before page load, overlaying warnings on detected phishing input fields.
* **Value Proposition:** Deep, context-aware protection right at the point of interaction with the web, preventing credential theft.

### 2.5 AI Security Assistant (UI/UX)
* **Scope:** In-Scope.
* **Target Users:** All users across all platforms.
* **Use Cases:** Providing clear, conversational explanations of *why* a block occurred (e.g., "This message creates false urgency and asks for money, which is a common scam tactic.").
* **Value Proposition:** Security education and transparency, reducing the friction and confusion typically associated with generic "Access Denied" screens.

### 2.6 Optional Backend Services
* **Scope:** In-Scope (Strictly limited).
* **Target Users:** System administrators, product telemetry systems.
* **Use Cases:** Delivering updated threat models/blocklists to clients, receiving anonymized, aggregated telemetry data (differential privacy enforced).
* **Value Proposition:** Keeps the offline on-device engines up-to-date with the evolving threat landscape without compromising individual user privacy.

---

## 3. Out-of-Scope (Excluded from Current Vision)

The following areas are explicitly **out-of-scope** for the PRIVEX product suite:
1. **Cloud Data Processing Engines:** Any architecture that requires sending user messages, emails, or browsing history to a remote server for AI inference or analysis.
2. **Kernel-Mode Endpoint Detection and Response (Kernel EDR):** Ring-0 kernel drivers, OS registry hooking, or invasive kernel process injection/termination (note: standard user-space filesystem scanning, ingress directory monitoring, and AES-256-GCM quarantine are **in-scope** under Section 2.3).
3. **Network Level Firewall / VPN:** Routing user traffic, deep packet inspection (DPI) of network streams, or IP/port blocking.
4. **Identity and Access Management (IAM):** Password management, SSO solutions, or multi-factor authentication generation.

---

## 4. Future Scope

The following items are deferred for future iterations:
1. **Web Application / Enterprise Dashboard:** A centralized management console for IT teams to deploy PRIVEX to employee fleets and manage security policies.
2. **Deep Voice/Audio Deepfake Detection:** Expanding on-device models to analyze live audio streams for AI-generated voice scams.
3. **Automated Incident Remediation:** Allowing the assistant to take autonomous actions (e.g., automatically deleting confirmed scam emails from an inbox via API).
