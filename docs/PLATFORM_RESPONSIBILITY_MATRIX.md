# Platform Responsibility Matrix

## Overview
PRIVATE PROTECTION is designed to run across multiple platforms, providing seamless, on-device AI security. This document details the exact responsibilities, boundaries, and capabilities of each platform in the ecosystem.

## Platforms
1. **Mobile App** (Android/iOS)
2. **Desktop Software** (Windows/macOS)
3. **Browser Extension** (Chrome/Firefox/Edge)
4. **Web Application** (Dashboard)
5. **Local Detection Engine** (Shared core library)
6. **Backend Service** (Optional/Minimal)

---

## Capability Mapping

| Capability | Mobile App | Desktop App | Browser Ext | Web App | Shared Engine | Backend (Opt) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SMS/Message Analysis | **Primary** | Secondary | N/A | N/A | Execution | N/A |
| User-submitted text | **Primary** | **Primary** | Secondary | **Primary** | Execution | Optional Fallback |
| Screenshot/Image | **Primary** | **Primary** | N/A | Secondary | Execution | Optional Fallback |
| QR Code Scanning | **Primary** | Secondary | N/A | N/A | Execution | N/A |
| URL/Link Scanning | **Primary** | **Primary** | **Primary** | **Primary** | Execution | Threat Intel Sync |
| Website Risk (Browsing) | Secondary | Secondary | **Primary** | N/A | Execution | N/A |
| Suspicious Redirect | N/A | N/A | **Primary** | N/A | Execution | N/A |
| Phishing Detection | Secondary | Secondary | **Primary** | N/A | Execution | N/A |
| File/Download Scan | Secondary | **Primary** | Secondary | N/A | Execution | N/A |
| Local File Monitor | N/A | **Primary** | N/A | N/A | Execution | N/A |
| System-Level Protection| N/A | **Primary** | N/A | N/A | Execution | N/A |
| Real-time Alerts | **Primary** | **Primary** | **Primary** | N/A | Triggers | N/A |
| Security Assistant AI | **Primary** | **Primary** | Secondary | **Primary** | Execution | Cloud-assisted |
| Security Dashboard | **Primary** | **Primary** | Secondary | **Primary** | N/A | Sync (Opt) |
| Manual Submissions | **Primary** | **Primary** | **Primary** | **Primary** | Execution | N/A |
| Account/Settings | **Primary** | **Primary** | Secondary | **Primary** | N/A | **Primary** |
| Education Content | **Primary** | **Primary** | Secondary | **Primary** | N/A | Content Delivery |
| Threat Intel Updates | Fetch/Apply | Fetch/Apply | Fetch/Apply | Fetch | N/A | **Primary** |
| Model Updates | Fetch/Apply | Fetch/Apply | N/A | N/A | N/A | **Primary** |
| Offline Detection | **Primary** | **Primary** | **Primary** | N/A | Execution | N/A |
| Cloud-Assisted | Secondary | Secondary | Secondary | Secondary | N/A | **Primary** |

---

## Detailed Platform Breakdown

### 1. Mobile App (Android/iOS)
**Primary Responsibilities:**
- SMS and message content scanning (via Notification Listener/SMS APIs).
- QR Code scanning and validation via camera.
- Screenshot and image analysis.
- Serving as the main hub for the Security Assistant AI.
- Providing on-the-go real-time notifications for malicious links.

**What it does NOT do:**
- Deep system-level OS monitoring.
- In-browser DOM parsing (relies on Web/Extension for that).

**Constraints & Permissions:**
- Battery and memory constrained; requires aggressive model quantization.
- Requires `READ_SMS`, `CAMERA`, `READ_EXTERNAL_STORAGE` (Android).
- iOS requires Safari Extension integration for browser protection.

**Offline Capabilities:**
- Full offline URL analysis and SMS filtering based on quantized local ML models and cached Bloom filters.

### 2. Desktop Software (Windows/macOS)
**Primary Responsibilities:**
- Local file system monitoring and download scanning.
- System-level protection and deep file analysis.
- Managing large-scale ML models that require more RAM/Compute.
- High-performance screenshot/image analysis.

**What it does NOT do:**
- SMS/Carrier level message scanning.
- Direct DOM manipulation (handled by extension).

**Constraints & Permissions:**
- Requires file system access and system accessibility permissions.
- Higher storage budget allows for more comprehensive models.

**Offline Capabilities:**
- Unrestricted offline detection with higher precision models than mobile.

### 3. Browser Extension
**Primary Responsibilities:**
- Real-time website risk detection and DOM analysis.
- Suspicious page and redirect warning.
- Phishing page detection via visual and structural heuristics.
- Intercepting and scanning downloads.

**What it does NOT do:**
- System file scanning.
- Running massive LLMs natively (relies on WASM or communicates with Desktop App).

**Constraints & Permissions:**
- Manifest V3 constraints (service workers, background execution limits).
- Requires `activeTab`, `webRequest`, `downloads` permissions.

**Offline Capabilities:**
- Relies on WASM-compiled rules and Bloom filters for offline phishing/URL checks. 

### 4. Web Application (Dashboard)
**Primary Responsibilities:**
- Cross-platform Security history/dashboard.
- Account and subscription management.
- Centralized hub for manual URL/text submission and security education.

**What it does NOT do:**
- Device-level monitoring.
- Offline execution.

### 5. Local Detection Engine (Shared)
**Primary Responsibilities:**
- Core execution environment for AI inference and rule matching.
- Uniform URL Analyzer, Message Analyzer, Content Analyzer, and File Analyzer.
- Ensures detection parity across Mobile, Desktop, and Extension (via Rust/C++ or WASM).

### 6. Optional Backend
**Primary Responsibilities:**
- Threat intelligence aggregation and update distribution (OTA updates).
- Providing heavy cloud-assisted analysis when user explicitly opts in or local confidence is low.
- Serving model updates and rule definitions.

**What it does NOT do:**
- Store raw user data, PII, or full messages (Privacy-first design).
