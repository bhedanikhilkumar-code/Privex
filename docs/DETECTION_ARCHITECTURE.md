# PRIVATE PROTECTION: Detection Architecture

## 1. Layered Detection System

To ensure a robust, low-latency, and privacy-preserving security posture, the PRIVATE PROTECTION assistant employs a 7-layered detection architecture. This structure ensures fast paths for known threats while reserving computationally expensive AI models for novel or ambiguous scenarios.

### 1.1 Deterministic Rules
- **Purpose:** Immediate classification of known threats with zero false positives.
- **Mechanism:** Regex-based checks, URL pattern matching (e.g., typosquatting of top 500 domains), embedded hardcoded blacklists, and known-bad file hashes (SHA-256).

### 1.2 Heuristics
- **Purpose:** Fast, rule-like evaluation of suspicious indicators that don't match specific signatures.
- **Mechanism:** Behavioral signals (e.g., executable hidden in an image), linguistic cues (e.g., highly urgent language paired with cryptocurrency mentions), structural anomalies (e.g., unusually high entropy in URLs).

### 1.3 Reputation & Threat Intelligence
- **Purpose:** Leverage global context for local decisions.
- **Mechanism:** Secure, privacy-preserving lookups (e.g., k-Anonymity or hash prefixes) against updated threat feeds. Checks domain age, certificate validity, and URL reputation. Heavily utilizes locally cached subsets of global threat intel.

### 1.4 Machine Learning Models
- **Purpose:** Detect variations of known threats and novel attacks using statistical patterns.
- **Mechanism:** On-device classifiers (Random Forests, LightGBM, small Neural Networks). Tasks include NLP for scam categorization, 1D CNNs for DGA (Domain Generation Algorithm) detection, and visual similarity for phishing page templates.

### 1.5 Local AI Models
- **Purpose:** Deep contextual understanding of content without compromising privacy.
- **Mechanism:** Quantized SLMs (Small Language Models, e.g., 2B-4B parameters) running via ONNX/CoreML/NPU. Evaluates zero-day phishing, complex social engineering, and semantic intent.

### 1.6 Optional Cloud AI
- **Purpose:** Handle edge cases requiring massive compute (e.g., complex binary sandboxing or large-scale web crawling).
- **Mechanism:** Strictly opt-in. Data is anonymized and stripped of PII before leaving the device. Used only when local confidence is critically low and the risk ceiling is high.

### 1.7 AI Security Assistant
- **Purpose:** Translate technical detection logic into actionable, human-readable advice.
- **Mechanism:** Local SLM generates natural language summaries ("This message claims your bank account is frozen, but the link points to a newly registered Russian domain. Do not click.").

---

## 2. Universal Detection Pipeline

Every piece of analyzed content follows a unified pipeline:

**Input** $\rightarrow$ **Normalization** (decoding, de-obfuscation) $\rightarrow$ **Static/Rule Analysis** (L1/L2) $\rightarrow$ **Threat Intelligence Lookup** (L3) $\rightarrow$ **ML/AI Analysis** (L4/L5) $\rightarrow$ **Risk Aggregation** (Scoring) $\rightarrow$ **Decision** (Block/Warn/Allow) $\rightarrow$ **Explanation** (AI Assistant) $\rightarrow$ **User Warning** (UI Rendering).

---

## 3. Detection Modalities

### 3.1 URL Analysis
*   **Pipeline:** Extract URL $\rightarrow$ Expand shorteners (if safe) $\rightarrow$ Parse components $\rightarrow$ Regex/Heuristics $\rightarrow$ Reputation check $\rightarrow$ ML classifier.
*   **Signals:** TLD legitimacy, domain age, typosquatting distance, path entropy, presence of brand names.
*   **Confidence:** High (if matched on threat feed/regex). Medium-High (if ML flags high entropy + typosquatting).
*   **Offline/Online:** Fully offline for heuristics/ML and cached feeds. Online required for real-time reputation and URL unshortening.

### 3.2 Message/Text Analysis (SMS, Email, Chat)
*   **Pipeline:** Extract text $\rightarrow$ Strip formatting $\rightarrow$ Heuristic keyword match $\rightarrow$ On-device NLP (intent classification) $\rightarrow$ Entity extraction (links, phone numbers).
*   **Signals:** Urgency, authority impersonation, financial requests, poor grammar mixed with corporate tone.
*   **Confidence:** Relies heavily on the presence of actionable items (links/numbers) combined with malicious intent. Text alone has lower confidence to prevent FPs.
*   **Offline/Online:** 100% offline using local SLMs/NLP models.

### 3.3 File Analysis
*   **Pipeline:** Hash extraction $\rightarrow$ Local blacklist check $\rightarrow$ File structure parsing (Magic numbers, PE headers) $\rightarrow$ Static heuristic analysis $\rightarrow$ ML malware classification.
*   **Signals:** Entropy, packed executables, suspicious imports, macro presence in documents.
*   **Confidence:** High for hash matches. Moderate for ML classification (prone to FPs with legitimate obfuscated software).
*   **Offline/Online:** Offline static analysis. Cloud required for dynamic detonation (sandboxing) if opted-in.

### 3.4 QR Code Analysis
*   **Pipeline:** Image processing $\rightarrow$ QR decoding $\rightarrow$ Payload extraction $\rightarrow$ Route to URL/Text/App pipeline based on payload.
*   **Signals:** Hidden parameters, custom URI schemes (e.g., forced app launches), intent to connect to rogue Wi-Fi.
*   **Confidence:** Inherits the confidence of the payload's specific pipeline (e.g., URL pipeline).

### 3.5 Screenshot/Visual Analysis
*   **Pipeline:** OCR text extraction $\rightarrow$ Object detection (Logos, UI elements) $\rightarrow$ Visual similarity embedding $\rightarrow$ Comparison against known-safe UI baselines.
*   **Signals:** Brand logo presence mismatched with origin (e.g., Chase logo on non-Chase domain), overlaid invisible UI elements (clickjacking).
*   **Confidence:** Moderate. Highly dependent on lighting, resolution, and OCR accuracy.
*   **Offline/Online:** 100% offline via NPU/GPU accelerated vision models.

### 3.6 Page Content (DOM) Analysis
*   **Pipeline:** Extract DOM $\rightarrow$ Remove scripts (safe view) $\rightarrow$ Parse forms and external resource links $\rightarrow$ NLP on page text $\rightarrow$ ML classifier on DOM structure.
*   **Signals:** Password fields on non-HTTPS, form action URLs pointing to different domains, obfuscated JavaScript.
*   **Confidence:** High when combined with URL analysis.

---

## 4. Risk Scoring System (Deliverable 3)

The risk scoring system translates raw signals into a unified metric that drives UX decisions.

### 4.1 Risk Categories
*   **Malware:** Intent to distribute malicious software or exploit vulnerabilities.
*   **Phishing:** Intent to steal credentials or sensitive data via impersonation.
*   **Scam:** Social engineering intended to extract financial resources (e.g., romance, crypto, tech support).
*   **Suspicious:** Anomalous behavior lacking definitive malicious signatures, but exhibiting high-risk indicators.
*   **Safe:** Verified clean, or no suspicious indicators found.

### 4.2 Risk Factors & Weights
Final Score = $\sum (Factor\_i \times Weight\_i) \times Confidence\_Multiplier$
*   *Deterministic Match (e.g., PhishTank):* +100 (Weight: 1.0)
*   *ML Intent Classification (Scam):* +75 (Weight: 0.8)
*   *Heuristic (Urgency + Link):* +40 (Weight: 0.6)
*   *Domain Age < 7 Days:* +30 (Weight: 0.5)
*   *Valid EV Certificate:* -20 (Weight: 0.5)

### 4.3 Confidence and Severity Levels
*   **Confidence (0.0 to 1.0):** How certain the system is of its assessment. 
    *   High (>0.9): Cryptographic match, known-bad hash.
    *   Medium (0.6-0.89): ML model consensus, strong heuristic cluster.
    *   Low (<0.6): Single anomalous signal, conflicting model outputs.
*   **Severity (1 to 5):** The potential impact to the user.
    *   Level 5: Device compromise (RCE, Malware).
    *   Level 4: Total account loss (Credential Phishing).
    *   Level 3: Financial fraud (Crypto Scam).
    *   Level 2: Privacy risk (Aggressive trackers, adware).
    *   Level 1: Spam / Unwanted communication.

### 4.4 Thresholds and Outcomes
*   **Score > 85 (BLOCK):** Automatic interception. User must manually override deep in settings.
*   **Score 60 - 84 (WARNING):** Full-screen or modal warning. Requires active user dismissal ("I understand the risk").
*   **Score 30 - 59 (INFORMATIONAL):** Inline banner or subtle indicator (e.g., yellow shield). AI provides contextual caution.
*   **Score < 30 (SAFE):** Invisible operation.

### 4.5 Evidence Chain & User-Facing Language
Every score > 30 generates an Evidence Chain array, fed into the local LLM to generate user-friendly explanations.
*   *Technical Evidence:* `[URL_ENTROPY_HIGH, DOMAIN_AGE_2_DAYS, NLP_INTENT_URGENCY]`
*   *User-Facing Translation:* "This sender is trying to create a false sense of urgency, and the link they provided was created only 2 days ago. This is a common tactic in phishing attacks."

### 4.6 Handling Layer Disagreements
*   **Rule > AI:** If a deterministic rule flags a known-bad hash, it overrides an AI model that says the file is safe.
*   **AI Context > Heuristic FP:** If a heuristic flags "Wire Transfer" as a scam, but the local AI determines the context is a legitimate conversation with a known family member, the AI suppresses the heuristic penalty.
*   **Safe-Fail:** In events of complete unresolvable disagreement with high severity potential, the system defaults to "Suspicious" (Informational warning) rather than a hard block, preserving user agency.
