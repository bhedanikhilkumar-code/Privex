# User Flow Specification - PRIVEX

This document outlines the conceptual user interaction flows for the PRIVEX on-device AI security assistant.

## Core Interaction Flows

### 1. User opens a suspicious URL
*   **Trigger:** User clicks or navigates to a URL in the browser.
*   **Detection (Invisible):** Browser extension intercepts the request and runs local rule/heuristic checks.
*   **Warning (Visible):** If flagged as suspicious, the extension blocks the page load and displays a full-page warning overlay.
*   **Actions:**
    *   **Primary Action (Safe):** "Go Back to Safety" (returns to previous page).
    *   **Secondary Action (Educational):** "Why is this dangerous?" (opens explanation panel).
    *   **Tertiary Action (Risky):** "Proceed Anyway" (small text, requires secondary confirmation).
*   **Explanation Panel:** Displays the specific reasons (e.g., "This site mimics a bank login but the domain is newly registered.").

### 2. User receives suspicious SMS/message
*   **Trigger:** User receives an SMS or chat message containing a link, phone number, or known phishing pattern.
*   **Detection (Invisible):** Mobile app scans incoming messages in the background using NLP classification.
*   **Warning (Visible):** System pushes a high-priority, customized notification: "Caution: Suspicious Message Detected". The message preview masks active links.
*   **Actions:**
    *   User taps notification -> Opens a detailed view within the app.
    *   Detailed view highlights the suspicious elements (e.g., urgency markers, unsafe links).
*   **Explanation Panel:** Explains why the message is flagged (e.g., "This message uses urgent language typical of scams and contains a hidden link").

### 3. User downloads suspicious file
*   **Trigger:** File download completes via browser or other application.
*   **Detection (Invisible):** Desktop app intercepts the file creation event and runs signature/heuristic scans.
*   **Warning (Visible):** A prominent desktop notification appears: "Threat Blocked: Suspicious File Quarantined".
*   **Actions:**
    *   Clicking notification opens the quarantine vault.
    *   Options: "Delete File" (default), "View Scan Results", "Restore File (Not Recommended)".
*   **Explanation Panel:** Shows malware type (e.g., "Ransomware signature detected") and potential impact.

### 4. User scans a QR code
*   **Trigger:** User points mobile camera at a QR code using the built-in scanner or the Privex app.
*   **Detection (Invisible):** URL is extracted and analyzed before opening the browser.
*   **Warning (Visible):** If suspicious, the scanner UI pauses and overlays a red caution banner on the viewfinder.
*   **Actions:**
    *   "Cancel Scan" (default).
    *   "View Details" (shows extracted URL and risk assessment).
*   **Explanation Panel:** Highlights mismatched domains or known malicious infrastructure.

### 5. User manually submits text/URL
*   **Trigger:** User pastes text or a URL into the web dashboard or standalone app analyzer.
*   **Detection (Visible):** A progress spinner indicates analysis is running (under 300ms).
*   **Warning (Visible):** Results are displayed in a dashboard widget with a clear risk gauge (Safe, Low Risk, High Risk, Critical).
*   **Actions:** Evidence is listed directly below the gauge.
*   **Explanation Panel:** Integrated directly into the results view with expandable sections for detailed AI analysis.

### 6. User receives a warning
*   **Information Hierarchy:**
    1.  **Risk Level (Visual):** Color-coded shield (Red = Danger, Orange = Warning, Yellow = Caution, Green = Safe).
    2.  **Headline:** Clear, concise statement (e.g., "Phishing Site Detected").
    3.  **Evidence Summary:** Bullet points (e.g., "Fake login form", "Hidden redirects").
    4.  **Recommended Action:** Prominent button (e.g., "Close Tab").
    5.  **Educational Hook:** "Why is this dangerous?" link.

### 7. User taps "Why is this dangerous?"
*   **Trigger:** User wants more context on a warning.
*   **Action:** An AI-generated, natural language explanation expands in a modal or side panel.
*   **Content:** The AI assistant provides a human-readable narrative based on the technical evidence, without using jargon. It explains *how* the attack works.

### 8. User wants recommended action
*   **Trigger:** User reads the warning and wants to proceed safely.
*   **System Suggestion:** The primary button is always the safest action (e.g., "Go Back", "Delete File", "Block Sender").
*   **Alternative Actions:** "Report as False Positive", "Ignore with Caution" are de-emphasized.

### 9. User disagrees with detection
*   **Trigger:** User believes a safe item was flagged (False Positive).
*   **Action:** User clicks "Report as False Positive" or "Proceed Anyway".
*   **Feedback Mechanism:** A quick form asks for optional feedback ("I know this sender", "This is a company portal").
*   **System Update:** Feedback is logged locally (and optionally sent anonymously) to improve future heuristic weights.

### 10. User is offline
*   **State:** Device has no internet connection.
*   **Functionality:**
    *   **Works:** Local rule/heuristic checks, quantized local AI inference, cached signature scans.
    *   **Degrades:** Cloud lookups, advanced ML models (if not downloaded), real-time URL reputation checks.
*   **UI Indication:** A small "Offline Mode" indicator appears on warnings. Warnings may state: "Based on local analysis, this appears suspicious."

## Warning Design Principles
*   **Fast:** Appear within milliseconds to prevent user action.
*   **Understandable:** Plain language, zero technical jargon.
*   **Actionable:** Clear, distinct buttons for next steps.
*   **Non-alarming without evidence:** Use confidence-based warning levels (Informational → Caution → Warning → Danger).
*   **Explainable:** Every warning includes a "Why?" option for transparency.
*   **Dismissible:** User retains final control (with appropriate friction for high-risk items).
