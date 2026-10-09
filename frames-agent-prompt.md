# Design Export Context

- Generated at: `2026-10-09T18:01:28.096Z`
- Document ID: `4627e3db-4cca-4e8c-818e-3418fea4aa31`
- Page count: 10

## Original Prompt

```text
# PRIVEX — COMPLETE ANDROID MOBILE SECURITY APP UI/UX MASTER DESIGN

## 1. ROLE AND MISSION

Act as a senior Android product designer, cybersecurity UX architect, design-system specialist, accessibility expert, and mobile interaction designer.

Design a complete, premium-quality Android security application called **PRIVEX**.

Privex is a privacy-first, on-device security application that helps users inspect suspicious links, messages, QR codes, and files; understand security risks; monitor protection status; review quarantined items; generate secure passwords; and manage privacy and security settings.

The goal is to transform the current basic mobile interface into a cohesive, modern, production-oriented mobile product.

This is a complete application design task, not merely a dashboard redesign.

Design all major screens, reusable components, navigation states, dialogs, sheets, loading states, empty states, errors, and important user journeys. Maintain a consistent design system across the entire app.

**Design first. Do not invent or implement a new security engine.**

## 2. EXISTING REPOSITORY AND TECHNICAL CONTEXT

Target repository:
https://github.com/bhedanikhilkumar-code/Privex

Current mobile application:

* `apps/mobile/`
* React 18
* TypeScript
* Vite
* Existing Android application with a WebView-based React interface
* Native Android Java services exposed through `AndroidSecurityBridge`
* Shared security logic in `@private-protection/core` and `@private-protection/ml`

Existing application entry:

* `apps/mobile/src/App.tsx`

Existing navigation:

* `apps/mobile/src/components/TabBar.tsx`

Existing screens include:

* `HomeScreen.tsx`
* `UrlScannerScreen.tsx`
* `TextScannerScreen.tsx`
* `FileScannerScreen.tsx`
* `QrScannerScreen.tsx`
* `ScanResultScreen.tsx`
* `AssistantScreen.tsx`
* `ProtectionStatusScreen.tsx`
* `PrivacyScreen.tsx`
* `SettingsScreen.tsx`
* `PasswordGeneratorScreen.tsx`

Existing shared components include:

* `SecurityBadge`
* `DevicePostureCard`
* `EvidenceCard`
* `FrictionGateModal`
* `PreThreatWarningModal`

These files establish existing capabilities and integration points. Before proposing final designs, inspect the actual repository where possible. Do not assume every service supports a capability merely because a design would benefit from it.

The root `design.md` describes Windows desktop UX. Do not copy its desktop sidebar or fixed desktop window geometry into the Android application.

The final visual design must be realistic to implement within the existing React/TypeScript mobile application. Do not require a complete rewrite in Jetpack Compose or a new backend.

## 3. PRODUCT DESIGN PRINCIPLES

Design Privex around these principles:

1. Security should feel reassuring and understandable, not frightening.
2. Make the protection state immediately understandable.
3. Put the most common security actions within one or two taps.
4. Present clear explanations before exposing technical evidence.
5. Use progressive disclosure for advanced settings and security details.
6. Never display fake live telemetry, invented scan counts, fabricated detections, or unsupported protection claims.
7. Never imply that the application has privileged Android capabilities that an ordinary third-party application does not possess.
8. Keep all major actions accessible on smaller Android phones.
9. Support light and dark themes with a complete semantic color system.
10. Use accessible contrast, readable typography, generous touch targets, and consistent component behavior.

Target feeling:

**Professional cybersecurity product + calm confidence + modern Android usability + trustworthy privacy-first design.**

Avoid a generic admin dashboard squeezed onto a phone.

## 4. VISUAL DIRECTION

Create a distinctive visual identity for Privex.

### Overall style

* Mobile-first Android application.
* Refined, premium, clean, trustworthy, and slightly technical.
* Use a restrained combination of cards, clear typography, semantic color, and subtle depth.
* Prefer a neutral surface system with a memorable security accent.
* Use simple, consistent line icons.
* Use subtle transitions rather than excessive animations.
* Avoid excessive gradients, neon cyberpunk effects, glowing borders, giant shields, decorative circuit backgrounds, and random emoji icons.
* Do not make every section a separate heavily bordered card.
* Avoid unnecessarily dense tables and desktop-style layouts.

### Suggested color tokens

Use these as a starting point and refine them into a harmonious system.

Dark theme:

* Main background: `#0B1220`
* Elevated surface: `#111B2E`
* Secondary surface: `#172338`
* Primary accent: `#38BDF8`
* Primary text: `#F1F5F9`
* Secondary text: `#A7B4C8`
* Divider: `#27364B`

Light theme:

* Main background: `#F5F7FB`
* Elevated surface: `#FFFFFF`
* Secondary surface: `#EDF2F8`
* Primary accent: `#0369A1`
* Primary text: `#142033`
* Secondary text: `#526176`
* Divider: `#DCE4EF`

Semantic colors:

* Protected / safe: green with readable text and icon.
* Informational: blue.
* Attention / suspicious: amber.
* High risk: orange.
* Confirmed critical threat: red.
* Unknown / unavailable: neutral gray.

Do not communicate security state through color alone. Every status must also have a label and suitable icon.

Create semantic tokens for:

* `color.background`
* `color.surface`
* `color.surfaceElevated`
* `color.textPrimary`
* `color.textSecondary`
* `color.border`
* `color.accent`
* `color.safe`
* `color.info`
* `color.warning`
* `color.danger`
* `color.unknown`
* `color.disabled`

### Typography

Use a modern Android-friendly sans-serif typeface, similar to Inter or Roboto.

Suggested hierarchy:

* Screen title: 24–28sp
* Section title: 18–20sp
* Card title: 16sp
* Body: 14–16sp
* Supporting text: 12–14sp
* Small technical metadata: never below 12sp for important content

Use short, clear labels and sentence-case copy. Avoid unnecessary all-caps labels.

### Layout and touch targets

* Design primarily for 360–430dp-wide Android screens.
* Support smaller phones, large text, and display scaling.
* Use approximately 16–20dp horizontal page padding.
* Maintain an 8dp spacing rhythm.
* Provide at least 48dp touch targets for important controls.
* Respect Android status bars, navigation bars, safe areas, and keyboard visibility.
* Forms must not become obscured by the software keyboard.
* Use scrolling content rather than fixed-height layouts that clip on small screens.

## 5. APPLICATION NAVIGATION

The existing application has ten primary destinations:

* Home
* URL Scanner
* Message Scanner
* QR Scanner
* File Scanner
* Password Generator
* Security Assistant
* Protection Status / Engine
* Privacy Center
* Settings

Design a cleaner navigation model without losing these capabilities.

Preferred direction:

* Bottom navigation with five primary destinations:

  1. Home
  2. Scan
  3. Activity
  4. Vault
  5. More

* The Scan destination opens a dedicated scan hub with URL, Message, QR, and File scanning options.

* Activity contains recent scan history and notification-related activity only where the existing data supports it.

* Vault opens the existing quarantine-management functionality and must clearly distinguish quarantined items from ordinary scan history.

* More opens a polished list or grid of secondary destinations:

  * Security Assistant
  * Protection Status
  * Password Generator
  * Privacy Center
  * Settings

Treat this as a proposed navigation redesign. Clearly map every existing destination to its new route. Do not remove existing routes or services.

If an implementation constraint makes this navigation unsuitable, provide an alternative that keeps the bottom navigation usable on narrow phones. Do not put all ten items in a tiny horizontally scrolling bottom bar.

Use:

* Clear active state
* Accessible selected labels
* Navigation badges only for genuine, available counts
* Consistent back navigation
* Confirmation only for consequential operations
* No dead navigation elements

## 6. SCREEN 01 — HOME / PROTECTION DASHBOARD

Create the most polished and important screen in the application.

### Header

* Privex icon and wordmark.
* Greeting such as “Your security overview”.
* Compact protection status indicator.
* Settings shortcut.
* Optional notification shortcut only if backed by an actual destination or supported UI.

### Protection hero

Design a compact but visually distinctive hero showing:

* Current overall security posture.
* A plain-language status such as “Protection is active”, “Needs attention”, “Protection is paused”, or “Status unavailable”.
* A short explanation of what that status means.
* A clear action to inspect protection details.

Do not always show “Protected” or a perfect score. The status must come from real application state.

Provide separate visual states for:

* Healthy
* Warning
* Risk / critical
* Protection paused
* Unknown
* Loading
* Failed to retrieve status

Do not fabricate a numerical protection score. Show one only if a real score exists in the implementation.

### Quick actions

Create four prominent actions:

* Scan a link
* Scan a message
* Scan a QR code
* Inspect a file

Each action must have:

* A consistent icon
* Short title
* Brief explanation
* Appropriate visual priority
* A defined navigation destination

### Protection summary

Create compact sections for:

* Protection / engine status
* Threat intelligence status
* Adaptive battery / thermal mode
* Quarantine summary
* Recent scans

Only display values returned by real services. If a value is unavailable, use a neutral “Unavailable” or “Not yet checked” state.

### Recent activity

Each activity item should show:

* Scan type
* Sanitized target summary
* Verdict
* Timestamp
* Optional risk score, if actually present
* Tap action to open the corresponding result

Provide a helpful empty state for first-time users.

## 7. SCREEN 02 — SCAN HUB

Create a dedicated scanning home.

Use a clear grid or vertically stacked action cards:

* Link / URL Scan
* Message / SMS Scan
* QR Code Scan
* File Inspection

Each card must explain what the scan does and how to begin.

Include:

* Optional recent scan summary
* Short privacy statement: “Analysis runs on your device” only when this matches actual execution behavior.
* Accessible touch targets
* Clear selected/loading states

Do not design a universal “scan entire phone” action unless it is explicitly available and accurately scoped in the application.

## 8. SCREEN 03 — URL / PHISHING SCANNER

Create a modern link scanner.

### Components

* Screen header and back button.
* URL input field.
* Paste action.
* Clear input action.
* Scan button.
* Optional input validation message.
* Small privacy explanation.
* Example URL helper that never looks like a real dangerous live site.

### Behavior and states

* Empty input: scan action disabled or helpful validation.
* Malformed input: clear validation message.
* Valid input: scanning state.
* Successful analysis: navigate to Scan Result.
* Service error: retryable error state.
* Long URL: wrap safely without breaking the layout.
* Dangerous result: clear warning and recommended safe action.

Do not show a success message before the scan actually completes.

## 9. SCREEN 04 — MESSAGE / SMS SCANNER

Design a scanner for suspicious messages, SMS text, emails, and copied content.

### Components

* Large accessible multiline text field.
* Paste action.
* Clear action.
* Character count if a real limit is enforced.
* Scan Message button.
* Privacy note.
* Optional sample demonstration separated clearly from real scanning.

### States

* Empty
* Input validation error
* Scanning
* Safe / allowed result
* Suspicious result
* Dangerous result
* Error / retry

Do not persist raw message content in scan history merely for visual convenience. Respect the existing data-minimization boundary.

## 10. SCREEN 05 — QR CODE SCANNER

Create a camera-first QR scanning interface.

### Components

* Camera preview region.
* Focus / scan frame.
* Start Camera button when inactive.
* Stop Camera control when active.
* Camera permission explanation.
* Torch control only if implemented and supported.
* Clear scanning status.
* Manual retry / permission settings action when appropriate.

### States

* Checking camera support
* Permission requested
* Camera active
* QR found / processing
* No QR detected
* Permission denied
* Camera unavailable
* Scan error
* Result ready

Do not simulate a functioning live camera in the final implementation. Stitch may illustrate the camera preview, but label it as a preview if it is only a design placeholder.

On camera shutdown or navigation away, the design must anticipate a clean stop of the camera stream.

## 11. SCREEN 06 — FILE INSPECTION

Create a trustworthy file inspection screen.

### Main layout

* File selection card.
* “Choose a file” action.
* Supported-content guidance based on real capabilities.
* Selected file summary:

  * File name
  * File type
  * File size
* Inspect File button.
* Progress / analysis status.
* Results and evidence.

### States

* No file selected
* File picker open
* File selected
* Empty file
* Unsupported or malformed content
* Inspecting
* Safe / suspicious / dangerous
* Inspection error

Important security requirement:
A design that allows the user to select a file must not imply that the application recursively scans every file on the device. Respect Android scoped storage and the actual Storage Access Framework integration.

If only header inspection is available for a particular path, say “File structure inspection” rather than claiming a complete malware scan.

Do not use sample simulation buttons as if they inspected real user files.

## 12. SCREEN 07 — UNIVERSAL SCAN RESULT

This is a critical reusable screen shared by URL, message, QR, and file scanners.

Create one consistent result layout.

### Result header

* Verdict icon
* Plain-language verdict title
* Semantic status badge
* Scan target type
* Risk score only if supplied by the real result

### Summary card

* Sanitized target summary
* Short explanation
* Timestamp
* Confidence, threat category, and execution duration only if available

### Four explanation sections

Use the product’s plain-language explanation contract:

1. What happened?
2. Why does it matter?
3. What did Privex do?
4. What should you do next?

Make the recommendation visually prominent and understandable to non-technical users.

### Evidence section

Use expandable evidence rows with:

* Detection reason
* Evidence category
* Rule identifier when available
* Score contribution when actually supplied
* Plain-language description

Do not fabricate evidence or display internal fields as if they were authoritative when unavailable.

### Actions

Actions depend on verdict and supported capabilities:

* Scan another item
* Return Home
* Review details
* Open the relevant quarantine workflow if a real quarantined item exists
* Retry only when appropriate

For consequential actions, design confirmation and clear outcome states.

A scan result must not be called “quarantined” until quarantine actually succeeds. Distinguish:

* Threat detected
* Action recommended
* Quarantine requested
* Quarantine succeeded
* Quarantine failed
* Original source file remains

## 13. SCREEN 08 — SECURITY ASSISTANT

Design a clear, friendly security explanation interface.

The assistant is an explanation layer, not the authority that determines security verdicts.

### Components

* Assistant header
* Short explanation of its role
* Suggested questions / topics
* Explanation card
* Simple / technical reading-level control
* Expandable technical evidence
* Copy explanation action where safe

### Behavior

* Generate an explanation from actual security evidence.
* Loading state.
* Deterministic fallback explanation if the assistant is unavailable.
* Error state.
* No fabricated analysis.
* No authority to change a verdict, risk score, security policy, or protection settings.

Use concise explanations by default. Keep advanced technical evidence optional.

## 14. SCREEN 09 — PROTECTION STATUS / ENGINE

Create a protection health center.

### Sections

* Overall security posture
* Threat database health and last verified update when available
* Quarantine status and counts
* Adaptive resource mode:

  * Normal
  * Battery saver
  * Thermal throttling
  * Low-memory mode
  * Deferred / partial work where applicable
* Protection feature availability
* Clear explanation of any degraded functionality

### Behavior

* Refresh status.
* Loading state.
* Unavailable service state.
* Degraded status.
* Retry.
* Open the relevant Android system settings when the existing native bridge supports it.

Do not use fake live charts or invented performance metrics. Static illustrative graphics should be identified as illustrative in the design handoff.

## 15. SCREEN 10 — QUARANTINE / VAULT

Design a secure, understandable quarantine-management experience.

### Summary

* Quarantined item count if actually available.
* Vault health.
* Storage usage if available.
* Plain-language explanation that quarantined items are isolated.

### Quarantine list

Each row may show:

* Sanitized file name
* File type
* Detection reason
* Date
* Isolation status
* Expandable details

### Detail screen / bottom sheet

* Item details
* Why it was quarantined
* Current isolation state
* Restore action
* Permanently delete / secure deletion action only when genuinely supported
* Cancel / return

### Restore workflow

Use an explicit confirmation flow:

1. User selects Restore.
2. Explain the risk.
3. Show the exact intended destination if available.
4. Require confirmation.
5. Show a truthful progress state.
6. Display verified success or failure.

Never make “Restore” and “Delete permanently” look like equivalent primary actions.

Do not imply that an original file was removed if the source remains on the device.

## 16. SCREEN 11 — PRIVACY CENTER

Design a privacy and permissions center with eight inspection areas where supported by the existing service.

### Summary

* Privacy status
* Last checked time
* Read-only audit explanation
* Refresh / recheck action

### Inspection cards

Display the real categories returned by `PermissionsPrivacyService`, including their status and recommended action.

Each card should contain:

* Category
* Current status
* Plain-language explanation
* Why it matters
* Optional “Open Android Settings” action when supported

### Data transparency

Add a clear, accurate section explaining:

* What stays on-device
* What data is retained locally
* Whether any optional network update is performed
* Which permissions are used and why

Do not claim “zero data leaves the device” in contexts where threat-intelligence updates or another explicitly supported network operation may occur. Explain the actual data boundaries accurately.

### Destructive action

If secure data purging is exposed, put it in a separate clearly labeled destructive section. Use confirmation and explain what will be erased before executing it.

## 17. SCREEN 12 — PASSWORD GENERATOR

Create a premium password and passphrase generator.

### Modes

* Password
* Passphrase

### Password options

* Length control
* Uppercase
* Lowercase
* Numbers
* Special characters
* Avoid ambiguous characters
* Avoid similar characters
* Preset selection

### Passphrase options

* Word count
* Separator
* Capitalization
* Include number

### Result area

* Generated secret shown in a readable but privacy-conscious field
* Copy action
* Regenerate action
* Optional show/hide action
* Clear copied feedback
* Error state

### Security behavior

* Use the existing cryptographically secure generator.
* Do not create passwords in the design layer.
* Do not display a fake strength score unless the underlying implementation provides a reliable calculation.
* Do not log or persist generated passwords.
* Clipboard clearing must be described only if the actual implementation performs it.
* Avoid exposing a password in notifications or analytics.

## 18. SCREEN 13 — SETTINGS

Organize settings into understandable groups.

### Protection

* Main protection toggle
* Real-time scanning setting where implemented
* Notification preferences
* Haptic alert preference where implemented

### Web protection

* Trusted-domain allowlist
* Add trusted domain
* Remove trusted domain
* Clear validation errors
* Explain the impact of trust exceptions

### Notifications

* Security alerts
* Download alerts
* Scan completion
* Protection health
* Threat updates
* Channel status where exposed by the existing bridge

### Preferences

* Simple / technical explanation level
* Theme: System, Light, Dark if implemented
* Privacy shortcuts
* About Privex
* App version from real metadata

### Interaction rules

* Toggles show their real persisted state.
* Save / failure feedback must be truthful.
* Do not claim a setting is enabled before persistence succeeds.
* Important security-weakening actions require clear explanation and confirmation.
* Use accessible switch labels and helper text.

## 19. SCREEN 14 — ACTIVITY AND SCAN HISTORY

Create a clean chronological activity interface using actual stored scan-history records.

### Components

* Search / filter if implemented
* Filter by URL, Message, QR, File
* Verdict filter
* Chronological rows
* Empty state
* Loading state
* Error state
* Tap to open saved result details when enough data exists

Do not retain or expose raw messages, full sensitive paths, passwords, or unnecessary personal information.

If a record contains only sanitized metadata, show only that metadata and do not invent missing details.

## 20. SECURITY WARNING MODAL

Design a reusable, accessible warning modal for pre-threat warnings.

### Content

* Severity
* Clear warning title
* Target summary
* Why the item appears risky
* Recommended safe action
* Expandable technical evidence
* Secondary action to dismiss or review, where allowed

### Interactions

* Primary safe action
* Review details
* Dismiss if policy permits
* Optional friction-gated override flow

For security-lowering overrides:

* Explain the risk before proceeding.
* Show the required countdown when the real payload specifies one.
* Keep the recommended safe action visually prominent.
* Require explicit user action.

Never make an override easier or more prominent than the safe option.

## 21. SHARED COMPONENT LIBRARY

Create a reusable component library, not one-off screen decorations.

Design these components with consistent sizing, variants, and interaction states:

1. `AppHeader`
2. `PrivexLogo`
3. `ProtectionStatusHero`
4. `SecurityBadge`
5. `DevicePostureCard`
6. `QuickActionCard`
7. `ScanTypeCard`
8. `SectionHeader`
9. `PrimaryButton`
10. `SecondaryButton`
11. `DestructiveButton`
12. `IconButton`
13. `TextInput`
14. `MultilineInput`
15. `FileSelectionCard`
16. `ScanProgressIndicator`
17. `ScanResultHero`
18. `RiskScoreDisplay` — only when a real score exists
19. `EvidenceCard`
20. `ExplanationPillars`
21. `ActivityListItem`
22. `QuarantineItemCard`
23. `PrivacyAuditCard`
24. `SettingsRow`
25. `AccessibleSwitch`
26. `FilterChip`
27. `EmptyState`
28. `ErrorState`
29. `LoadingSkeleton`
30. `InlineStatusMessage`
31. `ConfirmationBottomSheet`
32. `FrictionGateModal`
33. `PreThreatWarningModal`
34. `BottomNavigation`
35. `MoreMenuSheet`
36. `PermissionExplanationSheet`
37. `Toast / InlineFeedback`

For each component, specify:

* Default appearance
* Active / selected state
* Disabled state
* Loading state if relevant
* Success / warning / error variants if relevant
* Text wrapping behavior
* Touch target
* Accessibility label
* Keyboard and focus behavior
* Responsive behavior

Use consistent iconography, corner radii, spacing, and typography.

## 22. INTERACTION AND LOGIC SPECIFICATION

For each screen, provide an interaction table containing:

* Component
* Initial state
* User action
* Validation
* Loading state
* Service operation
* Success outcome
* Error outcome
* Navigation destination
* Data that may be displayed
* Accessibility behavior

The UI is a presentation layer. Actual security decisions must remain inside the existing core, native services, and typed service adapters.

Use the following logical patterns:

### Scan flow

`Idle → Validating → Scanning → Result`

Error branch:
`Scanning → Error → Retry or Cancel`

### File flow

`No File → File Selected → Inspecting → Inspection Result`

Do not assume that selecting a file means the file has been fully scanned.

### QR flow

`Camera Inactive → Permission / Support Check → Camera Active → Decoding → Result`

Provide permission-denied and camera-unavailable states.

### Settings flow

`Current Value → User Changes Value → Persist → Confirm New Value`

On persistence failure, show the previous confirmed value or a clearly labeled uncertain state. Never falsely report success.

### Quarantine flow

`Item Isolated → Restore Requested → Confirmation → Restoring → Verified Result`

### Notification flow

Render actual notification state, permission status, and outcomes. Do not manufacture unread counts or pretend a suppressed notification was delivered.

### General state management

* Use typed data contracts.
* Keep transient form state local to the relevant screen.
* Preserve navigation state when appropriate.
* Handle stale asynchronous results.
* Disable duplicate submissions while an operation is running.
* Provide retry and cancellation where supported.
* Prevent destructive actions from firing twice.
* Keep sensitive content out of logs and persistent UI history.

## 23. ACCESSIBILITY REQUIREMENTS

Design for WCAG 2.2 AA principles and Android usability.

Include:

* Accessible color contrast
* Visible keyboard focus where applicable
* Semantic labels
* Logical reading order
* Screen-reader-friendly status announcements
* Large touch targets
* Text resizing without clipping
* No color-only status indicators
* Clear error text associated with form fields
* Reduced-motion-friendly interactions
* Modal focus management
* Keyboard avoidance

Do not communicate security state using only green, yellow, orange, or red.

## 24. REQUIRED DESIGN STATES

For every major screen, design the states relevant to that screen:

* Initial / idle
* Loading
* Success
* Safe / allowed
* Suspicious / warning
* Dangerous / critical
* Unknown / unavailable
* Error
* Empty data
* Permission denied
* Offline / stale threat intelligence where relevant
* Degraded protection
* Disabled controls
* Confirmation modal
* Long content and narrow viewport

Do not draw every possible state as a separate full screen if a reusable component or sheet is more appropriate. Clearly document the variants.

## 25. REQUIRED STITCH DELIVERABLES

Produce the following:

### A. Complete visual system

* Color palette
* Typography scale
* Spacing tokens
* Corner-radius tokens
* Elevation / shadow rules
* Icon style
* Button variants
* Status colors and labels
* Light and dark theme
* Component variants

### B. High-fidelity screens

Generate polished designs for:

1. Home / Protection Dashboard
2. Scan Hub
3. URL Scanner
4. Message Scanner
5. QR Scanner
6. File Inspection
7. Scan Result — Safe
8. Scan Result — Suspicious
9. Scan Result — Dangerous
10. Security Assistant
11. Protection Status / Engine
12. Quarantine / Vault
13. Quarantine Item Details and Restore Confirmation
14. Privacy Center
15. Password Generator
16. Settings
17. Activity / Scan History
18. Pre-Threat Warning
19. Permission Denied / Recovery
20. General Error / Retry

### C. Reusable component sheet

Show the component variants and states in a structured component library.

### D. Navigation map

Show the route structure, tab mapping, back behavior, sheets, dialogs, and major navigation paths.

### E. Interaction specification

Document each major action, validation, loading state, success result, error result, and confirmation step.

### F. Responsive examples

Show at least:

* A narrow Android phone around 360dp
* A typical phone around 393–412dp
* A larger phone around 430dp

### G. Developer handoff

For each screen, provide:

* Screen name and purpose
* Component hierarchy
* Layout measurements
* Design tokens used
* Interactive states
* Data fields consumed
* Service integration points
* Empty/loading/error behavior
* Accessibility notes

## 26. DESIGN QUALITY BAR

The result should feel like a polished, credible cybersecurity application that a real user would trust with security decisions.

Prioritize:

* A visually strong but compact Home screen
* Excellent readability
* Simple scan initiation
* Clear scan results
* Honest protection-state messaging
* Excellent warning and confirmation UX
* Consistent reusable components
* A manageable navigation structure
* Privacy and security transparency
* Clean, responsive Android layouts

Do not produce a Windows desktop interface, wide desktop dashboard, admin panel, or oversized left sidebar.

Do not add fake analytics, invented threats, fake real-time charts, fake scan percentages, or unsupported device-wide capabilities.

Do not alter the existing security engine or invent new permissions, backend endpoints, or native bridge methods.

## 27. FINAL OUTPUT FORMAT

Present the design in this order:

1. Product design direction
2. Mobile information architecture
3. Design system and tokens
4. Navigation map
5. Home screen high-fidelity design
6. Scan hub and scanning screens
7. Result and warning screens
8. Assistant, status, vault, privacy, password, and settings screens
9. Reusable component library
10. Loading / empty / error / permission states
11. Interaction and state specification
12. Responsive and accessibility notes
13. Developer handoff and implementation mapping

Start with the **Home / Protection Dashboard** and the shared design system. Then create the remaining screens using the same design language.

The deliverable must be cohesive, detailed, implementable, and faithful to Privex’s existing mobile security capabilities.
```

## Theme (JSON)

```json
{
  "schema_version": 2,
  "fonts": {
    "primary": "google:Inter",
    "secondary": "google:Manrope",
    "mono": "google:JetBrains Mono"
  },
  "colors": {
    "light": {
      "primary": "#0369A1",
      "on_primary": "#FFFFFF",
      "primary_container": "#0369A11A",
      "on_primary_container": "#142033",
      "secondary": "#526176",
      "on_secondary": "#FFFFFF",
      "secondary_container": "#5261761A",
      "on_secondary_container": "#142033",
      "accent": "#0EA5E9",
      "on_accent": "#FFFFFF",
      "accent_container": "#0EA5E91A",
      "on_accent_container": "#142033",
      "background": "#F5F7FB",
      "on_background": "#142033",
      "secondary_background": "#EDF2F8",
      "surface": "#FFFFFF",
      "on_surface": "#142033",
      "surface_variant": "#F1F5F9",
      "on_surface_variant": "#526176",
      "primary_text": "#142033",
      "secondary_text": "#526176",
      "hint": "#94A3B8",
      "outline": "#DCE4EF",
      "divider": "#E2E8F0",
      "success": "#10B981",
      "on_success": "#FFFFFF",
      "warning": "#F59E0B",
      "on_warning": "#FFFFFF",
      "error": "#EF4444",
      "on_error": "#FFFFFF",
      "info": "#3B82F6",
      "on_info": "#FFFFFF",
      "transparent": "#00000000",
      "full_contrast": "#000000"
    },
    "dark": {
      "primary": "#38BDF8",
      "on_primary": "#FFFFFF",
      "primary_container": "#38BDF824",
      "on_primary_container": "#F1F5F9",
      "secondary": "#A7B4C8",
      "on_secondary": "#FFFFFF",
      "secondary_container": "#A7B4C824",
      "on_secondary_container": "#F1F5F9",
      "accent": "#0EA5E9",
      "on_accent": "#FFFFFF",
      "accent_container": "#0EA5E924",
      "on_accent_container": "#F1F5F9",
      "background": "#0B1220",
      "on_background": "#F1F5F9",
      "secondary_background": "#111B2E",
      "surface": "#172338",
      "on_surface": "#F1F5F9",
      "surface_variant": "#1E293B",
      "on_surface_variant": "#A7B4C8",
      "primary_text": "#F1F5F9",
      "secondary_text": "#A7B4C8",
      "hint": "#64748B",
      "outline": "#27364B",
      "divider": "#1E293B",
      "success": "#34D399",
      "on_success": "#FFFFFF",
      "warning": "#FBBF24",
      "on_warning": "#000000",
      "error": "#F87171",
      "on_error": "#FFFFFF",
      "info": "#60A5FA",
      "on_info": "#FFFFFF",
      "transparent": "#00000000",
      "full_contrast": "#FFFFFF"
    }
  },
  "text_styles": {
    "display_large": {
      "font": "primary",
      "size": 60,
      "weight": 800,
      "height": 1.1
    },
    "display_medium": {
      "font": "primary",
      "size": 48,
      "weight": 800,
      "height": 1.1
    },
    "display_small": {
      "font": "primary",
      "size": 40,
      "weight": 800,
      "height": 1.1
    },
    "headline_large": {
      "font": "primary",
      "size": 34,
      "weight": 800,
      "height": 1.2
    },
    "headline_medium": {
      "font": "primary",
      "size": 28,
      "weight": 800,
      "height": 1.2
    },
    "headline_small": {
      "font": "primary",
      "size": 24,
      "weight": 800,
      "height": 1.2
    },
    "title_large": {
      "font": "primary",
      "size": 22,
      "weight": 700,
      "height": 1.3
    },
    "title_medium": {
      "font": "primary",
      "size": 18,
      "weight": 700,
      "height": 1.4
    },
    "title_small": {
      "font": "primary",
      "size": 15,
      "weight": 700,
      "height": 1.4
    },
    "body_large": {
      "font": "secondary",
      "size": 17,
      "weight": 400,
      "height": 1.6
    },
    "body_medium": {
      "font": "secondary",
      "size": 15,
      "weight": 400,
      "height": 1.5
    },
    "body_small": {
      "font": "secondary",
      "size": 13,
      "weight": 400,
      "height": 1.5
    },
    "label_large": {
      "font": "secondary",
      "size": 15,
      "weight": 800,
      "height": 1.2
    },
    "label_medium": {
      "font": "secondary",
      "size": 13,
      "weight": 800,
      "height": 1.2
    },
    "label_small": {
      "font": "secondary",
      "size": 11,
      "weight": 800,
      "height": 1.2
    }
  },
  "spacing": {
    "none": 0,
    "xs": 4,
    "sm": 8,
    "md": 16,
    "lg": 24,
    "xl": 32,
    "xxl": 48,
    "xxxl": 64
  },
  "radii": {
    "none": 0,
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 20,
    "xl": 32,
    "xxl": 40,
    "full": 9999
  },
  "shadows": {
    "none": {
      "color": "#00000000",
      "dx": 0,
      "dy": 0,
      "blur": 0,
      "spread": 0
    },
    "xs": {
      "color": "#0000000D",
      "dx": 0,
      "dy": 2,
      "blur": 4,
      "spread": 0
    },
    "sm": {
      "color": "#0000001A",
      "dx": 0,
      "dy": 4,
      "blur": 8,
      "spread": 0
    },
    "md": {
      "color": "#0000001A",
      "dx": 0,
      "dy": 8,
      "blur": 16,
      "spread": 0
    },
    "lg": {
      "color": "#0000001A",
      "dx": 0,
      "dy": 12,
      "blur": 24,
      "spread": 0
    },
    "xl": {
      "color": "#00000033",
      "dx": 0,
      "dy": 20,
      "blur": 40,
      "spread": 0
    },
    "xxl": {
      "color": "#0000004D",
      "dx": 0,
      "dy": 32,
      "blur": 64,
      "spread": 0
    }
  },
  "gradients": {}
}
```

## Pages

### 1. Home Dashboard

- Frame ID: `frame1`
- Original page prompt: "Main protection overview with security posture hero, quick action scan buttons, and recent activity feed."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "stack",
            "properties": {
              "height": {
                "px": {
                  "value": 440,
                  "isInfinity": false
                }
              }
            },
            "children": [
              {
                "type": "shader_fill",
                "properties": {
                  "preset": {
                    "stringVal": {
                      "value": "neonDusk"
                    }
                  },
                  "gradient_angle": {
                    "numberVal": {
                      "value": 135
                    }
                  },
                  "color0": {
                    "color": {
                      "color": "primary"
                    }
                  },
                  "color1": {
                    "color": {
                      "color": "secondary_background"
                    }
                  },
                  "color2": {
                    "color": {
                      "color": "background"
                    }
                  },
                  "color3": {
                    "stringVal": {
                      "value": "surface_variant"
                    }
                  },
                  "color4": {
                    "stringVal": {
                      "value": "surface"
                    }
                  },
                  "color5": {
                    "stringVal": {
                      "value": "primary_container"
                    }
                  },
                  "color6": {
                    "stringVal": {
                      "value": "background"
                    }
                  }
                },
                "editorId": "shaderfill1"
              },
              {
                "type": "column",
                "properties": {
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "topToken": "xl",
                      "rightToken": "lg",
                      "bottomToken": "md",
                      "leftToken": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "xl"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "PRIVEX MOBILE"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 900
                                }
                              }
                            },
                            "editorId": "text31"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "System Status"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "display_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary_text"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 800
                                }
                              }
                            },
                            "editorId": "text32"
                          }
                        ],
                        "editorId": "column20"
                      },
                      {
                        "type": "avatar",
                        "properties": {
                          "text": {
                            "stringVal": {
                              "value": "JD"
                            }
                          },
                          "bg": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "on_primary"
                            }
                          },
                          "size": {
                            "numberVal": {
                              "value": 48
                            }
                          }
                        },
                        "editorId": "avatar1"
                      }
                    ],
                    "editorId": "row20"
                  },
                  {
                    "type": "center",
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "container",
                            "properties": {
                              "width": {
                                "px": {
                                  "value": 180,
                                  "isInfinity": false
                                }
                              },
                              "height": {
                                "px": {
                                  "value": 180,
                                  "isInfinity": false
                                }
                              },
                              "radius": {
                                "radius": {
                                  "topLeft": 0,
                                  "topRight": 0,
                                  "bottomLeft": 0,
                                  "bottomRight": 0,
                                  "token": "full"
                                }
                              },
                              "border": {
                                "border": {
                                  "width": 8,
                                  "color": "primary/20"
                                }
                              },
                              "align_child": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "container",
                                "properties": {
                                  "width": {
                                    "px": {
                                      "value": 140,
                                      "isInfinity": false
                                    }
                                  },
                                  "height": {
                                    "px": {
                                      "value": 140,
                                      "isInfinity": false
                                    }
                                  },
                                  "radius": {
                                    "radius": {
                                      "topLeft": 0,
                                      "topRight": 0,
                                      "bottomLeft": 0,
                                      "bottomRight": 0,
                                      "token": "full"
                                    }
                                  },
                                  "bg": {
                                    "color": {
                                      "color": "surface"
                                    }
                                  },
                                  "shadow": {
                                    "stringVal": {
                                      "value": "lg"
                                    }
                                  },
                                  "align_child": {
                                    "align": {
                                      "named": "center"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "icon",
                                    "properties": {
                                      "name": {
                                        "icon": {
                                          "name": "verified_user_rounded"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "success"
                                        }
                                      },
                                      "size": {
                                        "numberVal": {
                                          "value": 64
                                        }
                                      }
                                    },
                                    "editorId": "icon17"
                                  }
                                ],
                                "editorId": "container25"
                              }
                            ],
                            "editorId": "container24"
                          },
                          {
                            "type": "column",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              },
                              "cross_align": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "ALL SYSTEMS CLEAR"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_large"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "success"
                                    }
                                  },
                                  "font_weight": {
                                    "numberVal": {
                                      "value": 900
                                    }
                                  }
                                },
                                "editorId": "text33"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Protected for 12 days"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "body_medium"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text34"
                              }
                            ],
                            "editorId": "column22"
                          }
                        ],
                        "editorId": "column21"
                      }
                    ],
                    "editorId": "center1"
                  }
                ],
                "editorId": "column19"
              }
            ],
            "editorId": "stack1"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "rightToken": "lg",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "primary_text"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "lg"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "shadow": {
                "stringVal": {
                  "value": "xl"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "sm"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "container",
                        "properties": {
                          "width": {
                            "px": {
                              "value": 8,
                              "isInfinity": false
                            }
                          },
                          "height": {
                            "px": {
                              "value": 8,
                              "isInfinity": false
                            }
                          },
                          "bg": {
                            "color": {
                              "color": "success"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "full"
                            }
                          }
                        },
                        "editorId": "container27"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "REAL-TIME DIAGNOSTICS"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "#000000"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 900
                            }
                          }
                        },
                        "editorId": "text35"
                      }
                    ],
                    "editorId": "row21"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "> Initializing Privex core layer..."
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "font": {
                            "stringVal": {
                              "value": "mono"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "background"
                            }
                          }
                        },
                        "editorId": "text36"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "> Memory integrity: 100% verified"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "font": {
                            "stringVal": {
                              "value": "mono"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "background"
                            }
                          }
                        },
                        "editorId": "text37"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "> No active threats in quarantine"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "font": {
                            "stringVal": {
                              "value": "mono"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "background"
                            }
                          },
                          "opacity": {
                            "numberVal": {
                              "value": 0.7
                            }
                          }
                        },
                        "editorId": "text38"
                      }
                    ],
                    "editorId": "column24"
                  },
                  {
                    "type": "divider",
                    "properties": {
                      "color": {
                        "color": {
                          "color": "background",
                          "opacityPercent": 10
                        }
                      }
                    },
                    "editorId": "divider3"
                  },
                  {
                    "type": "@std.button",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Run Deep Audit"
                        }
                      },
                      "variant": {
                        "stringVal": {
                          "value": "outline"
                        }
                      },
                      "full_width": {
                        "boolVal": {
                          "value": true
                        }
                      },
                      "size": {
                        "stringVal": {
                          "value": "medium"
                        }
                      }
                    },
                    "editorId": "stdbutton3"
                  }
                ],
                "editorId": "column23"
              }
            ],
            "editorId": "container26"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "xl",
                  "leftToken": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "lg"
                }
              }
            },
            "children": [
              {
                "type": "text",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Protection Modules"
                    }
                  },
                  "style": {
                    "textStyle": {
                      "styleName": "headline_small"
                    }
                  },
                  "color": {
                    "color": {
                      "color": "primary_text"
                    }
                  },
                  "font_weight": {
                    "numberVal": {
                      "value": 800
                    }
                  }
                },
                "editorId": "text39"
              },
              {
                "type": "@action_tile",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "Link Sentry"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Real-time phishing & URL analysis"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "language_rounded"
                    }
                  },
                  "color": {
                    "stringVal": {
                      "value": "primary"
                    }
                  }
                },
                "editorId": "actiontile1"
              },
              {
                "type": "@action_tile",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "Message Guard"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Scanning SMS for malicious payloads"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "sms_failed_rounded"
                    }
                  },
                  "color": {
                    "stringVal": {
                      "value": "info"
                    }
                  }
                },
                "editorId": "actiontile2"
              },
              {
                "type": "@action_tile",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "File Vault"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Heuristic malware file detection"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "folder_shared_rounded"
                    }
                  },
                  "color": {
                    "stringVal": {
                      "value": "success"
                    }
                  }
                },
                "editorId": "actiontile3"
              },
              {
                "type": "@action_tile",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "QR Inspector"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Decrypting and verifying scan codes"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "qr_code_2_rounded"
                    }
                  },
                  "color": {
                    "stringVal": {
                      "value": "accent"
                    }
                  }
                },
                "editorId": "actiontile4"
              }
            ],
            "editorId": "column25"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface_variant"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "xl"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "xl"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "@std.pie_chart",
                    "properties": {
                      "data": {
                        "stringVal": {
                          "value": "85,15"
                        }
                      },
                      "labels": {
                        "stringVal": {
                          "value": "Safe,Risk"
                        }
                      },
                      "colors": {
                        "stringVal": {
                          "value": "success,divider"
                        }
                      },
                      "variant": {
                        "stringVal": {
                          "value": "donut"
                        }
                      },
                      "size": {
                        "stringVal": {
                          "value": "compact"
                        }
                      },
                      "ring": {
                        "stringVal": {
                          "value": "thick"
                        }
                      },
                      "legend": {
                        "stringVal": {
                          "value": "hidden"
                        }
                      }
                    },
                    "editorId": "stdpiechart1"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "expanded": {
                        "expanded": {
                          "enabled": true,
                          "flex": 1
                        }
                      },
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Privacy Index: 850"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "title_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "text40"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Top-tier on-device encryption active"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          }
                        },
                        "editorId": "text41"
                      },
                      {
                        "type": "@std.button",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Improve Score"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "ghost"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "arrow_forward"
                            }
                          },
                          "size": {
                            "stringVal": {
                              "value": "small"
                            }
                          }
                        },
                        "editorId": "stdbutton4"
                      }
                    ],
                    "editorId": "column26"
                  }
                ],
                "editorId": "row22"
              }
            ],
            "editorId": "container28"
          },
          {
            "type": "sizedbox",
            "properties": {
              "height": {
                "px": {
                  "value": 120,
                  "isInfinity": false
                }
              }
            },
            "editorId": "sizedbox1"
          }
        ],
        "editorId": "column18"
      }
    ],
    "editorId": "scaffold1"
  }
}
```

### 2. Scan Hub

- Frame ID: `frame5`
- Original page prompt: "A central grid of scanning options including URL, Message, QR, and File inspection."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "sm"
                    }
                  }
                },
                "children": [
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "SECURITY SCANNER"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "label_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 900
                        }
                      }
                    },
                    "editorId": "text42"
                  },
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Scan Hub"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "headline_large"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 800
                        }
                      }
                    },
                    "editorId": "text43"
                  },
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Analysis runs locally on your device"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "body_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      }
                    },
                    "editorId": "text44"
                  }
                ],
                "editorId": "column28"
              }
            ],
            "editorId": "container29"
          },
          {
            "type": "expanded",
            "children": [
              {
                "type": "column",
                "properties": {
                  "scroll": {
                    "boolVal": {
                      "value": true
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  }
                },
                "children": [
                  {
                    "type": "grid",
                    "properties": {
                      "columns": {
                        "numberVal": {
                          "value": 2
                        }
                      },
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      },
                      "run_spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      },
                      "aspect_ratio": {
                        "numberVal": {
                          "value": 0.85
                        }
                      },
                      "shrink_wrap": {
                        "boolVal": {
                          "value": true
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@scan_card",
                        "properties": {
                          "title": {
                            "stringVal": {
                              "value": "Link / URL"
                            }
                          },
                          "desc": {
                            "stringVal": {
                              "value": "Check for phishing & malicious redirects"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "language_rounded"
                            }
                          },
                          "color": {
                            "stringVal": {
                              "value": "primary"
                            }
                          }
                        },
                        "editorId": "scancard1"
                      },
                      {
                        "type": "@scan_card",
                        "properties": {
                          "title": {
                            "stringVal": {
                              "value": "Messages"
                            }
                          },
                          "desc": {
                            "stringVal": {
                              "value": "Scan SMS & chat for suspicious links"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "chat_bubble_outline_rounded"
                            }
                          },
                          "color": {
                            "stringVal": {
                              "value": "info"
                            }
                          }
                        },
                        "editorId": "scancard2"
                      },
                      {
                        "type": "@scan_card",
                        "properties": {
                          "title": {
                            "stringVal": {
                              "value": "QR Code"
                            }
                          },
                          "desc": {
                            "stringVal": {
                              "value": "Verify destination before you open"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "qr_code_scanner_rounded"
                            }
                          },
                          "color": {
                            "stringVal": {
                              "value": "accent"
                            }
                          }
                        },
                        "editorId": "scancard3"
                      },
                      {
                        "type": "@scan_card",
                        "properties": {
                          "title": {
                            "stringVal": {
                              "value": "File Scan"
                            }
                          },
                          "desc": {
                            "stringVal": {
                              "value": "Inspect documents for hidden threats"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "description_rounded"
                            }
                          },
                          "color": {
                            "stringVal": {
                              "value": "success"
                            }
                          }
                        },
                        "editorId": "scancard4"
                      }
                    ],
                    "editorId": "grid1"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "secondary_background"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "lg"
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "divider"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "shield_moon_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "secondary_text"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 20
                                }
                              }
                            },
                            "editorId": "icon18"
                          },
                          {
                            "type": "expanded",
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Privex uses on-device ML models. Your personal data and scanned content never leave this phone."
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "body_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text45"
                              }
                            ],
                            "editorId": "expanded2"
                          }
                        ],
                        "editorId": "row23"
                      }
                    ],
                    "editorId": "container30"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "align": {
                            "align": {
                              "named": "space_between"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Recent Scans"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "title_medium"
                                }
                              },
                              "font_weight": {
                                "stringVal": {
                                  "value": "bold"
                                }
                              }
                            },
                            "editorId": "text46"
                          },
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "View History"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "ghost"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "small"
                                }
                              }
                            },
                            "editorId": "stdbutton5"
                          }
                        ],
                        "editorId": "row24"
                      },
                      {
                        "type": "container",
                        "properties": {
                          "bg": {
                            "color": {
                              "color": "surface"
                            }
                          },
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "token": "md"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "md"
                            }
                          },
                          "border": {
                            "border": {
                              "width": 1,
                              "color": "outline"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "row",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "md"
                                }
                              },
                              "cross_align": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "icon",
                                "properties": {
                                  "name": {
                                    "icon": {
                                      "name": "check_circle_rounded"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "success"
                                    }
                                  },
                                  "size": {
                                    "numberVal": {
                                      "value": 20
                                    }
                                  }
                                },
                                "editorId": "icon19"
                              },
                              {
                                "type": "column",
                                "properties": {
                                  "expanded": {
                                    "expanded": {
                                      "enabled": true,
                                      "flex": 1
                                    }
                                  },
                                  "spacing": {
                                    "stringVal": {
                                      "value": "xs"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "https://secure-login.com/auth"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "label_large"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "primary_text"
                                        }
                                      },
                                      "max_lines": {
                                        "numberVal": {
                                          "value": 1
                                        }
                                      },
                                      "overflow": {
                                        "stringVal": {
                                          "value": "ellipsis"
                                        }
                                      }
                                    },
                                    "editorId": "text47"
                                  },
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "URL Scan • 2 minutes ago"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "label_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "secondary_text"
                                        }
                                      }
                                    },
                                    "editorId": "text48"
                                  }
                                ],
                                "editorId": "column31"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "SAFE"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "success"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text49"
                              }
                            ],
                            "editorId": "row25"
                          }
                        ],
                        "editorId": "act1"
                      },
                      {
                        "type": "container",
                        "properties": {
                          "bg": {
                            "color": {
                              "color": "surface"
                            }
                          },
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "token": "md"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "md"
                            }
                          },
                          "border": {
                            "border": {
                              "width": 1,
                              "color": "outline"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "row",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "md"
                                }
                              },
                              "cross_align": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "icon",
                                "properties": {
                                  "name": {
                                    "icon": {
                                      "name": "warning_rounded"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "warning"
                                    }
                                  },
                                  "size": {
                                    "numberVal": {
                                      "value": 20
                                    }
                                  }
                                },
                                "editorId": "icon20"
                              },
                              {
                                "type": "column",
                                "properties": {
                                  "expanded": {
                                    "expanded": {
                                      "enabled": true,
                                      "flex": 1
                                    }
                                  },
                                  "spacing": {
                                    "stringVal": {
                                      "value": "xs"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "Invoice_882.pdf"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "label_large"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "primary_text"
                                        }
                                      },
                                      "max_lines": {
                                        "numberVal": {
                                          "value": 1
                                        }
                                      },
                                      "overflow": {
                                        "stringVal": {
                                          "value": "ellipsis"
                                        }
                                      }
                                    },
                                    "editorId": "text50"
                                  },
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "File Scan • 1 hour ago"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "label_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "secondary_text"
                                        }
                                      }
                                    },
                                    "editorId": "text51"
                                  }
                                ],
                                "editorId": "column32"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "RISKY"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "warning"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text52"
                              }
                            ],
                            "editorId": "row26"
                          }
                        ],
                        "editorId": "act2"
                      }
                    ],
                    "editorId": "column30"
                  }
                ],
                "editorId": "column29"
              }
            ],
            "editorId": "expanded1"
          },
          {
            "type": "container",
            "properties": {
              "align": {
                "align": {
                  "named": "bottom"
                }
              }
            },
            "children": [
              {
                "type": "@std.bottom_nav",
                "children": [
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "home"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Home"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "home_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem1"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "scan_hub"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Scan"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "search_rounded"
                        }
                      },
                      "selected": {
                        "boolVal": {
                          "value": true
                        }
                      }
                    },
                    "editorId": "stdnavitem2"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "activity"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Activity"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "history_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem3"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "vault"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Vault"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "inventory_2_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem4"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "more"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "More"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "grid_view_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem5"
                  }
                ],
                "editorId": "stdbottomnav1"
              }
            ],
            "editorId": "container31"
          }
        ],
        "editorId": "column27"
      }
    ],
    "editorId": "scaffold2"
  }
}
```

### 3. URL Scanner

- Frame ID: `frame4`
- Original page prompt: "Input page for links with paste functionality and clear privacy labels."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      },
      "safe_area": {
        "boolVal": {
          "value": true
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "md",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "divider"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "align": {
                    "align": {
                      "named": "space_between"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "iconbutton",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "arrow_back_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      }
                    },
                    "editorId": "iconbutton3"
                  },
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "PRIVEX SENTRY"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "label_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 900
                        }
                      }
                    },
                    "editorId": "text53"
                  },
                  {
                    "type": "iconbutton",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "help_outline_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      }
                    },
                    "editorId": "iconbutton4"
                  }
                ],
                "editorId": "row27"
              }
            ],
            "editorId": "container32"
          },
          {
            "type": "column",
            "properties": {
              "scroll": {
                "boolVal": {
                  "value": true
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "xl"
                }
              },
              "expanded": {
                "expanded": {
                  "enabled": true,
                  "flex": 1
                }
              }
            },
            "children": [
              {
                "type": "@scanner_header",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "Link Scanner"
                    }
                  },
                  "subtitle": {
                    "stringVal": {
                      "value": "Paste a suspicious URL to perform a multi-layer phishing and malware analysis."
                    }
                  }
                },
                "editorId": "scannerheader1"
              },
              {
                "type": "container",
                "properties": {
                  "bg": {
                    "color": {
                      "color": "surface"
                    }
                  },
                  "radius": {
                    "radius": {
                      "topLeft": 0,
                      "topRight": 0,
                      "bottomLeft": 0,
                      "bottomRight": 0,
                      "token": "lg"
                    }
                  },
                  "border": {
                    "border": {
                      "width": 1,
                      "color": "outline"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "shadow": {
                    "stringVal": {
                      "value": "sm"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "lg"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "align": {
                            "align": {
                              "named": "space_between"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "TARGET URL"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "secondary_text"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 700
                                }
                              }
                            },
                            "editorId": "text54"
                          },
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Paste Link"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "ghost"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "small"
                                }
                              },
                              "icon": {
                                "stringVal": {
                                  "value": "content_paste_rounded"
                                }
                              }
                            },
                            "editorId": "stdbutton6"
                          }
                        ],
                        "editorId": "row28"
                      },
                      {
                        "type": "@std.textfield",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "URL Address"
                            }
                          },
                          "hint": {
                            "stringVal": {
                              "value": "https://example.com/path..."
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "outlined"
                            }
                          },
                          "leading_icon": {
                            "stringVal": {
                              "value": "language_rounded"
                            }
                          }
                        },
                        "editorId": "stdtextfield1"
                      },
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          },
                          "visible": {
                            "boolVal": {
                              "value": false
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "error_outline_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "error"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 14
                                }
                              }
                            },
                            "editorId": "icon21"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Please enter a valid URL"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "body_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "error"
                                }
                              }
                            },
                            "editorId": "text55"
                          }
                        ],
                        "editorId": "row29"
                      },
                      {
                        "type": "@std.button",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Scan Link"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "primary"
                            }
                          },
                          "full_width": {
                            "boolVal": {
                              "value": true
                            }
                          },
                          "size": {
                            "stringVal": {
                              "value": "large"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "search_rounded"
                            }
                          }
                        },
                        "editorId": "stdbutton7"
                      }
                    ],
                    "editorId": "column35"
                  }
                ],
                "editorId": "container33"
              },
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Security Protocol"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "title_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 700
                        }
                      }
                    },
                    "editorId": "text56"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "surface"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "lg"
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "divider"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "row",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "md"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "container",
                                "properties": {
                                  "width": {
                                    "px": {
                                      "value": 40,
                                      "isInfinity": false
                                    }
                                  },
                                  "height": {
                                    "px": {
                                      "value": 40,
                                      "isInfinity": false
                                    }
                                  },
                                  "radius": {
                                    "radius": {
                                      "topLeft": 0,
                                      "topRight": 0,
                                      "bottomLeft": 0,
                                      "bottomRight": 0,
                                      "token": "md"
                                    }
                                  },
                                  "bg": {
                                    "color": {
                                      "color": "success",
                                      "opacityPercent": 10
                                    }
                                  },
                                  "align_child": {
                                    "align": {
                                      "named": "center"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "icon",
                                    "properties": {
                                      "name": {
                                        "icon": {
                                          "name": "visibility_off_rounded"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "#FFFFFF"
                                        }
                                      }
                                    },
                                    "editorId": "icon22"
                                  }
                                ],
                                "editorId": "container35"
                              },
                              {
                                "type": "column",
                                "properties": {
                                  "expanded": {
                                    "expanded": {
                                      "enabled": true,
                                      "flex": 1
                                    }
                                  },
                                  "spacing": {
                                    "stringVal": {
                                      "value": "xs"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "On-Device Analysis"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "body_medium"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "primary_text"
                                        }
                                      },
                                      "font_weight": {
                                        "numberVal": {
                                          "value": 600
                                        }
                                      }
                                    },
                                    "editorId": "text57"
                                  },
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "Analysis runs locally. Privex does not log your browsing history or full URL content."
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "body_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "secondary_text"
                                        }
                                      }
                                    },
                                    "editorId": "text58"
                                  }
                                ],
                                "editorId": "column38"
                              }
                            ],
                            "editorId": "row30"
                          },
                          {
                            "type": "divider",
                            "properties": {
                              "color": {
                                "color": {
                                  "color": "divider"
                                }
                              }
                            },
                            "editorId": "div1"
                          },
                          {
                            "type": "row",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "md"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "container",
                                "properties": {
                                  "width": {
                                    "px": {
                                      "value": 40,
                                      "isInfinity": false
                                    }
                                  },
                                  "height": {
                                    "px": {
                                      "value": 40,
                                      "isInfinity": false
                                    }
                                  },
                                  "radius": {
                                    "radius": {
                                      "topLeft": 0,
                                      "topRight": 0,
                                      "bottomLeft": 0,
                                      "bottomRight": 0,
                                      "token": "md"
                                    }
                                  },
                                  "bg": {
                                    "color": {
                                      "color": "info",
                                      "opacityPercent": 10
                                    }
                                  },
                                  "align_child": {
                                    "align": {
                                      "named": "center"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "icon",
                                    "properties": {
                                      "name": {
                                        "icon": {
                                          "name": "hub_rounded"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "#FFFFFF"
                                        }
                                      }
                                    },
                                    "editorId": "icon23"
                                  }
                                ],
                                "editorId": "container36"
                              },
                              {
                                "type": "column",
                                "properties": {
                                  "expanded": {
                                    "expanded": {
                                      "enabled": true,
                                      "flex": 1
                                    }
                                  },
                                  "spacing": {
                                    "stringVal": {
                                      "value": "xs"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "Threat Intelligence"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "body_medium"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "primary_text"
                                        }
                                      },
                                      "font_weight": {
                                        "numberVal": {
                                          "value": 600
                                        }
                                      }
                                    },
                                    "editorId": "text59"
                                  },
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "Cross-references against 4.2M known malicious domains updated every 6 hours."
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "body_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "secondary_text"
                                        }
                                      }
                                    },
                                    "editorId": "text60"
                                  }
                                ],
                                "editorId": "column39"
                              }
                            ],
                            "editorId": "row31"
                          }
                        ],
                        "editorId": "column37"
                      }
                    ],
                    "editorId": "container34"
                  }
                ],
                "editorId": "column36"
              },
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "sm"
                    }
                  }
                },
                "children": [
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Example Scenarios"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "label_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 700
                        }
                      }
                    },
                    "editorId": "text61"
                  },
                  {
                    "type": "wrap",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "sm"
                        }
                      },
                      "run_spacing": {
                        "stringVal": {
                          "value": "sm"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "chip",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Suspicious SMS Link"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "action"
                            }
                          },
                          "icon": {
                            "icon": {
                              "name": "link_off_rounded"
                            }
                          }
                        },
                        "editorId": "chip1"
                      },
                      {
                        "type": "chip",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Unverified Email URL"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "action"
                            }
                          },
                          "icon": {
                            "icon": {
                              "name": "mail_lock_rounded"
                            }
                          }
                        },
                        "editorId": "chip2"
                      },
                      {
                        "type": "chip",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Shortened Link"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "action"
                            }
                          },
                          "icon": {
                            "icon": {
                              "name": "shortcut_rounded"
                            }
                          }
                        },
                        "editorId": "chip3"
                      }
                    ],
                    "editorId": "wrap1"
                  }
                ],
                "editorId": "column40"
              }
            ],
            "editorId": "column34"
          },
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "align_child": {
                "align": {
                  "named": "center"
                }
              }
            },
            "children": [
              {
                "type": "@privacy_badge",
                "properties": {
                  "label": {
                    "stringVal": {
                      "value": "Privacy-First Engine v2.4"
                    }
                  }
                },
                "editorId": "privacybadge1"
              }
            ],
            "editorId": "container37"
          }
        ],
        "editorId": "column33"
      }
    ],
    "editorId": "scaffold3"
  }
}
```

### 4. Universal Scan Result

- Frame ID: `frame9`
- Original page prompt: "Detailed verdict screen showing risk scores, plain-language explanations, and technical evidence rows."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "stack",
            "properties": {
              "height": {
                "px": {
                  "value": 320,
                  "isInfinity": false
                }
              }
            },
            "children": [
              {
                "type": "container",
                "properties": {
                  "height": {
                    "px": {
                      "value": 320,
                      "isInfinity": false
                    }
                  },
                  "gradient": {
                    "gradient": {
                      "type": "GRADIENT_TYPE_LINEAR",
                      "direction": "to_bottom",
                      "stops": [
                        {
                          "color": "secondary_background"
                        },
                        {
                          "color": "background"
                        }
                      ]
                    }
                  }
                },
                "editorId": "container38"
              },
              {
                "type": "column",
                "properties": {
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "topToken": "xl",
                      "rightToken": "lg",
                      "bottomToken": "xl",
                      "leftToken": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  },
                  "align_child": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "container",
                    "properties": {
                      "width": {
                        "px": {
                          "value": 120,
                          "isInfinity": false
                        }
                      },
                      "height": {
                        "px": {
                          "value": 120,
                          "isInfinity": false
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "full"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 4,
                          "color": "error/30"
                        }
                      },
                      "align_child": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "container",
                        "properties": {
                          "width": {
                            "px": {
                              "value": 90,
                              "isInfinity": false
                            }
                          },
                          "height": {
                            "px": {
                              "value": 90,
                              "isInfinity": false
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "full"
                            }
                          },
                          "bg": {
                            "color": {
                              "color": "error"
                            }
                          },
                          "shadow": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "align_child": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "report_problem_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 48
                                }
                              }
                            },
                            "editorId": "icon24"
                          }
                        ],
                        "editorId": "container40"
                      }
                    ],
                    "editorId": "container39"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "THREAT DETECTED"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "headline_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "error"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 900
                            }
                          }
                        },
                        "editorId": "text62"
                      },
                      {
                        "type": "container",
                        "properties": {
                          "bg": {
                            "color": {
                              "color": "error",
                              "opacityPercent": 15
                            }
                          },
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "topToken": "sm",
                              "rightToken": "md",
                              "bottomToken": "sm",
                              "leftToken": "md"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "full"
                            }
                          },
                          "border": {
                            "border": {
                              "width": 1,
                              "color": "error/30"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "RISK SCORE: 88/100"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_large"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 700
                                }
                              }
                            },
                            "editorId": "text63"
                          }
                        ],
                        "editorId": "container41"
                      }
                    ],
                    "editorId": "column43"
                  }
                ],
                "editorId": "column42"
              }
            ],
            "editorId": "stack2"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "rightToken": "lg",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "lg"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "shadow": {
                "stringVal": {
                  "value": "xl"
                }
              },
              "border": {
                "border": {
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "URL ANALYSIS"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 800
                            }
                          }
                        },
                        "editorId": "text64"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "2 mins ago"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          }
                        },
                        "editorId": "text65"
                      }
                    ],
                    "editorId": "row32"
                  },
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "http://secure-login-verify.com/update-account"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "title_medium"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      },
                      "max_lines": {
                        "numberVal": {
                          "value": 2
                        }
                      },
                      "overflow": {
                        "stringVal": {
                          "value": "ellipsis"
                        }
                      }
                    },
                    "editorId": "text66"
                  },
                  {
                    "type": "divider",
                    "properties": {
                      "color": {
                        "color": {
                          "color": "divider"
                        }
                      }
                    },
                    "editorId": "divider4"
                  },
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "icon",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "fingerprint_rounded"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          },
                          "size": {
                            "numberVal": {
                              "value": 16
                            }
                          }
                        },
                        "editorId": "icon25"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "SHA-256: 8f3a...2e1b"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          },
                          "font": {
                            "stringVal": {
                              "value": "mono"
                            }
                          }
                        },
                        "editorId": "text67"
                      }
                    ],
                    "editorId": "row33"
                  }
                ],
                "editorId": "column44"
              }
            ],
            "editorId": "container42"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "xl",
                  "leftToken": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "md"
                }
              }
            },
            "children": [
              {
                "type": "text",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Analysis Breakdown"
                    }
                  },
                  "style": {
                    "textStyle": {
                      "styleName": "title_medium"
                    }
                  },
                  "color": {
                    "color": {
                      "color": "primary_text"
                    }
                  },
                  "font_weight": {
                    "numberVal": {
                      "value": 800
                    }
                  }
                },
                "editorId": "text68"
              },
              {
                "type": "@explanation_pillar",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "What happened?"
                    }
                  },
                  "content": {
                    "stringVal": {
                      "value": "The engine identified a deceptive URL structure designed to mimic a legitimate banking portal."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "info_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "info"
                    }
                  }
                },
                "editorId": "pillar1"
              },
              {
                "type": "@explanation_pillar",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "Why it matters?"
                    }
                  },
                  "content": {
                    "stringVal": {
                      "value": "Interacting with this link could lead to credential theft or unauthorized access to your accounts."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "warning_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "warning"
                    }
                  }
                },
                "editorId": "pillar2"
              },
              {
                "type": "@explanation_pillar",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "What Privex did?"
                    }
                  },
                  "content": {
                    "stringVal": {
                      "value": "The request was intercepted and blocked. The signature has been added to your local blocklist."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "security_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "success"
                    }
                  }
                },
                "editorId": "pillar3"
              },
              {
                "type": "@explanation_pillar",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "Next steps"
                    }
                  },
                  "content": {
                    "stringVal": {
                      "value": "Do not enter any data. We recommend clearing your browser cache and running a full system audit."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "assistant_navigation_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "error"
                    }
                  }
                },
                "editorId": "pillar4"
              }
            ],
            "editorId": "column45"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "rightToken": "lg",
                  "bottomToken": "xl",
                  "leftToken": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "md"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "align": {
                    "align": {
                      "named": "space_between"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Technical Evidence"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "title_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 700
                        }
                      }
                    },
                    "editorId": "text69"
                  },
                  {
                    "type": "chip",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "4 Detections"
                        }
                      },
                      "variant": {
                        "stringVal": {
                          "value": "choice"
                        }
                      },
                      "selected": {
                        "boolVal": {
                          "value": true
                        }
                      },
                      "color": {
                        "color": {
                          "color": "error"
                        }
                      }
                    },
                    "editorId": "chip4"
                  }
                ],
                "editorId": "row34"
              },
              {
                "type": "container",
                "properties": {
                  "bg": {
                    "color": {
                      "color": "surface",
                      "opacityPercent": 50
                    }
                  },
                  "radius": {
                    "radius": {
                      "topLeft": 0,
                      "topRight": 0,
                      "bottomLeft": 0,
                      "bottomRight": 0,
                      "token": "lg"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "border": {
                    "border": {
                      "width": 1,
                      "color": "divider"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "children": [
                      {
                        "type": "@evidence_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Detection Reason"
                            }
                          },
                          "value": {
                            "stringVal": {
                              "value": "Phishing Heuristics"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "search_rounded"
                            }
                          },
                          "tone": {
                            "stringVal": {
                              "value": "error"
                            }
                          }
                        },
                        "editorId": "ev1"
                      },
                      {
                        "type": "@evidence_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Evidence Category"
                            }
                          },
                          "value": {
                            "stringVal": {
                              "value": "Deceptive Domain"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "language_rounded"
                            }
                          }
                        },
                        "editorId": "ev2"
                      },
                      {
                        "type": "@evidence_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Rule Identifier"
                            }
                          },
                          "value": {
                            "stringVal": {
                              "value": "RULE_PHISH_084"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "code_rounded"
                            }
                          }
                        },
                        "editorId": "ev3"
                      },
                      {
                        "type": "@evidence_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Confidence"
                            }
                          },
                          "value": {
                            "stringVal": {
                              "value": "94.2% Match"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "speed_rounded"
                            }
                          },
                          "tone": {
                            "stringVal": {
                              "value": "success"
                            }
                          }
                        },
                        "editorId": "ev4"
                      }
                    ],
                    "editorId": "column47"
                  }
                ],
                "editorId": "container43"
              }
            ],
            "editorId": "column46"
          },
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "secondary_background"
                }
              },
              "border": {
                "borderSided": {
                  "side": "top",
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "@std.button",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "Return to Dashboard"
                        }
                      },
                      "variant": {
                        "stringVal": {
                          "value": "primary"
                        }
                      },
                      "full_width": {
                        "boolVal": {
                          "value": true
                        }
                      },
                      "size": {
                        "stringVal": {
                          "value": "large"
                        }
                      }
                    },
                    "editorId": "stdbutton8"
                  },
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "expanded",
                        "children": [
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "New Scan"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "outline"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "medium"
                                }
                              },
                              "icon": {
                                "stringVal": {
                                  "value": "add_rounded"
                                }
                              }
                            },
                            "editorId": "stdbutton9"
                          }
                        ],
                        "editorId": "expanded3"
                      },
                      {
                        "type": "expanded",
                        "children": [
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "View Vault"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "ghost"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "medium"
                                }
                              },
                              "icon": {
                                "stringVal": {
                                  "value": "inventory_2_rounded"
                                }
                              }
                            },
                            "editorId": "stdbutton10"
                          }
                        ],
                        "editorId": "expanded4"
                      }
                    ],
                    "editorId": "row35"
                  }
                ],
                "editorId": "column48"
              }
            ],
            "editorId": "container44"
          },
          {
            "type": "sizedbox",
            "properties": {
              "height": {
                "px": {
                  "value": 40,
                  "isInfinity": false
                }
              }
            },
            "editorId": "sizedbox2"
          }
        ],
        "editorId": "column41"
      }
    ],
    "editorId": "scaffold4"
  }
}
```

### 5. Security Assistant

- Frame ID: `frame8`
- Original page prompt: "AI-driven explanation interface with suggested security questions and technical evidence toggles."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "divider"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "align": {
                    "align": {
                      "named": "space_between"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "iconbutton",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "arrow_back_rounded"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "iconbutton5"
                      },
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Security Assistant"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "title_large"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 800
                                }
                              }
                            },
                            "editorId": "text70"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "AI-Powered Protection Insights"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              }
                            },
                            "editorId": "text71"
                          }
                        ],
                        "editorId": "column50"
                      }
                    ],
                    "editorId": "row37"
                  },
                  {
                    "type": "iconbutton",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "history_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      }
                    },
                    "editorId": "iconbutton6"
                  }
                ],
                "editorId": "row36"
              }
            ],
            "editorId": "container45"
          },
          {
            "type": "expanded",
            "children": [
              {
                "type": "column",
                "properties": {
                  "scroll": {
                    "boolVal": {
                      "value": true
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  }
                },
                "children": [
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "primary",
                          "opacityPercent": 5
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "lg"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "primary/20"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "auto_awesome_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 24
                                }
                              }
                            },
                            "editorId": "icon26"
                          },
                          {
                            "type": "expanded",
                            "children": [
                              {
                                "type": "column",
                                "properties": {
                                  "spacing": {
                                    "stringVal": {
                                      "value": "xs"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "Privex Assistant"
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "title_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "#FFFFFF"
                                        }
                                      },
                                      "font_weight": {
                                        "stringVal": {
                                          "value": "bold"
                                        }
                                      }
                                    },
                                    "editorId": "text72"
                                  },
                                  {
                                    "type": "text",
                                    "properties": {
                                      "content": {
                                        "stringVal": {
                                          "value": "I can explain security verdicts, analyze technical evidence, and provide privacy recommendations."
                                        }
                                      },
                                      "style": {
                                        "textStyle": {
                                          "styleName": "body_small"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "#FFFFFF"
                                        }
                                      }
                                    },
                                    "editorId": "text73"
                                  }
                                ],
                                "editorId": "column52"
                              }
                            ],
                            "editorId": "expanded6"
                          }
                        ],
                        "editorId": "row38"
                      }
                    ],
                    "editorId": "container46"
                  },
                  {
                    "type": "@assistant_message",
                    "properties": {
                      "is_ai": {
                        "boolVal": {
                          "value": true
                        }
                      },
                      "content": {
                        "stringVal": {
                          "value": "I've analyzed your recent file scan for 'update_patch.apk'. The verdict is Suspicious due to unsigned code signatures and unusual permission requests."
                        }
                      }
                    },
                    "editorId": "assistantmessage1"
                  },
                  {
                    "type": "@assistant_message",
                    "properties": {
                      "is_ai": {
                        "boolVal": {
                          "value": false
                        }
                      },
                      "content": {
                        "stringVal": {
                          "value": "Why does unsigned code matter?"
                        }
                      }
                    },
                    "editorId": "assistantmessage2"
                  },
                  {
                    "type": "@assistant_message",
                    "properties": {
                      "is_ai": {
                        "boolVal": {
                          "value": true
                        }
                      },
                      "content": {
                        "stringVal": {
                          "value": "Unsigned code means the developer's identity hasn't been verified by a trusted authority. This is a common tactic for distributing modified or malicious apps."
                        }
                      }
                    },
                    "editorId": "assistantmessage3"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "surface"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "lg"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "outline"
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "row",
                            "properties": {
                              "align": {
                                "align": {
                                  "named": "space_between"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Technical Evidence"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "title_small"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text74"
                              },
                              {
                                "type": "@std.switch",
                                "properties": {
                                  "label": {
                                    "stringVal": {
                                      "value": "Detailed View"
                                    }
                                  },
                                  "active": {
                                    "boolVal": {
                                      "value": true
                                    }
                                  },
                                  "variant": {
                                    "stringVal": {
                                      "value": "iOS"
                                    }
                                  }
                                },
                                "editorId": "stdswitch2"
                              }
                            ],
                            "editorId": "row39"
                          },
                          {
                            "type": "divider",
                            "properties": {
                              "color": {
                                "color": {
                                  "color": "divider"
                                }
                              }
                            },
                            "editorId": "divider5"
                          },
                          {
                            "type": "@evidence_row__67d74ca0",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Signature Status"
                                }
                              },
                              "value": {
                                "stringVal": {
                                  "value": "UNSIGNED"
                                }
                              },
                              "tone": {
                                "stringVal": {
                                  "value": "error"
                                }
                              }
                            },
                            "editorId": "evidencerow1"
                          },
                          {
                            "type": "@evidence_row__67d74ca0",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Entropy Score"
                                }
                              },
                              "value": {
                                "stringVal": {
                                  "value": "6.8 (High)"
                                }
                              },
                              "tone": {
                                "stringVal": {
                                  "value": "warning"
                                }
                              }
                            },
                            "editorId": "evidencerow2"
                          },
                          {
                            "type": "@evidence_row__67d74ca0",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Heuristic Match"
                                }
                              },
                              "value": {
                                "stringVal": {
                                  "value": "Generic.Packer"
                                }
                              },
                              "tone": {
                                "stringVal": {
                                  "value": "warning"
                                }
                              }
                            },
                            "editorId": "evidencerow3"
                          },
                          {
                            "type": "@evidence_row__67d74ca0",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Network Activity"
                                }
                              },
                              "value": {
                                "stringVal": {
                                  "value": "NONE"
                                }
                              },
                              "tone": {
                                "stringVal": {
                                  "value": "success"
                                }
                              }
                            },
                            "editorId": "evidencerow4"
                          }
                        ],
                        "editorId": "column53"
                      }
                    ],
                    "editorId": "container47"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Suggested Topics"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_large"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          }
                        },
                        "editorId": "text75"
                      },
                      {
                        "type": "wrap",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "sm"
                            }
                          },
                          "run_spacing": {
                            "stringVal": {
                              "value": "sm"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@suggestion_chip",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "How to stay safe?"
                                }
                              }
                            },
                            "editorId": "suggestionchip1"
                          },
                          {
                            "type": "@suggestion_chip",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "What is a heuristic scan?"
                                }
                              }
                            },
                            "editorId": "suggestionchip2"
                          },
                          {
                            "type": "@suggestion_chip",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Check my privacy index"
                                }
                              }
                            },
                            "editorId": "suggestionchip3"
                          },
                          {
                            "type": "@suggestion_chip",
                            "properties": {
                              "label": {
                                "stringVal": {
                                  "value": "Explain 'Generic.Packer'"
                                }
                              }
                            },
                            "editorId": "suggestionchip4"
                          }
                        ],
                        "editorId": "wrap2"
                      }
                    ],
                    "editorId": "column54"
                  }
                ],
                "editorId": "column51"
              }
            ],
            "editorId": "expanded5"
          },
          {
            "type": "container",
            "properties": {
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "border": {
                "borderSided": {
                  "side": "top",
                  "width": 1,
                  "color": "divider"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "sm"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "container",
                        "properties": {
                          "bg": {
                            "color": {
                              "color": "secondary_background"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "md"
                            }
                          },
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "topToken": "sm",
                              "rightToken": "md",
                              "bottomToken": "sm",
                              "leftToken": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "row",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "icon",
                                "properties": {
                                  "name": {
                                    "icon": {
                                      "name": "tune_rounded"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  },
                                  "size": {
                                    "numberVal": {
                                      "value": 18
                                    }
                                  }
                                },
                                "editorId": "icon27"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Reading Level: Simple"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text76"
                              }
                            ],
                            "editorId": "row41"
                          }
                        ],
                        "editorId": "container49"
                      }
                    ],
                    "editorId": "row40"
                  },
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "expanded",
                        "children": [
                          {
                            "type": "@std.textfield",
                            "properties": {
                              "variant": {
                                "stringVal": {
                                  "value": "outlined"
                                }
                              },
                              "hint": {
                                "stringVal": {
                                  "value": "Ask about a threat or setting..."
                                }
                              },
                              "leading_icon": {
                                "stringVal": {
                                  "value": "psychology_rounded"
                                }
                              }
                            },
                            "editorId": "stdtextfield2"
                          }
                        ],
                        "editorId": "expanded7"
                      },
                      {
                        "type": "container",
                        "properties": {
                          "width": {
                            "px": {
                              "value": 52,
                              "isInfinity": false
                            }
                          },
                          "height": {
                            "px": {
                              "value": 52,
                              "isInfinity": false
                            }
                          },
                          "bg": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "lg"
                            }
                          },
                          "align_child": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "send_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 24
                                }
                              }
                            },
                            "editorId": "icon28"
                          }
                        ],
                        "editorId": "container50"
                      }
                    ],
                    "editorId": "row42"
                  }
                ],
                "editorId": "column55"
              }
            ],
            "editorId": "container48"
          }
        ],
        "editorId": "column49"
      }
    ],
    "editorId": "scaffold5"
  }
}
```

### 6. Protection Status

- Frame ID: `frame10`
- Original page prompt: "System health center showing engine status, update history, and resource usage modes."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "stack",
            "properties": {
              "height": {
                "px": {
                  "value": 320,
                  "isInfinity": false
                }
              }
            },
            "children": [
              {
                "type": "container",
                "properties": {
                  "gradient": {
                    "gradient": {
                      "type": "GRADIENT_TYPE_LINEAR",
                      "direction": "to_bottom_right",
                      "stops": [
                        {
                          "color": "background"
                        },
                        {
                          "color": "secondary_background"
                        }
                      ]
                    }
                  },
                  "height": {
                    "px": {
                      "value": 320,
                      "isInfinity": false
                    }
                  }
                },
                "editorId": "container51"
              },
              {
                "type": "column",
                "properties": {
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "topToken": "xl",
                      "rightToken": "lg",
                      "bottomToken": "xl",
                      "leftToken": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "iconbutton",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "arrow_back_rounded"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "iconbutton7"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Protection Engine"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "title_large"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          }
                        },
                        "editorId": "text77"
                      },
                      {
                        "type": "iconbutton",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "refresh_rounded"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "iconbutton8"
                      }
                    ],
                    "editorId": "row43"
                  },
                  {
                    "type": "center",
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "container",
                            "properties": {
                              "width": {
                                "px": {
                                  "value": 120,
                                  "isInfinity": false
                                }
                              },
                              "height": {
                                "px": {
                                  "value": 120,
                                  "isInfinity": false
                                }
                              },
                              "radius": {
                                "radius": {
                                  "topLeft": 0,
                                  "topRight": 0,
                                  "bottomLeft": 0,
                                  "bottomRight": 0,
                                  "token": "full"
                                }
                              },
                              "border": {
                                "border": {
                                  "width": 4,
                                  "color": "success/30"
                                }
                              },
                              "align_child": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "container",
                                "properties": {
                                  "width": {
                                    "px": {
                                      "value": 90,
                                      "isInfinity": false
                                    }
                                  },
                                  "height": {
                                    "px": {
                                      "value": 90,
                                      "isInfinity": false
                                    }
                                  },
                                  "radius": {
                                    "radius": {
                                      "topLeft": 0,
                                      "topRight": 0,
                                      "bottomLeft": 0,
                                      "bottomRight": 0,
                                      "token": "full"
                                    }
                                  },
                                  "bg": {
                                    "color": {
                                      "color": "success",
                                      "opacityPercent": 10
                                    }
                                  },
                                  "shadow": {
                                    "shadow": {
                                      "color": "#00FF0033",
                                      "dx": 0,
                                      "dy": 0,
                                      "blur": 20,
                                      "spread": 5
                                    }
                                  },
                                  "align_child": {
                                    "align": {
                                      "named": "center"
                                    }
                                  }
                                },
                                "children": [
                                  {
                                    "type": "icon",
                                    "properties": {
                                      "name": {
                                        "icon": {
                                          "name": "security_rounded"
                                        }
                                      },
                                      "color": {
                                        "color": {
                                          "color": "#FFFFFF"
                                        }
                                      },
                                      "size": {
                                        "numberVal": {
                                          "value": 48
                                        }
                                      }
                                    },
                                    "editorId": "icon29"
                                  }
                                ],
                                "editorId": "container53"
                              }
                            ],
                            "editorId": "container52"
                          },
                          {
                            "type": "column",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              },
                              "cross_align": {
                                "align": {
                                  "named": "center"
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "SYSTEM HEALTHY"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "headline_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "success"
                                    }
                                  },
                                  "font_weight": {
                                    "numberVal": {
                                      "value": 900
                                    }
                                  }
                                },
                                "editorId": "text78"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Last verified: 4 mins ago"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text79"
                              }
                            ],
                            "editorId": "column59"
                          }
                        ],
                        "editorId": "column58"
                      }
                    ],
                    "editorId": "center2"
                  }
                ],
                "editorId": "column57"
              }
            ],
            "editorId": "stack3"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "md"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "@health_metric",
                    "properties": {
                      "label": {
                        "stringVal": {
                          "value": "Threat Database"
                        }
                      },
                      "value": {
                        "stringVal": {
                          "value": "v2.4.812"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "update_rounded"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "info"
                        }
                      }
                    },
                    "editorId": "healthmetric1"
                  },
                  {
                    "type": "@health_metric",
                    "properties": {
                      "label": {
                        "stringVal": {
                          "value": "In Quarantine"
                        }
                      },
                      "value": {
                        "stringVal": {
                          "value": "0 Items"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "inventory_2_rounded"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "success"
                        }
                      }
                    },
                    "editorId": "healthmetric2"
                  }
                ],
                "editorId": "row44"
              },
              {
                "type": "row",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "@health_metric",
                    "properties": {
                      "label": {
                        "stringVal": {
                          "value": "Power Mode"
                        }
                      },
                      "value": {
                        "stringVal": {
                          "value": "Adaptive"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "battery_charging_full_rounded"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "accent"
                        }
                      }
                    },
                    "editorId": "healthmetric3"
                  },
                  {
                    "type": "@health_metric",
                    "properties": {
                      "label": {
                        "stringVal": {
                          "value": "Thermal State"
                        }
                      },
                      "value": {
                        "stringVal": {
                          "value": "Normal"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "thermostat_rounded"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "success"
                        }
                      }
                    },
                    "editorId": "healthmetric4"
                  }
                ],
                "editorId": "row45"
              }
            ],
            "editorId": "column60"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "rightToken": "lg",
                  "leftToken": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "md"
                }
              }
            },
            "children": [
              {
                "type": "text",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Active Modules"
                    }
                  },
                  "style": {
                    "textStyle": {
                      "styleName": "title_medium"
                    }
                  },
                  "color": {
                    "color": {
                      "color": "primary_text"
                    }
                  },
                  "font_weight": {
                    "stringVal": {
                      "value": "bold"
                    }
                  }
                },
                "editorId": "text80"
              },
              {
                "type": "@module_status",
                "properties": {
                  "name": {
                    "stringVal": {
                      "value": "Privex Core Layer"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "On-device analysis active"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "memory_rounded"
                    }
                  }
                },
                "editorId": "modulestatus1"
              },
              {
                "type": "@module_status",
                "properties": {
                  "name": {
                    "stringVal": {
                      "value": "Heuristic Engine"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "Pattern matching enabled"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "psychology_rounded"
                    }
                  }
                },
                "editorId": "modulestatus2"
              },
              {
                "type": "@module_status",
                "properties": {
                  "name": {
                    "stringVal": {
                      "value": "Web Sentry"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "Phishing database connected"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "public_rounded"
                    }
                  }
                },
                "editorId": "modulestatus3"
              },
              {
                "type": "@module_status",
                "properties": {
                  "name": {
                    "stringVal": {
                      "value": "File Inspector"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "Real-time monitoring active"
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "folder_managed_rounded"
                    }
                  }
                },
                "editorId": "modulestatus4"
              }
            ],
            "editorId": "column61"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "lg"
                }
              },
              "border": {
                "border": {
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "System Resources"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_large"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          }
                        },
                        "editorId": "text81"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Optimized"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "success"
                            }
                          }
                        },
                        "editorId": "text82"
                      }
                    ],
                    "editorId": "row46"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "align": {
                            "align": {
                              "named": "space_between"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Memory Usage"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "body_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary_text"
                                }
                              }
                            },
                            "editorId": "text83"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "42 MB"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              }
                            },
                            "editorId": "text84"
                          }
                        ],
                        "editorId": "row47"
                      },
                      {
                        "type": "progress",
                        "properties": {
                          "value": {
                            "numberVal": {
                              "value": 0.15
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "bg_color": {
                            "color": {
                              "color": "divider"
                            }
                          },
                          "thickness": {
                            "numberVal": {
                              "value": 4
                            }
                          }
                        },
                        "editorId": "progress1"
                      }
                    ],
                    "editorId": "column63"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "align": {
                            "align": {
                              "named": "space_between"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "CPU Impact"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "body_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary_text"
                                }
                              }
                            },
                            "editorId": "text85"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "< 1%"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "success"
                                }
                              }
                            },
                            "editorId": "text86"
                          }
                        ],
                        "editorId": "row48"
                      },
                      {
                        "type": "progress",
                        "properties": {
                          "value": {
                            "numberVal": {
                              "value": 0.05
                            }
                          },
                          "color": {
                            "color": {
                              "color": "success"
                            }
                          },
                          "bg_color": {
                            "color": {
                              "color": "divider"
                            }
                          },
                          "thickness": {
                            "numberVal": {
                              "value": 4
                            }
                          }
                        },
                        "editorId": "progress2"
                      }
                    ],
                    "editorId": "column64"
                  }
                ],
                "editorId": "column62"
              }
            ],
            "editorId": "container54"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "md"
                }
              }
            },
            "children": [
              {
                "type": "@std.button",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Run System Integrity Audit"
                    }
                  },
                  "variant": {
                    "stringVal": {
                      "value": "primary"
                    }
                  },
                  "full_width": {
                    "boolVal": {
                      "value": true
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "rule_rounded"
                    }
                  }
                },
                "editorId": "stdbutton11"
              },
              {
                "type": "@std.button",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Check for Threat Updates"
                    }
                  },
                  "variant": {
                    "stringVal": {
                      "value": "outline"
                    }
                  },
                  "full_width": {
                    "boolVal": {
                      "value": true
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "download_rounded"
                    }
                  }
                },
                "editorId": "stdbutton12"
              }
            ],
            "editorId": "column65"
          },
          {
            "type": "sizedbox",
            "properties": {
              "height": {
                "px": {
                  "value": 40,
                  "isInfinity": false
                }
              }
            },
            "editorId": "sizedbox3"
          }
        ],
        "editorId": "column56"
      }
    ],
    "editorId": "scaffold6"
  }
}
```

### 7. Quarantine Vault

- Frame ID: `frame6`
- Original page prompt: "List of isolated threats with options to view details, restore with warnings, or delete permanently."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "SECURE STORAGE"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 900
                                }
                              }
                            },
                            "editorId": "text87"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Quarantine Vault"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "headline_medium"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary_text"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 800
                                }
                              }
                            },
                            "editorId": "text88"
                          }
                        ],
                        "editorId": "column68"
                      },
                      {
                        "type": "container",
                        "properties": {
                          "bg": {
                            "color": {
                              "color": "error",
                              "opacityPercent": 10
                            }
                          },
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "topToken": "sm",
                              "rightToken": "md",
                              "bottomToken": "sm",
                              "leftToken": "md"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "full"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "3 ITEMS"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "font_weight": {
                                "stringVal": {
                                  "value": "bold"
                                }
                              }
                            },
                            "editorId": "text89"
                          }
                        ],
                        "editorId": "container56"
                      }
                    ],
                    "editorId": "row49"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "secondary_background"
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "md"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "md"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "divider"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "security_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "info"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 20
                                }
                              }
                            },
                            "editorId": "icon30"
                          },
                          {
                            "type": "expanded",
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Items in the vault are isolated from the system and cannot execute or be accessed by other apps."
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "body_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text90"
                              }
                            ],
                            "editorId": "expanded8"
                          }
                        ],
                        "editorId": "row50"
                      }
                    ],
                    "editorId": "container57"
                  }
                ],
                "editorId": "column67"
              }
            ],
            "editorId": "container55"
          },
          {
            "type": "expanded",
            "children": [
              {
                "type": "column",
                "properties": {
                  "scroll": {
                    "boolVal": {
                      "value": true
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  }
                },
                "children": [
                  {
                    "type": "@quarantine_card",
                    "properties": {
                      "name": {
                        "stringVal": {
                          "value": "invoice_3921.apk"
                        }
                      },
                      "type": {
                        "stringVal": {
                          "value": "File"
                        }
                      },
                      "reason": {
                        "stringVal": {
                          "value": "Heuristic: Android.Trojan.Downloader"
                        }
                      },
                      "date": {
                        "stringVal": {
                          "value": "Oct 24, 2023"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "error"
                        }
                      }
                    },
                    "editorId": "item1"
                  },
                  {
                    "type": "@quarantine_card",
                    "properties": {
                      "name": {
                        "stringVal": {
                          "value": "bit.ly/secure-login-update"
                        }
                      },
                      "type": {
                        "stringVal": {
                          "value": "URL"
                        }
                      },
                      "reason": {
                        "stringVal": {
                          "value": "Phishing: Credential Harvester"
                        }
                      },
                      "date": {
                        "stringVal": {
                          "value": "Oct 22, 2023"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "warning"
                        }
                      }
                    },
                    "editorId": "item2"
                  },
                  {
                    "type": "@quarantine_card",
                    "properties": {
                      "name": {
                        "stringVal": {
                          "value": "SMS from +1 (555) 0129"
                        }
                      },
                      "type": {
                        "stringVal": {
                          "value": "Message"
                        }
                      },
                      "reason": {
                        "stringVal": {
                          "value": "Suspicious: Smishing Pattern Detected"
                        }
                      },
                      "date": {
                        "stringVal": {
                          "value": "Oct 20, 2023"
                        }
                      },
                      "tone": {
                        "stringVal": {
                          "value": "warning"
                        }
                      }
                    },
                    "editorId": "item3"
                  },
                  {
                    "type": "sizedbox",
                    "properties": {
                      "height": {
                        "px": {
                          "value": 80,
                          "isInfinity": false
                        }
                      }
                    },
                    "editorId": "sizedbox4"
                  }
                ],
                "editorId": "column69"
              }
            ],
            "editorId": "expanded9"
          },
          {
            "type": "container",
            "properties": {
              "align": {
                "align": {
                  "named": "bottom"
                }
              }
            },
            "children": [
              {
                "type": "@std.bottom_nav",
                "children": [
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "home"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Home"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "home_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem6"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "scan"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Scan"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "center_focus_strong_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem7"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "activity"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Activity"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "history_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem8"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "vault"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Vault"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "inventory_2_rounded"
                        }
                      },
                      "selected": {
                        "boolVal": {
                          "value": true
                        }
                      }
                    },
                    "editorId": "stdnavitem9"
                  },
                  {
                    "type": "@std.nav_item",
                    "properties": {
                      "target": {
                        "stringVal": {
                          "value": "more"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "More"
                        }
                      },
                      "icon": {
                        "stringVal": {
                          "value": "grid_view_rounded"
                        }
                      }
                    },
                    "editorId": "stdnavitem10"
                  }
                ],
                "editorId": "stdbottomnav2"
              }
            ],
            "editorId": "container58"
          }
        ],
        "editorId": "column66"
      }
    ],
    "editorId": "scaffold7"
  }
}
```

### 8. Privacy Center

- Frame ID: `frame7`
- Original page prompt: "Audit dashboard for device permissions and data transparency categories."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "divider"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "PRIVACY CENTER"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 900
                                }
                              }
                            },
                            "editorId": "text91"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Privacy Audit"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "headline_medium"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary_text"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 800
                                }
                              }
                            },
                            "editorId": "text92"
                          }
                        ],
                        "editorId": "column72"
                      },
                      {
                        "type": "iconbutton",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "shield_moon_rounded"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          }
                        },
                        "editorId": "iconbutton9"
                      }
                    ],
                    "editorId": "row51"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "bg": {
                        "color": {
                          "color": "primary",
                          "opacityPercent": 5
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "lg"
                        }
                      },
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "primary/20"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.pie_chart",
                            "properties": {
                              "data": {
                                "stringVal": {
                                  "value": "92,8"
                                }
                              },
                              "labels": {
                                "stringVal": {
                                  "value": "Protected,Exposed"
                                }
                              },
                              "colors": {
                                "stringVal": {
                                  "value": "primary,divider"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "donut"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "compact"
                                }
                              },
                              "ring": {
                                "stringVal": {
                                  "value": "thick"
                                }
                              },
                              "legend": {
                                "stringVal": {
                                  "value": "hidden"
                                }
                              }
                            },
                            "editorId": "stdpiechart2"
                          },
                          {
                            "type": "column",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              },
                              "expanded": {
                                "expanded": {
                                  "enabled": true,
                                  "flex": 1
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Privacy status is optimal"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "title_medium"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "#FFFFFF"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text93"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Last checked: Today, 10:45 AM"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "#FFFFFF"
                                    }
                                  }
                                },
                                "editorId": "text94"
                              }
                            ],
                            "editorId": "column73"
                          },
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Refresh"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "secondary"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "small"
                                }
                              }
                            },
                            "editorId": "stdbutton13"
                          }
                        ],
                        "editorId": "row52"
                      }
                    ],
                    "editorId": "container60"
                  }
                ],
                "editorId": "column71"
              }
            ],
            "editorId": "container59"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "lg"
                }
              }
            },
            "children": [
              {
                "type": "text",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Data Boundaries"
                    }
                  },
                  "style": {
                    "textStyle": {
                      "styleName": "title_medium"
                    }
                  },
                  "color": {
                    "color": {
                      "color": "primary_text"
                    }
                  },
                  "font_weight": {
                    "numberVal": {
                      "value": 700
                    }
                  }
                },
                "editorId": "text95"
              },
              {
                "type": "container",
                "properties": {
                  "bg": {
                    "color": {
                      "color": "surface_variant"
                    }
                  },
                  "radius": {
                    "radius": {
                      "topLeft": 0,
                      "topRight": 0,
                      "bottomLeft": 0,
                      "bottomRight": 0,
                      "token": "lg"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "key_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 20
                                }
                              }
                            },
                            "editorId": "icon31"
                          },
                          {
                            "type": "column",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              },
                              "expanded": {
                                "expanded": {
                                  "enabled": true,
                                  "flex": 1
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "On-Device Processing"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_large"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "primary_text"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text96"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "All security analysis and file inspections are performed locally. No personal content leaves this device."
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "body_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text97"
                              }
                            ],
                            "editorId": "column76"
                          }
                        ],
                        "editorId": "row53"
                      },
                      {
                        "type": "divider",
                        "properties": {
                          "color": {
                            "color": {
                              "color": "divider"
                            }
                          }
                        },
                        "editorId": "divider6"
                      },
                      {
                        "type": "row",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "cloud_off_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "secondary_text"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 20
                                }
                              }
                            },
                            "editorId": "icon32"
                          },
                          {
                            "type": "column",
                            "properties": {
                              "spacing": {
                                "stringVal": {
                                  "value": "xs"
                                }
                              },
                              "expanded": {
                                "expanded": {
                                  "enabled": true,
                                  "flex": 1
                                }
                              }
                            },
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Minimal Retainment"
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "label_large"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "primary_text"
                                    }
                                  },
                                  "font_weight": {
                                    "stringVal": {
                                      "value": "bold"
                                    }
                                  }
                                },
                                "editorId": "text98"
                              },
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "stringVal": {
                                      "value": "Privex only stores sanitized metadata for scan history. Raw messages and URLs are never logged."
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "body_small"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "secondary_text"
                                    }
                                  }
                                },
                                "editorId": "text99"
                              }
                            ],
                            "editorId": "column77"
                          }
                        ],
                        "editorId": "row54"
                      }
                    ],
                    "editorId": "column75"
                  }
                ],
                "editorId": "container61"
              },
              {
                "type": "text",
                "properties": {
                  "content": {
                    "stringVal": {
                      "value": "Permissions Audit"
                    }
                  },
                  "style": {
                    "textStyle": {
                      "styleName": "title_medium"
                    }
                  },
                  "color": {
                    "color": {
                      "color": "primary_text"
                    }
                  },
                  "font_weight": {
                    "numberVal": {
                      "value": 700
                    }
                  }
                },
                "editorId": "text100"
              },
              {
                "type": "@privacy_category_card",
                "properties": {
                  "category": {
                    "stringVal": {
                      "value": "Location Services"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "SAFE"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "No persistent background tracking detected."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "location_off_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "success"
                    }
                  }
                },
                "editorId": "privacycategorycard1"
              },
              {
                "type": "@privacy_category_card",
                "properties": {
                  "category": {
                    "stringVal": {
                      "value": "Camera & Mic"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "MONITORED"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Only active during QR scans and manual inputs."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "sensitive_it_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "info"
                    }
                  }
                },
                "editorId": "privacycategorycard2"
              },
              {
                "type": "@privacy_category_card",
                "properties": {
                  "category": {
                    "stringVal": {
                      "value": "File System"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "SCOPED"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "Access restricted to selected files via Storage Access Framework."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "folder_special_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "success"
                    }
                  }
                },
                "editorId": "privacycategorycard3"
              },
              {
                "type": "@privacy_category_card",
                "properties": {
                  "category": {
                    "stringVal": {
                      "value": "Clipboard Access"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "WARNING"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "3 apps have permission to read your clipboard history."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "assignment_late_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "warning"
                    }
                  }
                },
                "editorId": "privacycategorycard4"
              },
              {
                "type": "@privacy_category_card",
                "properties": {
                  "category": {
                    "stringVal": {
                      "value": "Contact Data"
                    }
                  },
                  "status": {
                    "stringVal": {
                      "value": "PRIVATE"
                    }
                  },
                  "desc": {
                    "stringVal": {
                      "value": "No unauthorized contact harvesting detected."
                    }
                  },
                  "icon": {
                    "stringVal": {
                      "value": "contact_page_rounded"
                    }
                  },
                  "tone": {
                    "stringVal": {
                      "value": "success"
                    }
                  }
                },
                "editorId": "privacycategorycard5"
              },
              {
                "type": "container",
                "properties": {
                  "margin": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "topToken": "top",
                      "rightToken": "md",
                      "bottomToken": "top",
                      "leftToken": "md"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "token": "lg"
                    }
                  },
                  "radius": {
                    "radius": {
                      "topLeft": 0,
                      "topRight": 0,
                      "bottomLeft": 0,
                      "bottomRight": 0,
                      "token": "lg"
                    }
                  },
                  "bg": {
                    "color": {
                      "color": "error",
                      "opacityPercent": 5
                    }
                  },
                  "border": {
                    "border": {
                      "width": 1,
                      "color": "error/20"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "sm"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Sensitive Data Management"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_large"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "#FFFFFF"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          }
                        },
                        "editorId": "text101"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Securely purge all local scan metadata, cached threat signatures, and vault indexing."
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "#FFFFFF"
                            }
                          }
                        },
                        "editorId": "text102"
                      },
                      {
                        "type": "@std.button",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Purge Local Privacy Logs"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "destructive"
                            }
                          },
                          "full_width": {
                            "boolVal": {
                              "value": true
                            }
                          },
                          "size": {
                            "stringVal": {
                              "value": "medium"
                            }
                          }
                        },
                        "editorId": "stdbutton14"
                      }
                    ],
                    "editorId": "column78"
                  }
                ],
                "editorId": "container62"
              }
            ],
            "editorId": "column74"
          },
          {
            "type": "sizedbox",
            "properties": {
              "height": {
                "px": {
                  "value": 40,
                  "isInfinity": false
                }
              }
            },
            "editorId": "sizedbox5"
          }
        ],
        "editorId": "column70"
      }
    ],
    "editorId": "scaffold8"
  }
}
```

### 9. Password Generator

- Frame ID: `frame2`
- Original page prompt: "Tool for creating secure passwords or passphrases with customizable complexity toggles."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "iconbutton",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "arrow_back_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary_text"
                        }
                      }
                    },
                    "editorId": "iconbutton10"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "expanded": {
                        "expanded": {
                          "enabled": true,
                          "flex": 1
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Password Generator"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "title_large"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "text103"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Secure, on-device secret creation"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          }
                        },
                        "editorId": "text104"
                      }
                    ],
                    "editorId": "column80"
                  }
                ],
                "editorId": "row55"
              }
            ],
            "editorId": "container63"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "xl"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface_variant"
                }
              },
              "border": {
                "border": {
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "lg"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "text",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "GENERATED SECRET"
                        }
                      },
                      "style": {
                        "textStyle": {
                          "styleName": "label_small"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      },
                      "font_weight": {
                        "numberVal": {
                          "value": 800
                        }
                      }
                    },
                    "editorId": "text105"
                  },
                  {
                    "type": "container",
                    "properties": {
                      "padding": {
                        "edgeInsets": {
                          "top": 0,
                          "right": 0,
                          "bottom": 0,
                          "left": 0,
                          "token": "lg"
                        }
                      },
                      "radius": {
                        "radius": {
                          "topLeft": 0,
                          "topRight": 0,
                          "bottomLeft": 0,
                          "bottomRight": 0,
                          "token": "md"
                        }
                      },
                      "bg": {
                        "color": {
                          "color": "background"
                        }
                      },
                      "width": {
                        "px": {
                          "value": "Infinity",
                          "isInfinity": true
                        }
                      },
                      "border": {
                        "border": {
                          "width": 1,
                          "color": "divider"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "row",
                        "properties": {
                          "align": {
                            "align": {
                              "named": "space_between"
                            }
                          },
                          "cross_align": {
                            "align": {
                              "named": "center"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "expanded",
                            "children": [
                              {
                                "type": "text",
                                "properties": {
                                  "content": {
                                    "interpolatedString": {
                                      "parts": [
                                        {
                                          "literal": "K9#m"
                                        },
                                        {
                                          "slot": "P2v"
                                        },
                                        {
                                          "literal": "!xQ7*L9z"
                                        }
                                      ]
                                    }
                                  },
                                  "style": {
                                    "textStyle": {
                                      "styleName": "headline_small"
                                    }
                                  },
                                  "font": {
                                    "stringVal": {
                                      "value": "mono"
                                    }
                                  },
                                  "color": {
                                    "color": {
                                      "color": "primary"
                                    }
                                  },
                                  "max_lines": {
                                    "numberVal": {
                                      "value": 1
                                    }
                                  },
                                  "overflow": {
                                    "stringVal": {
                                      "value": "ellipsis"
                                    }
                                  }
                                },
                                "editorId": "text106"
                              }
                            ],
                            "editorId": "expanded10"
                          },
                          {
                            "type": "iconbutton",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "visibility_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "secondary_text"
                                }
                              },
                              "size": {
                                "numberVal": {
                                  "value": 20
                                }
                              }
                            },
                            "editorId": "iconbutton11"
                          }
                        ],
                        "editorId": "row56"
                      }
                    ],
                    "editorId": "container65"
                  },
                  {
                    "type": "row",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "md"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@std.button",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Copy Password"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "content_copy_rounded"
                            }
                          },
                          "variant": {
                            "stringVal": {
                              "value": "primary"
                            }
                          },
                          "expanded": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "editorId": "stdbutton15"
                      },
                      {
                        "type": "iconbutton",
                        "properties": {
                          "name": {
                            "icon": {
                              "name": "refresh_rounded"
                            }
                          },
                          "bg": {
                            "color": {
                              "color": "primary",
                              "opacityPercent": 10
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "radius": {
                            "radius": {
                              "topLeft": 0,
                              "topRight": 0,
                              "bottomLeft": 0,
                              "bottomRight": 0,
                              "token": "md"
                            }
                          },
                          "size": {
                            "numberVal": {
                              "value": 28
                            }
                          }
                        },
                        "editorId": "iconbutton12"
                      }
                    ],
                    "editorId": "row57"
                  }
                ],
                "editorId": "column81"
              }
            ],
            "editorId": "container64"
          },
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "rightToken": "lg",
                  "leftToken": "lg"
                }
              }
            },
            "children": [
              {
                "type": "@std.tab_group",
                "properties": {
                  "label_1": {
                    "stringVal": {
                      "value": "Password"
                    }
                  },
                  "label_2": {
                    "stringVal": {
                      "value": "Passphrase"
                    }
                  }
                },
                "editorId": "stdtabgroup1"
              }
            ],
            "editorId": "container66"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "xl"
                }
              }
            },
            "children": [
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "row",
                    "properties": {
                      "align": {
                        "align": {
                          "named": "space_between"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Password Length"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "title_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          }
                        },
                        "editorId": "text107"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "16"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "title_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "font_weight": {
                            "stringVal": {
                              "value": "bold"
                            }
                          }
                        },
                        "editorId": "text108"
                      }
                    ],
                    "editorId": "row58"
                  },
                  {
                    "type": "@std.slider",
                    "properties": {
                      "value_percentage": {
                        "numberVal": {
                          "value": 60
                        }
                      },
                      "color": {
                        "stringVal": {
                          "value": "primary"
                        }
                      },
                      "label": {
                        "stringVal": {
                          "value": "Length"
                        }
                      }
                    },
                    "editorId": "stdslider1"
                  }
                ],
                "editorId": "column83"
              },
              {
                "type": "container",
                "properties": {
                  "bg": {
                    "color": {
                      "color": "surface"
                    }
                  },
                  "radius": {
                    "radius": {
                      "topLeft": 0,
                      "topRight": 0,
                      "bottomLeft": 0,
                      "bottomRight": 0,
                      "token": "lg"
                    }
                  },
                  "border": {
                    "border": {
                      "width": 1,
                      "color": "outline"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "bottomToken": "md"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "numberVal": {
                          "value": 0
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "container",
                        "properties": {
                          "padding": {
                            "edgeInsets": {
                              "top": 0,
                              "right": 0,
                              "bottom": 0,
                              "left": 0,
                              "token": "lg"
                            }
                          },
                          "border": {
                            "borderSided": {
                              "side": "bottom",
                              "width": 1,
                              "color": "divider"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Complexity Rules"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "secondary_text"
                                }
                              },
                              "font_weight": {
                                "numberVal": {
                                  "value": 800
                                }
                              }
                            },
                            "editorId": "text109"
                          }
                        ],
                        "editorId": "container68"
                      },
                      {
                        "type": "sizedbox",
                        "properties": {
                          "height": {
                            "stringVal": {
                              "value": "md"
                            }
                          }
                        },
                        "editorId": "sizedbox6"
                      },
                      {
                        "type": "@option_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Uppercase (A-Z)"
                            }
                          },
                          "active": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "editorId": "optionrow1"
                      },
                      {
                        "type": "divider",
                        "properties": {
                          "indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "end_indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "divider"
                            }
                          }
                        },
                        "editorId": "divider7"
                      },
                      {
                        "type": "@option_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Lowercase (a-z)"
                            }
                          },
                          "active": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "editorId": "optionrow2"
                      },
                      {
                        "type": "divider",
                        "properties": {
                          "indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "end_indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "divider"
                            }
                          }
                        },
                        "editorId": "divider8"
                      },
                      {
                        "type": "@option_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Numbers (0-9)"
                            }
                          },
                          "active": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "editorId": "optionrow3"
                      },
                      {
                        "type": "divider",
                        "properties": {
                          "indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "end_indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "divider"
                            }
                          }
                        },
                        "editorId": "divider9"
                      },
                      {
                        "type": "@option_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Special Characters (!@#$)"
                            }
                          },
                          "active": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "editorId": "optionrow4"
                      },
                      {
                        "type": "divider",
                        "properties": {
                          "indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "end_indent": {
                            "stringVal": {
                              "value": "lg"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "divider"
                            }
                          }
                        },
                        "editorId": "divider10"
                      },
                      {
                        "type": "@option_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Avoid Ambiguous (l, 1, O, 0)"
                            }
                          },
                          "active": {
                            "boolVal": {
                              "value": false
                            }
                          }
                        },
                        "editorId": "optionrow5"
                      }
                    ],
                    "editorId": "column84"
                  }
                ],
                "editorId": "container67"
              }
            ],
            "editorId": "column82"
          },
          {
            "type": "container",
            "properties": {
              "margin": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "radius": {
                "radius": {
                  "topLeft": 0,
                  "topRight": 0,
                  "bottomLeft": 0,
                  "bottomRight": 0,
                  "token": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "info",
                  "opacityPercent": 10
                }
              },
              "border": {
                "border": {
                  "width": 1,
                  "color": "info/30"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "start"
                    }
                  }
                },
                "children": [
                  {
                    "type": "icon",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "security_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "#FFFFFF"
                        }
                      },
                      "size": {
                        "numberVal": {
                          "value": 20
                        }
                      }
                    },
                    "editorId": "icon33"
                  },
                  {
                    "type": "expanded",
                    "children": [
                      {
                        "type": "column",
                        "properties": {
                          "spacing": {
                            "stringVal": {
                              "value": "xs"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Privacy Guaranteed"
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "label_large"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              },
                              "font_weight": {
                                "stringVal": {
                                  "value": "bold"
                                }
                              }
                            },
                            "editorId": "text110"
                          },
                          {
                            "type": "text",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Passwords are generated using cryptographically secure entropy and are never stored or transmitted."
                                }
                              },
                              "style": {
                                "textStyle": {
                                  "styleName": "body_small"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "#FFFFFF"
                                }
                              }
                            },
                            "editorId": "text111"
                          }
                        ],
                        "editorId": "column85"
                      }
                    ],
                    "editorId": "expanded11"
                  }
                ],
                "editorId": "row59"
              }
            ],
            "editorId": "container69"
          },
          {
            "type": "sizedbox",
            "properties": {
              "height": {
                "px": {
                  "value": 80,
                  "isInfinity": false
                }
              }
            },
            "editorId": "sizedbox7"
          }
        ],
        "editorId": "column79"
      }
    ],
    "editorId": "scaffold9"
  }
}
```

### 10. Settings

- Frame ID: `frame3`
- Original page prompt: "Categorized app preferences for protection toggles, notifications, and theme selection."
- Follow-up prompts: _None_

#### DslDocument (JSON)

```json
{
  "root": {
    "type": "scaffold",
    "properties": {
      "bg": {
        "color": {
          "color": "background"
        }
      }
    },
    "children": [
      {
        "type": "column",
        "properties": {
          "scroll": {
            "boolVal": {
              "value": true
            }
          },
          "cross_align": {
            "align": {
              "named": "stretch"
            }
          }
        },
        "children": [
          {
            "type": "container",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "topToken": "xl",
                  "rightToken": "lg",
                  "bottomToken": "md",
                  "leftToken": "lg"
                }
              },
              "bg": {
                "color": {
                  "color": "surface"
                }
              },
              "border": {
                "borderSided": {
                  "side": "bottom",
                  "width": 1,
                  "color": "outline"
                }
              }
            },
            "children": [
              {
                "type": "row",
                "properties": {
                  "align": {
                    "align": {
                      "named": "space_between"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "PRIVEX SECURITY"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 900
                            }
                          }
                        },
                        "editorId": "text112"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Settings"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "headline_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 800
                            }
                          }
                        },
                        "editorId": "text113"
                      }
                    ],
                    "editorId": "column87"
                  },
                  {
                    "type": "iconbutton",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "close_rounded"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "secondary_text"
                        }
                      },
                      "size": {
                        "numberVal": {
                          "value": 24
                        }
                      }
                    },
                    "editorId": "iconbutton13"
                  }
                ],
                "editorId": "row60"
              }
            ],
            "editorId": "container70"
          },
          {
            "type": "column",
            "properties": {
              "padding": {
                "edgeInsets": {
                  "top": 0,
                  "right": 0,
                  "bottom": 0,
                  "left": 0,
                  "token": "lg"
                }
              },
              "spacing": {
                "stringVal": {
                  "value": "xl"
                }
              }
            },
            "children": [
              {
                "type": "@settings_group",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "PROTECTION"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "cross_align": {
                        "align": {
                          "named": "stretch"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Main Protection"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Active real-time shielding"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "shield_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": true
                                }
                              }
                            },
                            "editorId": "stdswitch3"
                          }
                        ],
                        "editorId": "settingsrow1"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Real-time Scanning"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Scan items as they arrive"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "memory_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": true
                                }
                              }
                            },
                            "editorId": "stdswitch4"
                          }
                        ],
                        "editorId": "settingsrow2"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Haptic Alerts"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Vibrate on threat detection"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "vibrator_rounded"
                            }
                          },
                          "last": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": false
                                }
                              }
                            },
                            "editorId": "stdswitch5"
                          }
                        ],
                        "editorId": "settingsrow3"
                      }
                    ],
                    "editorId": "column89"
                  }
                ],
                "editorId": "settingsgroup1"
              },
              {
                "type": "@settings_group",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "WEB PROTECTION"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "cross_align": {
                        "align": {
                          "named": "stretch"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Trusted Domains"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Manage your allowlist"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "language_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "icon",
                            "properties": {
                              "name": {
                                "icon": {
                                  "name": "chevron_right_rounded"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "hint"
                                }
                              }
                            },
                            "editorId": "icon34"
                          }
                        ],
                        "editorId": "settingsrow4"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Phishing Database"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Last updated: 2h ago"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "update_rounded"
                            }
                          },
                          "last": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.button",
                            "properties": {
                              "content": {
                                "stringVal": {
                                  "value": "Update"
                                }
                              },
                              "variant": {
                                "stringVal": {
                                  "value": "ghost"
                                }
                              },
                              "size": {
                                "stringVal": {
                                  "value": "small"
                                }
                              }
                            },
                            "editorId": "stdbutton16"
                          }
                        ],
                        "editorId": "settingsrow5"
                      }
                    ],
                    "editorId": "column90"
                  }
                ],
                "editorId": "settingsgroup2"
              },
              {
                "type": "@settings_group",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "NOTIFICATIONS"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "cross_align": {
                        "align": {
                          "named": "stretch"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Security Alerts"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Critical threat warnings"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "notifications_active_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": true
                                }
                              }
                            },
                            "editorId": "stdswitch6"
                          }
                        ],
                        "editorId": "settingsrow6"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Scan Completion"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Summary after every scan"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "task_alt_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": false
                                }
                              }
                            },
                            "editorId": "stdswitch7"
                          }
                        ],
                        "editorId": "settingsrow7"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Health Reports"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Weekly security summary"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "assessment_rounded"
                            }
                          },
                          "last": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": true
                                }
                              }
                            },
                            "editorId": "stdswitch8"
                          }
                        ],
                        "editorId": "settingsrow8"
                      }
                    ],
                    "editorId": "column91"
                  }
                ],
                "editorId": "settingsgroup3"
              },
              {
                "type": "@settings_group",
                "properties": {
                  "title": {
                    "stringVal": {
                      "value": "PREFERENCES"
                    }
                  }
                },
                "children": [
                  {
                    "type": "column",
                    "properties": {
                      "cross_align": {
                        "align": {
                          "named": "stretch"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Explanation Level"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Simple or Technical view"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "psychology_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "dropdown",
                            "properties": {
                              "value": {
                                "stringVal": {
                                  "value": "Simple"
                                }
                              },
                              "options": {
                                "stringVal": {
                                  "value": "Simple,Technical"
                                }
                              },
                              "bg": {
                                "color": {
                                  "color": "transparent"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "radius": {
                                "radius": {
                                  "topLeft": 0,
                                  "topRight": 0,
                                  "bottomLeft": 0,
                                  "bottomRight": 0,
                                  "token": "md"
                                }
                              }
                            },
                            "editorId": "dropdown1"
                          }
                        ],
                        "editorId": "settingsrow9"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Theme"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "System default active"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "dark_mode_rounded"
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "dropdown",
                            "properties": {
                              "value": {
                                "stringVal": {
                                  "value": "System"
                                }
                              },
                              "options": {
                                "stringVal": {
                                  "value": "System,Light,Dark"
                                }
                              },
                              "bg": {
                                "color": {
                                  "color": "transparent"
                                }
                              },
                              "color": {
                                "color": {
                                  "color": "primary"
                                }
                              },
                              "radius": {
                                "radius": {
                                  "topLeft": 0,
                                  "topRight": 0,
                                  "bottomLeft": 0,
                                  "bottomRight": 0,
                                  "token": "md"
                                }
                              }
                            },
                            "editorId": "dropdown2"
                          }
                        ],
                        "editorId": "settingsrow10"
                      },
                      {
                        "type": "@settings_row",
                        "properties": {
                          "label": {
                            "stringVal": {
                              "value": "Biometric Lock"
                            }
                          },
                          "subtitle": {
                            "stringVal": {
                              "value": "Require ID to open Privex"
                            }
                          },
                          "icon": {
                            "stringVal": {
                              "value": "fingerprint_rounded"
                            }
                          },
                          "last": {
                            "boolVal": {
                              "value": true
                            }
                          }
                        },
                        "children": [
                          {
                            "type": "@std.switch",
                            "properties": {
                              "active": {
                                "boolVal": {
                                  "value": true
                                }
                              }
                            },
                            "editorId": "stdswitch9"
                          }
                        ],
                        "editorId": "settingsrow11"
                      }
                    ],
                    "editorId": "column92"
                  }
                ],
                "editorId": "settingsgroup4"
              },
              {
                "type": "column",
                "properties": {
                  "spacing": {
                    "stringVal": {
                      "value": "md"
                    }
                  },
                  "cross_align": {
                    "align": {
                      "named": "center"
                    }
                  },
                  "padding": {
                    "edgeInsets": {
                      "top": 0,
                      "right": 0,
                      "bottom": 0,
                      "left": 0,
                      "topToken": "xl",
                      "bottomToken": "xl"
                    }
                  }
                },
                "children": [
                  {
                    "type": "logo_icon",
                    "properties": {
                      "name": {
                        "icon": {
                          "name": "privex"
                        }
                      },
                      "color": {
                        "color": {
                          "color": "primary",
                          "opacityPercent": 40
                        }
                      },
                      "size": {
                        "numberVal": {
                          "value": 48
                        }
                      }
                    },
                    "editorId": "logoicon1"
                  },
                  {
                    "type": "column",
                    "properties": {
                      "spacing": {
                        "stringVal": {
                          "value": "xs"
                        }
                      },
                      "cross_align": {
                        "align": {
                          "named": "center"
                        }
                      }
                    },
                    "children": [
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Privex Mobile Security"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "body_medium"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "primary_text"
                            }
                          },
                          "font_weight": {
                            "numberVal": {
                              "value": 600
                            }
                          }
                        },
                        "editorId": "text114"
                      },
                      {
                        "type": "text",
                        "properties": {
                          "content": {
                            "stringVal": {
                              "value": "Version 2.4.0 (Build 1082)"
                            }
                          },
                          "style": {
                            "textStyle": {
                              "styleName": "label_small"
                            }
                          },
                          "color": {
                            "color": {
                              "color": "secondary_text"
                            }
                          }
                        },
                        "editorId": "text115"
                      }
                    ],
                    "editorId": "column94"
                  },
                  {
                    "type": "@std.button",
                    "properties": {
                      "content": {
                        "stringVal": {
                          "value": "View Privacy Policy"
                        }
                      },
                      "variant": {
                        "stringVal": {
                          "value": "ghost"
                        }
                      },
                      "size": {
                        "stringVal": {
                          "value": "small"
                        }
                      }
                    },
                    "editorId": "stdbutton17"
                  }
                ],
                "editorId": "column93"
              },
              {
                "type": "sizedbox",
                "properties": {
                  "height": {
                    "px": {
                      "value": 40,
                      "isInfinity": false
                    }
                  }
                },
                "editorId": "sizedbox8"
              }
            ],
            "editorId": "column88"
          }
        ],
        "editorId": "column86"
      }
    ],
    "editorId": "scaffold10"
  }
}
```