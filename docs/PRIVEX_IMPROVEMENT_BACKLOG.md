# PRIVEX — Prioritized Improvement Roadmap & Findings Backlog (Phase 5)

> **Document Status:** CANONICAL PRODUCT & QUALITY ROADMAP  
> **Target Release:** Privex v0.1.1 -> v0.1.2 Hardening  
> **Prioritization Model:** MoSCoW & Risk-Weighted Impact (P0 Blocker -> P3 Low)  
> **Governance:** Strict Bounded Iterations • One Change at a Time • Monorepo Regression Verification  

---

## 1. Prioritized Findings Register

| Issue ID | Priority | Category | Title | Summary / Root Cause | Target Phase |
|---|---|---|---|---|---|
| **IMP-001** | **P1 (High)** | **UX & Accessibility** | Navigation Bar Touch Target & Overflow Remediation | `TabBar.tsx` packs 10 tabs into a single flex row. Targets are $< 48\text{dp}$ and overflow on mobile viewports. | Phase 6 (Immediate) |
| **IMP-002** | **P1 (High)** | **UX & Functional** | Interactive Recent Scan History on HomeScreen | `HomeScreen.tsx` renders history items as static `div`s with no tap action. `onSelectResult` is unhandled. | Phase 6 (Immediate) |
| **IMP-003** | **P2 (Medium)** | **UX & Usability** | Dashboard Quick Action Shortcuts for Privacy & Settings | HomeScreen quick actions only cover scans; Privacy and Settings lack direct dashboard tiles. | Phase 6 (Immediate) |
| **IMP-004** | **P2 (Medium)** | **Release & DevOps** | Production Keystore Signing Pipeline & Script | Release APK falls back to debug keystore when environment variables are omitted; needs documented release signing script. | Release Ops |
| **IMP-005** | **P3 (Low)** | **Feature Polish** | Exported Quarantine Audit Log | Allow users to export sanitized audit events (hashes/timestamps only) to external storage. | Future Roadmap |

---

## 2. Detailed Issue Specifications

### Issue IMP-001: Navigation Bar Touch Target & Overflow Remediation
- **Priority:** P1 (High)
- **Component:** `apps/mobile/src/components/TabBar.tsx`
- **Root Cause:** All 10 application destinations are placed in a single flat navigation bar with `minWidth: 45px`. This creates tiny touch targets violating Android Material Accessibility standards ($48\times 48\text{dp}$) and causes horizontal scrolling where "Privacy" and "Settings" are obscured.
- **Expected Behavior:**
  - Provide a clean, structured primary navigation bar with standard core destinations (`Home`, `Scans`, `Assistant`, `Engine`, `More/Settings`), or an optimized tab layout with minimum $48\times 48\text{dp}$ touch targets.
  - Include full W3C ARIA accessibility attributes: `role="tablist"`, `role="tab"`, `aria-selected`, and `aria-label`.
- **Acceptance Criteria:**
  1. Touch targets meet or exceed $48\text{px}$ minimum clickable area.
  2. All navigation items are accessible without awkward truncation.
  3. ARIA attributes present and verified by screen reader tests.
  4. 100% passing tests in `@private-protection/mobile`.

---

### Issue IMP-002: Interactive Recent Scan History on HomeScreen
- **Priority:** P1 (High)
- **Component:** `apps/mobile/src/screens/HomeScreen.tsx` & `apps/mobile/src/App.tsx`
- **Root Cause:** In `HomeScreen.tsx:179-207`, recent scan history items are rendered as inert `div` tags. In `App.tsx:143`, `onSelectResult={() => {}}` is an empty no-op.
- **Expected Behavior:**
  - History items render as interactive, accessible list items with hover/active states.
  - Tapping a history item navigates the user directly to the appropriate scanner screen (e.g., URL scan or Text scan) with the target pre-loaded, or displays detailed threat evidence.
- **Acceptance Criteria:**
  1. History items are keyboard-focusable and clickable.
  2. Clicking an item triggers `onSelectResult` and routes to the relevant scan view.
  3. Automated screen test verifies history click interaction.

---

### Issue IMP-003: Dashboard Quick Action Shortcuts for Privacy & Settings
- **Priority:** P2 (Medium)
- **Component:** `apps/mobile/src/screens/HomeScreen.tsx`
- **Root Cause:** Quick action cards on the home dashboard only link to scanners and engine diagnostics. Direct access to the Privacy Center (crypto-shredder) and Security Settings is absent.
- **Expected Behavior:**
  - Add quick action cards for "Privacy Center" and "Protection Settings" to the HomeScreen quick action grid.
- **Acceptance Criteria:**
  1. Quick actions grid includes Privacy Center and Protection Settings.
  2. Clicking them navigates directly to `PRIVACY` and `SETTINGS` tabs.
  3. Screen tests pass cleanly.

---

## 3. Phase 6 Execution Plan

In accordance with the project constitution, improvements will be executed strictly **one bounded improvement at a time**:
1. **Target:** Implement **IMP-001**, **IMP-002**, and **IMP-003** in an integrated, verified UX enhancement.
2. **Pre-verification:** Run current tests to establish test baseline.
3. **Implementation:** Update `TabBar.tsx`, `HomeScreen.tsx`, and `App.tsx`.
4. **Post-verification:** Add/update unit tests in `apps/mobile/src/__tests__/screens/screens.test.tsx` and run full test suites.
5. **Asset & APK Rebuild:** Recompile mobile web bundle and re-verify release APK build.
