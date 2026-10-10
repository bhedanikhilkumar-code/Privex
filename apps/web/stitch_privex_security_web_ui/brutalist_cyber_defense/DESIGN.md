---
name: Brutalist Cyber-Defense
colors:
  surface: '#111317'
  surface-dim: '#111317'
  surface-bright: '#37393e'
  surface-container-lowest: '#0c0e12'
  surface-container-low: '#1a1c20'
  surface-container: '#1e2024'
  surface-container-high: '#282a2e'
  surface-container-highest: '#333539'
  on-surface: '#e2e2e8'
  on-surface-variant: '#c4c5d9'
  inverse-surface: '#e2e2e8'
  inverse-on-surface: '#2f3035'
  outline: '#8d90a2'
  outline-variant: '#434656'
  surface-tint: '#b8c3ff'
  primary: '#b8c3ff'
  on-primary: '#002487'
  primary-container: '#2457ff'
  on-primary-container: '#e9eaff'
  inverse-primary: '#0549f3'
  secondary: '#cbf231'
  on-secondary: '#2a3500'
  secondary-container: '#afd500'
  on-secondary-container: '#485900'
  tertiary: '#53e076'
  on-tertiary: '#003914'
  tertiary-container: '#007b33'
  on-tertiary-container: '#aaffb2'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#dde1ff'
  primary-fixed-dim: '#b8c3ff'
  on-primary-fixed: '#001355'
  on-primary-fixed-variant: '#0036bc'
  secondary-fixed: '#cbf231'
  secondary-fixed-dim: '#afd500'
  on-secondary-fixed: '#171e00'
  on-secondary-fixed-variant: '#3e4c00'
  tertiary-fixed: '#72fe8f'
  tertiary-fixed-dim: '#53e076'
  on-tertiary-fixed: '#002108'
  on-tertiary-fixed-variant: '#005320'
  background: '#111317'
  on-background: '#e2e2e8'
  surface-variant: '#333539'
typography:
  headline-xl:
    fontFamily: Playfair Display
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Playfair Display
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Playfair Display
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Playfair Display
    fontSize: 26px
    fontWeight: '700'
    lineHeight: 34px
    letterSpacing: 0em
  headline-sm:
    fontFamily: Playfair Display
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: 0em
  body-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 28px
  body-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
  body-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  label-lg:
    fontFamily: Space Mono
    fontSize: 14px
    fontWeight: '700'
    lineHeight: 20px
    letterSpacing: 0.08em
  label-md:
    fontFamily: Space Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.1em
  label-sm:
    fontFamily: Space Mono
    fontSize: 10px
    fontWeight: '700'
    lineHeight: 14px
    letterSpacing: 0.12em
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-desktop: 2.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2.5rem
---

## Brand & Style
This design system embodies an uncompromising, tactical cyber-defense posture. Merging raw neo-brutalism with mission-critical telemetry, the interface treats every pixel as operational infrastructure. It serves security engineers, cryptographers, and incident response teams navigating local-first zero-trust networks.

The visual style pairs structural mechanical rigor with high-contrast tactical signals. Editorial serif display elements anchor high-level system states with gravitas, while dense geometric sans and monospaced data grids deliver instantaneous, unambiguous status reads. Physical hard borders, brutalist displacement shadows, and raw tabular layouts evoke air-gapped terminal consoles engineered for clarity under extreme operational pressure.

## Colors
The palette operates with stark high-contrast separation, avoiding subtle gradients or low-contrast washes. 

- **Brand Primary (`#2457FF`):** Hard cobalt blue deployed for active states, selected cryptographic channels, and authoritative interface actions.
- **Accent Neon (`#D7FF3F`):** High-frequency cyber yellow-green reserved for active scan focus, live trace indicators, and primary CTAs.
- **Status Palettes:**
  - **Safe (`#1DB954`):** Verified nodes, encrypted links, and healthy operational states.
  - **Caution (`#FFB800`):** Threat mitigation in progress, anomalous traffic, and rate-limiting triggers.
  - **Danger (`#FF5A36`):** Active intrusion, signature mismatch, failed integrity checks, and purge commands.
- **Surfaces & Neutrals:**
  - Dark Theme (Default): Canvas sits at `#0F1115`, surface containers at `#181B22`, and raised telemetry cards at `#21252E`.
  - Light Theme: Canvas at `#F4F5F8`, cards at `#FFFFFF`, with ink black `#050608` for all structural linework.
  - Night Theme (OLED / Air-Gap): True pitch `#000000` canvas with `#08090C` containers and hyper-saturated signal strokes.
- Borders universally bind to `#050608` in light mode and `#000000` or `#2E3440` in dark and night modes, maintaining absolute 2px structural containment.

## Typography
The typographic hierarchy produces an intentional tension between editorial authority and machine readouts.

- **Headlines (Playfair Display):** Imparts solemnity and institutional weight to top-level section headers, security briefings, and primary metric thresholds. Never used in all-caps.
- **Body Text (Plus Jakarta Sans):** Delivers clean, highly legible operational explanations, incident summaries, and audit logs without visual fatigue.
- **Labels, Telemetry, and Metadata (Space Mono):** Used strictly in uppercase for status tags, memory addresses, SHA-256 hashes, network routes, and interactive controls. Space Mono maintains strict horizontal tracking across dense comparative security matrices.

## Layout & Spacing
The layout relies on a strict 12-column modular grid built on a 4px base increment. Layout components prioritize dense information distribution and immediate spatial scanning over excessive whitespace.

- **Breakpoints:**
  - Mobile (<768px): 4-column layout, margin `1rem`, gutter `1rem`. Panels stack vertically into full-width monolithic cards.
  - Tablet (768px - 1024px): 8-column layout, margin `1.5rem`, gutter `1rem`. Dual telemetry streams side-by-side.
  - Desktop (>1024px): 12-column layout, margin `2.5rem`, gutter `1.5rem`. Multi-pane command view with persistent status sidecars.
- **Alignment:** Every container snaps rigidly to the grid lines. Nested child elements align flush to their parent borders, preserving an industrial, technical framework.

## Elevation & Depth
This design system explicitly rejects Gaussian blur, ambient shadow plumes, and diffuse light physics. Depth is conveyed exclusively through hard geometric displacement and structural containment:

- **Brutalist Hard Drop Shadow:** Elevated elements (modals, active cards, floating toolbars) employ an opaque, hard-edged offset: `4px 4px 0px #000000` (in light mode: `4px 4px 0px #050608`).
- **Interactive State Displacement:** On button press or card activation, the element translates `+2px, +2px` along the X/Y axes while reducing its shadow to `2px 2px 0px`, simulating the mechanical depression of a hardware relay. Disabled elements render flat with zero shadow.
- **Hard Layering:** Modals and flyout panels do not use transparent scrims. Instead, they sit above an opaque, cross-hatched SVG canvas overlay with solid 2px outer strokes.

## Shapes
All structural components enforce a zero-radius rule (`0px`). Curves, pill shapes, and subtle corner rounding are entirely prohibited. 

Interfaces adopt sharp, hard-cornered geometries reminiscent of architectural blueprints and industrial hardware consoles. Slanted or chamfered 45-degree edge cuts are permissible exclusively for micro-tags and hardware status badges to reinforce defense-grade aesthetic framing.

## Components

- **Buttons:**
  - Enclosed in a solid 2px black border with a hard `4px 4px 0px` offset shadow.
  - Typography: Space Mono uppercase (`label-md`).
  - Variants:
    - *Primary:* Accent Neon (`#D7FF3F`) background with pitch-black text.
    - *Brand:* Cobalt (`#2457FF`) background with white text.
    - *Danger / Purge:* Danger (`#FF5A36`) background with white text.
    - *Outline / Ghost:* Transparent background, 2px solid border, fills on hover.
  - Active: Translates `+2px, +2px` with a `2px 2px 0px` shadow reduction.

- **Status Chips & Monospace Badges:**
  - Compact padding (`0.15rem 0.5rem`), 2px solid border, 0px border-radius.
  - Monospace uppercase typography (`label-sm`).
  - Paired with raw categorical states: safe (`#1DB954`), caution (`#FFB800`), danger (`#FF5A36`). Optional leading glyph (e.g., `[✓]`, `[!]`, `[×]`).

- **Cards & Data Panels:**
  - 2px solid border framing container surfaces.
  - Optional header bar separated by a solid 2px horizontal border, often containing a Playfair Display title juxtaposed with an uppercase Space Mono status counter.
  - Interactive cards display the `4px 4px 0px` brutalist shadow; static panels remain flat.

- **Input Fields & Search Bars:**
  - Boxy inputs with a 2px solid border and high-contrast background.
  - Monospace text input (`Space Mono`). Placeholder text styled in uppercase muted tone.
  - Focus state: Outline thickens to an inverted high-visibility color or triggers a `3px 3px 0px #D7FF3F` hard offset without rounded rings.

- **Checkboxes & Radios:**
  - Strict square checkboxes (`16px x 16px`) and diamond or square radios with 2px solid outlines.
  - Checked state fills with Accent Neon or Safe Green, displaying a hard sharp `X` or solid square block rather than a curved checkmark.

- **Telemetry Data Tables & Log Streams:**
  - Dense monospaced data grids with solid 1px inner grid lines and a 2px outer frame.
  - Alternating row zebra strips using micro-contrasted neutral steps. 
  - Threat score columns feature full-saturation background fills using semantic status tokens.

- **Kill-Switch / Hardware Toggle:**
  - Heavy rectangular block toggles with visible two-position sliding indicators, labeled mechanically with uppercase `LOCKED / ARMED` indicators.