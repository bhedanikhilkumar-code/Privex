# RISK_ENGINE_ARCHITECTURE.md — Multi-Factor Risk Engine & Scoring Mathematics

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION RISK ENGINE**  
> This document specifies the mathematical model, weighting mechanisms, confidence scoring, conflict resolution rules, and uncertainty quantification governing the Multi-Factor Risk Engine.

---

## 1. MATHEMATICAL FORMULATION & AGGREGATION MODEL

The Risk Engine rejects naive linear summation ($R = \sum w_i S_i$) because linear addition either under-represents high-severity critical single indicators or over-represents multiple weak benign signals.

Instead, PRIVATE PROTECTION employs a **Bounded Non-Linear Diminishing-Returns Aggregation Model with Critical Override Logic**:

### 1.1 Base Formulation
Let $\mathcal{E} = \{e_1, e_2, \dots, e_n\}$ be the set of triggered `Evidence` tokens.
Each evidence token $e_i$ is characterized by:
- $s_i \in [0, 100]$: Raw threat score contribution.
- $w_i \in [0.0, 1.0]$: Base detector reliability weight.
- $c_i \in [0.0, 1.0]$: Detector confidence in this specific observation.

The effective signal contribution $x_i$ is defined as:
$$x_i = s_i \times w_i \times c_i$$

### 1.2 Non-Linear Diminishing Returns (Log-Odds Combination)
To ensure multiple medium signals asymptotically approach 100 without exceeding it:
$$R_{\text{raw}} = 100 \times \left(1 - \prod_{i=1}^n \left(1 - \frac{x_i}{100}\right)\right)$$

### 1.3 Critical Rule Priority Override
Certain deterministic indicators represent unambiguous, mathematically proven threats (e.g., IDN homoglyph spoofing targeting high-value financial institutions, or exact Bloom filter blocklist matches). If any evidence token carries the `CRITICAL_OVERRIDE` flag:
$$R_{\text{final}} = \max\left(R_{\text{raw}}, \max_{e_k \in \mathcal{E}_{\text{critical}}} s_k\right)$$

---

## 2. DETECTOR WEIGHTING MATRIX

Base reliability weights ($w_i$) reflect the empirical false positive rates of the respective detector classes:

| Detector Plane | Category | Base Weight ($w_i$) | False Positive Rate | Justification |
|---|---|---|---|---|
| **Deterministic Rule Engine** | Structural / Scheme / IP | **1.00** | $0.00\%$ | Definite protocol violations (e.g. `http://` on bank domain, raw IP hostname). |
| **Threat Intelligence** | Local Bloom Filter Hit | **0.95** | $< 0.10\%$ | Cryptographic hash match against curated active phishing/malware feeds. |
| **Lexical Analyzer** | Brand Levenshtein Match | **0.85** | $< 1.00\%$ | High-precision brand spoofing detection (e.g. `paypa1.com` edit distance = 1). |
| **Heuristic Parser** | Shannon Entropy / Keywords | **0.70** | $\approx 3.00\%$ | Measures randomness/urgency; requires corroboration with other signals. |
| **On-Device ML Classifier**| Quantized Intent Model | **0.65** | $\approx 4.50\%$ | Statistical natural language inference; weighted lower than deterministic rules. |
| **DOM Content Analyzer** | Password over HTTP / Actions | **0.90** | $< 0.50\%$ | Severe browser DOM security boundary violation. |

---

## 3. CONFIDENCE CALCULATION & UNCERTAINTY QUANTIFICATION

The aggregate confidence score $C_{\text{final}} \in [0.0, 1.0]$ represents the statistical certainty of the verdict. It balances:
1. **Signal Agreement ($A$)**: Degree of consensus among active detectors.
2. **Detector Coverage ($K$)**: Proportion of available detectors that successfully executed.
3. **Data Freshness Penalty ($P_{\text{stale}}$)**: Time elapsed since the last threat feed update.

### Formula
$$C_{\text{final}} = \left(\frac{1}{n} \sum_{i=1}^n c_i\right) \times K \times (1 - P_{\text{stale}}) \times A$$

Where:
- **Detector Coverage ($K$)**:
  $$K = \frac{\text{Active Detectors Successfully Executed}}{\text{Total Available Detectors for Target Type}}$$
- **Staleness Penalty ($P_{\text{stale}}$)**:
  - If Threat Intel Age $\le 7\text{ days}$: $P_{\text{stale}} = 0.0$
  - If Threat Intel Age $> 7\text{ days}$: $P_{\text{stale}} = \min\left(0.20, \frac{\text{Days} - 7}{100}\right)$
- **Signal Agreement ($A$)**:
  $$A = 1.0 - \frac{\sigma(s_i)}{50}$$
  (Where $\sigma(s_i)$ is the standard deviation of triggered score contributions).

---

## 4. SEVERITY LEVEL & ACTION MAPPING THRESHOLDS

The final numeric risk score $R_{\text{final}}$ and confidence $C_{\text{final}}$ map deterministically to security actions:

```
┌──────────────┬──────────────────┬─────────────────┬───────────────────┬───────────────────────┐
│ Risk Score   │ Severity Level   │ Verdict         │ UI Action         │ User Friction Level   │
├──────────────┼──────────────────┼─────────────────┼───────────────────┼───────────────────────┤
│ 0 – 19       │ NONE             │ ALLOW           │ Silent Proceed    │ Zero friction         │
│ 20 – 49      │ LOW              │ INFORM          │ Passive Badge     │ Zero friction         │
│ 50 – 69      │ MEDIUM           │ CAUTION         │ Warning Banner    │ Low (Dismissable)     │
│ 70 – 84      │ HIGH             │ SUSPICIOUS      │ Modal Interstitial│ Medium (Explicit tap) │
│ 85 – 100     │ CRITICAL         │ DANGEROUS       │ Hard Interstitial │ High (5s delay gate)  │
└──────────────┴──────────────────┴─────────────────┴───────────────────┴───────────────────────┘
```

### Edge-Case Safety Rule
If $R_{\text{final}} \ge 70$ but Confidence $C_{\text{final}} < 0.40$ (e.g. single noisy heuristic triggered in an isolated offline environment), the verdict is automatically clamped to `CAUTION` rather than `DANGEROUS`, and the UI explicitly explains the uncertainty to avoid false alarm fatigue.

---

## 5. CONFLICT RESOLUTION RULES

When different detectors emit opposing or conflicting evaluations:

### Rule 1: High Entropy vs. Benign Rule
- *Scenario*: URL has high Shannon entropy (e.g., CDN hash `cdn-ak.a83f99a.net`) but matches a verified benign domain pattern.
- *Resolution*: Verified structural allowlists suppress entropy penalties. Legitimate CDNs and signed software distributors do not trigger warnings on entropy alone without brand spoofing or known bad TLD correlation.

### Rule 2: Rule Engine Clean vs. High Urgency Heuristic
- *Scenario*: Inbound SMS contains no links and no blacklisted terms, but scores 90 on urgency pressure.
- *Resolution*: The message receives a `CAUTION` verdict categorized as `SOCIAL_ENGINEERING_PRESSURE`. The user is informed of psychological pressure tactics without falsely claiming technical malware exists.

### Rule 3: Detector Failure (Fail-Closed Policy)
- *Scenario*: An analyzer crashes, encounters an unsupported encoding, or hits an execution timeout.
- *Resolution*: The engine records an `ANALYSIS_DEGRADED` evidence token with $s = 35, w = 1.0$. The system **never defaults to silent ALLOW**. It outputs a `CAUTION` verdict indicating that full verification could not be completed.

---

## 6. EXPLAINABILITY TRACING & ATTRIBUTION

To ensure that every warning presented by the AI Assistant is completely substantiated:
1. **Traceability Chain**:
   $$\text{Raw Target} \longrightarrow \text{Rule / Heuristic} \longrightarrow \text{Evidence Token} \longrightarrow \text{Risk Score} \longrightarrow \text{AI Explanation}$$
2. **Attribution Integrity**:
   - The `RiskAssessment` records the `primaryThreatFactor` (the evidence token contributing the highest $x_i$).
   - The AI Assistant prompt is populated strictly with the top 3 contributing `Evidence` tokens.
   - The AI Assistant is prohibited from inventing threats not present in the evidence list.
