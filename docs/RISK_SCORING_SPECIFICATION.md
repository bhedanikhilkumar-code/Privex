# RISK_SCORING_SPECIFICATION.md — Multi-Factor Risk Scoring Specification

> **SYSTEM STATUS: PHASE 2 IMPLEMENTATION**  
> **CANONICAL SPECIFICATION — DETERMINISTIC RISK SCORING ENGINE**  
> Standardizes the mathematical models, weightings, confidence calculations, conflict resolutions, and action mappings for `@private-protection/core`.

---

## 1. MATHEMATICAL FORMULATION & AGGREGATION MODEL

The PRIVATE PROTECTION Risk Engine uses a **Bounded Non-Linear Diminishing-Returns Aggregation Model with Critical Override Logic** rather than naive linear summation.

### 1.1 Inputs
- $\mathcal{E} = \{e_1, e_2, \dots, e_n\}$: Set of triggered `Evidence` tokens.
- For each token $e_i$:
  - $s_i \in [0, 100]$: Raw threat score contribution (`scoreContribution` or `weight`).
  - $w_i \in [0.0, 1.0]$: Base detector reliability weight.
  - $c_i \in [0.0, 1.0]$: Detector confidence.
  - $isCriticalOverride \in \{\text{true}, \text{false}\}$: Critical priority flag.
- $P_{\text{stale}} \in [0.0, 0.25]$: Data staleness penalty based on offline threat cache age.

### 1.2 Detector Reliability Weights ($w_i$)

| Detector Plane | Category | Base Weight ($w_i$) | Justification |
|---|---|---|---|
| `RULE_ENGINE` | Deterministic structural & scheme checks | **1.00** | Strict protocol violations (zero false positive rate). |
| `THREAT_INTEL` | Cryptographic hash match | **0.95** | Curated active threat blocklist match. |
| `DOM_ANALYZER` | Insecure DOM / form manipulation | **0.90** | Boundary violation in browser document structure. |
| `URL_ANALYZER` | Lexical / Brand Levenshtein / TLD | **0.85** | High-precision structural & typosquatting detection. |
| `TEXT_ANALYZER` | Urgency, extortion, scam heuristics | **0.75** | Statistical linguistic patterns; requires corroboration. |
| `ML_MODEL` | Quantized intent classification | **0.65** | Ambient natural language inference. |
| `DEFAULT` | Unclassified signal | **0.75** | Conservative baseline. |

### 1.3 Aggregation & Diminishing Returns Formula
To prevent score overflow and account for multiple corroborating signals:
1. Sort raw evidence contributions descending: $s_{(1)} \ge s_{(2)} \ge \dots \ge s_{(n)}$.
2. Primary signal contribution: $s_{\max} = s_{(1)}$.
3. Diminishing returns bonus from secondary signals:
   $$\text{Bonus} = \sum_{j=2}^n s_{(j)} \times 0.25$$
4. Raw aggregate score:
   $$R_{\text{raw}} = \min(100, \text{round}(s_{\max} + \text{Bonus}))$$
5. Critical rule priority override:
   $$R_{\text{final}} = \max\left(R_{\text{raw}}, \max_{e_k \in \mathcal{E}_{\text{critical}}} s_k\right)$$

---

## 2. MULTI-FACTOR CONFIDENCE & UNCERTAINTY QUANTIFICATION

The final confidence score $C_{\text{final}} \in [0.0, 1.0]$ measures the statistical certainty of the verdict:
$$C_{\text{final}} = \text{clamp}\left(0.20, 1.0, \left(\frac{1}{n}\sum_{i=1}^n c_i + \text{ConsensusBoost}\right) \times (1 - P_{\text{stale}})\right)$$

Where:
- $\text{ConsensusBoost} = 0.05$ if $n \ge 2$, else $0.0$.
- $P_{\text{stale}}$:
  - Age $\le 7$ days: $P_{\text{stale}} = 0.0$
  - $8 \le \text{Age} \le 30$ days: $P_{\text{stale}} = 0.05$
  - $31 \le \text{Age} \le 90$ days: $P_{\text{stale}} = 0.15$
  - $> 90$ days: $P_{\text{stale}} = 0.25$

---

## 3. SEVERITY TIERS & DETERMINISTIC ACTION MAPPING

| Risk Score Range | Verdict | Severity Level | Recommendation Action | UI Friction Level | User Directive |
|---|---|---|---|---|---|
| **0 – 29** | `ALLOW` | `SAFE` / `NONE` | `PROCEED` | `NONE` | Content verified. Safe to proceed. |
| **30 – 59** | `INFORM` | `SUSPICIOUS` | `WARN_USER` | `LOW` | Verify source before interacting. |
| **60 – 84** | `CAUTION` | `WARNING` | `WARN_USER` | `MEDIUM` | Exercise extreme caution. Do not enter credentials. |
| **85 – 100** | `DANGEROUS` | `BLOCK` / `CRITICAL` | `BLOCK_NAVIGATION` | `HIGH` | Do not proceed. Threat poses imminent risk. |

---

## 4. CONFLICT RESOLUTION RULES

1. **Explicit Allowlist Priority**: Verified user or system allowlist entries (`isAllowed = true`) suppress heuristic and rule evidence unless an active executable malware payload is detected.
2. **Layer Disagreement**: When one analyzer scores low ($s = 10$) and another scores high ($s = 90$), the system strictly avoids averaging out the danger; the high signal takes precedence ($R \ge 90$).
3. **Fail-Closed Principle**: If an analyzer times out or encounters invalid encoding, an `ANALYSIS_DEGRADED` caution token ($s = 35$) is emitted. The system never fails to silent `ALLOW`.
