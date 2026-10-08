# RISK_SCORING_SPECIFICATION.md — Multi-Factor Risk Scoring Specification

> **SYSTEM STATUS: PHASE 2 VERIFIED & FINALIZED**  
> **CANONICAL SPECIFICATION — DETERMINISTIC RISK SCORING ENGINE**  
> Standardizes the mathematical models, weightings, confidence calculations, conflict resolutions, and action mappings for `@private-protection/core`.

---

## 1. MATHEMATICAL FORMULATION & AGGREGATION MODEL

The PRIVEX Risk Engine uses the **Canonical Bounded Non-Linear Diminishing-Returns Aggregation Model with Critical Override Logic** (conforming to `docs/RISK_ENGINE_ARCHITECTURE.md`).

### 1.1 Inputs
- $\mathcal{E} = \{e_1, e_2, \dots, e_n\}$: Set of triggered `Evidence` tokens.
- For each token $e_i$:
  - $s_i \in [0, 100]$: Raw threat score contribution (`scoreContribution` or `weight`).
  - $w_i \in [0.0, 1.0]$: Base detector reliability weight.
  - $c_i \in [0.0, 1.0]$: Detector confidence in this observation.
  - $isCriticalOverride \in \{\text{true}, \text{false}\}$: Critical priority flag.
- $P_{\text{stale}} \in [0.0, 0.25]$: Data staleness penalty based on offline threat cache age.

### 1.2 Detector Reliability Weights ($w_i$)

| Detector Plane | Category | Base Weight ($w_i$) | Justification |
|---|---|---|---|
| `RULE_ENGINE` | Deterministic structural & scheme checks | **1.00** | Strict protocol violations (zero false positive rate). |
| `THREAT_INTEL` | Local Bloom Filter & hash blocklist | **0.95** | Curated active threat blocklist match. |
| `DOM_ANALYZER` | Insecure DOM / form manipulation | **0.90** | Boundary violation in browser document structure. |
| `URL_ANALYZER` | Lexical / Brand Levenshtein / TLD | **0.85** | High-precision structural & typosquatting detection. |
| `TEXT_ANALYZER` | Urgency, extortion, scam heuristics | **0.75** | Statistical linguistic patterns; requires corroboration. |
| `ML_MODEL` | Quantized intent classification | **0.65** | Statistical natural language inference. |
| `DEFAULT` | Unclassified signal | **0.75** | Conservative baseline. |

### 1.3 Effective Signal Contribution ($x_i$)
For each triggered evidence token:
$$x_i = \min(100, \max(0, s_i \times w_i \times c_i))$$

### 1.4 Non-Linear Diminishing Returns Formula
To prevent score overflow and account for multiple corroborating signals asymptotically:
$$R_{\text{raw}} = 100 \times \left(1 - \prod_{i=1}^n \left(1 - \frac{x_i}{100}\right)\right)$$

### 1.5 Critical Rule Priority Override
Deterministic indicators that represent mathematically proven threats carry the critical override flag:
$$R_{\text{final}} = \min\left(100, \max\left(\text{round}(R_{\text{raw}}), \max_{e_k \in \mathcal{E}_{\text{critical}}} s_k\right)\right)$$

---

## 2. MULTI-FACTOR CONFIDENCE & UNCERTAINTY QUANTIFICATION

The final confidence score $C_{\text{final}} \in [0.20, 1.0]$ measures the statistical certainty of the verdict:
$$C_{\text{final}} = \text{clamp}\left(0.20, 1.0, \left(\frac{1}{n}\sum_{i=1}^n c_i + \text{ConsensusBoost}\right) \times (1 - P_{\text{stale}}) \times A\right)$$

Where:
- $\text{ConsensusBoost} = 0.05$ if $n \ge 2$, else $0.0$.
- $P_{\text{stale}}$:
  - Age $\le 7$ days: $P_{\text{stale}} = 0.0$
  - Age $> 7$ days: $P_{\text{stale}} = \min\left(0.20, \frac{\text{Age} - 7}{100}\right)$
- **Signal Agreement ($A$)**:
  $$A = \max\left(0.6, 1.0 - \frac{\sigma(s_i)}{100}\right)$$
  (Where $\sigma(s_i)$ is the standard deviation of raw score contributions).
- **Uncertainty**:
  $$U = 1.0 - C_{\text{final}}$$

---

## 3. CANONICAL 5-TIER VERDICT & ACTION MAPPING THRESHOLDS

The final numeric risk score $R_{\text{final}}$ and confidence $C_{\text{final}}$ map deterministically to security actions across all client platforms:

| Risk Score | Verdict | Severity Level | UI Action | Action Recommendation | Friction Level | Bypass Permitted |
|---|---|---|---|---|---|---|
| **0 – 19** | `ALLOW` | `NONE` (Legacy: `SAFE`) | Silent Proceed | `ALLOW` | `NONE` | `true` |
| **20 – 49** | `INFORM` | `LOW` (Legacy: `LOW`) | Passive Badge | `INFORM` | `LOW` | `true` |
| **50 – 69** | `CAUTION` | `MEDIUM` (Legacy: `WARNING`) | Warning Banner | `WARN` | `LOW` | `true` |
| **70 – 84** | `SUSPICIOUS` | `HIGH` (Legacy: `SUSPICIOUS`)| Modal Interstitial | `WARN` | `MEDIUM` | `true` |
| **85 – 100**| `DANGEROUS` | `CRITICAL` (Legacy: `BLOCK`)| Hard Interstitial | `BLOCK` | `HIGH` | `false` |

### 3.1 Edge-Case Safety Rule
If $R_{\text{final}} \ge 70$ but Confidence $C_{\text{final}} < 0.40$ (e.g. single noisy heuristic triggered in an isolated offline environment), the verdict is automatically clamped to `CAUTION` rather than `DANGEROUS`, and the UI explicitly explains the uncertainty to avoid false alarm fatigue.

---

## 4. CONFLICT RESOLUTION RULES

1. **Constitutional Allowlist Priority**: Verified user or system allowlist entries (`isAllowed = true`) suppress heuristic and rule evidence unless an active executable malware payload is detected.
2. **Layer Disagreement**: When one analyzer scores low ($s = 10$) and another scores high ($s = 90$), the non-linear log-odds aggregation ensures the high signal maintains dominance ($R \ge 90$).
3. **Fail-Closed Principle**: If an analyzer times out or encounters invalid encoding, an `ANALYSIS_DEGRADED` caution token ($s = 35$) is emitted. The system never fails to silent `ALLOW`.
4. **Bloom Filter Fast Rejection**: If a cryptographic domain/URL hash tests negative in the local Bloom filter, it is mathematically guaranteed to not exist in the malicious indicator set ($0\%$ false negative rate), enabling instant sub-millisecond allowlist bypass.
