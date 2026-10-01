import { ActionRecommendation, Evidence, RiskCategory } from '../types';

export interface ExplanationResult {
  text: string;
  action: string;
  toString(): string;
}

export class ExplanationEngine {
  public generate(category: RiskCategory, recommendation: ActionRecommendation, evidence: Evidence[]): string {
    const res = this.generateExplanation({
      category,
      severity: category.toString(),
      evidence
    });
    return `${res.text}\n\n${res.action}`;
  }

  public generateExplanation(options: {
    score?: number;
    severity?: string;
    category?: RiskCategory;
    evidence?: any[];
  }): ExplanationResult {
    const evidence = options.evidence || [];
    const isExplicitlyDangerous =
      (options.score !== undefined && options.score >= 60) ||
      options.severity === 'BLOCK' ||
      options.severity === 'WARNING' ||
      options.category === RiskCategory.MALWARE ||
      options.category === RiskCategory.PHISHING ||
      options.category === RiskCategory.SCAM;

    const isSafe = !isExplicitlyDangerous && (
      (options.score !== undefined && options.score < 30) ||
      options.severity === 'SAFE' ||
      options.category === RiskCategory.SAFE ||
      (options.score === undefined && options.severity === undefined && evidence.length === 0)
    );

    if (isSafe) {
      const text = "This content appears safe. No threat indicators or suspicious patterns were found.";
      const action = "It is safe to proceed.";
      return {
        text,
        action,
        toString() { return `${text}\n${action}`; }
      };
    }

    // Check if this relates to a scam
    const isScam =
      options.category === RiskCategory.SCAM ||
      evidence.some(e =>
        (e.indicator && e.indicator.includes('scam')) ||
        (e.description && e.description.toLowerCase().includes('scam')) ||
        (e.type === 'text' && e.indicator && e.indicator.includes('financial'))
      );

    // Build evidence-based explanations with plain-language, non-jargon terms
    const lines: string[] = [];

    for (const item of evidence) {
      let desc = item.description || '';
      // Sanitize technical jargon
      if (item.indicator === 'punycode-domain' || /punycode|homograph/i.test(desc)) {
        desc = "This domain uses deceptive character styling to imitate a trusted website";
      }
      lines.push(desc);
    }

    let narrative = lines.length > 0 ? lines.join('. ') : 'High-risk indicators were detected.';
    let prefix = 'Caution: Potential security risk detected.';
    if (isScam) {
      prefix = 'Warning: Potential scam or financial fraud pattern detected.';
    } else if (options.severity === 'BLOCK' || (options.score !== undefined && options.score >= 85)) {
      prefix = 'Critical: Severe threat detected.';
    }

    const text = `${prefix} ${narrative}`;

    let action = "Review with caution.";
    if (options.severity === 'BLOCK' || (options.score !== undefined && options.score >= 85)) {
      action = "Recommended action: Do not click links or proceed. Close or delete this content immediately.";
    } else if (options.severity === 'WARNING' || (options.score !== undefined && options.score >= 60)) {
      action = "Recommended action: Avoid interacting or providing credentials.";
    } else {
      action = "Recommended action: Verify sender identity before taking action.";
    }

    return {
      text,
      action,
      toString() { return `${text}\n\n${action}`; }
    };
  }
}
