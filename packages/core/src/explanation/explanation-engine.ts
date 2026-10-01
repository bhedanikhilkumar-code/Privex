import { ActionRecommendation, Evidence, Explanation, RiskCategory } from '../types';

export interface ExplanationResult extends Explanation {
  text: string;
  action: string;
  toString(): string;
}

export class ExplanationEngine {
  public generate(
    category: RiskCategory,
    recommendation: ActionRecommendation,
    evidence: Evidence[]
  ): string {
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
    confidence?: number;
  }): ExplanationResult {
    const evidence = options.evidence || [];
    const isExplicitlyDangerous =
      (options.score !== undefined && options.score >= 60) ||
      options.severity === 'BLOCK' ||
      options.severity === 'WARNING' ||
      options.category === RiskCategory.MALWARE ||
      options.category === RiskCategory.PHISHING ||
      options.category === RiskCategory.SCAM;

    const isSafe =
      !isExplicitlyDangerous &&
      ((options.score !== undefined && options.score < 30) ||
        options.severity === 'SAFE' ||
        options.category === RiskCategory.SAFE ||
        (options.score === undefined && options.severity === undefined && evidence.length === 0));

    // Confidence Label determination
    const confVal = options.confidence ?? 0.85;
    const confidenceLabel: 'HIGH' | 'MEDIUM' | 'LOW' =
      confVal >= 0.8 ? 'HIGH' : confVal >= 0.5 ? 'MEDIUM' : 'LOW';

    if (isSafe) {
      const headline = 'Content Verified Safe';
      const plainTextSummary =
        'This content appears safe. No threat indicators, deceptive links, or suspicious patterns were found.';
      const technicalDetails = ['No known threat indicators detected', 'Security rules passed'];
      const recommendedSteps = ['It is safe to proceed.', 'No further action needed.'];
      const text = plainTextSummary;
      const action = 'It is safe to proceed.';

      return {
        headline,
        plainTextSummary,
        technicalDetails,
        recommendedSteps,
        confidenceLabel,
        text,
        action,
        toString() {
          return `${text}\n${action}`;
        }
      };
    }

    // Determine threat nature
    const isScam =
      options.category === RiskCategory.SCAM ||
      evidence.some(
        (e: any) =>
          (e.indicator && e.indicator.includes('scam')) ||
          (e.description && e.description.toLowerCase().includes('scam')) ||
          (e.type === 'text' && e.indicator && e.indicator.includes('financial')) ||
          (e.source === 'TEXT_ANALYZER')
      );

    const isExtortion = evidence.some(
      (e: any) =>
        e.indicator === 'ransomware-extortion' ||
        e.indicator === 'legal-police-threat' ||
        (e.name && e.name.toLowerCase().includes('extortion'))
    );

    // Build plain-language, non-jargon technical details
    const technicalDetails: string[] = [];
    const narrativeLines: string[] = [];

    for (const item of evidence) {
      let desc = item.description || '';
      // Translate technical jargon into Grade-6 cognitive reading level
      if (item.indicator === 'punycode-domain' || /punycode|homograph/i.test(desc)) {
        desc = 'This domain uses deceptive look-alike characters to imitate a trusted website';
      } else if (item.indicator === 'ip-based-host') {
        desc = 'This link points directly to a raw numerical computer address instead of a legitimate domain';
      } else if (item.indicator === 'double-percent-encoding') {
        desc = 'This link hides its real destination using nested web encoding';
      } else if (item.indicator === 'private-ip-ssrf') {
        desc = 'This address targets an internal private network or local device';
      } else if (item.indicator === 'credentials-in-url') {
        desc = 'This address hides the real destination domain using an embedded username symbol';
      }

      technicalDetails.push(desc);
      narrativeLines.push(desc);
    }

    let headline = 'Warning: Potential Security Risk';
    let prefix = 'Caution: Potential security risk detected.';
    let plainTextSummary = 'Suspicious signals were detected in this content.';

    if (isExtortion) {
      headline = 'Critical Threat: Coercive Extortion Attempt';
      prefix = 'Critical: Threat or extortion pattern detected.';
      plainTextSummary =
        'This message attempts to coerce or intimidate you into sending money or cryptocurrency.';
    } else if (isScam) {
      headline = 'Warning: Potential Scam Detected';
      prefix = 'Warning: Potential scam or financial fraud pattern detected.';
      plainTextSummary =
        'This content displays classic patterns of fraud, designed to trick you into sending money or disclosing sensitive details.';
    } else if (options.severity === 'BLOCK' || (options.score !== undefined && options.score >= 85)) {
      headline = 'Critical: Severe Malicious Threat';
      prefix = 'Critical: Severe threat detected.';
      plainTextSummary =
        'This content is confirmed to be deceptive or dangerous. Interacting with it could compromise your device or accounts.';
    }

    const narrative = narrativeLines.length > 0 ? narrativeLines.join('. ') : 'High-risk indicators were detected.';
    const text = `${prefix} ${narrative}`;

    // Recommended Actions & Avoidance Steps
    const recommendedSteps: string[] = [];
    let action = 'Review with caution.';

    if (options.severity === 'BLOCK' || (options.score !== undefined && options.score >= 85)) {
      action = 'Recommended action: Do not click links or proceed. Close or delete this content immediately.';
      recommendedSteps.push('Do NOT click any links, open attachments, or send payments.');
      recommendedSteps.push('Close or delete this communication immediately.');
      recommendedSteps.push('If you already entered passwords, change them immediately from a separate device.');
    } else if (options.severity === 'WARNING' || (options.score !== undefined && options.score >= 60)) {
      action = 'Recommended action: Avoid interacting or providing credentials.';
      recommendedSteps.push('Do not share passwords, credit card numbers, or one-time codes.');
      recommendedSteps.push('Verify the identity of the sender through official public contact channels.');
      recommendedSteps.push('Do not click on shortened or suspicious links.');
    } else {
      action = 'Recommended action: Verify sender identity before taking action.';
      recommendedSteps.push('Check the sender address carefully for slight misspellings.');
      recommendedSteps.push('Do not rush into taking urgent actions.');
    }

    return {
      headline,
      plainTextSummary,
      technicalDetails,
      recommendedSteps,
      confidenceLabel,
      text,
      action,
      toString() {
        return `${text}\n\n${action}`;
      }
    };
  }
}
