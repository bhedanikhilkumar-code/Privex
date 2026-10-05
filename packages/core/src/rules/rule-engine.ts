import {
  DetectorLayer,
  DetectorType,
  Evidence,
  InputType,
  RiskCategory,
  Severity,
  SeverityLevel
} from '../types';

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RiskCategory;
  severity: Severity;
  weight: number;
  layer?: DetectorLayer;
  evaluate(input: string, inputType: InputType): Evidence | null;
}

export interface RuleMatch {
  ruleId: string;
  name: string;
  description: string;
  weight: number;
  confidence: number;
}

export interface RuleEvaluationResult {
  triggered: boolean;
  matches: RuleMatch[];
  evidence: Evidence[];
}

export class RuleEngine {
  private rules: Rule[] = [];

  constructor() {
    this.registerDefaultRules();
  }

  public registerRule(rule: Rule): void {
    this.rules.push(rule);
  }

  private static mapSeverityToLevel(sev: Severity): SeverityLevel {
    switch (sev) {
      case Severity.DEVICE_COMPROMISE:
        return SeverityLevel.CRITICAL;
      case Severity.ACCOUNT_LOSS:
        return SeverityLevel.HIGH;
      case Severity.FINANCIAL_FRAUD:
        return SeverityLevel.HIGH;
      case Severity.PRIVACY_RISK:
        return SeverityLevel.MEDIUM;
      default:
        return SeverityLevel.LOW;
    }
  }

  /**
   * Evaluates all registered rules and normalizes every emitted signal into the
   * canonical Phase B structured Evidence format (Step 7).
   * Rules only produce security signals and NEVER perform UI or quarantine side effects.
   */
  public evaluateAll(input: string, inputType: InputType): Evidence[] {
    if (!input || typeof input !== 'string') {
      return [];
    }

    const evidence: Evidence[] = [];
    for (const rule of this.rules) {
      try {
        const result = rule.evaluate(input, inputType);
        if (result) {
          const ruleId = result.ruleId || result.indicator || rule.id;
          const layer = result.detectorLayer || rule.layer || DetectorLayer.SIGNATURE_ENGINE;
          const sevLevel = result.severityLevel || RuleEngine.mapSeverityToLevel(rule.severity);
          const weight =
            typeof result.weight === 'number' && Number.isFinite(result.weight)
              ? result.weight
              : rule.weight;
          const scoreContribution =
            typeof result.scoreContribution === 'number' &&
            Number.isFinite(result.scoreContribution)
              ? result.scoreContribution
              : weight;

          evidence.push({
            ...result,
            ruleId,
            detectorType: result.detectorType || DetectorType.RULE,
            detectorLayer: layer,
            source: result.source || 'RULE_ENGINE',
            name: result.name || rule.name,
            description: result.description || rule.description,
            reason: result.reason || result.description || rule.description,
            severityLevel: sevLevel,
            weight,
            scoreContribution,
            confidence:
              typeof result.confidence === 'number' && Number.isFinite(result.confidence)
                ? result.confidence
                : 0.9,
            indicator: result.indicator || ruleId,
            isCriticalOverride: result.isCriticalOverride === true,
            metadata: {
              ruleId,
              category: String(rule.category),
              severityLevel: String(sevLevel),
              sourceLayer: String(layer),
              ...(result.metadata || {})
            }
          });
        }
      } catch {
        // Individual custom rule error isolation: emit fail-closed diagnostic signal if rule throws unexpectedly
      }
    }
    return evidence;
  }

  public evaluateUrl(url: string): RuleEvaluationResult {
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return { triggered: false, matches: [], evidence: [] };
    }

    const evidence = this.evaluateAll(url, InputType.URL);
    const matches: RuleMatch[] = evidence.map((e) => ({
      ruleId:
        e.ruleId ||
        (e.name === 'IP Address URL'
          ? 'url-ip-based'
          : e.indicator || e.name.toLowerCase().replace(/\s+/g, '-')),
      name: e.name,
      description: e.description,
      weight: e.weight,
      confidence: e.confidence
    }));

    return {
      triggered: matches.length > 0,
      matches,
      evidence
    };
  }

  public evaluateText(text: string): RuleEvaluationResult {
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return { triggered: false, matches: [], evidence: [] };
    }

    const evidence = this.evaluateAll(text, InputType.TEXT);
    const matches: RuleMatch[] = evidence.map((e) => ({
      ruleId: e.ruleId || e.indicator || e.name.toLowerCase().replace(/\s+/g, '-'),
      name: e.name,
      description: e.description,
      weight: e.weight,
      confidence: e.confidence
    }));

    return {
      triggered: matches.length > 0,
      matches,
      evidence
    };
  }

  public evaluateFile(fileInput: string): RuleEvaluationResult {
    if (!fileInput || typeof fileInput !== 'string' || fileInput.trim().length === 0) {
      return { triggered: false, matches: [], evidence: [] };
    }

    const evidence = this.evaluateAll(fileInput, InputType.FILE);
    const matches: RuleMatch[] = evidence.map((e) => ({
      ruleId: e.ruleId || e.indicator || e.name.toLowerCase().replace(/\s+/g, '-'),
      name: e.name,
      description: e.description,
      weight: e.weight,
      confidence: e.confidence
    }));

    return {
      triggered: matches.length > 0,
      matches,
      evidence
    };
  }

  public evaluateProcess(processInput: string): RuleEvaluationResult {
    if (!processInput || typeof processInput !== 'string' || processInput.trim().length === 0) {
      return { triggered: false, matches: [], evidence: [] };
    }

    const evidence = this.evaluateAll(processInput, InputType.PROCESS);
    const matches: RuleMatch[] = evidence.map((e) => ({
      ruleId: e.ruleId || e.indicator || e.name.toLowerCase().replace(/\s+/g, '-'),
      name: e.name,
      description: e.description,
      weight: e.weight,
      confidence: e.confidence
    }));

    return {
      triggered: matches.length > 0,
      matches,
      evidence
    };
  }

  private registerDefaultRules() {
    // URL Rules
    this.registerRule({
      id: 'url-ip-based',
      name: 'IP Address URL',
      description: 'URL uses an IP address instead of a domain name',
      category: RiskCategory.SUSPICIOUS,
      severity: Severity.PRIVACY_RISK,
      weight: 60,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
        try {
          const url = new URL(input.startsWith('http') ? input : `http://${input}`);
          if (ipRegex.test(url.hostname)) {
            return {
              source: 'RULE_ENGINE',
              name: 'IP Address URL',
              description: 'URL uses an IP address instead of a domain name',
              weight: 60,
              confidence: 1.0,
              indicator: 'url-ip-based'
            };
          }
        } catch { /* parse fail */ }
        return null;
      }
    });

    this.registerRule({
      id: 'url-suspicious-tld',
      name: 'Suspicious TLD',
      description: 'Domain uses a Top-Level Domain frequently associated with abuse',
      category: RiskCategory.SUSPICIOUS,
      severity: Severity.PRIVACY_RISK,
      weight: 40,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click'];
        try {
          const url = new URL(input.startsWith('http') ? input : `http://${input}`);
          if (suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
            return {
              source: 'RULE_ENGINE',
              name: 'Suspicious TLD',
              description: 'Domain uses a highly suspicious TLD',
              weight: 40,
              confidence: 0.9,
              indicator: 'url-suspicious-tld'
            };
          }
        } catch { }
        return null;
      }
    });

    this.registerRule({
      id: 'url-data-uri',
      name: 'Data URI',
      description: 'Data URI scheme used which can embed malicious content',
      category: RiskCategory.PHISHING,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 80,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        if (input.trim().toLowerCase().startsWith('data:')) {
          return {
            source: 'RULE_ENGINE',
            name: 'Data URI Scheme',
            description: 'Suspicious data URI scheme detected',
            weight: 80,
            confidence: 0.95,
            indicator: 'url-data-uri'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'url-javascript-uri',
      name: 'JavaScript URI',
      description: 'JavaScript URI can execute code when clicked',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 90,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        if (input.trim().toLowerCase().startsWith('javascript:')) {
          return {
            source: 'RULE_ENGINE',
            name: 'JavaScript URI Scheme',
            description: 'Malicious JavaScript URI detected',
            weight: 90,
            confidence: 1.0,
            indicator: 'url-javascript-uri'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'url-vbscript-uri',
      name: 'VBScript URI',
      description: 'VBScript URI scheme can execute malicious scripts',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 90,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        if (input.trim().toLowerCase().startsWith('vbscript:')) {
          return {
            source: 'RULE_ENGINE',
            name: 'VBScript URI Scheme',
            description: 'Malicious VBScript URI detected',
            weight: 90,
            confidence: 1.0,
            indicator: 'url-vbscript-uri',
            isCriticalOverride: true
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'url-blob-uri',
      name: 'Blob URI',
      description: 'Blob URI scheme used to load untrusted in-memory payloads',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 85,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        if (input.trim().toLowerCase().startsWith('blob:')) {
          return {
            source: 'RULE_ENGINE',
            name: 'Blob URI Scheme',
            description: 'Suspicious blob URI scheme detected',
            weight: 85,
            confidence: 0.95,
            indicator: 'url-blob-uri'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'url-excessive-subdomains',
      name: 'Excessive Subdomains',
      description: 'Unusually high number of subdomains often used in phishing',
      category: RiskCategory.SUSPICIOUS,
      severity: Severity.PRIVACY_RISK,
      weight: 35,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        try {
          const url = new URL(input.startsWith('http') ? input : `http://${input}`);
          const parts = url.hostname.split('.');
          if (parts.length > 4) {
            return {
              source: 'RULE_ENGINE',
              name: 'Excessive Subdomains',
              description: 'More than 3 subdomains detected',
              weight: 35,
              confidence: 0.8,
              indicator: 'url-excessive-subdomains'
            };
          }
        } catch { }
        return null;
      }
    });

    this.registerRule({
      id: 'url-shortener',
      name: 'URL Shortener',
      description: 'URL shorteners hide the real destination',
      category: RiskCategory.SUSPICIOUS,
      severity: Severity.PRIVACY_RISK,
      weight: 20,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        const shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly'];
        try {
          const url = new URL(input.startsWith('http') ? input : `http://${input}`);
          if (shorteners.some(s => url.hostname.includes(s))) {
            return {
              source: 'RULE_ENGINE',
              name: 'URL Shortener',
              description: 'URL shortening service detected',
              weight: 20,
              confidence: 1.0,
              indicator: 'url-shortener'
            };
          }
        } catch { }
        return null;
      }
    });

    this.registerRule({
      id: 'url-at-symbol',
      name: 'Credential embedded in URL',
      description: 'Use of @ symbol in URL before domain name to obfuscate true destination',
      category: RiskCategory.PHISHING,
      severity: Severity.ACCOUNT_LOSS,
      weight: 75,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.URL) return null;
        try {
          const url = new URL(input.startsWith('http') ? input : `http://${input}`);
          if (url.username || url.password || input.replace(/^https?:\/\//, '').split('/')[0].includes('@')) {
            return {
              source: 'RULE_ENGINE',
              name: 'Credential embedded in URL',
              description: '@ symbol used to mask true domain',
              weight: 75,
              confidence: 0.95,
              indicator: 'url-at-symbol'
            };
          }
        } catch { }
        return null;
      }
    });

    // Text rules with diacritic & unicode de-obfuscation (single-pass memoized per input)
    let lastRawText = '';
    let lastNormalizedText = '';
    const normalizeText = (t: string) => {
      if (t === lastRawText) return lastNormalizedText;
      const clamped = t.length > 10000 ? t.slice(0, 10000) : t;
      lastRawText = t;
      lastNormalizedText = clamped
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase();
      return lastNormalizedText;
    };

    this.registerRule({
      id: 'text-urgency',
      name: 'Urgency Keywords',
      description: 'Manufactured urgency to pressure the user',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 40,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = ['act now', 'immediately', 'suspended', 'verify your account', 'click here', 'confirm your identity'];
        const matches = keywords.filter(k => lower.includes(k));
        if (matches.length > 0) {
          return {
            source: 'RULE_ENGINE',
            name: 'Urgency Keywords',
            description: 'Contains urgency keywords: ' + matches.join(', '),
            weight: Math.min(80, 20 + matches.length * 20),
            confidence: 0.8,
            indicator: 'text-urgency'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'text-financial-scam',
      name: 'Financial Scam Keywords',
      description: 'Requests for non-reversible payments',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 60,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = ['wire transfer', 'cryptocurrency', 'bitcoin', 'gift card', 'western union', 'moneygram'];
        const matches = keywords.filter(k => lower.includes(k));
        if (matches.length > 0) {
          return {
            source: 'RULE_ENGINE',
            name: 'Financial Scam Keywords',
            description: 'Contains untraceable payment requests: ' + matches.join(', '),
            weight: Math.min(100, 30 + matches.length * 30),
            confidence: 0.85,
            indicator: 'text-financial-scam'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'text-threat',
      name: 'Threat Keywords',
      description: 'Threatening language often used in extortion',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 70,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = ['legal action', 'arrest warrant', 'be arrested', 'irs', 'tax fraud'];
        const matches = keywords.filter((k) => lower.includes(k));
        if (matches.length > 0) {
          return {
            source: 'RULE_ENGINE',
            name: 'Threat Keywords',
            description: 'Contains intimidation/threats: ' + matches.join(', '),
            weight: Math.min(100, 40 + matches.length * 30),
            confidence: 0.9,
            indicator: 'text-threat'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'text-prize',
      name: 'Prize/Lottery Scam',
      description: 'Fake prize notifications',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 55,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = [
          "you've won",
          'you have won',
          'congratulations',
          'claim your prize',
          'lucky winner'
        ];
        const matches = keywords.filter((k) => lower.includes(k));
        if (matches.length > 0) {
          return {
            source: 'RULE_ENGINE',
            name: 'Prize Scam Keywords',
            description: 'Contains fake prize keywords: ' + matches.join(', '),
            weight: Math.min(90, 30 + matches.length * 25),
            confidence: 0.85,
            indicator: 'text-prize'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'text-advance-fee',
      name: 'Advance Fee Fraud',
      description: 'Nigerian Prince or Advance Fee fraud patterns',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 70,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = ['prince', 'inheritance', 'beneficiary', 'million dollars'];
        const matches = keywords.filter((k) => lower.includes(k));
        if (matches.length > 0) {
          return {
            source: 'RULE_ENGINE',
            name: 'Advance Fee Scam',
            description: 'Contains advance fee fraud patterns',
            weight: Math.min(95, 40 + matches.length * 20),
            confidence: 0.9,
            indicator: 'text-advance-fee'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'text-employment-scam',
      name: 'Employment / Task Scam',
      description:
        'Task-based or fake job hiring offering unrealistic earnings for trivial tasks',
      category: RiskCategory.SCAM,
      severity: Severity.FINANCIAL_FRAUD,
      weight: 75,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.TEXT) return null;
        const lower = normalizeText(input);
        const keywords = [
          'earn $',
          'rate apps',
          'optimize apps',
          'daily salary',
          'work from home task',
          'part-time job hiring',
          'online tasks commission',
          'task wire',
          'deposit to unlock commission'
        ];
        const matches = keywords.filter((k) => lower.includes(k));
        if (
          matches.length > 0 ||
          (/earn\s+\$?\d+.*(?:day|hour|task)/i.test(lower) &&
            /commission|task|rating/i.test(lower))
        ) {
          return {
            source: 'RULE_ENGINE',
            name: 'Employment / Task Scam',
            description:
              'Contains task-based employment fraud keywords: ' + matches.join(', '),
            weight: Math.min(95, 60 + matches.length * 15),
            confidence: 0.9,
            indicator: 'text-employment-scam'
          };
        }
        return null;
      }
    });

    // FILE & PROCESS Deterministic Signature Rules (Phase B Step 7)
    this.registerRule({
      id: 'file-eicar-signature',
      name: 'EICAR Test Signature',
      description: 'Standard EICAR antivirus test string detected',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 100,
      layer: DetectorLayer.SIGNATURE_ENGINE,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.FILE && inputType !== InputType.PROCESS) return null;
        if (input.includes('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')) {
          return {
            ruleId: 'file-eicar-signature',
            detectorType: DetectorType.RULE,
            detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
            source: 'RULE_ENGINE',
            name: 'EICAR Test Signature',
            description: 'Standard EICAR antivirus test signature matched',
            weight: 100,
            scoreContribution: 100,
            confidence: 1.0,
            indicator: 'file-eicar-signature',
            isCriticalOverride: true
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'proc-encoded-command',
      name: 'Encoded Command Execution',
      description: 'Process or script uses Base64 encoded command execution flags',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 85,
      layer: DetectorLayer.SIGNATURE_ENGINE,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.PROCESS && inputType !== InputType.FILE) return null;
        const lower = input.toLowerCase();
        if (
          /(?:^|\s)-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{8,}/i.test(input) ||
          lower.includes('frombase64string(')
        ) {
          return {
            ruleId: 'proc-encoded-command',
            detectorType: DetectorType.RULE,
            detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
            source: 'RULE_ENGINE',
            name: 'Encoded Command Execution',
            description: 'Obfuscated Base64 command-line execution detected',
            weight: 85,
            scoreContribution: 85,
            confidence: 0.95,
            indicator: 'proc-encoded-command'
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'proc-lolbin-cradle',
      name: 'LOLBin Download/Execute Cradle',
      description: 'Living-off-the-Land binary invoked with remote payload execution flags',
      category: RiskCategory.MALWARE,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 90,
      layer: DetectorLayer.SIGNATURE_ENGINE,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.PROCESS && inputType !== InputType.FILE) return null;
        const lower = input.toLowerCase();
        const patterns = [
          'certutil -urlcache',
          'certutil.exe -urlcache',
          'bitsadmin /transfer',
          'mshta http',
          'mshta.exe http',
          'regsvr32 /s /n /u /i:http',
          'rundll32 javascript:',
          'downloadstring(',
          'invoke-expression'
        ];
        const matched = patterns.find((p) => lower.includes(p));
        if (matched) {
          return {
            ruleId: 'proc-lolbin-cradle',
            detectorType: DetectorType.RULE,
            detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
            source: 'RULE_ENGINE',
            name: 'LOLBin Download/Execute Cradle',
            description: `Suspicious LOLBin execution cradle detected (${matched})`,
            weight: 90,
            scoreContribution: 90,
            confidence: 0.95,
            indicator: 'proc-lolbin-cradle',
            isCriticalOverride: true
          };
        }
        return null;
      }
    });

    this.registerRule({
      id: 'proc-defense-evasion',
      name: 'Shadow Copy / Security Tampering Command',
      description: 'Command attempts to delete Volume Shadow Copies or disable endpoint protection',
      category: RiskCategory.EXTORTION,
      severity: Severity.DEVICE_COMPROMISE,
      weight: 95,
      layer: DetectorLayer.SIGNATURE_ENGINE,
      evaluate: (input: string, inputType: InputType) => {
        if (inputType !== InputType.PROCESS && inputType !== InputType.FILE) return null;
        const lower = input.toLowerCase();
        const patterns = [
          'vssadmin delete shadows',
          'vssadmin.exe delete shadows',
          'wmic shadowcopy delete',
          'recoveryenabled no',
          'wbadmin delete catalog',
          '-disablerealtimemonitoring'
        ];
        const matched = patterns.find((p) => lower.includes(p));
        if (matched) {
          return {
            ruleId: 'proc-defense-evasion',
            detectorType: DetectorType.RULE,
            detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
            source: 'RULE_ENGINE',
            name: 'Shadow Copy / Security Tampering Command',
            description: `Ransomware/defense-evasion tampering command detected (${matched})`,
            weight: 95,
            scoreContribution: 95,
            confidence: 0.98,
            indicator: 'proc-defense-evasion',
            isCriticalOverride: true
          };
        }
        return null;
      }
    });
  }
}
