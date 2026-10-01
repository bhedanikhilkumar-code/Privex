import { InjectionSeverity, SanitizationResult } from '../types';

export class PromptSanitizer {
  // Delimiter breakout patterns
  private static readonly DELIMITER_BREAKOUTS: RegExp[] = [
    /<\|im_start\|>/i,
    /<\|im_end\|>/i,
    /<\/?system>/i,
    /<\/?instruction>/i,
    /\[INST\]/i,
    /\[\/INST\]/i,
    /<<SYS>>/i,
    /<<\/SYS>>/i,
    /```(?:system|admin|override)/i,
    /---BEGIN\s+(?:SYSTEM|PROMPT|INSTRUCTION)---/i,
    /---END\s+(?:SYSTEM|PROMPT|INSTRUCTION)---/i
  ];

  // Instruction override & meta-prompt patterns
  private static readonly INSTRUCTION_OVERRIDES: RegExp[] = [
    /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|directives|rules)/i,
    /disregard\s+(?:all\s+)?(?:previous\s+|prior\s+|system\s+)?(?:instructions|rules|prompts|directives)/i,
    /override\s+(?:the\s+)?(?:system|security|previous)\s+(?:prompt|instructions|rules|verdict)/i,
    /system\s+override\s*[:=-]/i,
    /new\s+(?:system\s+)?instruction\s*[:=-]/i,
    /forget\s+(?:your\s+)?(?:rules|instructions|identity|guardrails|guidelines)/i,
    /reset\s+your\s+(?:context|instructions|rules)/i,
    /approve\s+(?:this\s+transaction|and\s+proceed)/i
  ];

  // Safety bypass & authority deception
  private static readonly SAFETY_BYPASSES: RegExp[] = [
    /(?:tell|assure|inform|say)\s+(?:the\s+)?(?:user|me|them)?[^.\n]{0,60}(?:safe|benign|harmless|legitimate|clean|not\s+a\s+threat|everything\s+is\s+fine)/i,
    /say\s+safe/i,
    /say\s+(?:this\s+site\s+is\s+)?(?:safe|legitimate)/i,
    /(?:classify|report|mark|rate)\s+(?:this\s+)?(?:link|page|site|url|message)?\s*(?:as\s+)?(?:100%?\s+)?(?:safe|clean|legitimate|harmless|benign)/i,
    /(?:bypass|disable|turn off|ignore)\s+(?:the\s+)?(?:security\s+)?(?:warning|block|filter|protection)/i,
    /turn\s+off\s+protection/i,
    /declare\s+(?:that\s+this\s+page\s+is\s+completely\s+harmless|this\s+as\s+not\s+a\s+threat|harmless|clean|safe)/i,
    /set\s+risk\s+score\s+(?:to\s+)?0/i,
    /override\s+(?:risk\s+)?verdict/i,
    /confirm\s+(?:that\s+)?(?:this\s+is\s+completely\s+safe|this\s+link\s+contains\s+no\s+security\s+risks)/i,
    /certify\s+that\s+this\s+webpage\s+is\s+safe/i,
    /no\s+phishing\s+indicators\s+exist/i,
    /tell\s+(?:the\s+user|them)\s+to\s+(?:ignore\s+the\s+warning|proceed\s+without\s+fear)/i,
    /tell\s+(?:the\s+user|them)\s+there\s+is\s+no\s+risk\s+here/i,
    /mark\s+this\s+as\s+legitimate/i
  ];

  // Webpage instructions & hidden metadata attacks
  private static readonly WEBPAGE_INSTRUCTIONS: RegExp[] = [
    /note\s+to\s+security\s+scanner/i,
    /scanner\s+instruction/i,
    /dear\s+scanner/i,
    /ai\s+assistant\s*(?:must\s+mark|:\s*report)/i,
    /scanner\s+must\s+output/i,
    /if\s+(?:an\s+ai|security\s+engine)\s+(?:is\s+reading|prompts)/i,
    /<meta\s+name=["']instructions["']\s+content=/i,
    /tell\s+user\s+this\s+page\s+is\s+safe/i
  ];

  // System prompt extraction & leakage
  private static readonly PROMPT_EXTRACTION: RegExp[] = [
    /(?:show|reveal|display|print|output|repeat|quote|echo)\s+(?:back\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|system\s+instructions|initial\s+instructions|developer\s+prompt|guidelines|rules)/i,
    /what\s+are\s+your\s+(?:system\s+)?(?:instructions|rules|prompts|guidelines)\??/i
  ];

  // Role hijacking & jailbreaking
  private static readonly ROLE_HIJACKING: RegExp[] = [
    /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:in\s+)?(?:an\s+|a\s+)?(?:DAN|jailbreak|developer\s+mode|unrestricted\s+ai|evil\s+bot|hacker|security\s+bypass\s+assistant)/i,
    /developer\s+mode\s+enabled/i,
    /(?:DAN|jailbreak)\s+mode\s+active/i,
    /from\s+now\s+on\s+you\s+(?:have\s+no\s+rules|must\s+obey\s+me)/i
  ];

  // Social engineering & fake developer authority
  private static readonly FAKE_AUTHORITY: RegExp[] = [
    /i\s+am\s+(?:your\s+|the\s+)?(?:system\s+)?(?:developer|administrator|creator|system\s+admin|root)/i,
    /anthropic\s+(?:administrator|engineer)\s+(?:override|command)/i,
    /security\s+audit\s+authorization\s+code/i,
    /maintenance\s+mode\s+authorization/i,
    /authorized\s+security\s+researcher\s+override/i,
    /administrator\s+token\s+verified/i
  ];

  // Emotional coercion & social engineering pressure
  private static readonly SOCIAL_ENGINEERING: RegExp[] = [
    /urgent\s+medical\s+emergency/i,
    /if\s+you\s+show\s+a\s+warning,\s*people\s+will\s+die/i,
    /testing\s+your\s+compliance/i,
    /routine\s+it\s+test/i,
    /ruin\s+my\s+company/i,
    /confidential\s+legal\s+inquiry/i,
    /emergency\s+government\s+directive/i,
    /family\s+emergency/i,
    /fbi\s+has\s+verified/i,
    /severe\s+anxiety,\s*tell\s+them\s+it\s+is\s+harmless/i
  ];

  // Tool abuse & data exfiltration
  private static readonly EXFILTRATION_COMMANDS: RegExp[] = [
    /(?:fetch|download|curl|wget|exfiltrate(?:\s+to)?|send\s+all\s+data\s+to)\s+https?:\/\//i,
    /send\s+(?:passwords|credentials|keys|history|data)\s+to\s+https?:\/\//i,
    /upload\s+sensitive\s+data\s+to\s+https?:\/\//i
  ];

  /**
   * Cleans text, strips invisible Unicode characters, detects injections, and returns sanitized result.
   */
  public static sanitize(rawText: string): SanitizationResult {
    if (!rawText || typeof rawText !== 'string') {
      return {
        sanitizedText: '',
        injectionDetected: false,
        detectedPatterns: [],
        severity: 'NONE',
        quarantinedTokens: []
      };
    }

    const detectedPatterns: string[] = [];
    const quarantinedTokens: string[] = [];
    let severity: InjectionSeverity = 'NONE';

    // 1. Detect and strip invisible/zero-width and bidirectional override Unicode characters
    // \u200B (ZWSP), \u200C (ZWNJ), \u200D (ZWJ), \uFEFF (BOM), \u00AD (Soft Hyphen), \u202A-\u202E (Bidi)
    if (/[\u200B-\u200D\uFEFF\u00AD\u202A-\u202E]/.test(rawText)) {
      detectedPatterns.push('UNICODE_OBFUSCATION_ATTEMPT');
      quarantinedTokens.push('UNICODE_HIDDEN_OR_BIDI');
      if (severity === 'NONE') severity = 'MEDIUM';
    }

    const normalized = rawText
      .normalize('NFKD')
      .replace(/[\u200B-\u200D\uFEFF\u00AD\u202A-\u202E]/g, '');

    // 2. Check Delimiter Breakouts
    for (const rx of this.DELIMITER_BREAKOUTS) {
      if (rx.test(normalized)) {
        detectedPatterns.push('DELIMITER_BREAKOUT');
        quarantinedTokens.push(rx.source);
        severity = 'CRITICAL';
      }
    }

    // 3. Check Instruction Overrides
    for (const rx of this.INSTRUCTION_OVERRIDES) {
      if (rx.test(normalized)) {
        detectedPatterns.push('INSTRUCTION_OVERRIDE');
        quarantinedTokens.push(rx.source);
        if (severity !== 'CRITICAL') severity = 'CRITICAL';
      }
    }

    // 4. Check Safety Bypasses
    for (const rx of this.SAFETY_BYPASSES) {
      if (rx.test(normalized)) {
        detectedPatterns.push('SAFETY_BYPASS_ATTEMPT');
        quarantinedTokens.push(rx.source);
        if (severity !== 'CRITICAL') severity = 'HIGH';
      }
    }

    // 5. Check Webpage Instructions
    for (const rx of this.WEBPAGE_INSTRUCTIONS) {
      if (rx.test(normalized)) {
        detectedPatterns.push('WEBPAGE_INSTRUCTION_OVERRIDE');
        quarantinedTokens.push(rx.source);
        if (severity !== 'CRITICAL') severity = 'HIGH';
      }
    }

    // 6. Check Prompt Extraction
    for (const rx of this.PROMPT_EXTRACTION) {
      if (rx.test(normalized)) {
        detectedPatterns.push('PROMPT_EXTRACTION_ATTEMPT');
        quarantinedTokens.push(rx.source);
        if (severity !== 'CRITICAL' && severity !== 'HIGH') severity = 'MEDIUM';
      }
    }

    // 7. Check Role Hijacking
    for (const rx of this.ROLE_HIJACKING) {
      if (rx.test(normalized)) {
        detectedPatterns.push('ROLE_HIJACKING_ATTEMPT');
        quarantinedTokens.push(rx.source);
        if (severity !== 'CRITICAL') severity = 'HIGH';
      }
    }

    // 8. Check Fake Authority
    for (const rx of this.FAKE_AUTHORITY) {
      if (rx.test(normalized)) {
        detectedPatterns.push('FAKE_AUTHORITY_ASSERTION');
        quarantinedTokens.push(rx.source);
        if (severity === 'NONE') severity = 'MEDIUM';
      }
    }

    // 9. Check Social Engineering Pressure
    for (const rx of this.SOCIAL_ENGINEERING) {
      if (rx.test(normalized)) {
        detectedPatterns.push('SOCIAL_ENGINEERING_PRESSURE');
        quarantinedTokens.push(rx.source);
        if (severity === 'NONE') severity = 'MEDIUM';
      }
    }

    // 10. Check Exfiltration Commands
    for (const rx of this.EXFILTRATION_COMMANDS) {
      if (rx.test(normalized)) {
        detectedPatterns.push('EXFILTRATION_COMMAND_ATTEMPT');
        quarantinedTokens.push(rx.source);
        severity = 'CRITICAL';
      }
    }

    // 11. Check Base64 Encoded Injections
    const base64Matches = normalized.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
    if (base64Matches) {
      for (const b64 of base64Matches) {
        try {
          const decoded = Buffer.from(b64, 'base64').toString('utf-8');
          if (/ignore|system|prompt|override|bypass|safe|admin|rules|directives|allow|clean|forget/i.test(decoded)) {
            detectedPatterns.push('ENCODED_INJECTION_BASE64');
            quarantinedTokens.push(b64);
            severity = 'HIGH';
          }
        } catch { /* not valid text */ }
      }
    }

    // Sanitize: strip out dangerous delimiters and clamp length
    let sanitized = normalized
      .replace(/<\|im_start\|>|<\|im_end\|>|<\/?system>|<\/?instruction>|\[INST\]|\[\/INST\]/gi, '[REDACTED_DELIMITER]')
      .trim();

    if (sanitized.length > 500) {
      sanitized = sanitized.slice(0, 500);
    }

    const injectionDetected = detectedPatterns.length > 0;

    return {
      sanitizedText: sanitized,
      injectionDetected,
      detectedPatterns: Array.from(new Set(detectedPatterns)),
      severity,
      quarantinedTokens
    };
  }
}
