export class ResponsePolicy {
  // Prohibited request patterns where users ask for help bypassing controls or writing attacks
  private static readonly DANGEROUS_INTENTS: RegExp[] = [
    /(?:how\s+to|help\s+me|show\s+me\s+how\s+to|how\s+can\s+i|how\s+do\s+i)\s+(?:create|write|craft|make|build)\s+(?:a\s+)?(?:phishing|malware|virus|trojan|ransomware|exploit)/i,
    /(?:how\s+to|can\s+you|how\s+can\s+i|how\s+do\s+i)\s+(?:bypass|evade|disable|circumvent|turn\s+off)\s+(?:detection|antivirus|filter|security|protection|pipeline)/i,
    /(?:steal|harvest|sniff|exfiltrate)\s+(?:passwords|credentials|keys|tokens)/i,
    /(?:generate|create)\s+(?:an?\s+)?(?:evil|fake|spoofed)\s+(?:login|bank|paypal|website)/i,
    /(?:how\s+to\s+hack|hack\s+into)\s+[a-z0-9.-]+/i
  ];

  /**
   * Evaluates whether a query violates the safety boundary by requesting weaponization or evasion help.
   */
  public static evaluateUserIntent(query: string): { isProhibited: boolean; reason?: string; safeResponse?: string } {
    if (!query || typeof query !== 'string') {
      return { isProhibited: false };
    }

    for (const rx of this.DANGEROUS_INTENTS) {
      if (rx.test(query)) {
        return {
          isProhibited: true,
          reason: 'DANGEROUS_INTENT_VIOLATION',
          safeResponse: 'I cannot help create cyber threats, bypass security filters, or disable digital protections. I can only help you recognize, understand, and avoid cyber attacks.'
        };
      }
    }

    return { isProhibited: false };
  }
}
