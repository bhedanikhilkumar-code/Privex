import { describe, it, expect } from 'vitest';
import { DeepLinkValidatorService } from '../../services/deep-link-validator.service';

describe('DeepLinkValidatorService (Secure URI Handling)', () => {
  it('accepts valid privateprotection://scan?url=... parameter', () => {
    const raw = 'privateprotection://scan?url=' + encodeURIComponent('https://example.com/test');
    const result = DeepLinkValidatorService.parseAndValidate(raw);

    expect(result.valid).toBe(true);
    expect(result.action).toBe('SCAN_URL');
    expect(result.target).toBe('https://example.com/test');
  });

  it('accepts valid privateprotection://scan-text?text=... parameter', () => {
    const raw = 'privateprotection://scan-text?text=' + encodeURIComponent('Suspicious package text');
    const result = DeepLinkValidatorService.parseAndValidate(raw);

    expect(result.valid).toBe(true);
    expect(result.action).toBe('SCAN_TEXT');
    expect(result.target).toBe('Suspicious package text');
  });

  it('rejects unauthorized URI schemes', () => {
    const raw = 'https://malicious.com/scan?url=test';
    const result = DeepLinkValidatorService.parseAndValidate(raw);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Unauthorized scheme');
  });

  it('rejects command execution and policy alteration verbs', () => {
    const attack1 = 'privateprotection://disable-protection?force=true';
    const res1 = DeepLinkValidatorService.parseAndValidate(attack1);
    expect(res1.valid).toBe(false);
    expect(res1.error).toContain('Unauthorized administrative command');

    const attack2 = 'privateprotection://allow?domain=malicious.ru';
    const res2 = DeepLinkValidatorService.parseAndValidate(attack2);
    expect(res2.valid).toBe(false);
  });

  it('rejects oversized deep link URIs exceeding threshold', () => {
    const huge = 'privateprotection://scan?url=' + 'a'.repeat(5000);
    const result = DeepLinkValidatorService.parseAndValidate(huge);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Oversized URI');
  });
});
