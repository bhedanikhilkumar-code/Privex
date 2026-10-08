import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PasswordGeneratorService } from '../../services/password-generator.service';
import { UnbiasedRandom } from '../../lib/unbiased-random';
import { PASSPHRASE_WORDLIST } from '../../lib/passphrase-wordlist';
import { PasswordGeneratorOptions } from '../../types/mobile.types';

describe('Phase T8: PasswordGeneratorService & UnbiasedRandom', () => {
  let service: PasswordGeneratorService;

  beforeEach(() => {
    service = PasswordGeneratorService.getInstance();
  });

  describe('UnbiasedRandom', () => {
    it('generates numbers within bounds [0, bound - 1]', () => {
      for (let i = 0; i < 500; i++) {
        const val = UnbiasedRandom.nextInt(15);
        expect(val).toBeGreaterThanOrEqual(0);
        expect(val).toBeLessThan(15);
      }
    });

    it('rejects non-positive and non-integer bounds', () => {
      expect(() => UnbiasedRandom.nextInt(0)).toThrow();
      expect(() => UnbiasedRandom.nextInt(-5)).toThrow();
      expect(() => UnbiasedRandom.nextInt(3.5)).toThrow();
    });

    it('shuffles array in place without losing items', () => {
      const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const clone = [...arr];
      UnbiasedRandom.shuffle(arr);
      expect(arr.sort()).toEqual(clone.sort());
    });
  });

  describe('Password Generation', () => {
    it('generates standard 20-character password with all groups represented', () => {
      const opts = service.getPresetOptions('STANDARD');
      const result = service.generatePassword(opts);

      expect(result.length).toBe(20);
      expect(result.secret.length).toBe(20);
      expect(result.mode).toBe('PASSWORD');
      expect(result.characterGroups.hasUppercase).toBe(true);
      expect(result.characterGroups.hasLowercase).toBe(true);
      expect(result.characterGroups.hasNumbers).toBe(true);
      expect(result.characterGroups.hasSpecial).toBe(true);
      expect(result.entropyBits).toBeGreaterThanOrEqual(100);
      expect(result.strengthLevel).toBe('VERY_STRONG');
    });

    it('respects STRONG (32 chars) and VERY_STRONG (48 chars) presets', () => {
      const strong = service.generatePassword(service.getPresetOptions('STRONG'));
      expect(strong.length).toBe(32);
      expect(strong.secret.length).toBe(32);
      expect(strong.strengthLevel).toBe('VERY_STRONG');

      const veryStrong = service.generatePassword(service.getPresetOptions('VERY_STRONG'));
      expect(veryStrong.length).toBe(48);
      expect(veryStrong.secret.length).toBe(48);
      expect(veryStrong.strengthLevel).toBe('VERY_STRONG');
    });

    it('clamps custom length within [12, 128] bounds', () => {
      const shortRes = service.generatePassword({
        ...service.getPresetOptions('STANDARD'),
        length: 5
      });
      expect(shortRes.length).toBe(12);
      expect(shortRes.secret.length).toBe(12);

      const longRes = service.generatePassword({
        ...service.getPresetOptions('STANDARD'),
        length: 250
      });
      expect(longRes.length).toBe(128);
      expect(longRes.secret.length).toBe(128);
    });

    it('filters out similar characters when avoidSimilar is true', () => {
      const opts: PasswordGeneratorOptions = {
        length: 64,
        useUppercase: true,
        useLowercase: true,
        useNumbers: true,
        useSpecial: false,
        avoidAmbiguous: false,
        avoidSimilar: true
      };
      const result = service.generatePassword(opts);

      // l, 1, I, o, 0, O
      expect(result.secret).not.toMatch(/[l1Io0O]/);
    });

    it('filters out ambiguous characters when avoidAmbiguous is true', () => {
      const opts: PasswordGeneratorOptions = {
        length: 64,
        useUppercase: false,
        useLowercase: true,
        useNumbers: false,
        useSpecial: true,
        avoidAmbiguous: true,
        avoidSimilar: false
      };
      const result = service.generatePassword(opts);

      // Ambiguous: {}[]()/\'"`~,;:.<>
      expect(result.secret).not.toMatch(/[{}\[\]()\/\\'"`~,;:.<>]/);
    });

    it('throws when no character group is enabled', () => {
      const opts: PasswordGeneratorOptions = {
        length: 20,
        useUppercase: false,
        useLowercase: false,
        useNumbers: false,
        useSpecial: false,
        avoidAmbiguous: false,
        avoidSimilar: false
      };
      expect(() => service.generatePassword(opts)).toThrow('At least one character group must be selected');
    });
  });

  describe('Passphrase Generation', () => {
    it('verifies bundled 2,048-word BIP39 dictionary integrity', () => {
      expect(PASSPHRASE_WORDLIST.length).toBe(2048);
      const unique = new Set(PASSPHRASE_WORDLIST);
      expect(unique.size).toBe(2048);
    });

    it('generates 5-word passphrase with custom separator', () => {
      const result = service.generatePassphrase({
        wordCount: 5,
        separator: '_',
        capitalize: true,
        includeNumber: false
      });

      expect(result.mode).toBe('PASSPHRASE');
      expect(result.wordCount).toBe(5);
      expect(result.wordlistSize).toBe(2048);
      expect(result.separator).toBe('_');

      const parts = result.secret.split('_');
      expect(parts.length).toBe(5);
      // Each word should be capitalized
      parts.forEach(part => {
        expect(part.charAt(0)).toBe(part.charAt(0).toUpperCase());
      });

      // Entropy: 5 * 11 bits = 55 + 5 capital bits = 60 bits
      expect(result.entropyBits).toBeGreaterThanOrEqual(55);
    });

    it('clamps word count within [3, 10]', () => {
      const shortPass = service.generatePassphrase({ wordCount: 1 });
      expect(shortPass.wordCount).toBe(3);
      expect(shortPass.secret.split('-').length).toBe(3);

      const longPass = service.generatePassphrase({ wordCount: 25 });
      expect(longPass.wordCount).toBe(10);
      expect(longPass.secret.split('-').length).toBe(10);
    });

    it('attaches random number when includeNumber is true', () => {
      const result = service.generatePassphrase({
        wordCount: 4,
        includeNumber: true
      });
      expect(result.secret).toMatch(/[0-9]/);
    });
  });

  describe('Clipboard Protection', () => {
    it('returns false for empty secret', async () => {
      const copied = await service.copyToClipboard('');
      expect(copied).toBe(false);
    });

    it('delegates to AndroidSecurityBridge if present', async () => {
      const mockBridge = {
        copySensitiveToClipboard: vi.fn().mockReturnValue(true)
      };
      (window as any).AndroidSecurityBridge = mockBridge;

      const copied = await service.copyToClipboard('SuperSecret123!', 'Password');
      expect(copied).toBe(true);
      expect(mockBridge.copySensitiveToClipboard).toHaveBeenCalledWith('Password', 'SuperSecret123!');

      delete (window as any).AndroidSecurityBridge;
    });
  });
});
