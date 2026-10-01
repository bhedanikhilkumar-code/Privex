import { describe, it, expect } from 'vitest';
import { CryptoUtils } from '../../utils/crypto';

describe('CryptoUtils', () => {
  describe('UUID Format Validation', () => {
    it('should generate valid UUIDs', () => {
      const uuid = CryptoUtils.generateUUID();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(uuidRegex.test(uuid)).toBe(true);
    });

    it('should validate UUID formats correctly', () => {
      expect(CryptoUtils.isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(CryptoUtils.isValidUUID('invalid-uuid-string')).toBe(false);
    });
  });

  describe('SHA-256 Hash Correctness', () => {
    it('should generate correct SHA-256 hashes', () => {
      // "hello world" hash
      const expectedHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      expect(CryptoUtils.sha256('hello world')).toBe(expectedHash);
    });

    it('should return different hashes for different inputs', () => {
      expect(CryptoUtils.sha256('a')).not.toBe(CryptoUtils.sha256('b'));
    });
  });

  describe('Shannon Entropy', () => {
    it('should return high entropy for uniform distribution', () => {
      const entropy = CryptoUtils.shannonEntropy('abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()');
      expect(entropy).toBeGreaterThan(4);
    });

    it('should return low entropy for repeated characters', () => {
      const entropy = CryptoUtils.shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaa');
      expect(entropy).toBeCloseTo(0, 2);
    });
  });

  describe('Levenshtein Distance', () => {
    it('should return 0 for identical strings', () => {
      expect(CryptoUtils.levenshteinDistance('kitten', 'kitten')).toBe(0);
    });

    it('should return correct distance for single edits', () => {
      expect(CryptoUtils.levenshteinDistance('kitten', 'sitten')).toBe(1); // substitution
      expect(CryptoUtils.levenshteinDistance('kitten', 'kittens')).toBe(1); // insertion
      expect(CryptoUtils.levenshteinDistance('kitten', 'kiten')).toBe(1); // deletion
    });

    it('should calculate distance correctly for different strings', () => {
      expect(CryptoUtils.levenshteinDistance('flaw', 'lawn')).toBe(2);
      expect(CryptoUtils.levenshteinDistance('google', 'g00gle')).toBe(2);
    });
  });
});
