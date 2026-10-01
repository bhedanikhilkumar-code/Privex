import { describe, it, expect, beforeEach } from 'vitest';
import { BloomFilter } from '../../threat-intel/bloom-filter';

describe('BloomFilter Production Engine', () => {
  let filter: BloomFilter;

  beforeEach(() => {
    filter = new BloomFilter({
      expectedElements: 1000,
      targetFalsePositiveRate: 0.01
    });
  });

  it('should initialize with mathematically optimal m and k', () => {
    expect(filter.capacity).toBe(1000);
    expect(filter.sizeBits).toBeGreaterThan(5000); // For n=1000, p=0.01: m ≈ 9585 bits
    expect(filter.hashCount).toBeGreaterThanOrEqual(5);
    expect(filter.elementCount).toBe(0);
    expect(filter.getFalsePositiveRate()).toBe(0.0);
  });

  it('should guarantee ZERO false negatives (fundamental theorem of Bloom filters)', () => {
    const testItems = [
      'phishing-portal.com',
      'malware-drop.xyz',
      'crypto-drainer.cc',
      'urgent-bank-verify.org',
      'https://evil.ru/payload.exe',
      '198.51.100.42'
    ];

    testItems.forEach(item => filter.add(item));
    expect(filter.elementCount).toBe(testItems.length);

    // Every single added item MUST test positive
    for (const item of testItems) {
      expect(filter.has(item)).toBe(true);
    }
  });

  it('should return false for items not in the filter (with bounded FPR)', () => {
    filter.add('bad-actor-1.com');
    filter.add('bad-actor-2.com');

    // Unadded items should predominantly return false
    expect(filter.has('definitely-clean-google.com')).toBe(false);
    expect(filter.has('legitimate-microsoft.com')).toBe(false);
    expect(filter.has('apple.com')).toBe(false);
  });

  it('should measure empirical false positive probability as bit density increases', () => {
    expect(filter.getFalsePositiveRate()).toBe(0.0);

    for (let i = 0; i < 500; i++) {
      filter.add(`malicious-sample-${i}.org`);
    }

    const fpr = filter.getFalsePositiveRate();
    expect(fpr).toBeGreaterThan(0.0);
    expect(fpr).toBeLessThan(0.05); // Well within target bounds
  });

  it('should support binary serialization and deserialization with BLOM header', () => {
    const items = ['evil-site.net', 'scam-call.biz', 'fake-login.io'];
    items.forEach(it => filter.add(it));

    const binary = filter.serialize();
    expect(binary).toBeInstanceOf(Uint8Array);
    // BLOM header check: 'B', 'L', 'O', 'M' (0x42, 0x4C, 0x4F, 0x4D)
    expect(binary[0]).toBe(0x42);
    expect(binary[1]).toBe(0x4c);
    expect(binary[2]).toBe(0x4f);
    expect(binary[3]).toBe(0x4d);
    expect(binary[4]).toBe(1); // Version 1

    const deserialized = BloomFilter.deserialize(binary);
    expect(deserialized.capacity).toBe(filter.elementCount);
    expect(deserialized.sizeBits).toBe(filter.sizeBits);
    expect(deserialized.hashCount).toBe(filter.hashCount);
    expect(deserialized.elementCount).toBe(filter.elementCount);

    // All original items must be retained
    for (const it of items) {
      expect(deserialized.has(it)).toBe(true);
    }
    expect(deserialized.has('not-in-deserialized.org')).toBe(false);
  });

  it('should reject invalid or corrupted binary buffers on deserialization', () => {
    expect(() => BloomFilter.deserialize(new Uint8Array(10))).toThrow(
      'InvalidBloomFilterError: buffer too short for header'
    );

    const corruptedHeader = new Uint8Array(32);
    corruptedHeader[0] = 0x58; // 'X' instead of 'B'
    expect(() => BloomFilter.deserialize(corruptedHeader)).toThrow(
      'InvalidBloomFilterError: magic bytes mismatch'
    );

    const corruptedVersion = new Uint8Array(32);
    corruptedVersion[0] = 0x42;
    corruptedVersion[1] = 0x4c;
    corruptedVersion[2] = 0x4f;
    corruptedVersion[3] = 0x4d;
    corruptedVersion[4] = 99; // Invalid version
    expect(() => BloomFilter.deserialize(corruptedVersion)).toThrow(
      'InvalidBloomFilterError: unsupported version 99'
    );
  });

  it('should properly clear all bit states and counters', () => {
    filter.add('temp-threat.com');
    expect(filter.has('temp-threat.com')).toBe(true);
    expect(filter.elementCount).toBe(1);

    filter.clear();
    expect(filter.elementCount).toBe(0);
    expect(filter.getFalsePositiveRate()).toBe(0.0);
    expect(filter.has('temp-threat.com')).toBe(false);
  });
});
