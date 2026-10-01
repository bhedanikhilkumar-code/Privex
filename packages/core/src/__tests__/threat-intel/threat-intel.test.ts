import { describe, it, expect, beforeEach } from 'vitest';
import { ThreatIntel } from '../../threat-intel/threat-intel';

describe('ThreatIntel', () => {
  let threatIntel: ThreatIntel;

  beforeEach(() => {
    threatIntel = new ThreatIntel();
    threatIntel.addMaliciousDomain('evil.com');
    threatIntel.addMaliciousDomain('phishing.net');
    threatIntel.addAllowedDomain('google.com');
  });

  it('should detect known-bad domains', () => {
    expect(threatIntel.checkDomain('evil.com').isMalicious).toBe(true);
    expect(threatIntel.checkDomain('phishing.net').isMalicious).toBe(true);
  });

  it('should not detect clean domains', () => {
    expect(threatIntel.checkDomain('example.com').isMalicious).toBe(false);
  });

  it('should support domain hash matching correctly', () => {
    // Assuming checkDomainHash takes a SHA-256 hash
    const evilHash = 'some-precalculated-hash-for-evil-com';
    threatIntel.addMaliciousHash(evilHash);
    expect(threatIntel.checkHash(evilHash).isMalicious).toBe(true);
  });

  it('should prevent false positives on major domains via allowlist', () => {
    // Even if somehow flagged, allowlist takes precedence
    threatIntel.addMaliciousDomain('google.com');
    expect(threatIntel.checkDomain('google.com').isMalicious).toBe(false);
  });

  it('should track staleness of intelligence data', () => {
    threatIntel.addMaliciousDomain('temp-evil.com', { ttl: -1000 }); // Expired
    expect(threatIntel.checkDomain('temp-evil.com').isMalicious).toBe(false);
  });

  it('should support add and remove operations', () => {
    threatIntel.addMaliciousDomain('test.com');
    expect(threatIntel.checkDomain('test.com').isMalicious).toBe(true);
    
    threatIntel.removeMaliciousDomain('test.com');
    expect(threatIntel.checkDomain('test.com').isMalicious).toBe(false);
  });
});
