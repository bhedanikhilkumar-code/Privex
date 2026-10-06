import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ExclusionManagerService } from '../../services/exclusion-manager.service';

describe('ExclusionManagerService (Phase I — False-Positive Exclusion Manager)', () => {
  let tempDir: string;
  let service: ExclusionManagerService;
  let mockTime: number;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exclusion-test-'));
    mockTime = 1760000000000;
    service = new ExclusionManagerService({
      configDir: tempDir,
      clock: () => mockTime
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  describe('3-Tier Exclusion Types & Canonicalization', () => {
    it('creates and canonicalizes HASH exclusion (uppercase to lowercase hex)', () => {
      const sha256 = 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90';
      const item = service.addExclusion({
        type: 'HASH',
        value: sha256,
        reason: 'Developer internal tool'
      });

      expect(item.type).toBe('HASH');
      expect(item.canonicalValue).toBe(sha256.toLowerCase());
      expect(item.enabled).toBe(true);

      const check = service.checkHash(sha256);
      expect(check.isExcluded).toBe(true);
      expect(check.matchedExclusion?.id).toBe(item.id);
    });

    it('rejects invalid non-64-character SHA-256 hashes', () => {
      expect(() => {
        service.addExclusion({
          type: 'HASH',
          value: 'short-hash-123',
          reason: 'invalid'
        });
      }).toThrow(/INVALID_HASH/);
    });

    it('creates and canonicalizes PATH exclusion with normalized separators', () => {
      const targetPath = path.join(os.homedir(), 'Development', 'tools', 'myapp.exe');

      const item = service.addExclusion({
        type: 'PATH',
        value: targetPath,
        reason: 'Authorized local compiler'
      });

      expect(item.type).toBe('PATH');
      expect(item.canonicalValue).toBe(path.resolve(targetPath));

      const check = service.checkPath(targetPath);
      expect(check.isExcluded).toBe(true);
      expect(check.matchedExclusion?.id).toBe(item.id);
    });

    it('creates and canonicalizes DOMAIN exclusion with mandatory TTL', () => {
      const item = service.addExclusion({
        type: 'DOMAIN',
        value: 'API.INTERNAL-CORP.COM',
        ttl: '7d',
        reason: 'Internal corporate API endpoint'
      });

      expect(item.type).toBe('DOMAIN');
      expect(item.canonicalValue).toBe('api.internal-corp.com');
      expect(item.expiresAt).toBe(mockTime + 7 * 24 * 60 * 60 * 1000);

      const check = service.checkDomain('api.internal-corp.com');
      expect(check.isExcluded).toBe(true);
      expect(check.matchedExclusion?.id).toBe(item.id);
    });
  });

  describe('TTL Expiration & Pruning', () => {
    it('expires domain exclusions accurately when clock advances past expiresAt', () => {
      service.addExclusion({
        type: 'DOMAIN',
        value: 'temp-trusted.org',
        ttl: '24h',
        reason: 'Temporary test domain'
      });

      expect(service.checkDomain('temp-trusted.org').isExcluded).toBe(true);

      // Advance clock past 24 hours + 1 ms
      mockTime += 24 * 60 * 60 * 1000 + 1;

      expect(service.checkDomain('temp-trusted.org').isExcluded).toBe(false);
      expect(service.getExclusions(false).length).toBe(0);
      expect(service.getExclusions(true).length).toBe(1);
    });

    it('supports toggle enable / disable without deleting exclusion item', () => {
      const sha256 = '1111111111111111111111111111111111111111111111111111111111111111';
      const item = service.addExclusion({
        type: 'HASH',
        value: sha256,
        reason: 'Test toggle'
      });

      expect(service.checkHash(sha256).isExcluded).toBe(true);

      service.toggleExclusion(item.id, false);
      expect(service.checkHash(sha256).isExcluded).toBe(false);

      service.toggleExclusion(item.id, true);
      expect(service.checkHash(sha256).isExcluded).toBe(true);
    });
  });

  describe('Encrypted Persistence & Crash Recovery', () => {
    it('persists encrypted exclusions.enc and reloads state across service instances', () => {
      const sha256 = '2222222222222222222222222222222222222222222222222222222222222222';
      service.addExclusion({
        type: 'HASH',
        value: sha256,
        reason: 'Persistent exclusion'
      });

      // Verify file on disk is AES-256-GCM encrypted, not plain text JSON
      const encPath = path.join(tempDir, 'exclusions.enc');
      expect(fs.existsSync(encPath)).toBe(true);
      const encContent = fs.readFileSync(encPath, 'utf8');
      expect(encContent).not.toContain('Persistent exclusion');

      // Create a fresh ExclusionManagerService pointing to the same config directory
      const reloadedService = new ExclusionManagerService({
        configDir: tempDir,
        clock: () => mockTime
      });

      expect(reloadedService.getExclusions().length).toBe(1);
      expect(reloadedService.checkHash(sha256).isExcluded).toBe(true);
    });

    it('recovers cleanly from .bak backup file if exclusions.enc is corrupted', () => {
      const sha256 = '3333333333333333333333333333333333333333333333333333333333333333';
      service.addExclusion({
        type: 'HASH',
        value: sha256,
        reason: 'Backup recovery test'
      });

      const encPath = path.join(tempDir, 'exclusions.enc');
      const bakPath = path.join(tempDir, 'exclusions.enc.bak');

      // Emulate valid .bak existing and corrupted main .enc
      fs.copyFileSync(encPath, bakPath);
      fs.writeFileSync(encPath, 'corrupted_garbage_bytes');

      const recoveryService = new ExclusionManagerService({
        configDir: tempDir,
        clock: () => mockTime
      });

      expect(recoveryService.getExclusions().length).toBe(1);
      expect(recoveryService.checkHash(sha256).isExcluded).toBe(true);
    });
  });

  describe('Restore & Trust SHA-256 Workflow', () => {
    it('creates exact verified SHA-256 exclusion on restore & trust', () => {
      const sha256 = '4444444444444444444444444444444444444444444444444444444444444444';
      const item = service.addRestoreAndTrustExclusion(
        sha256,
        'C:\\Users\\test\\Downloads\\mytool.exe',
        sha256
      );

      expect(item.type).toBe('HASH');
      expect(item.canonicalValue).toBe(sha256);
      expect(item.createdBy).toBe('RESTORE_AND_TRUST');

      const check = service.checkHash(sha256);
      expect(check.isExcluded).toBe(true);
    });

    it('rejects restore & trust if candidate hash does not match verified hash', () => {
      const sha256A = '4444444444444444444444444444444444444444444444444444444444444444';
      const sha256B = '5555555555555555555555555555555555555555555555555555555555555555';

      expect(() => {
        service.addRestoreAndTrustExclusion(
          sha256A,
          'C:\\Users\\test\\Downloads\\mytool.exe',
          sha256B
        );
      }).toThrow(/INTEGRITY_VIOLATION/);
    });
  });
});
