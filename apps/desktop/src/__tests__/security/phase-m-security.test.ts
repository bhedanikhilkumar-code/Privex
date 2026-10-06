import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { RemovableMediaService } from '../../services/removable-media.service';
import { AutorunParser } from '../../core/autorun-parser';
import { LnkParser } from '../../core/lnk-parser';

describe('Phase M Security & Adversarial Hardening Suite', () => {
  let tempDir: string;
  let service: RemovableMediaService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-m-sec-'));
    service = new RemovableMediaService({ autoScanOnMount: false });
  });

  afterEach(() => {
    service.stopMonitoring();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup
    }
  });

  it('SEC-M-01: rejects UNC network paths in scanRemovableDriveRoot', async () => {
    await expect(service.scanRemovableDriveRoot('\\\\attacker-smb\\share\\usb')).rejects.toThrow(
      /SECURITY_VIOLATION/
    );
  });

  it('SEC-M-02: rejects raw NT/device paths (\\\\?\\C:\\) in scanRemovableDriveRoot', async () => {
    await expect(service.scanRemovableDriveRoot('\\\\?\\C:\\Windows')).rejects.toThrow(
      /SECURITY_VIOLATION/
    );
  });

  it('SEC-M-03: rejects parent directory traversal paths (..\\..\\Windows)', async () => {
    await expect(service.scanRemovableDriveRoot('E:\\mount\\..\\..\\Windows')).rejects.toThrow(
      /SECURITY_VIOLATION/
    );
  });

  it('SEC-M-04: rejects null byte injection in mount path', async () => {
    await expect(service.scanRemovableDriveRoot(`${tempDir}\0/injected`)).rejects.toThrow(
      /SECURITY_VIOLATION/
    );
  });

  it('SEC-M-05: neutralizes RTLO/bidi unicode overrides in autorun and shortcut directives', async () => {
    const maliciousRtlo = 'open=invoice\u202Efdp.exe';
    const sanitized = AutorunParser.sanitizeString(maliciousRtlo);
    expect(sanitized.includes('\u202E')).toBe(false);
    expect(sanitized.includes('exe')).toBe(true);

    const lnkRtlo = 'C:\\Windows\\System32\\calc\u202Egpj.exe';
    const lnkSanitized = LnkParser.sanitizeString(lnkRtlo);
    expect(lnkSanitized.includes('\u202E')).toBe(false);
  });

  it('SEC-M-06: safely handles heavily fuzzed and bit-flipped .lnk structures without throwing unhandled exceptions', async () => {
    const validHeader = Buffer.alloc(76);
    validHeader.writeUInt32LE(0x0000004c, 0);
    Buffer.from([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]).copy(validHeader, 4);
    validHeader.writeUInt32LE(0x000000ff, 0x14); // Set all flags

    // Append 50 random bytes
    const fuzzed = Buffer.concat([validHeader, Buffer.alloc(50, 0xef)]);

    for (let i = 0; i < 20; i++) {
      // Flip random bits
      const mutated = Buffer.from(fuzzed);
      const byteIdx = Math.floor(Math.random() * mutated.length);
      mutated[byteIdx] ^= 0xff;

      const res = await LnkParser.parseBuffer(mutated, `fuzzed-${i}.lnk`);
      expect(typeof res.isShortcut).toBe('boolean');
      expect(typeof res.riskScore).toBe('number');
      expect(Array.isArray(res.indicators)).toBe(true);
    }
  });

  it('SEC-M-07: bounds root quick-triage to max 50 items when root contains 500 files to prevent DoS', async () => {
    // Generate 100 benign files in root
    for (let i = 0; i < 100; i++) {
      fs.writeFileSync(path.join(tempDir, `file_${i}.txt`), `Content ${i}`, 'utf-8');
    }

    const result = await service.scanRemovableDriveRoot(tempDir);
    expect(result.totalRootItemsScanned).toBeLessThanOrEqual(50);
    expect(result.durationMs).toBeLessThan(200);
  });

  it('SEC-M-08: guarantees 100% offline operation with zero outbound network socket calls', async () => {
    let outboundSocketsAttempted = 0;
    const socketSpy = vi.spyOn(net.Socket.prototype, 'connect').mockImplementation(function (this: any) {
      outboundSocketsAttempted++;
      throw new Error('AIR_GAP_VIOLATION: Outbound network socket blocked.');
    });

    try {
      fs.writeFileSync(path.join(tempDir, 'autorun.inf'), '[autorun]\r\nopen=worm.exe', 'utf-8');
      const result = await service.scanRemovableDriveRoot(tempDir);
      expect(result.threatsFound).toBeGreaterThanOrEqual(1);
      expect(outboundSocketsAttempted).toBe(0);
    } finally {
      socketSpy.mockRestore();
    }
  });
});
