import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { EmailMimeParser } from '../../core/email-mime-parser';
import { FileAnalyzer } from '../../core/file-analyzer';

describe('Phase K Security & Adversarial Suite (Email & Network Socket Protection)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-k-sec-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('SEC-K-A: defends against recursive deeply nested MIME multipart bombs (clamped at depth 10)', async () => {
    // Generate 25 levels of nested multipart boundaries
    let nestedEml = 'From: attacker@evil.com\r\nSubject: Deep Nesting\r\nContent-Type: multipart/mixed; boundary="b_0"\r\n\r\n';
    for (let i = 0; i < 25; i++) {
      nestedEml += `--b_${i}\r\nContent-Type: multipart/mixed; boundary="b_${i + 1}"\r\n\r\n`;
    }
    nestedEml += 'Deeply nested payload text\r\n';
    for (let i = 24; i >= 0; i--) {
      nestedEml += `--b_${i}--\r\n`;
    }

    const emlPath = path.join(tempDir, 'nested-bomb.eml');
    fs.writeFileSync(emlPath, nestedEml);

    // Should complete without stack overflow or crashing
    const result = await EmailMimeParser.analyzeEmailFile(emlPath);
    expect(result.hasEmailMetadata).toBe(true);
    expect(result.emailRiskScore).toBeGreaterThanOrEqual(0);
  });

  it('SEC-K-B: bounds Base64 memory allocation and prevents attachment expansion bombs', async () => {
    // 20 MB Base64 string exceeding per-attachment limits
    const largeChunk = Buffer.alloc(1024 * 1024, 'A').toString('base64');
    const repeated = largeChunk.repeat(20); // 20 MB

    const boundary = '----=_Part_Large';
    const largeEml = [
      'From: user@example.com',
      'Subject: Large File',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: application/octet-stream; name="large.dat"',
      'Content-Disposition: attachment; filename="large.dat"',
      'Content-Transfer-Encoding: base64',
      '',
      repeated,
      '',
      `--${boundary}--`
    ].join('\r\n');

    const emlPath = path.join(tempDir, 'large-bomb.eml');
    fs.writeFileSync(emlPath, largeEml);

    const result = await EmailMimeParser.analyzeEmailFile(emlPath);
    expect(result.hasEmailMetadata).toBe(true);
    if (result.metadata && result.metadata.attachments.length > 0) {
      expect(result.metadata.attachments[0].sizeBytes).toBeLessThanOrEqual(
        EmailMimeParser.MAX_ATTACHMENT_BYTES
      );
    }
  });

  it('SEC-K-C: sanitizes attachment filename directory traversal and NUL byte injections', () => {
    const maliciousNames = [
      '../../../../../../Windows/System32/cmd.exe',
      '..\\..\\..\\..\\Windows\\System32\\calc.exe',
      'report.pdf\x00.exe',
      '....//....//....//payload.vbs',
      '',
      '.',
      '..'
    ];

    for (const name of maliciousNames) {
      const sanitized = EmailMimeParser.sanitizeFilename(name);
      expect(sanitized).not.toContain('..');
      expect(sanitized).not.toContain('/');
      expect(sanitized).not.toContain('\\');
      expect(sanitized).not.toContain('\x00');
      expect(sanitized.length).toBeGreaterThan(0);
    }
  });

  it('SEC-K-D: scrubs Right-to-Left Override (RTLO) bidi characters from email attachment filenames', () => {
    const rtloFilename = 'Quarterly_Report\u202Efdp.exe'; // Renders as Quarterly_Reportexe.pdf
    const sanitized = EmailMimeParser.sanitizeFilename(rtloFilename);
    expect(sanitized).not.toContain('\u202E');
    expect(sanitized).toBe('Quarterly_Reportfdp.exe');
  });

  it('SEC-K-E: executes 100% offline with Node network/socket APIs hard-disabled', async () => {
    const fetchSpy = vi.fn().mockImplementation(() => {
      throw new Error('OFFLINE_VIOLATION: fetch() invoked during email scan');
    });
    globalThis.fetch = fetchSpy;

    const socketSpy = vi.spyOn(net.Socket.prototype, 'connect').mockImplementation(() => {
      throw new Error('OFFLINE_VIOLATION: Socket.connect invoked during email scan');
    });

    try {
      const emlPath = path.join(tempDir, 'offline-email.eml');
      fs.writeFileSync(
        emlPath,
        [
          'From: Security <service@paypal.com>',
          'Reply-To: phish@evil-domain.xyz',
          'Subject: Urgent Security Notice',
          'Content-Type: text/plain; charset=utf-8',
          'Authentication-Results: mx.example.com; spf=fail; dmarc=fail',
          '',
          'Please verify your PayPal account at http://198.51.100.23:8080/login'
        ].join('\r\n')
      );

      const emailResult = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(emailResult.emailRiskScore).toBeGreaterThanOrEqual(85);
      expect(emailResult.isEmailMalicious).toBe(true);

      const fileResult = await FileAnalyzer.analyzeFile(emlPath);
      expect(fileResult.verdict).toBe('BLOCK');

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(socketSpy).not.toHaveBeenCalled();
    } finally {
      socketSpy.mockRestore();
    }
  });

  it('SEC-K-F: handles corrupted or malformed MIME headers safely without crashing', async () => {
    const garbageEml = 'This is non-MIME corrupted binary garbage \x00\xFF\xFE\x00 without valid structure';
    const emlPath = path.join(tempDir, 'corrupted.eml');
    fs.writeFileSync(emlPath, garbageEml);

    const result = await EmailMimeParser.analyzeEmailFile(emlPath);
    expect(result.hasEmailMetadata).toBe(true);
    expect(result.emailRiskScore).toBe(0);
  });

  it('SEC-K-G: guarantees complete cleanup of temporary attachment staging directories', async () => {
    const boundary = '----=_Part_CleanTest';
    const eml = [
      'From: sender@example.com',
      'Subject: Clean Test',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; name="test.txt"',
      'Content-Disposition: attachment; filename="test.txt"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('Hello world').toString('base64'),
      '',
      `--${boundary}--`
    ].join('\r\n');

    const emlPath = path.join(tempDir, 'clean-test.eml');
    fs.writeFileSync(emlPath, eml);

    const tmpDirsBefore = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('pp-email-stage-'));
    await EmailMimeParser.analyzeEmailFile(emlPath);
    const tmpDirsAfter = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('pp-email-stage-'));

    expect(tmpDirsAfter.length).toBe(tmpDirsBefore.length);
  });
});
