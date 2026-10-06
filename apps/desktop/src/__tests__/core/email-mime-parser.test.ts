import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { EmailMimeParser } from '../../core/email-mime-parser';

describe('EmailMimeParser (Phase K — Practical Email Threat Security)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'email-mime-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  describe('RFC 5322 MIME & Header Parsing', () => {
    it('unfolds multi-line RFC 5322 headers correctly', () => {
      const raw = 'Subject: Urgent Notice\r\n Regarding Your\r\n Account\r\nFrom: test@example.com';
      const unfolded = EmailMimeParser.unfoldHeaders(raw);
      expect(unfolded.length).toBe(2);
      expect(unfolded[0]).toBe('Subject: Urgent Notice Regarding Your Account');
      expect(unfolded[1]).toBe('From: test@example.com');
    });

    it('extracts domain correctly from email addresses with display names', () => {
      expect(EmailMimeParser.extractDomain('PayPal Security <service@paypal.com>')).toBe('paypal.com');
      expect(EmailMimeParser.extractDomain('"Support" <help@sub.domain.org>')).toBe('sub.domain.org');
      expect(EmailMimeParser.extractDomain('user@example.com')).toBe('example.com');
      expect(EmailMimeParser.extractDomain('')).toBeUndefined();
    });

    it('sanitizes malicious attachment filenames (path traversal, RTLO, control chars)', () => {
      expect(EmailMimeParser.sanitizeFilename('../../../../Windows/System32/calc.exe')).toBe('calc.exe');
      expect(EmailMimeParser.sanitizeFilename('report\u202Eexe.pdf')).toBe('reportexe.pdf');
      expect(EmailMimeParser.sanitizeFilename('clean-invoice.pdf')).toBe('clean-invoice.pdf');
      expect(EmailMimeParser.sanitizeFilename('\x00malicious.bat')).toBe('malicious.bat');
    });

    it('parses SPF, DMARC, and DKIM results from Authentication-Results headers', () => {
      const headers = new Map<string, string>([
        [
          'authentication-results',
          'mx.google.com; dkim=pass header.i=@paypal.com; spf=fail (google.com: domain does not designate 192.0.2.1); dmarc=fail action=quarantine'
        ]
      ]);
      const auth = EmailMimeParser.parseAuthResults(headers);
      expect(auth.spf).toBe('fail');
      expect(auth.dmarc).toBe('fail');
      expect(auth.dkim).toBe('pass');
    });
  });

  describe('Email Threat Analysis (`analyzeEmailFile`)', () => {
    it('analyzes clean legitimate email and assigns safe rating', async () => {
      const cleanEml = [
        'From: team@github.com',
        'To: developer@example.com',
        'Subject: Your pull request was approved',
        'Date: Wed, 07 Oct 2026 12:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8',
        'Authentication-Results: mx.example.com; spf=pass; dmarc=pass; dkim=pass',
        '',
        'Hello developer, your pull request #101 was approved.',
        'View PR at https://github.com/org/repo/pull/101'
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'clean.eml');
      fs.writeFileSync(emlPath, cleanEml);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBe(0);
      expect(result.emailSeverity).toBe('safe');
      expect(result.isEmailMalicious).toBe(false);
      expect(result.metadata?.isAuthFailed).toBe(false);
      expect(result.metadata?.isSenderSpoofed).toBe(false);
    });

    it('detects Sender/Reply-To mismatch and flags suspicious rating', async () => {
      const spoofEml = [
        'From: Billing Support <support@paypal.com>',
        'Reply-To: Payment Collector <drop-account@scammer-portal.top>',
        'Subject: Urgent: Verify your PayPal account',
        'Content-Type: text/plain; charset=utf-8',
        'Authentication-Results: mx.example.com; spf=softfail; dmarc=none',
        '',
        'Your account has been suspended. Reply immediately with your credentials.'
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'mismatch.eml');
      fs.writeFileSync(emlPath, spoofEml);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBeGreaterThanOrEqual(45);
      expect(result.metadata?.isReplyToMismatched).toBe(true);
      expect(result.threatIndicators.some((i) => i.includes('Reply-To'))).toBe(true);
    });

    it('detects Brand Impersonation attack with failed SPF/DMARC authentication', async () => {
      const brandImpersonationEml = [
        'From: Security Alert <service@paypal.com>',
        'Reply-To: security@evil-attacker.xyz',
        'Subject: Critical Alert: Unauthorized Login Detected',
        'Content-Type: text/plain; charset=utf-8',
        'Authentication-Results: mx.example.com; spf=fail; dmarc=fail',
        '',
        'We detected unauthorized login attempts from Russia. Click below to verify.'
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'brand-spoof.eml');
      fs.writeFileSync(emlPath, brandImpersonationEml);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBeGreaterThanOrEqual(85);
      expect(result.emailSeverity).toBe('critical');
      expect(result.isEmailMalicious).toBe(true);
      expect(result.metadata?.isSenderSpoofed).toBe(true);
      expect(result.threatIndicators.some((i) => i.includes('Brand Impersonation'))).toBe(true);
    });

    it('detects malicious phishing URLs in email body', async () => {
      const phishUrlEml = [
        'From: Notification <notify@bank-alerts.com>',
        'Subject: Action Required',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body>Please confirm your login at <a href="http://paypa1-security-login.top/account/verify">PayPal Security Portal</a></body></html>'
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'phish-url.eml');
      fs.writeFileSync(emlPath, phishUrlEml);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBeGreaterThanOrEqual(70);
      expect(result.metadata?.urlsFound.length).toBeGreaterThan(0);
      expect(result.metadata?.urlThreatsCount).toBeGreaterThan(0);
    });

    it('extracts Base64 EICAR attachment inside .eml and triggers critical threat rating', async () => {
      const eicarStr = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const eicarBase64 = Buffer.from(eicarStr).toString('base64');

      const boundary = '----=_Part_12345_67890';
      const emlWithAttachment = [
        'From: admin@company-payroll.com',
        'Subject: Updated Employee Salary List',
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Please review the attached spreadsheet.',
        '',
        `--${boundary}`,
        'Content-Type: application/octet-stream; name="eicar-test.com"',
        'Content-Disposition: attachment; filename="eicar-test.com"',
        'Content-Transfer-Encoding: base64',
        '',
        eicarBase64,
        '',
        `--${boundary}--`
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'eicar-attached.eml');
      fs.writeFileSync(emlPath, emlWithAttachment);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBe(100);
      expect(result.emailSeverity).toBe('critical');
      expect(result.isEmailMalicious).toBe(true);
      expect(result.metadata?.attachmentsCount).toBe(1);
      expect(result.metadata?.attachmentThreatsCount).toBe(1);
      expect(result.metadata?.attachments[0].fileName).toBe('eicar-test.com');
      expect(result.metadata?.attachments[0].isThreat).toBe(true);
    });

    it('extracts malicious executable attachment inside .eml and raises threat alert', async () => {
      const mzPayload = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
      const mzBase64 = mzPayload.toString('base64');

      const boundary = '----=_Part_99999_88888';
      const emlWithExe = [
        'From: hr@recruitment-corp.com',
        'Subject: Resume of Candidate',
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Find resume attached.',
        '',
        `--${boundary}`,
        'Content-Type: application/x-dosexec; name="resume.pdf.exe"',
        'Content-Disposition: attachment; filename="resume.pdf.exe"',
        'Content-Transfer-Encoding: base64',
        '',
        mzBase64,
        '',
        `--${boundary}--`
      ].join('\r\n');

      const emlPath = path.join(tempDir, 'exe-attached.eml');
      fs.writeFileSync(emlPath, emlWithExe);

      const result = await EmailMimeParser.analyzeEmailFile(emlPath);
      expect(result.hasEmailMetadata).toBe(true);
      expect(result.emailRiskScore).toBeGreaterThanOrEqual(70);
      expect(result.metadata?.attachments[0].isExecutable).toBe(true);
    });
  });
});
