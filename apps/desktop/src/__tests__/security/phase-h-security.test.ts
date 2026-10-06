import { describe, it, expect, beforeEach } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import { IpcValidator } from '../../ipc/ipc-validator';
import { NotificationSeverity } from '../../types/desktop.types';

describe('Phase H Security & Adversarial Test Suite (SEC-H-01 to SEC-H-10)', () => {
  let virtualTime: number;
  let service: NotificationService;
  let dispatchedToasts: Array<{ title: string; message: string; severity: NotificationSeverity }>;

  beforeEach(() => {
    virtualTime = 5000000;
    dispatchedToasts = [];
    service = new NotificationService({
      clock: () => virtualTime,
      toastDispatcher: (title, message, severity) => {
        dispatchedToasts.push({ title, message, severity });
        return true;
      }
    });
  });

  describe('SEC-H-01: Directional Override & RTLO Spoofing Neutralization', () => {
    it('strips Right-to-Left Override (U+202E) to prevent disguised extension presentation', () => {
      // Attacker attempts to disguise 'invoice.exe' as 'invoice_docx.exe' using \u202E
      const payload = 'Infected File: invoice_\u202Ecod.exe';
      const res = service.notify({
        title: 'Threat Detected',
        message: payload,
        category: 'SECURITY_ALERT'
      });
      expect(res.inboxInserted).toBe(true);

      const inbox = service.getNotifications()[0];
      expect(inbox.message).not.toContain('\u202E');
      expect(inbox.message).toBe('Infected File: invoice_cod.exe');
      expect(dispatchedToasts[0].message).not.toContain('\u202E');
    });

    it('neutralizes all bidirectional control characters (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI)', () => {
      const bidiPayload = '\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069\u200E\u200Fmalicious.exe';
      const clean = NotificationService.sanitizeNotificationText(bidiPayload);
      expect(clean).toBe('malicious.exe');
    });
  });

  describe('SEC-H-02: Bounded Text Length & Safe Truncation (DoS Prevention)', () => {
    it('truncates 5,000-character oversized title to 120 characters safely', () => {
      const hugeTitle = 'MALWARE_ALERT_'.repeat(350);
      service.notify({
        title: hugeTitle,
        message: 'Standard message',
        category: 'SECURITY_ALERT'
      });

      const notif = service.getNotifications()[0];
      expect(notif.title.length).toBeLessThanOrEqual(120);
      expect(notif.title.endsWith('...')).toBe(true);
    });

    it('truncates 10,000-character oversized message to 255 characters safely', () => {
      const hugeMessage = 'A'.repeat(10000);
      service.notify({
        title: 'Title',
        message: hugeMessage,
        category: 'SECURITY_ALERT'
      });

      const notif = service.getNotifications()[0];
      expect(notif.message.length).toBeLessThanOrEqual(255);
      expect(notif.message.endsWith('...')).toBe(true);
    });
  });

  describe('SEC-H-03: Null Byte & Control Byte Injection Defense', () => {
    it('strips null bytes and terminal escape codes from titles and messages', () => {
      const injection = 'Trojan.Win32\0\x1B[31mCritical\x07Alert\r\nExploit';
      const clean = NotificationService.sanitizeNotificationText(injection);

      expect(clean).not.toContain('\0');
      expect(clean).not.toContain('\x1B');
      expect(clean).not.toContain('\x07');
      expect(clean).toBe('Trojan.Win32[31mCriticalAlert\r\nExploit');
    });
  });

  describe('SEC-H-04: Strict Token Bucket Integrity Under Heavy Assault', () => {
    it('strictly caps toast count to 3 when flooded with 1,000 notifications in 100ms', () => {
      for (let i = 0; i < 1000; i++) {
        virtualTime += 0.1;
        service.notify({
          title: `Flood ${i}`,
          message: `Flood item ${i}`,
          category: 'SECURITY_ALERT'
        });
      }

      // Exact token-bucket limit: At most 3 toasts during 10-second window
      expect(dispatchedToasts.length).toBeLessThanOrEqual(3);
      // All 1000 items still safely entered inbox
      expect(service.getNotifications().length).toBe(500); // 500 max inbox capacity with FIFO
    });
  });

  describe('SEC-H-05: Critical Severity Immunity from Suppression', () => {
    it('always preserves critical security events even when all tokens are consumed and user is fullscreen', () => {
      let isFullscreen = true;
      const fullScreenService = new NotificationService({
        clock: () => virtualTime,
        isFullscreenFn: () => isFullscreen,
        toastDispatcher: (t, m, s) => {
          dispatchedToasts.push({ title: t, message: m, severity: s });
          return true;
        }
      });

      // 1. Consume 3 tokens with critical alerts
      fullScreenService.notify({ title: 'Crit 1', message: 'Ransomware 1', severity: 'critical', category: 'SECURITY_ALERT' });
      fullScreenService.notify({ title: 'Crit 2', message: 'Ransomware 2', severity: 'critical', category: 'SECURITY_ALERT' });
      fullScreenService.notify({ title: 'Crit 3', message: 'Ransomware 3', severity: 'critical', category: 'SECURITY_ALERT' });

      // 4th critical alert arrives while fullscreen and tokens are 0
      const res4 = fullScreenService.notify({
        title: 'Crit 4',
        message: 'Ransomware 4',
        severity: 'critical',
        category: 'SECURITY_ALERT'
      });

      // Inbox ALWAYS records the critical threat
      expect(res4.inboxInserted).toBe(true);
      expect(fullScreenService.getNotifications().length).toBe(4);
      expect(fullScreenService.getNotifications()[0].title).toBe('Crit 4');
    });
  });

  describe('SEC-H-06: IPC Validator Boundary & Schema Hardening', () => {
    it('validates notification ID rejecting control characters and path traversal', () => {
      expect(IpcValidator.validateNotificationId('notif-12345')).toBe('notif-12345');
      expect(() => IpcValidator.validateNotificationId('../../../etc/passwd')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validateNotificationId('notif\0evil')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validateNotificationId('notif|evil')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validateNotificationId('')).toThrow(/INVALID_NOTIFICATION_ID/);
      expect(() => IpcValidator.validateNotificationId(null)).toThrow(/INVALID_NOTIFICATION_ID/);
    });

    it('validates notification query limit bounds (1 to 1000)', () => {
      expect(IpcValidator.validateNotificationLimit(50)).toBe(50);
      expect(IpcValidator.validateNotificationLimit(undefined)).toBe(100);
      expect(() => IpcValidator.validateNotificationLimit(0)).toThrow(/INVALID_LIMIT/);
      expect(() => IpcValidator.validateNotificationLimit(-5)).toThrow(/INVALID_LIMIT/);
      expect(() => IpcValidator.validateNotificationLimit(5000)).toThrow(/INVALID_LIMIT/);
      expect(() => IpcValidator.validateNotificationLimit('fifty')).toThrow(/INVALID_LIMIT/);
    });
  });
});
