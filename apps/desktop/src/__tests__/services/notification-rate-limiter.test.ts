import { describe, it, expect, beforeEach } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import { NotificationSeverity } from '../../types/desktop.types';

describe('NotificationService (RULE-15 Token-Bucket Rate Limiter & Burst Coalescer)', () => {
  let virtualTime: number;
  let service: NotificationService;
  let dispatchedToasts: Array<{ title: string; message: string; severity: NotificationSeverity }>;

  beforeEach(() => {
    virtualTime = 1000000;
    dispatchedToasts = [];

    service = new NotificationService({
      clock: () => virtualTime,
      toastDispatcher: (title, message, severity) => {
        dispatchedToasts.push({ title, message, severity });
        return true;
      }
    });
  });

  describe('Token-Bucket Rate Limiting (RULE-15)', () => {
    it('allows initial burst of up to 3 native OS toasts', () => {
      const res1 = service.notify({ title: 'Alert 1', message: 'Message 1', category: 'SYSTEM_HEALTH' });
      const res2 = service.notify({ title: 'Alert 2', message: 'Message 2', category: 'SYSTEM_HEALTH' });
      const res3 = service.notify({ title: 'Alert 3', message: 'Message 3', category: 'SYSTEM_HEALTH' });

      expect(res1.toastDispatched).toBe(true);
      expect(res2.toastDispatched).toBe(true);
      expect(res3.toastDispatched).toBe(true);
      expect(dispatchedToasts.length).toBe(3);
    });

    it('rate-limits the 4th toast within the 10-second window', () => {
      service.notify({ title: 'Alert 1', message: 'Message 1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'Alert 2', message: 'Message 2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'Alert 3', message: 'Message 3', category: 'SYSTEM_HEALTH' });

      // 4th notification at T + 100ms
      virtualTime += 100;
      const res4 = service.notify({ title: 'Alert 4', message: 'Message 4', category: 'SYSTEM_HEALTH' });

      expect(res4.toastDispatched).toBe(false);
      expect(res4.toastSuppressedReason).toBe('RATE_LIMITED');
      expect(res4.inboxInserted).toBe(true); // Inbox ALWAYS receives notification
      expect(dispatchedToasts.length).toBe(3);
    });

    it('refills tokens linearly over time (1 token every 3.33 seconds)', () => {
      // Consume all 3 tokens
      service.notify({ title: 'Alert 1', message: 'Message 1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'Alert 2', message: 'Message 2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'Alert 3', message: 'Message 3', category: 'SYSTEM_HEALTH' });

      // Advance 3.4 seconds (should refill ~1.02 tokens)
      virtualTime += 3400;
      const res4 = service.notify({ title: 'Alert 4', message: 'Message 4', category: 'SYSTEM_HEALTH' });
      expect(res4.toastDispatched).toBe(true);

      // Attempt immediate 5th notification (should be rate-limited)
      const res5 = service.notify({ title: 'Alert 5', message: 'Message 5', category: 'SYSTEM_HEALTH' });
      expect(res5.toastDispatched).toBe(false);
      expect(res5.toastSuppressedReason).toBe('RATE_LIMITED');
    });

    it('refills to full capacity (3 tokens) after 10 seconds of idle time', () => {
      // Consume all 3 tokens
      service.notify({ title: 'A1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A2', message: 'M2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A3', message: 'M3', category: 'SYSTEM_HEALTH' });

      // Advance 10 full seconds
      virtualTime += 10000;

      const res4 = service.notify({ title: 'A4', message: 'M4', category: 'SYSTEM_HEALTH' });
      const res5 = service.notify({ title: 'A5', message: 'M5', category: 'SYSTEM_HEALTH' });
      const res6 = service.notify({ title: 'A6', message: 'M6', category: 'SYSTEM_HEALTH' });

      expect(res4.toastDispatched).toBe(true);
      expect(res5.toastDispatched).toBe(true);
      expect(res6.toastDispatched).toBe(true);
      expect(dispatchedToasts.length).toBe(6);
    });

    it('clamps tokens at max capacity (3) even after long idle periods', () => {
      // Advance 100 seconds
      virtualTime += 100000;
      expect(service.getAvailableTokens()).toBe(3);

      service.notify({ title: 'A1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A2', message: 'M2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A3', message: 'M3', category: 'SYSTEM_HEALTH' });

      const res4 = service.notify({ title: 'A4', message: 'M4', category: 'SYSTEM_HEALTH' });
      expect(res4.toastDispatched).toBe(false);
      expect(res4.toastSuppressedReason).toBe('RATE_LIMITED');
    });

    it('handles clock backward drift safely without giving infinite tokens', () => {
      service.notify({ title: 'A1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A2', message: 'M2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'A3', message: 'M3', category: 'SYSTEM_HEALTH' });

      // Clock jumps backward 5 seconds (e.g. NTP synchronization adjustment)
      virtualTime -= 5000;

      const res4 = service.notify({ title: 'A4', message: 'M4', category: 'SYSTEM_HEALTH' });
      expect(res4.toastDispatched).toBe(false);
      expect(res4.toastSuppressedReason).toBe('RATE_LIMITED');
    });
  });

  describe('Burst Coalescer (RULE-15)', () => {
    it('dispatches individual toasts when threats arrive outside the 5-second burst threshold', () => {
      const res1 = service.notify({ title: 'Threat 1', message: 'EICAR 1', category: 'SECURITY_ALERT' });
      virtualTime += 6000;
      const res2 = service.notify({ title: 'Threat 2', message: 'EICAR 2', category: 'SECURITY_ALERT' });

      expect(res1.isCoalesced).toBe(false);
      expect(res2.isCoalesced).toBe(false);
      expect(dispatchedToasts.length).toBe(2);
    });

    it('coalesces 3rd threat within 5 seconds into a single summary notification', () => {
      // Threat 1 at T=0
      service.notify({ title: 'Threat 1', message: 'EICAR 1', category: 'SECURITY_ALERT' });
      // Threat 2 at T=1000
      virtualTime += 1000;
      service.notify({ title: 'Threat 2', message: 'EICAR 2', category: 'SECURITY_ALERT' });
      // Threat 3 at T=2000 (trips burst threshold >= 3 within 5s)
      virtualTime += 1000;
      const res3 = service.notify({ title: 'Threat 3', message: 'EICAR 3', category: 'SECURITY_ALERT' });

      expect(res3.isCoalesced).toBe(true);
      // The 3rd toast is a coalesced summary toast
      const lastToast = dispatchedToasts[dispatchedToasts.length - 1];
      expect(lastToast.title).toBe('Multiple Threats Blocked');
      expect(lastToast.message).toContain('3 threats in the last 5 seconds');
    });

    it('retains all 10 threat items in In-App Inbox while coalescing toasts during a storm', () => {
      for (let i = 1; i <= 10; i++) {
        virtualTime += 100;
        service.notify({
          title: `Threat ${i}`,
          message: `Infected file ${i}.exe`,
          category: 'SECURITY_ALERT',
          metadata: { fileName: `file_${i}.exe` }
        });
      }

      const inbox = service.getNotifications();
      expect(inbox.length).toBe(10);
      expect(service.getUnreadCount()).toBe(10);
      expect(dispatchedToasts.length).toBeLessThanOrEqual(3);
    });
  });

  describe('Sanitization & Payload Safety', () => {
    it('scrubs Unicode RTLO (\\u202E) and directional overrides from notification text', () => {
      const spoofedTitle = 'Important_\u202Efdp.exe_Document';
      const clean = NotificationService.sanitizeNotificationText(spoofedTitle);

      expect(clean).not.toContain('\u202E');
      expect(clean).toBe('Important_fdp.exe_Document');
    });

    it('safely truncates long 500-character filenames to maximum 255 characters with ellipsis', () => {
      const longName = 'A'.repeat(400);
      const clean = NotificationService.sanitizeNotificationText(longName, 255);

      expect(clean.length).toBe(255);
      expect(clean.endsWith('...')).toBe(true);
    });

    it('strips null bytes and control characters', () => {
      const malformed = 'Threat\0Detected\x07\x1B';
      const clean = NotificationService.sanitizeNotificationText(malformed);

      expect(clean).toBe('ThreatDetected');
    });
  });
});
