import { describe, it, expect, beforeEach } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import { IpcValidator } from '../../ipc/ipc-validator';
import { NotificationSeverity } from '../../types/desktop.types';

describe('Phase H Adversarial Audit & Boundary Regression Suite', () => {
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

  describe('1. Clock Boundary & Anomaly Hardening', () => {
    it('handles clock rollback safely without token corruption or negative tokens', () => {
      // Consume all 3 tokens at t=1000000
      service.notify({ title: 'T1', message: 'M1', category: 'SECURITY_ALERT' });
      service.notify({ title: 'T2', message: 'M2', category: 'SECURITY_ALERT' });
      service.notify({ title: 'T3', message: 'M3', category: 'SECURITY_ALERT' });
      expect(dispatchedToasts.length).toBe(3);

      // System clock rolls backward by 1 hour (3,600,000 ms)
      virtualTime -= 3600000;

      // 4th notification must still be rate-limited (not crash or grant infinite tokens)
      const res = service.notify({ title: 'T4', message: 'M4', category: 'SECURITY_ALERT' });
      expect(res.toastDispatched).toBe(false);
      expect(res.toastSuppressedReason).toBe('RATE_LIMITED');
      expect(service.getAvailableTokens()).toBeGreaterThanOrEqual(0);
      expect(service.getAvailableTokens()).toBeLessThanOrEqual(3.0);
    });

    it('caps token bucket at max capacity when clock leaps forward into the future', () => {
      // Consume 1 token
      service.notify({ title: 'T1', message: 'M1', category: 'SECURITY_ALERT' });
      expect(dispatchedToasts.length).toBe(1);

      // Clock leaps forward 30 days
      virtualTime += 30 * 24 * 3600 * 1000;

      // Tokens must cap exactly at max (3.0), not grow to millions
      expect(service.getAvailableTokens()).toBe(3.0);

      // Verify exactly 3 toasts allowed in immediate burst
      service.notify({ title: 'T2', message: 'M2', category: 'SECURITY_ALERT' });
      service.notify({ title: 'T3', message: 'M3', category: 'SECURITY_ALERT' });
      service.notify({ title: 'T4', message: 'M4', category: 'SECURITY_ALERT' });
      const res4 = service.notify({ title: 'T5', message: 'M5', category: 'SECURITY_ALERT' });

      expect(dispatchedToasts.length).toBe(4); // T1 + T2, T3, T4
      expect(res4.toastDispatched).toBe(false);
      expect(res4.toastSuppressedReason).toBe('RATE_LIMITED');
    });

    it('evaluates exact 5,000 ms sliding burst window boundary', () => {
      // Event 1 at t=0
      virtualTime = 10000;
      service.notify({ title: 'E1', message: 'M1', category: 'SECURITY_ALERT' });

      // Event 2 at t=2500
      virtualTime = 12500;
      service.notify({ title: 'E2', message: 'M2', category: 'SECURITY_ALERT' });

      // Event 3 at exact 5000ms boundary (t=15000)
      virtualTime = 15000;
      const res3 = service.notify({ title: 'E3', message: 'M3', category: 'SECURITY_ALERT' });

      // Must be classified as burst (>= 3 within <= 5000ms)
      expect(res3.isCoalesced).toBe(true);
      expect(res3.toastDispatched).toBe(true);
      expect(dispatchedToasts[2].title).toBe('Multiple Threats Blocked');
    });

    it('treats 3rd event outside 5,000 ms boundary as independent non-burst', () => {
      // Event 1 at t=10000
      virtualTime = 10000;
      service.notify({ title: 'E1', message: 'M1', category: 'SECURITY_ALERT' });

      // Event 2 at t=12500
      virtualTime = 12500;
      service.notify({ title: 'E2', message: 'M2', category: 'SECURITY_ALERT' });

      // Event 3 at t=15001 (5001ms after Event 1)
      virtualTime = 15001;
      const res3 = service.notify({ title: 'E3', message: 'M3', category: 'SECURITY_ALERT' });

      // Event 1 has rolled out of the 5s window, leaving only 2 events in window -> not a burst
      expect(res3.isCoalesced).toBe(false);
      expect(res3.toastDispatched).toBe(true);
      expect(dispatchedToasts[2].title).toBe('E3');
    });
  });

  describe('2. Inbox State Integrity Under Storm Eviction', () => {
    it('maintains exact unreadCount invariant when unread items are FIFO-evicted', () => {
      const tinyService = new NotificationService({
        maxInboxSize: 5,
        toastDispatcher: () => true
      });

      // Insert 5 unread items
      for (let i = 1; i <= 5; i++) {
        tinyService.notify({ id: `n-${i}`, title: `Title ${i}`, message: `Msg ${i}` });
      }

      expect(tinyService.getUnreadCount()).toBe(5);
      expect(tinyService.getNotifications().length).toBe(5);

      // Insert 6th unread item -> oldest unread item (n-1) is evicted
      tinyService.notify({ id: 'n-6', title: 'Title 6', message: 'Msg 6' });

      expect(tinyService.getNotifications().length).toBe(5);
      expect(tinyService.getUnreadCount()).toBe(5); // Still 5 unread items in memory

      const remainingIds = tinyService.getNotifications().map((n) => n.id);
      expect(remainingIds).toEqual(['n-6', 'n-5', 'n-4', 'n-3', 'n-2']);
      expect(remainingIds).not.toContain('n-1');
    });

    it('maintains exact unreadCount when read items are FIFO-evicted', () => {
      const tinyService = new NotificationService({
        maxInboxSize: 3,
        toastDispatcher: () => true
      });

      // Insert 3 items
      tinyService.notify({ id: 'n-1', title: 'T1', message: 'M1' });
      tinyService.notify({ id: 'n-2', title: 'T2', message: 'M2' });
      tinyService.notify({ id: 'n-3', title: 'T3', message: 'M3' });

      // Mark oldest item (n-1) as read
      tinyService.markRead('n-1');
      expect(tinyService.getUnreadCount()).toBe(2);

      // Insert 4th item -> n-1 (which was read) is evicted
      tinyService.notify({ id: 'n-4', title: 'T4', message: 'M4' });

      // Unread count must now be 3 (n-4 unread, n-3 unread, n-2 unread)
      expect(tinyService.getNotifications().length).toBe(3);
      expect(tinyService.getUnreadCount()).toBe(3);
    });

    it('ensures unreadCount never drops below zero regardless of markRead calls', () => {
      service.markRead('non-existent-id');
      service.markRead('');
      expect(service.getUnreadCount()).toBe(0);

      service.notify({ id: 'n-1', title: 'T1', message: 'M1' });
      expect(service.getUnreadCount()).toBe(1);

      service.markRead('n-1');
      expect(service.getUnreadCount()).toBe(0);

      // Second markRead on already read item
      service.markRead('n-1');
      expect(service.getUnreadCount()).toBe(0);

      service.clearAll();
      expect(service.getUnreadCount()).toBe(0);
    });
  });

  describe('3. Adversarial Input & Fuzzing Resilience', () => {
    it('sanitizes mixed complex directional overrides and unicode spoofing attacks', () => {
      const maliciousName = 'payload_\u202E\u2066\u2067\u2068\u2069\u200E\u200Fexe.pdf';
      const clean = NotificationService.sanitizeNotificationText(maliciousName);
      expect(clean).toBe('payload_exe.pdf');
    });

    it('safely handles null bytes, control characters, and leading/trailing whitespace', () => {
      const dirty = '   \0\x01\x02\x03Trojan\x1b[31mInfection\x7f   ';
      const clean = NotificationService.sanitizeNotificationText(dirty);
      expect(clean).toBe('Trojan[31mInfection');
    });

    it('safely truncates massive 50,000-character payload without CPU hang', () => {
      const hugeString = 'A'.repeat(50000);
      const tStart = performance.now();
      const clean = NotificationService.sanitizeNotificationText(hugeString, 255);
      const elapsed = performance.now() - tStart;

      expect(clean.length).toBe(255);
      expect(clean.endsWith('...')).toBe(true);
      expect(elapsed).toBeLessThan(10); // Under 10 ms
    });

    it('safely handles non-string and malformed inputs in sanitizeNotificationText', () => {
      expect(NotificationService.sanitizeNotificationText(null as any)).toBe('');
      expect(NotificationService.sanitizeNotificationText(undefined as any)).toBe('');
      expect(NotificationService.sanitizeNotificationText(12345 as any)).toBe('');
      expect(NotificationService.sanitizeNotificationText({} as any)).toBe('');
    });
  });

  describe('4. IPC Validator Security Gates', () => {
    it('rejects path traversal, null bytes, and non-string inputs in validateNotificationId', () => {
      expect(IpcValidator.validateNotificationId('valid-id-123')).toBe('valid-id-123');
      expect(() => IpcValidator.validateNotificationId('../escape')).toThrow('SECURITY_VIOLATION');
      expect(() => IpcValidator.validateNotificationId('id\0withnull')).toThrow('SECURITY_VIOLATION');
      expect(() => IpcValidator.validateNotificationId('folder/sub/id')).toThrow('SECURITY_VIOLATION');
      expect(() => IpcValidator.validateNotificationId('folder\\sub\\id')).toThrow('SECURITY_VIOLATION');
      expect(() => IpcValidator.validateNotificationId('')).toThrow('INVALID_NOTIFICATION_ID');
      expect(() => IpcValidator.validateNotificationId(null)).toThrow('INVALID_NOTIFICATION_ID');
      expect(() => IpcValidator.validateNotificationId(undefined)).toThrow('INVALID_NOTIFICATION_ID');
      expect(() => IpcValidator.validateNotificationId(12345)).toThrow('INVALID_NOTIFICATION_ID');
      expect(() => IpcValidator.validateNotificationId('A'.repeat(200))).toThrow('INVALID_NOTIFICATION_ID');
    });

    it('enforces bounds on validateNotificationLimit', () => {
      expect(IpcValidator.validateNotificationLimit(50, 100)).toBe(50);
      expect(IpcValidator.validateNotificationLimit(null, 100)).toBe(100);
      expect(IpcValidator.validateNotificationLimit(undefined, 100)).toBe(100);

      expect(() => IpcValidator.validateNotificationLimit(0, 100)).toThrow('INVALID_LIMIT');
      expect(() => IpcValidator.validateNotificationLimit(-10, 100)).toThrow('INVALID_LIMIT');
      expect(() => IpcValidator.validateNotificationLimit(1001, 100)).toThrow('INVALID_LIMIT');
      expect(() => IpcValidator.validateNotificationLimit('50', 100)).toThrow('INVALID_LIMIT');
      expect(() => IpcValidator.validateNotificationLimit(NaN, 100)).toThrow('INVALID_LIMIT');
      expect(() => IpcValidator.validateNotificationLimit(Infinity, 100)).toThrow('INVALID_LIMIT');
    });
  });

  describe('5. High-Velocity Storm Immunity', () => {
    it('handles 2,000 rapid notifications with exact bounded toast dispatch and zero crash', () => {
      const stormService = new NotificationService({
        maxToastsPerWindow: 3,
        toastWindowMs: 10000,
        burstCoalesceThreshold: 3,
        burstWindowMs: 5000,
        toastDispatcher: () => true
      });

      for (let i = 0; i < 2000; i++) {
        stormService.notify({
          title: `Threat ${i}`,
          message: `Blocked malware ${i}`,
          category: 'SECURITY_ALERT',
          severity: 'high'
        });
      }

      const history = stormService.getDispatchedToastsHistory();
      // Only 3 toasts dispatched during the initial window
      expect(history.length).toBeLessThanOrEqual(3);
      expect(stormService.getInboxState().totalCount).toBe(500); // Capped at default maxInboxSize 500
    });
  });
});
