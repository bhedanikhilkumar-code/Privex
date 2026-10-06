import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import {
  NotificationSeverity,
  DetectedThreat,
  RansomwareIncident,
  ProcessContainmentResult
} from '../../types/desktop.types';

describe('NotificationService (In-App Inbox, Tray, Fullscreen, and Event Adapters)', () => {
  let virtualTime: number;
  let service: NotificationService;
  let isFullscreen = false;
  let trayUpdates: Array<{ unreadCount: number; latestThreatTitle?: string }>;
  let dispatchedToasts: Array<{ title: string; message: string; severity: NotificationSeverity }>;

  beforeEach(() => {
    virtualTime = 2000000;
    isFullscreen = false;
    trayUpdates = [];
    dispatchedToasts = [];

    service = new NotificationService({
      clock: () => virtualTime,
      isFullscreenFn: () => isFullscreen,
      maxInboxSize: 10,
      trayUpdater: (unreadCount, latestThreatTitle) => {
        trayUpdates.push({ unreadCount, latestThreatTitle });
      },
      toastDispatcher: (title, message, severity) => {
        dispatchedToasts.push({ title, message, severity });
        return true;
      }
    });
  });

  describe('In-App Notification Inbox Management', () => {
    it('initializes with empty inbox and 0 unread count', () => {
      expect(service.getNotifications().length).toBe(0);
      expect(service.getUnreadCount()).toBe(0);
      const state = service.getInboxState();
      expect(state.totalCount).toBe(0);
      expect(state.unreadCount).toBe(0);
    });

    it('inserts notifications in descending chronological order (newest first)', () => {
      virtualTime = 1000;
      service.notify({ title: 'First', message: 'M1', category: 'SYSTEM_HEALTH' });
      virtualTime = 2000;
      service.notify({ title: 'Second', message: 'M2', category: 'SYSTEM_HEALTH' });
      virtualTime = 3000;
      service.notify({ title: 'Third', message: 'M3', category: 'SYSTEM_HEALTH' });

      const inbox = service.getNotifications();
      expect(inbox.length).toBe(3);
      expect(inbox[0].title).toBe('Third');
      expect(inbox[1].title).toBe('Second');
      expect(inbox[2].title).toBe('First');
      expect(service.getUnreadCount()).toBe(3);
    });

    it('marks individual notification as read and decrements unread count', () => {
      service.notify({ id: 'notif-1', title: 'T1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ id: 'notif-2', title: 'T2', message: 'M2', category: 'SYSTEM_HEALTH' });

      expect(service.getUnreadCount()).toBe(2);

      const success = service.markRead('notif-1');
      expect(success).toBe(true);
      expect(service.getUnreadCount()).toBe(1);

      const n1 = service.getNotifications().find((n) => n.id === 'notif-1');
      expect(n1?.isRead).toBe(true);

      // Calling markRead on already read item returns false
      expect(service.markRead('notif-1')).toBe(false);
      expect(service.getUnreadCount()).toBe(1);
    });

    it('marks all notifications as read', () => {
      service.notify({ title: 'T1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'T2', message: 'M2', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'T3', message: 'M3', category: 'SYSTEM_HEALTH' });

      expect(service.getUnreadCount()).toBe(3);

      const changed = service.markAllRead();
      expect(changed).toBe(3);
      expect(service.getUnreadCount()).toBe(0);

      const allRead = service.getNotifications().every((n) => n.isRead);
      expect(allRead).toBe(true);
    });

    it('clears all notifications', () => {
      service.notify({ title: 'T1', message: 'M1', category: 'SYSTEM_HEALTH' });
      service.notify({ title: 'T2', message: 'M2', category: 'SYSTEM_HEALTH' });

      service.clearAll();
      expect(service.getNotifications().length).toBe(0);
      expect(service.getUnreadCount()).toBe(0);
    });

    it('enforces FIFO eviction when inbox exceeds maxInboxSize (10 items)', () => {
      for (let i = 1; i <= 15; i++) {
        virtualTime += 100;
        service.notify({ title: `Alert ${i}`, message: `Msg ${i}`, category: 'SYSTEM_HEALTH' });
      }

      const inbox = service.getNotifications();
      expect(inbox.length).toBe(10);
      // Newest should be Alert 15, oldest in buffer should be Alert 6
      expect(inbox[0].title).toBe('Alert 15');
      expect(inbox[9].title).toBe('Alert 6');
      expect(service.getUnreadCount()).toBe(10);
    });

    it('supports query limit parameter', () => {
      for (let i = 1; i <= 8; i++) {
        service.notify({ title: `Alert ${i}`, message: `Msg ${i}`, category: 'SYSTEM_HEALTH' });
      }

      const limited = service.getNotifications(3);
      expect(limited.length).toBe(3);
    });
  });

  describe('Fullscreen-Aware Toast Suppression', () => {
    it('suppresses low/medium/info toasts when in fullscreen mode while keeping inbox record', () => {
      isFullscreen = true;

      const resInfo = service.notify({ title: 'Info', message: 'Low priority', severity: 'info', category: 'SYSTEM_HEALTH' });
      const resLow = service.notify({ title: 'Low', message: 'Low priority', severity: 'low', category: 'SYSTEM_HEALTH' });
      const resMed = service.notify({ title: 'Med', message: 'Med priority', severity: 'medium', category: 'SYSTEM_HEALTH' });

      expect(resInfo.toastDispatched).toBe(false);
      expect(resInfo.toastSuppressedReason).toBe('FULLSCREEN_SUPPRESSED');
      expect(resLow.toastDispatched).toBe(false);
      expect(resLow.toastSuppressedReason).toBe('FULLSCREEN_SUPPRESSED');
      expect(resMed.toastDispatched).toBe(false);
      expect(resMed.toastSuppressedReason).toBe('FULLSCREEN_SUPPRESSED');

      // Inbox still has all 3
      expect(service.getNotifications().length).toBe(3);
      expect(dispatchedToasts.length).toBe(0);
    });

    it('delivers critical and high severity toasts even during fullscreen', () => {
      isFullscreen = true;

      const resHigh = service.notify({ title: 'High Threat', message: 'Urgent', severity: 'high', category: 'SECURITY_ALERT' });
      const resCrit = service.notify({ title: 'Critical Threat', message: 'Ransomware', severity: 'critical', category: 'SECURITY_ALERT' });

      expect(resHigh.toastDispatched).toBe(true);
      expect(resCrit.toastDispatched).toBe(true);
      expect(dispatchedToasts.length).toBe(2);
    });
  });

  describe('System Tray Updates', () => {
    it('updates system tray on new notifications, markRead, and clearAll', () => {
      service.notify({ title: 'Security Alert', message: 'Threat found', category: 'SECURITY_ALERT' });
      expect(trayUpdates.length).toBe(1);
      expect(trayUpdates[0].unreadCount).toBe(1);

      service.markAllRead();
      expect(trayUpdates.length).toBe(2);
      expect(trayUpdates[1].unreadCount).toBe(0);

      service.clearAll();
      expect(trayUpdates.length).toBe(3);
      expect(trayUpdates[2].unreadCount).toBe(0);
    });
  });

  describe('Security Event Adapters', () => {
    it('notifies security threat from DetectedThreat object', () => {
      const threat: DetectedThreat = {
        id: 't-101',
        filePath: 'C:\\Downloads\\trojan.exe',
        fileName: 'trojan.exe',
        fileSize: 1024,
        sha256: 'a'.repeat(64),
        riskScore: 95,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'Trojan.Win32.Generic',
        detectedAt: Date.now(),
        evidenceFactors: ['MZ header match', 'High entropy'],
        quarantined: true
      };

      const res = service.notifySecurityThreat(threat, { source: 'Realtime Monitor' });
      expect(res.inboxInserted).toBe(true);
      expect(res.toastDispatched).toBe(true);

      const notif = service.getNotifications()[0];
      expect(notif.title).toContain('Threat Blocked & Quarantined');
      expect(notif.message).toContain('trojan.exe was classified as Trojan.Win32.Generic');
      expect(notif.severity).toBe('critical');
    });

    it('notifies ransomware incident with forceToast=true', () => {
      const incident: RansomwareIncident = {
        incidentId: 'inc-99',
        detectedAt: Date.now(),
        threatType: 'CANARY_TAMPER',
        reason: 'Decoy canary modified',
        riskScore: 100,
        severity: 'critical',
        engineVerdict: 'BLOCK',
        responsiblePid: 4560,
        processName: 'badware.exe',
        affectedFiles: ['C:\\Documents\\test.docx'],
        backupIds: [],
        rollbackStatus: 'NOT_REQUIRED',
        lifecycleState: 'CLASSIFIED',
        stateHistory: [],
        metrics: {
          modificationsInWindow: 1,
          highEntropyCount: 0,
          renameCount: 0,
          maxEntropyObserved: 0
        }
      };

      const res = service.notifyRansomwareIncident(incident);
      expect(res.inboxInserted).toBe(true);
      expect(res.toastDispatched).toBe(true);

      const notif = service.getNotifications()[0];
      expect(notif.title).toBe('Ransomware Attack Blocked');
      expect(notif.category).toBe('RANSOMWARE_BLOCKED');
      expect(notif.metadata?.incidentId).toBe('inc-99');
    });

    it('notifies process containment outcome', () => {
      const result: ProcessContainmentResult = {
        success: true,
        pid: 3412,
        processName: 'miner.exe',
        action: 'TERMINATED',
        reason: 'High velocity threat detected',
        containedAt: Date.now()
      };

      const res = service.notifyProcessContained(result);
      expect(res.inboxInserted).toBe(true);
      expect(res.toastDispatched).toBe(true);

      const notif = service.getNotifications()[0];
      expect(notif.title).toBe('Malicious Process Terminated');
      expect(notif.category).toBe('PROCESS_CONTAINED');
    });
  });

  describe('Failure Isolation', () => {
    it('isolates custom toast dispatcher errors without throwing to the caller', () => {
      const brokenService = new NotificationService({
        toastDispatcher: () => {
          throw new Error('OS_TOAST_CRASH: Native toast server disconnected');
        }
      });

      const errorHandler = vi.fn();
      brokenService.on('error', errorHandler);

      let res: any;
      expect(() => {
        res = brokenService.notify({ title: 'Test', message: 'Test message', category: 'SYSTEM_HEALTH' });
      }).not.toThrow();

      expect(res?.toastDispatched).toBe(false);
      expect(res?.inboxInserted).toBe(true);
      expect(errorHandler).toHaveBeenCalled();
    });

    it('isolates tray updater errors without breaking notification flow', () => {
      const brokenTrayService = new NotificationService({
        trayUpdater: () => {
          throw new Error('TRAY_HANDLE_INVALID');
        }
      });

      const errorHandler = vi.fn();
      brokenTrayService.on('error', errorHandler);

      expect(() => {
        brokenTrayService.notify({ title: 'Test', message: 'Test message', category: 'SYSTEM_HEALTH' });
      }).not.toThrow();

      expect(errorHandler).toHaveBeenCalled();
      expect(brokenTrayService.getNotifications().length).toBe(1);
    });
  });
});
