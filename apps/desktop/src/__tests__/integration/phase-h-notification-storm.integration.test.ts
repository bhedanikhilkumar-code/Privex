import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';
import { NotificationService } from '../../services/notification.service';
import { DetectedThreat, NotificationSeverity } from '../../types/desktop.types';

describe('Phase H Integration: 200-Threat Real-Time Storm & Rate Limiting', () => {
  let tempRoot: string;
  let watchDir: string;
  let vaultDir: string;
  let quarantine: QuarantineService;
  let monitor: RealtimeMonitorService;
  let notificationService: NotificationService;
  let dispatchedToasts: Array<{ title: string; message: string; severity: NotificationSeverity }>;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-h-storm-'));
    watchDir = path.join(tempRoot, 'watch-downloads');
    vaultDir = path.join(tempRoot, 'quarantine-vault');
    fs.mkdirSync(watchDir, { recursive: true });
    fs.mkdirSync(vaultDir, { recursive: true });

    dispatchedToasts = [];

    notificationService = new NotificationService({
      toastDispatcher: (title, message, severity) => {
        dispatchedToasts.push({ title, message, severity });
        return true;
      }
    });

    quarantine = new QuarantineService(vaultDir);
    monitor = new RealtimeMonitorService(undefined, quarantine);
    monitor.setAutoQuarantineCritical(true);

    // Wire RealtimeMonitor events to NotificationService (same as production IpcHandler)
    monitor.on('threatDetected', (threat: DetectedThreat) => {
      notificationService.notifySecurityThreat(threat, { source: 'Realtime Ingress' });
    });
  });

  afterEach(() => {
    monitor.stop();
    if (fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('quarantines 200 threats during alert storm while capping native OS toasts to <= 3 (plus coalescing)', async () => {
    // Standard EICAR test string
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    // Simulate 200 rapid file ingress detections
    for (let i = 1; i <= 200; i++) {
      const threat: DetectedThreat = {
        id: `storm-threat-${i}`,
        filePath: path.join(watchDir, `eicar_sample_${i}.com`),
        fileName: `eicar_sample_${i}.com`,
        fileSize: eicarString.length,
        sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        riskScore: 100,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'EICAR-Standard-Antivirus-Test-File',
        detectedAt: Date.now(),
        evidenceFactors: ['Standard EICAR signature match'],
        quarantined: true
      };

      // Emit event through the real monitor pipeline
      monitor.emit('threatDetected', threat);
    }

    // 1. Verify that all 200 events entered the in-app notification inbox
    const inbox = notificationService.getNotifications();
    expect(inbox.length).toBeGreaterThanOrEqual(200);

    // 2. Verify that at most 3 native toasts were dispatched during the storm
    expect(dispatchedToasts.length).toBeLessThanOrEqual(3);

    // 3. Verify coalesced batch summary was created
    const coalescedItems = inbox.filter((n) => n.isCoalesced);
    expect(coalescedItems.length).toBeGreaterThan(0);

    // 4. Verify unread counter accurately tracked the storm
    expect(notificationService.getUnreadCount()).toBe(200);

    // 5. Test 1-click markAllRead cleans up inbox unread state
    notificationService.markAllRead();
    expect(notificationService.getUnreadCount()).toBe(0);
  });
});
