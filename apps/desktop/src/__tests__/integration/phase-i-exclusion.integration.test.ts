import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { QuarantineService } from '../../services/quarantine.service';
import { ExclusionManagerService } from '../../services/exclusion-manager.service';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('Phase I Integration — E2E False-Positive Workflow & Realtime Integration', () => {
  let tempDir: string;
  let vaultDir: string;
  let configDir: string;
  let testFileDir: string;
  let quarantine: QuarantineService;
  let exclusionManager: ExclusionManagerService;
  let realtimeMonitor: RealtimeMonitorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-i-integ-'));
    vaultDir = path.join(tempDir, 'quarantine-vault');
    configDir = path.join(tempDir, 'config');
    testFileDir = path.join(tempDir, 'watch-folder');

    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(configDir, { recursive: true });
    fs.mkdirSync(testFileDir, { recursive: true });

    exclusionManager = new ExclusionManagerService({ configDir });
    quarantine = new QuarantineService(vaultDir, exclusionManager);
    realtimeMonitor = new RealtimeMonitorService(
      {
        monitoredPaths: [testFileDir],
        autoQuarantineCritical: true,
        stabilityCheckMs: 0
      },
      quarantine,
      exclusionManager
    );
  });

  afterEach(() => {
    try {
      realtimeMonitor.stop();
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('completes the entire False-Positive cycle: Detection -> Quarantine -> Restore & Trust -> Clean Rescan', async () => {
    // 1. Create a false-positive file
    const samplePath = path.join(testFileDir, 'internal-tool.exe');
    const content = Buffer.from('MZ_SIMULATED_INTERNAL_TOOL_HEADER_WITH_SUSPICIOUS_STRING');
    fs.writeFileSync(samplePath, content);
    const originalSha256 = crypto.createHash('sha256').update(content).digest('hex');

    const threat: DetectedThreat = {
      id: 'threat-fp-1',
      filePath: samplePath,
      fileName: 'internal-tool.exe',
      fileSize: content.length,
      sha256: originalSha256,
      riskScore: 92,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'Heuristic.SuspiciousTool.Gen',
      detectedAt: Date.now(),
      evidenceFactors: ['Simulated critical signature'],
      quarantined: false
    };

    // 2. File is quarantined
    const qItem = await quarantine.isolateFile(threat);
    expect(fs.existsSync(samplePath)).toBe(false);
    expect(quarantine.listQuarantine().length).toBe(1);

    // 3. User triggers "Restore & Trust SHA-256"
    const restoredPath = await quarantine.restoreItem(qItem.quarantineId, {
      trustSha256: true
    });

    expect(fs.existsSync(restoredPath)).toBe(true);
    expect(quarantine.listQuarantine().length).toBe(0);

    // 4. Verify exclusion was registered in ExclusionManagerService
    const check = exclusionManager.checkHash(originalSha256);
    expect(check.isExcluded).toBe(true);
    expect(check.matchedExclusion?.createdBy).toBe('RESTORE_AND_TRUST');

    // 5. Verify RealtimeMonitor allows the restored file without re-quarantining
    realtimeMonitor.start([testFileDir]);
    await realtimeMonitor.evaluateIncomingFile(restoredPath);

    // Should NOT be re-quarantined
    expect(fs.existsSync(restoredPath)).toBe(true);
    expect(quarantine.listQuarantine().length).toBe(0);

    // 6. Test a deceptive threat file with active hash exclusion emits fileExcluded
    const deceptivePath = path.join(testFileDir, 'report.pdf.exe');
    const deceptiveContent = Buffer.from('MZ_SIMULATED_DECEPTIVE_EXECUTABLE_PAYLOAD');
    fs.writeFileSync(deceptivePath, deceptiveContent);
    const deceptiveSha = crypto.createHash('sha256').update(deceptiveContent).digest('hex');

    exclusionManager.addExclusion({
      type: 'HASH',
      value: deceptiveSha,
      reason: 'Pre-approved admin tool',
      metadata: { originalPath: deceptivePath },
      createdBy: 'USER'
    });

    let deceptiveExcludedEmitted = false;
    realtimeMonitor.on('fileExcluded', (ev) => {
      if (ev.sha256 === deceptiveSha) {
        deceptiveExcludedEmitted = true;
      }
    });

    await realtimeMonitor.evaluateIncomingFile(deceptivePath);
    expect(deceptiveExcludedEmitted).toBe(true);
    expect(fs.existsSync(deceptivePath)).toBe(true);
    expect(quarantine.listQuarantine().length).toBe(0);
  });
});
