import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { QuarantineService } from '../../services/quarantine.service';
import { ExclusionManagerService } from '../../services/exclusion-manager.service';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { MotwAnalyzer } from '../../core/motw-analyzer';

describe('Phase J Integration — E2E Download Protection & MOTW Correlation', () => {
  let tempDir: string;
  let vaultDir: string;
  let configDir: string;
  let downloadsDir: string;
  let quarantine: QuarantineService;
  let exclusionManager: ExclusionManagerService;
  let realtimeMonitor: RealtimeMonitorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-j-integ-'));
    vaultDir = path.join(tempDir, 'quarantine-vault');
    configDir = path.join(tempDir, 'config');
    downloadsDir = path.join(tempDir, 'downloads');

    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(configDir, { recursive: true });
    fs.mkdirSync(downloadsDir, { recursive: true });

    exclusionManager = new ExclusionManagerService({ configDir });
    quarantine = new QuarantineService(vaultDir, exclusionManager);
    realtimeMonitor = new RealtimeMonitorService(
      {
        monitoredPaths: [downloadsDir],
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

  it('detects a phishing-origin download via MOTW, elevates verdict to BLOCK, and auto-quarantines into PPVAULT2', async () => {
    realtimeMonitor.start([downloadsDir]);

    // 1. Simulate browser completing a download of an executable from a phishing domain
    const downloadFilePath = path.join(downloadsDir, 'account-security-update.exe');
    fs.writeFileSync(downloadFilePath, 'MZ_SIMULATED_DOWNLOADED_EXECUTABLE_PAYLOAD');

    // 2. Attach MOTW metadata indicating origin from a typosquatted domain
    const companionPath = `${downloadFilePath}.zone.identifier`;
    const adsContent = MotwAnalyzer.createZoneIdentifierAds({
      zoneId: 3,
      hostUrl: 'https://paypa1-security-verification.com/account-security-update.exe',
      referrerUrl: 'https://phishing-portal.com/login'
    });
    fs.writeFileSync(companionPath, adsContent);

    let threatDetectedEmitted = false;
    realtimeMonitor.on('threatDetected', (threat) => {
      if (threat.filePath === downloadFilePath || threat.fileName === 'account-security-update.exe') {
        threatDetectedEmitted = true;
        expect(threat.verdict).toBe('BLOCK');
        expect(threat.riskScore).toBeGreaterThanOrEqual(85);
        expect(threat.evidenceFactors.some((f: string) => f.includes('Mark-of-the-Web'))).toBe(true);
      }
    });

    // 3. Trigger realtime evaluation
    await realtimeMonitor.evaluateIncomingFile(downloadFilePath);

    // 4. Assert threat was detected, original download was quarantined, and vault contains the item
    expect(threatDetectedEmitted).toBe(true);
    expect(fs.existsSync(downloadFilePath)).toBe(false);
    expect(quarantine.listQuarantine().length).toBe(1);

    const quarantinedItem = quarantine.listQuarantine()[0];
    expect(quarantinedItem.fileName).toBe('account-security-update.exe');
  });

  it('allows a clean download from a trusted domain (ZoneId=3) without alerting or quarantining', async () => {
    realtimeMonitor.start([downloadsDir]);

    // 1. Simulate browser completing a download from a trusted legitimate domain
    const cleanFilePath = path.join(downloadsDir, 'developer-package.msi');
    fs.writeFileSync(cleanFilePath, 'BENIGN_MSI_PACKAGE_CONTENT');

    const companionPath = `${cleanFilePath}.zone.identifier`;
    const adsContent = MotwAnalyzer.createZoneIdentifierAds({
      zoneId: 3,
      hostUrl: 'https://nodejs.org/dist/v20.0.0/node-v20.0.0-x64.msi',
      referrerUrl: 'https://nodejs.org/en/download'
    });
    fs.writeFileSync(companionPath, adsContent);

    let threatDetected = false;
    realtimeMonitor.on('threatDetected', () => {
      threatDetected = true;
    });

    await realtimeMonitor.evaluateIncomingFile(cleanFilePath);

    // 2. Assert clean file remains on disk and no quarantine occurred
    expect(threatDetected).toBe(false);
    expect(fs.existsSync(cleanFilePath)).toBe(true);
    expect(quarantine.listQuarantine().length).toBe(0);
  });
});
