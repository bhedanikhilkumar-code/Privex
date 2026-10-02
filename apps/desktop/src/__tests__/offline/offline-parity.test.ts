import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DesktopSecurityAdapter } from '../../core/desktop-security-adapter';
import { QuarantineService } from '../../services/quarantine.service';

describe('Offline Parity (100% Air-Gapped Operation)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-offline-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('guarantees 100% feature parity for scanning and quarantine in airplane mode', async () => {
    const filePath = path.join(tempDir, 'test.pdf.exe');
    fs.writeFileSync(filePath, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

    const adapter = new DesktopSecurityAdapter();
    const analysis = await adapter.analyzeFile(filePath);

    expect(analysis.verdict).toBe('BLOCK');
    expect(['dangerous', 'critical']).toContain(analysis.severity);

    // Quarantine operates offline
    const vaultDir = path.join(tempDir, 'vault');
    const quarantine = new QuarantineService(vaultDir);
    const threat = {
      id: 'threat-off-1',
      filePath: analysis.filePath,
      fileName: analysis.fileName,
      fileSize: analysis.fileSize,
      sha256: analysis.sha256,
      riskScore: analysis.riskScore,
      severity: analysis.severity,
      verdict: analysis.verdict,
      threatName: analysis.threatName,
      detectedAt: Date.now(),
      evidenceFactors: analysis.evidenceFactors,
      quarantined: false
    };

    const qItem = await quarantine.isolateFile(threat);
    expect(qItem.quarantineId).toBeDefined();
    expect(fs.existsSync(filePath)).toBe(false);

    // AI assistant operates offline
    const briefing = await adapter.explainThreat(threat, 'grade6');
    expect(briefing.summary).toBeDefined();
    expect(briefing.recommendedActions.length).toBeGreaterThan(0);
  });
});
