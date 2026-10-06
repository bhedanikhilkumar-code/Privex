import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { FileAnalyzer } from '../../core/file-analyzer';
import { QuarantineService } from '../../services/quarantine.service';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { NetworkMonitorService, NetworkCommandRunner } from '../../services/network-monitor.service';

class MockNetworkRunner implements NetworkCommandRunner {
  public async exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    if (command === 'netstat' && args.includes('TCP')) {
      return {
        stdout: [
          '  Proto  Local Address          Foreign Address        State           PID',
          '  TCP    192.168.1.50:51234     198.51.100.23:4444     ESTABLISHED     7777',
          '  TCP    127.0.0.1:3000         0.0.0.0:0              LISTENING       1010'
        ].join('\r\n'),
        stderr: ''
      };
    }
    if (command === 'netstat' && args.includes('UDP')) {
      return { stdout: '', stderr: '' };
    }
    if (command === 'netsh') {
      return {
        stdout: 'Domain Profile Settings:\r\nState ON\r\nPrivate Profile Settings:\r\nState ON\r\nPublic Profile Settings:\r\nState ON',
        stderr: ''
      };
    }
    return { stdout: '', stderr: '' };
  }
}

describe('Phase K E2E Integration Suite (Email Threat & Network Posture Pipeline)', () => {
  let tempDir: string;
  let vaultDir: string;
  let quarantine: QuarantineService;
  let realtimeMonitor: RealtimeMonitorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-k-integ-'));
    vaultDir = path.join(tempDir, 'quarantine-vault');
    fs.mkdirSync(vaultDir, { recursive: true });

    quarantine = new QuarantineService(vaultDir);
    realtimeMonitor = new RealtimeMonitorService(
      {
        monitoredPaths: [tempDir],
        autoQuarantineCritical: true,
        stabilityCheckMs: 0
      },
      quarantine
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

  it('INT-K-01: Ingress .eml with Base64 EICAR attachment is detected by RealtimeMonitor and auto-quarantined', async () => {
    realtimeMonitor.start([tempDir]);

    const eicarStr = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarBase64 = Buffer.from(eicarStr).toString('base64');

    const boundary = '----=_Part_Integ_123';
    const maliciousEmail = [
      'From: Security Alert <service@paypal.com>',
      'Reply-To: attacker@phishing-drop.xyz',
      'Subject: Critical Account Update Required',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      'Authentication-Results: mx.example.com; spf=fail; dmarc=fail',
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Please open the attached security report immediately.',
      '',
      `--${boundary}`,
      'Content-Type: application/octet-stream; name="eicar-security-scan.com"',
      'Content-Disposition: attachment; filename="eicar-security-scan.com"',
      'Content-Transfer-Encoding: base64',
      '',
      eicarBase64,
      '',
      `--${boundary}--`
    ].join('\r\n');

    const emailFilePath = path.join(tempDir, 'incoming-threat.eml');
    fs.writeFileSync(emailFilePath, maliciousEmail);

    let threatEventEmitted = false;
    realtimeMonitor.on('threatDetected', (threat) => {
      if (threat.filePath === emailFilePath || threat.fileName === 'incoming-threat.eml') {
        threatEventEmitted = true;
        expect(threat.verdict).toBe('BLOCK');
        expect(threat.riskScore).toBeGreaterThanOrEqual(85);
        expect(threat.evidenceFactors.some((f: string) => f.includes('attachment') || f.includes('EICAR'))).toBe(true);
      }
    });

    await realtimeMonitor.evaluateIncomingFile(emailFilePath);

    expect(threatEventEmitted).toBe(true);
    expect(fs.existsSync(emailFilePath)).toBe(false); // Quarantined and removed from disk
    expect(quarantine.listQuarantine().length).toBe(1);

    const item = quarantine.listQuarantine()[0];
    expect(item.fileName).toBe('incoming-threat.eml');
    expect(item.riskScore).toBeGreaterThanOrEqual(85);
  });

  it('INT-K-02: Clean .eml file is evaluated with ALLOW verdict and left intact on disk', async () => {
    const cleanEmail = [
      'From: notifications@github.com',
      'To: dev@example.com',
      'Subject: Clean Notification',
      'Content-Type: text/plain; charset=utf-8',
      'Authentication-Results: mx.example.com; spf=pass; dmarc=pass; dkim=pass',
      '',
      'Build succeeded for commit a1b2c3d.'
    ].join('\r\n');

    const cleanEmailPath = path.join(tempDir, 'clean-notification.eml');
    fs.writeFileSync(cleanEmailPath, cleanEmail);

    const result = await FileAnalyzer.analyzeFile(cleanEmailPath);
    expect(result.verdict).toBe('ALLOW');
    expect(result.riskScore).toBe(0);
    expect(fs.existsSync(cleanEmailPath)).toBe(true);
    expect(quarantine.listQuarantine().length).toBe(0);
  });

  it('INT-K-03: Network monitor correlates active socket to ThreatIntel C2 and flags malicious posture', async () => {
    const mockRunner = new MockNetworkRunner();
    const networkMonitor = new NetworkMonitorService(mockRunner);

    const posture = await networkMonitor.getNetworkPosture();
    expect(posture.hasExternalConnectivity).toBe(true);
    expect(posture.firewallStatus.isFirewallActive).toBe(true);
    expect(posture.maliciousSocketsCount).toBe(1);
    expect(posture.connections.some((c) => c.isRemoteMalicious && c.remotePort === 4444)).toBe(true);
  });
});
