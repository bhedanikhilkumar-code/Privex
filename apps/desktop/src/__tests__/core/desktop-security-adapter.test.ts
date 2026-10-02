import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DesktopSecurityAdapter } from '../../core/desktop-security-adapter';
import { DetectedThreat } from '../../types/desktop.types';

describe('DesktopSecurityAdapter (Core & ML Integration)', () => {
  let adapter: DesktopSecurityAdapter;
  let tempDir: string;

  beforeEach(() => {
    adapter = new DesktopSecurityAdapter();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-adapter-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('analyzes local files and returns structured detection results', async () => {
    const testFile = path.join(tempDir, 'readme.txt');
    fs.writeFileSync(testFile, 'Clean documentation file', 'utf8');

    const result = await adapter.analyzeFile(testFile);
    expect(result.fileName).toBe('readme.txt');
    expect(result.verdict).toBe('ALLOW');
    expect(result.severity).toBe('safe');
  });

  it('scans deceptive phishing URLs through core and ML classifier', async () => {
    const result = await adapter.scanUrl('http://192.168.1.1/paypal-login-verify/secure');
    expect(result.riskScore).toBeGreaterThanOrEqual(40);
    expect(result.verdict).toBeDefined();
    expect(result.explanation).toBeDefined();
    expect(result.explanation.headline).toBeDefined();
  });

  it('scans extortion text messages through core detection engine', async () => {
    const result = await adapter.scanText(
      'URGENT: Your account has been compromised. Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours!'
    );
    expect(result.riskScore).toBeGreaterThan(40);
    expect(result.explanation).toBeDefined();
  });

  it('synthesizes plain-language threat explanations via AISecurityAssistant', async () => {
    const threat: DetectedThreat = {
      id: 'threat-101',
      filePath: 'C:\\Users\\Alice\\Downloads\\invoice.pdf.exe',
      fileName: 'invoice.pdf.exe',
      fileSize: 40960,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      riskScore: 85,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'DECEPTIVE_DOUBLE_EXTENSION',
      detectedAt: Date.now(),
      evidenceFactors: [
        "Double extension deception: disguised as '.pdf', actual '.exe'",
        'High Shannon entropy indicates packed code'
      ],
      quarantined: false
    };

    const explanationGrade6 = await adapter.explainThreat(threat, 'grade6');
    expect(explanationGrade6.threatTitle).toBe('DECEPTIVE_DOUBLE_EXTENSION');
    expect(explanationGrade6.summary).toBeDefined();
    expect(explanationGrade6.explanation).toBeDefined();
    expect(explanationGrade6.recommendedActions.length).toBeGreaterThan(0);
    expect(explanationGrade6.cognitiveLevel).toBe('grade6');

    const explanationGrade8 = await adapter.explainThreat(threat, 'grade8');
    expect(explanationGrade8.cognitiveLevel).toBe('grade8');
  });

  it('reports verified core and ML engine versions for transparency', () => {
    const versions = adapter.getEngineVersions();
    expect(versions.coreVersion).toBe('1.0.0-verified');
    expect(versions.mlVersion).toBe('1.0.0-verified');
    expect(versions.threatDatabaseVersion).toContain('offline-seed');
  });
});
