import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PreThreatWarningService } from '../../services/pre-threat-warning.service';
import { PreThreatWarningPayload } from '../../types/mobile.types';

describe('PreThreatWarningService (Phase T7 Mobile)', () => {
  let service: PreThreatWarningService;

  beforeEach(() => {
    vi.restoreAllMocks();
    delete (window as any).AndroidSecurityBridge;
    service = PreThreatWarningService.getInstance();
    service.reset();
  });

  it('synthesizes URL warning with CONFIRMED_MALWARE for dangerous schemes', async () => {
    const report = {
      normalizedUrl: 'javascript:alert(1)',
      scheme: 'javascript',
      riskScore: 95,
      verdict: 'DANGEROUS',
      threatType: 'DANGEROUS_SCHEME',
      indicators: ['Executable script scheme']
    };

    const warning = await service.synthesizeWarning('URL', 'javascript:alert(1)', report);
    expect(warning).not.toBeNull();
    expect(warning!.targetType).toBe('URL');
    expect(warning!.confidenceLevel).toBe('CONFIRMED_MALWARE');
    expect(warning!.verdict).toBe('DANGEROUS');
    expect(warning!.recommendedAction).toBe('GO_BACK');
    expect(warning!.requiresFrictionGate).toBe(true);
    expect(warning!.frictionGateSeconds).toBe(5);
    expect(warning!.whatDetected).toContain('Dangerous executable URI scheme');
    expect(warning!.potentialConsequences).toContain('unauthorized script code');
  });

  it('synthesizes URL warning with STRONG_SUSPICION for homoglyph lookalikes', async () => {
    const report = {
      normalizedUrl: 'https://xn--pypal-4ve.com/login',
      domain: 'xn--pypal-4ve.com',
      scheme: 'https',
      riskScore: 80,
      verdict: 'DANGEROUS',
      threatType: 'HOMOGLYPH_ATTACK',
      indicators: ['Cyrillic homoglyph spoofing PayPal']
    };

    const warning = await service.synthesizeWarning('URL', 'https://xn--pypal-4ve.com/login', report);
    expect(warning).not.toBeNull();
    expect(warning!.confidenceLevel).toBe('STRONG_SUSPICION');
    expect(warning!.whatDetected).toContain('lookalike domain');
    expect(warning!.potentialConsequences).toContain('steal your account passwords');
  });

  it('synthesizes File warning with CONFIRMED_MALWARE for EICAR test signature', async () => {
    const report = {
      score: 100,
      verdict: 'DANGEROUS',
      fileIdentity: { fileName: 'eicar.com' },
      evidence: [{ code: 'EICAR_TEST_PAYLOAD', severity: 'CRITICAL', description: 'Antivirus test pattern' }]
    };

    const warning = await service.synthesizeWarning('FILE', 'eicar.com', report);
    expect(warning).not.toBeNull();
    expect(warning!.targetType).toBe('FILE');
    expect(warning!.confidenceLevel).toBe('CONFIRMED_MALWARE');
    expect(warning!.recommendedAction).toBe('DELETE_DOWNLOAD');
    expect(warning!.whatDetected).toContain('EICAR standard antivirus test pattern');
    expect(warning!.supportedChoices).toContain('QUARANTINE');
  });

  it('synthesizes File warning for archive zip bombs with storage exhaustion consequences', async () => {
    const report = {
      score: 95,
      verdict: 'DANGEROUS',
      fileIdentity: { fileName: 'bomb.zip' },
      evidence: [{ code: 'ARCHIVE_ZIP_BOMB', severity: 'CRITICAL', description: 'Compression bomb' }]
    };

    const warning = await service.synthesizeWarning('DOWNLOAD', 'bomb.zip', report);
    expect(warning).not.toBeNull();
    expect(warning!.confidenceLevel).toBe('CONFIRMED_MALWARE');
    expect(warning!.potentialConsequences).toContain('exhaust system storage');
  });

  it('synthesizes Package warning for embedded payloads and dangerous permissions', async () => {
    const report = {
      score: 85,
      verdict: 'DANGEROUS',
      appLabel: 'TrojanFlash',
      isSideloaded: true,
      evidence: [
        { code: 'APK_SUSPICIOUS_EMBEDDED_PAYLOAD', severity: 'HIGH', description: 'Dynamic dropper' },
        { code: 'DANGEROUS_PERMISSIONS_CLUSTER', severity: 'HIGH', description: 'SMS + Accessibility' }
      ]
    };

    const warning = await service.synthesizeWarning('APP_PACKAGE', 'com.trojan.flash', report);
    expect(warning).not.toBeNull();
    expect(warning!.targetType).toBe('APP_PACKAGE');
    expect(warning!.confidenceLevel).toBe('CONFIRMED_MALWARE');
    expect(warning!.recommendedAction).toBe('CANCEL_INSTALL');
    expect(warning!.whatDetected).toContain('embedded dynamic droppers');
    expect(warning!.potentialConsequences).toContain('unauthorized background processes');
  });

  it('handles deduplication and rate limiting across warnings for identical targets', () => {
    const payload: PreThreatWarningPayload = {
      warningId: 'w-1',
      targetType: 'URL',
      targetIdentifier: 'https://bad.com',
      riskScore: 90,
      verdict: 'DANGEROUS',
      confidenceLevel: 'CONFIRMED_MALWARE',
      whatDetected: 'Phishing',
      potentialConsequences: 'Theft',
      recommendedAction: 'GO_BACK',
      supportedChoices: ['GO_BACK', 'CONTINUE_AT_OWN_RISK'],
      evidenceDetails: [],
      requiresFrictionGate: true,
      frictionGateSeconds: 5,
      timestamp: Date.now()
    };

    const first = service.setActiveWarning(payload);
    expect(first).toBe(true);

    // Immediate second invocation with same identifier is throttled
    const second = service.setActiveWarning({ ...payload, warningId: 'w-2' });
    expect(second).toBe(false);
  });

  it('subscribes to warning events and notifies listeners', () => {
    const listener = vi.fn();
    const unsubscribe = service.subscribeToWarnings(listener);

    const payload: PreThreatWarningPayload = {
      warningId: 'w-sub',
      targetType: 'URL',
      targetIdentifier: 'https://test-sub.com',
      riskScore: 80,
      verdict: 'DANGEROUS',
      confidenceLevel: 'STRONG_SUSPICION',
      whatDetected: 'Suspicious link',
      potentialConsequences: 'Phishing',
      recommendedAction: 'GO_BACK',
      supportedChoices: ['GO_BACK'],
      evidenceDetails: [],
      requiresFrictionGate: true,
      frictionGateSeconds: 5,
      timestamp: Date.now()
    };

    service.setActiveWarning(payload);
    expect(listener).toHaveBeenCalledWith(payload);

    unsubscribe();
    service.setActiveWarning({ ...payload, targetIdentifier: 'https://another.com' });
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('records user decisions and manages bounded decision history', async () => {
    const dec1 = {
      warningId: 'w-1',
      targetIdentifier: 'https://bad.com',
      selectedAction: 'GO_BACK' as const,
      timestamp: Date.now(),
      bypassedWithFrictionGate: false
    };

    const dec2 = {
      warningId: 'w-2',
      targetIdentifier: 'malware.apk',
      selectedAction: 'CANCEL_INSTALL' as const,
      timestamp: Date.now(),
      bypassedWithFrictionGate: false
    };

    await service.recordDecision(dec1);
    await service.recordDecision(dec2);

    const history = await service.getDecisionHistory();
    expect(history.length).toBe(2);
    expect(history[0].warningId).toBe('w-1');
    expect(history[1].warningId).toBe('w-2');
  });

  it('utilizes window.AndroidSecurityBridge when available in native WebView', async () => {
    const mockBridge = {
      synthesizePreThreatWarning: vi.fn().mockReturnValue(JSON.stringify({
        warningId: 'native-w',
        targetType: 'URL',
        targetIdentifier: 'https://native.com',
        riskScore: 92,
        verdict: 'DANGEROUS',
        confidenceLevel: 'CONFIRMED_MALWARE',
        whatDetected: 'Native bridge detected dangerous scheme',
        potentialConsequences: 'Native bridge warning',
        recommendedAction: 'GO_BACK',
        supportedChoices: ['GO_BACK'],
        evidenceDetails: [],
        requiresFrictionGate: true,
        frictionGateSeconds: 5,
        timestamp: Date.now()
      })),
      showPreThreatWarningNotification: vi.fn().mockReturnValue(true),
      recordPreThreatWarningDecision: vi.fn().mockReturnValue(true),
      getPreThreatWarningDecisionHistory: vi.fn().mockReturnValue(JSON.stringify([{
        warningId: 'native-w',
        targetIdentifier: 'https://native.com',
        selectedAction: 'GO_BACK',
        timestamp: 12345,
        bypassedWithFrictionGate: false
      }])),
      triggerWarningHaptics: vi.fn()
    };

    (window as any).AndroidSecurityBridge = mockBridge;
    expect(service.isNativeBridgeAvailable()).toBe(true);

    const warning = await service.synthesizeWarning('URL', 'https://native.com', { score: 92 });
    expect(mockBridge.synthesizePreThreatWarning).toHaveBeenCalled();
    expect(warning!.warningId).toBe('native-w');

    service.setActiveWarning(warning!);
    expect(mockBridge.showPreThreatWarningNotification).toHaveBeenCalled();
    expect(mockBridge.triggerWarningHaptics).toHaveBeenCalledWith('DANGEROUS');

    await service.recordDecision({
      warningId: 'native-w',
      targetIdentifier: 'https://native.com',
      selectedAction: 'GO_BACK',
      timestamp: Date.now(),
      bypassedWithFrictionGate: false
    });
    expect(mockBridge.recordPreThreatWarningDecision).toHaveBeenCalled();

    const history = await service.getDecisionHistory();
    expect(mockBridge.getPreThreatWarningDecisionHistory).toHaveBeenCalled();
    expect(history[0].warningId).toBe('native-w');
  });
});
