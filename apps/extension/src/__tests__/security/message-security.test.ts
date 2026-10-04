import { describe, it, expect, beforeEach } from 'vitest';
import { validateInboundMessage, MessageType } from '../../shared/messages';
import { MessageRouter } from '../../background/message-router';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { ExtensionStorage } from '../../shared/storage';

describe('Message Security & Schema Validation', () => {
  let router: MessageRouter;

  beforeEach(async () => {
    await ExtensionStorage.clearAllStorage();
    const interceptor = new NavigationInterceptor();
    router = new MessageRouter(interceptor);
  });

  it('rejects malformed and non-object messages', () => {
    expect(validateInboundMessage(null).valid).toBe(false);
    expect(validateInboundMessage('plain-string').valid).toBe(false);
    expect(validateInboundMessage(12345).valid).toBe(false);
    expect(validateInboundMessage({}).valid).toBe(false);
  });

  it('rejects unknown or unauthorized message types', () => {
    const invalidTypeMsg = {
      id: 'msg-1',
      type: 'EXECUTE_ARBITRARY_CODE',
      payload: {},
      timestamp: Date.now()
    };
    const validation = validateInboundMessage(invalidTypeMsg);
    expect(validation.valid).toBe(false);
    expect(validation.error).toContain('Unauthorized or unknown message type');
  });

  it('rejects oversized payloads exceeding 64KB', () => {
    const hugePayload = { data: 'A'.repeat(70000) };
    const hugeMsg = {
      id: 'msg-huge',
      type: MessageType.GET_SETTINGS,
      payload: hugePayload,
      timestamp: Date.now()
    };
    const validation = validateInboundMessage(hugeMsg);
    expect(validation.valid).toBe(false);
    expect(validation.error).toContain('exceeds 64KB');
  });

  it('safely handles valid GET_SETTINGS message', async () => {
    const validMsg = {
      id: 'msg-valid-1',
      type: MessageType.GET_SETTINGS,
      payload: {},
      timestamp: Date.now()
    };

    const res = await router.handleMessage(validMsg, {});
    expect(res.success).toBe(true);
    expect(res.settings).toBeDefined();
    expect(res.settings.enabled).toBe(true);
  });

  it('elevates tab risk when content script reports insecure password form', async () => {
    // 1. Establish benign tab 20
    await ExtensionStorage.setTabState(20, {
      tabId: 20,
      url: 'http://my-insecure-site.com',
      domain: 'my-insecure-site.com',
      verdict: 'ALLOW' as any,
      overallScore: 10,
      severity: 'NONE' as any,
      confidence: 0.9,
      threatCategory: 'BENIGN',
      evidence: [],
      recommendation: {
        action: 'ALLOW' as any,
        frictionLevel: 'NONE' as any,
        suggestedAction: 'None',
        bypassPermitted: true
      },
      timestamp: Date.now(),
      overridden: false
    });

    // 2. Report insecure password form
    const domMsg = {
      id: 'msg-dom-1',
      type: MessageType.REPORT_DOM_SIGNALS,
      payload: {
        hasPasswordInput: true,
        isFormInsecure: true,
        formActionUrl: 'http://my-insecure-site.com/auth.php'
      },
      timestamp: Date.now()
    };

    const res = await router.handleMessage(domMsg, { tab: { id: 20 } as any });
    expect(res.success).toBe(true);
    expect(res.actionRequired).toBe('SHOW_SHADOW_BANNER');

    // 3. Confirm elevated state
    const updated = await ExtensionStorage.getTabState(20);
    expect(updated?.verdict).toBe('DANGEROUS');
    expect(updated?.overallScore).toBeGreaterThanOrEqual(85);
  });

  it('respects showShadowDomBanners=false when reporting DOM signals (DEFECT-EXT-01)', async () => {
    await ExtensionStorage.saveSettings({
      enabled: true,
      readingGrade: 6,
      allowlistDomains: [],
      showShadowDomBanners: false,
      frictionGateDurationSec: 5
    });

    await ExtensionStorage.setTabState(21, {
      tabId: 21,
      url: 'http://insecure-login.example.com',
      domain: 'insecure-login.example.com',
      verdict: 'ALLOW' as any,
      overallScore: 10,
      severity: 'NONE' as any,
      confidence: 0.9,
      threatCategory: 'BENIGN',
      evidence: [],
      recommendation: {
        action: 'ALLOW' as any,
        frictionLevel: 'NONE' as any,
        suggestedAction: 'None',
        bypassPermitted: true
      },
      timestamp: Date.now(),
      overridden: false
    });

    const domMsg = {
      id: 'msg-dom-2',
      type: MessageType.REPORT_DOM_SIGNALS,
      payload: {
        hasPasswordInput: true,
        isFormInsecure: true,
        formActionUrl: 'http://insecure-login.example.com/login'
      },
      timestamp: Date.now()
    };

    const res = await router.handleMessage(domMsg, { tab: { id: 21 } as any });
    expect(res.success).toBe(true);
    expect(res.actionRequired).toBeUndefined();
    expect(res.updatedState?.verdict).toBe('DANGEROUS');
  });
});
