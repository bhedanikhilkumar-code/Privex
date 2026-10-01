import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanDomAndReport } from '../../content/content';
import { ShadowBanner } from '../../content/shadow-banner';

describe('Content Script Lifecycle & IPC Dispatch', () => {
  beforeEach(() => {
    ShadowBanner.remove();
    document.body.innerHTML = '';
  });

  it('scans DOM and dispatches message when password input exists', () => {
    document.body.innerHTML = `
      <form action="http://insecure.test/login">
        <input type="password" />
      </form>
    `;

    const sendMsgSpy = vi.fn((_message, callback) => {
      callback({ success: true, actionRequired: 'SHOW_SHADOW_BANNER' });
    });

    (globalThis as any).chrome = {
      runtime: {
        sendMessage: sendMsgSpy
      }
    };

    scanDomAndReport();

    expect(sendMsgSpy).toHaveBeenCalled();
    const host = document.getElementById('private-protection-shield-host');
    expect(host).not.toBeNull();
  });

  it('does not dispatch messages on benign pages without passwords or iframes', () => {
    document.body.innerHTML = `
      <div>Just a normal text paragraph</div>
    `;

    const sendMsgSpy = vi.fn();
    (globalThis as any).chrome = {
      runtime: {
        sendMessage: sendMsgSpy
      }
    };

    scanDomAndReport();
    expect(sendMsgSpy).not.toHaveBeenCalled();
  });
});
