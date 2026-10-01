import { describe, it, expect, beforeEach } from 'vitest';
import { ShadowBanner } from '../../content/shadow-banner';

describe('ShadowBanner (Closed Mode Shadow DOM Warning)', () => {
  beforeEach(() => {
    ShadowBanner.remove();
    document.body.innerHTML = '';
  });

  it('injects closed-mode shadow DOM banner into page when warned', () => {
    ShadowBanner.showInsecurePasswordWarning('http://insecure-login.com');

    const host = document.getElementById('private-protection-shield-host');
    expect(host).not.toBeNull();

    // Verify host page scripts cannot inspect inner elements via normal DOM queries
    expect(document.querySelector('.banner')).toBeNull();
    expect(document.getElementById('dismiss-btn')).toBeNull();

    // Verify host element cannot be duplicated
    ShadowBanner.showInsecurePasswordWarning('http://another-url.com');
    expect(document.querySelectorAll('#private-protection-shield-host').length).toBe(1);
  });

  it('removes shadow banner when remove() is called', () => {
    ShadowBanner.showInsecurePasswordWarning('http://insecure.com');
    expect(document.getElementById('private-protection-shield-host')).not.toBeNull();

    ShadowBanner.remove();
    expect(document.getElementById('private-protection-shield-host')).toBeNull();
  });
});
