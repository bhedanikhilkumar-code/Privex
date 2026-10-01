import { describe, it, expect, beforeEach } from 'vitest';
import { DomAnalyzer } from '../../content/dom-analyzer';

describe('DomAnalyzer (Content Script Structural Signal Extractor)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('detects insecure password forms submitting over plaintext HTTP', () => {
    document.body.innerHTML = `
      <form action="http://insecure-auth-server.com/login" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" value="secret123" />
        <button type="submit">Sign In</button>
      </form>
    `;

    const signals = DomAnalyzer.extractSignals(document, window);

    expect(signals.hasPasswordInput).toBe(true);
    expect(signals.isFormInsecure).toBe(true);
    expect(signals.formActionUrl).toContain('http://insecure-auth-server.com/login');
  });

  it('permits secure HTTPS password forms', () => {
    document.body.innerHTML = `
      <form action="https://secure.bank.com/login" method="POST">
        <input type="password" name="pwd" />
      </form>
    `;

    const signals = DomAnalyzer.extractSignals(document, window);

    expect(signals.hasPasswordInput).toBe(true);
    expect(signals.isFormInsecure).toBe(false);
  });

  it('handles benign pages without password inputs', () => {
    document.body.innerHTML = `
      <article>
        <h1>News Article</h1>
        <p>This is a safe content page.</p>
        <form action="https://example.com/search">
          <input type="text" name="q" />
        </form>
      </article>
    `;

    const signals = DomAnalyzer.extractSignals(document, window);

    expect(signals.hasPasswordInput).toBe(false);
    expect(signals.isFormInsecure).toBe(false);
  });

  it('never inspects or persists user keystroke values', () => {
    const input = document.createElement('input');
    input.type = 'password';
    input.value = 'super-sensitive-master-password';
    const form = document.createElement('form');
    form.action = 'https://login.example.com';
    form.appendChild(input);
    document.body.appendChild(form);

    const signals = DomAnalyzer.extractSignals(document, window);

    // Verify signals contain zero credential strings
    const serialized = JSON.stringify(signals);
    expect(serialized).not.toContain('super-sensitive-master-password');
    expect(signals.hasPasswordInput).toBe(true);
  });
});
