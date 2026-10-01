import React from 'react';

export const PrivacyView: React.FC = () => {
  return (
    <section aria-labelledby="privacy-heading" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 id="privacy-heading" style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          Privacy Architecture & Cryptographic Boundaries
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Traditional security services upload your visited URLs, private SMS messages, and emails to remote cloud servers.
          PRIVATE PROTECTION is architected on a zero-cloud, client-side execution model.
        </p>
      </div>

      {/* Main Privacy Guarantee Banner */}
      <div
        style={{
          padding: '1.25rem',
          backgroundColor: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '0.75rem',
          marginBottom: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '1.25rem' }}>🔒</span>
          <strong style={{ fontSize: '1rem', color: '#34d399' }}>
            Your scan is processed locally in your browser.
          </strong>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          All URL parsers, homograph decoders, Shannon entropy calculations, Bloom filters, and intent classification
          engines run in volatile RAM on this device. No network socket is opened to process your input.
        </p>
      </div>

      {/* Data Handling Classification Table */}
      <div
        style={{
          backgroundColor: 'var(--bg-card)',
          borderRadius: '0.75rem',
          border: '1px solid var(--border-color)',
          overflow: 'hidden',
          marginBottom: '1.5rem'
        }}
      >
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
          Data Handling Principles Matrix
        </div>

        <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <strong style={{ color: '#f87171', fontSize: '0.9rem' }}>
              Tier 1: Scanned Content (URLs, Message Texts, Snippets)
            </strong>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              • <strong>Transmission:</strong> NEVER transmitted off this device. Zero HTTP requests.<br />
              • <strong>Storage:</strong> NEVER persisted to disk or indexed databases. Zero retention.<br />
              • <strong>Lifecycle:</strong> Exists strictly in volatile browser RAM and is discarded immediately after scan display.
            </p>
          </div>

          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
            <strong style={{ color: '#60a5fa', fontSize: '0.9rem' }}>
              Tier 2: Client Settings (Reading Grade, Worker Preference)
            </strong>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              • <strong>Transmission:</strong> Never transmitted.<br />
              • <strong>Storage:</strong> Saved strictly in local browser storage on this device.<br />
              • <strong>Purge:</strong> Can be crypto-shredded and cleared instantly via the Settings tab.
            </p>
          </div>

          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
            <strong style={{ color: '#34d399', fontSize: '0.9rem' }}>
              Network & Telemetry Isolation
            </strong>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              • <strong>Content Security Policy:</strong> Enforces <code style={{ color: '#93c5fd' }}>connect-src &apos;self&apos;</code> to prevent unauthorized background exfiltration.<br />
              • <strong>Air-Gapped Parity:</strong> Fully operational with Wi-Fi, Ethernet, and cellular data turned off.
            </p>
          </div>
        </div>
      </div>

      {/* Verification Instructions */}
      <div
        style={{
          padding: '1rem',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-color)',
          borderRadius: '0.5rem',
          fontSize: '0.8rem',
          color: 'var(--text-muted)'
        }}
      >
        <strong style={{ color: '#ffffff', display: 'block', marginBottom: '0.35rem' }}>
          How to Independently Verify Zero Network Transmission:
        </strong>
        <ol style={{ paddingLeft: '1.25rem', lineHeight: 1.6 }}>
          <li>Open your browser Developer Tools (<kbd>F12</kbd> or <kbd>Ctrl+Shift+I</kbd>).</li>
          <li>Navigate to the <strong>Network</strong> tab.</li>
          <li>Paste any URL or sensitive message in the scanner and click <strong>Scan</strong>.</li>
          <li>Observe that <strong>zero outbound HTTP requests</strong> occur during detection.</li>
        </ol>
      </div>
    </section>
  );
};
