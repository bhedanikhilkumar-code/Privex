import React from 'react';

export const PrivacyView: React.FC = () => {
  return (
    <section aria-labelledby="privacy-heading" style={{ maxWidth: '980px', margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <span
            style={{
              padding: '0.2rem 0.6rem',
              backgroundColor: 'var(--color-brand)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            ARCHITECTURE SPECIFICATION
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            ZERO-KNOWLEDGE • ZERO-CLOUD • RAM-ONLY
          </span>
        </div>

        <h2
          id="privacy-heading"
          className="font-headline-lg"
          style={{
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: 'var(--text-primary)'
          }}
        >
          Privacy Architecture &amp; Cryptographic Boundaries
        </h2>
        <p className="font-body-md" style={{ color: 'var(--text-muted)', maxWidth: '750px', lineHeight: 1.5, margin: 0 }}>
          Traditional security services upload your visited URLs, private SMS messages, and emails to remote cloud servers.
          PRIVEX is architected on a zero-cloud, client-side execution model.
        </p>
      </div>

      {/* Main Privacy Guarantee Banner (Matches How It Works.png) */}
      <div
        className="cyber-panel"
        style={{
          padding: '1.5rem',
          backgroundColor: 'var(--color-accent)',
          marginBottom: '2rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.65rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <span style={{ fontSize: '1.5rem' }}>🔒</span>
          <strong style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', color: '#050608' }}>
            Your scan is processed locally in your browser.
          </strong>
        </div>
        <p style={{ fontSize: '0.9rem', color: '#050608', lineHeight: 1.6, margin: 0 }}>
          All URL parsers, homograph decoders, Shannon entropy calculations, Bloom filters, and intent classification
          engines run in volatile device memory on this endpoint. No network socket is opened to process your input.
        </p>
      </div>

      {/* Authority Comparison (From How It Works.png) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1.25rem',
          marginBottom: '2rem'
        }}
      >
        <div
          className="cyber-panel"
          style={{
            backgroundColor: 'var(--bg-card)',
            padding: '1.5rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
            SECURITY DECISION MAKER
          </div>
          <h3 className="font-headline-sm" style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
            Core Detection Engine
          </h3>
          <p className="font-body-sm" style={{ color: 'var(--text-muted)', margin: 0 }}>
            <strong>100% Authority.</strong> Deterministic rule evaluation, IP host detection, Shannon entropy, and Bloom filters establish the final risk verdict and action recommendations.
          </p>
        </div>

        <div
          className="cyber-panel"
          style={{
            backgroundColor: 'var(--bg-card)',
            padding: '1.5rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
            EXPLANATION SYNTHESIZER
          </div>
          <h3 className="font-headline-sm" style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
            AI Security Assistant
          </h3>
          <p className="font-body-sm" style={{ color: 'var(--text-muted)', margin: 0 }}>
            <strong>0% Decision Authority.</strong> Read-only synthesis layer. Translates structured deterministic evidence tokens into plain-language Grade 6 explanations. Cannot downgrade verdicts.
          </p>
        </div>
      </div>

      {/* Data Handling Classification Table */}
      <div
        className="cyber-panel"
        style={{
          backgroundColor: 'var(--bg-card)',
          overflow: 'hidden',
          marginBottom: '2rem'
        }}
      >
        <div style={{ padding: '1rem 1.5rem', backgroundColor: 'var(--surface-container-lowest, var(--bg-secondary))', borderBottom: '2px solid var(--border-dark)', fontWeight: 800, fontFamily: 'var(--font-mono)', fontSize: '0.85rem', textTransform: 'uppercase', color: 'var(--text-primary)' }}>
          Data Handling Principles Matrix
        </div>

        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <strong style={{ color: 'var(--color-danger)', fontSize: '0.95rem', fontFamily: 'var(--font-mono)' }}>
              Tier 1: Scanned Content (URLs, Message Texts, Snippets)
            </strong>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.35rem', lineHeight: 1.55 }}>
              • <strong>Transmission:</strong> NEVER transmitted off this device. Zero HTTP requests.<br />
              • <strong>Storage:</strong> NEVER persisted to disk or indexed databases. Zero retention.<br />
              • <strong>Lifecycle:</strong> Exists strictly in Volatile RAM and is discarded immediately after scan display.
            </p>
          </div>

          <div style={{ borderTop: '1px solid #EBE7DE', paddingTop: '1rem' }}>
            <strong style={{ color: 'var(--color-brand)', fontSize: '0.95rem', fontFamily: 'var(--font-mono)' }}>
              Tier 2: Client Settings (Reading Grade, Worker Preference)
            </strong>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.35rem', lineHeight: 1.55 }}>
              • <strong>Transmission:</strong> Never transmitted.<br />
              • <strong>Storage:</strong> Saved strictly in local browser storage on this device.<br />
              • <strong>Purge:</strong> Can be crypto-shredded and cleared instantly via the Settings tab.
            </p>
          </div>

          <div style={{ borderTop: '1px solid #EBE7DE', paddingTop: '1rem' }}>
            <strong style={{ color: 'var(--color-safe)', fontSize: '0.95rem', fontFamily: 'var(--font-mono)' }}>
              Network &amp; Telemetry Isolation
            </strong>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.35rem', lineHeight: 1.55 }}>
              • <strong>Content Security Policy:</strong> Enforces <code style={{ color: 'var(--color-brand)', backgroundColor: 'var(--bg-secondary)', padding: '0.1rem 0.3rem', border: '1px solid var(--border-dark)' }}>connect-src &apos;self&apos;</code> to prevent unauthorized background exfiltration.<br />
              • <strong>Air-Gapped Parity:</strong> Fully operational with Wi-Fi, Ethernet, and cellular data turned off.
            </p>
          </div>
        </div>
      </div>

      {/* Verification Instructions */}
      <div
        style={{
          padding: '1.25rem 1.5rem',
          backgroundColor: '#FFFFFF',
          border: '2px solid var(--border-dark)',
          boxShadow: 'var(--shadow-brutal)',
          fontSize: '0.85rem',
          color: 'var(--text-muted)'
        }}
      >
        <strong style={{ color: '#111111', display: 'block', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', textTransform: 'uppercase' }}>
          How to Independently Verify Zero Network Transmission:
        </strong>
        <ol style={{ paddingLeft: '1.25rem', lineHeight: 1.7, margin: 0 }}>
          <li>Open your browser Developer Tools (<kbd style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.1rem 0.4rem', border: '1px solid var(--border-dark)' }}>F12</kbd> or <kbd style={{ backgroundColor: 'var(--bg-secondary)', padding: '0.1rem 0.4rem', border: '1px solid var(--border-dark)' }}>Ctrl+Shift+I</kbd>).</li>
          <li>Navigate to the <strong>Network</strong> tab.</li>
          <li>Paste any URL or sensitive message in the scanner and click <strong>Scan</strong>.</li>
          <li>Observe that <strong>zero outbound HTTP requests</strong> occur during detection.</li>
        </ol>
      </div>
    </section>
  );
};
