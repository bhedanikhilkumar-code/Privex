import React, { useState, useEffect } from 'react';
import { generateSecurePassword, analyzePasswordSecurity } from '../../lib/security/password-security';

export const PasswordGenerator: React.FC = () => {
  const [length, setLength] = useState<number>(16);
  const [useUppercase, setUseUppercase] = useState<boolean>(true);
  const [useLowercase, setUseLowercase] = useState<boolean>(true);
  const [useNumbers, setUseNumbers] = useState<boolean>(true);
  const [useSpecial, setUseSpecial] = useState<boolean>(true);
  const [avoidAmbiguous, setAvoidAmbiguous] = useState<boolean>(false);
  const [avoidSimilar, setAvoidSimilar] = useState<boolean>(false);

  const [generatedPassword, setGeneratedPassword] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  // Generate initial password on mount or option change
  const handleGenerate = () => {
    try {
      const pwd = generateSecurePassword({
        length,
        useUppercase,
        useLowercase,
        useNumbers,
        useSpecial,
        avoidAmbiguous,
        avoidSimilar
      });
      setGeneratedPassword(pwd);
      setCopied(false);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    handleGenerate();
  }, [length, useUppercase, useLowercase, useNumbers, useSpecial, avoidAmbiguous, avoidSimilar]);

  const handleCopy = async () => {
    if (!generatedPassword) return;
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(generatedPassword);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = generatedPassword;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const strength = analyzePasswordSecurity(generatedPassword);

  return (
    <div
      style={{
        backgroundColor: '#FFFFFF',
        border: '2px solid var(--border-dark)',
        boxShadow: 'var(--shadow-brutal)',
        padding: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <span
            style={{
              padding: '0.2rem 0.5rem',
              backgroundColor: 'var(--color-safe)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            CSPRNG HARDENED
          </span>
          <h3
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: '1.4rem',
              fontWeight: 800,
              margin: '0.4rem 0 0 0',
              color: '#111111'
            }}
          >
            Strong Password Generator
          </h3>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          🎲 crypto.getRandomValues()
        </div>
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
        Generate high-entropy credentials locally on your endpoint. No Math.random(), no cloud transit, zero logging.
      </p>

      {/* Generated Output Display */}
      <div
        style={{
          border: '2px solid var(--border-dark)',
          backgroundColor: '#FAFAF8',
          padding: '1rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}
      >
        <div style={{ flex: '1 1 260px', overflowX: 'auto' }}>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '1.25rem',
              fontWeight: 800,
              letterSpacing: '0.08em',
              wordBreak: 'break-all',
              color: '#111111'
            }}
          >
            {generatedPassword || '—'}
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            onClick={handleGenerate}
            title="Regenerate password"
            style={{
              padding: '0.55rem 0.85rem',
              backgroundColor: '#FFFFFF',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px #111111',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 800,
              cursor: 'pointer'
            }}
          >
            🔄 Regenerate
          </button>

          <button
            type="button"
            onClick={handleCopy}
            style={{
              padding: '0.55rem 1rem',
              backgroundColor: copied ? 'var(--color-safe)' : 'var(--color-brand)',
              color: '#FFFFFF',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px #111111',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 800,
              cursor: 'pointer',
              transition: 'background-color 0.15s ease'
            }}
          >
            {copied ? '✓ Copied!' : '📋 Copy Password'}
          </button>
        </div>
      </div>

      {/* Automatic Strength Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase' }}>
          Generated Strength:
        </span>
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            fontWeight: 800,
            padding: '0.2rem 0.5rem',
            backgroundColor: strength.color,
            color: strength.level === 'MEDIUM' ? '#111111' : '#FFFFFF',
            border: '1px solid var(--border-dark)'
          }}
        >
          {strength.level} ({strength.score}%)
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
          Entropy: ~{strength.estimatedEntropyBits} bits
        </span>
      </div>

      {/* Length Controls */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <label
            htmlFor="pwd-length-slider"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 700,
              textTransform: 'uppercase'
            }}
          >
            Password Length: {length} Characters
          </label>
          <div style={{ display: 'flex', gap: '0.35rem' }}>
            {[8, 12, 16, 20, 24].map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => setLength(preset)}
                style={{
                  padding: '0.2rem 0.5rem',
                  backgroundColor: length === preset ? 'var(--color-brand)' : '#FFFFFF',
                  color: length === preset ? '#FFFFFF' : '#111111',
                  border: '1px solid var(--border-dark)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.725rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                {preset}
              </button>
            ))}
          </div>
        </div>

        <input
          id="pwd-length-slider"
          type="range"
          min={6}
          max={48}
          value={length}
          onChange={(e) => setLength(parseInt(e.target.value, 10))}
          style={{ width: '100%', cursor: 'pointer' }}
        />
      </div>

      {/* Character Options */}
      <div>
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.8rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            marginBottom: '0.6rem'
          }}
        >
          Character Sets &amp; Options:
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '0.65rem'
          }}
        >
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useUppercase}
              onChange={(e) => setUseUppercase(e.target.checked)}
            />
            <span>[✓] Uppercase (A-Z)</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useLowercase}
              onChange={(e) => setUseLowercase(e.target.checked)}
            />
            <span>[✓] Lowercase (a-z)</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useNumbers}
              onChange={(e) => setUseNumbers(e.target.checked)}
            />
            <span>[✓] Numbers (0-9)</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useSpecial}
              onChange={(e) => setUseSpecial(e.target.checked)}
            />
            <span>[✓] Special Symbols (!@#$%^&*)</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={avoidAmbiguous}
              onChange={(e) => setAvoidAmbiguous(e.target.checked)}
            />
            <span>Avoid ambiguous chars ({'{}[]()/\'"`~,;:.<>'})</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={avoidSimilar}
              onChange={(e) => setAvoidSimilar(e.target.checked)}
            />
            <span>Avoid similar characters (l, 1, I, o, 0, O)</span>
          </label>
        </div>
      </div>
    </div>
  );
};
