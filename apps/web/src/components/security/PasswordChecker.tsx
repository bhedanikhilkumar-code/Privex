import React, { useState } from 'react';
import { analyzePasswordSecurity } from '../../lib/security/password-security';

export const PasswordChecker: React.FC = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const analysis = analyzePasswordSecurity(password);

  const handleClear = () => {
    setPassword('');
  };

  const handleLoadSample = (sample: string) => {
    setPassword(sample);
  };

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
              backgroundColor: 'var(--color-brand)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            CLIENT-SIDE EVALUATION
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
            Password Security Checker
          </h3>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          🔒 Zero-Transmission Guarantee
        </div>
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
        Evaluate your password against brute-force entropy models, sequential walks, and breached dictionary heuristics.
        <strong> Your password is never sent to any server or stored on disk.</strong>
      </p>

      {/* Password Input Area */}
      <div>
        <label
          htmlFor="pwd-checker-input"
          style={{
            display: 'block',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.8rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            marginBottom: '0.4rem'
          }}
        >
          Enter Password To Analyze
        </label>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 280px' }}>
            <input
              id="pwd-checker-input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Type or paste a password..."
              autoComplete="off"
              spellCheck="false"
              style={{
                width: '100%',
                padding: '0.75rem 2.75rem 0.75rem 0.85rem',
                border: '2px solid var(--border-dark)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.95rem',
                backgroundColor: '#FAFAF8',
                outline: 'none'
              }}
            />
            {password.length > 0 && (
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Hide password' : 'Show password'}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                style={{
                  position: 'absolute',
                  right: '0.5rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: '1rem',
                  padding: '0.25rem'
                }}
              >
                {showPassword ? '🙈' : '👁️'}
              </button>
            )}
          </div>

          <button
            type="button"
            onClick={handleClear}
            disabled={password.length === 0}
            style={{
              padding: '0.75rem 1.25rem',
              backgroundColor: '#FFFFFF',
              color: '#111111',
              border: '2px solid var(--border-dark)',
              boxShadow: password.length > 0 ? '2px 2px 0px #111111' : 'none',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: password.length > 0 ? 'pointer' : 'default',
              opacity: password.length > 0 ? 1 : 0.5
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* Quick Test Samples */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
          Quick Test Examples:
        </span>
        {[
          { label: 'password (Common)', val: 'password' },
          { label: '12345678 (Sequential)', val: '12345678' },
          { label: 'Password123 (Weak)', val: 'Password123' },
          { label: 'Password@123 (Medium)', val: 'Password@123' },
          { label: 'VeryStrongRandomPassword!2026 (Very Strong)', val: 'VeryStrongRandomPassword!2026' }
        ].map((item) => (
          <button
            key={item.label}
            type="button"
            onClick={() => handleLoadSample(item.val)}
            style={{
              padding: '0.25rem 0.5rem',
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-dark)',
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer'
            }}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Visual Strength Meter */}
      <div
        style={{
          border: '2px solid var(--border-dark)',
          backgroundColor: '#FAFAF8',
          padding: '1.25rem'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 800, textTransform: 'uppercase' }}>
              Password Strength:
            </span>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontWeight: 900,
                fontSize: '0.85rem',
                padding: '0.15rem 0.5rem',
                backgroundColor: analysis.color,
                color: analysis.level === 'MEDIUM' ? '#111111' : '#FFFFFF',
                border: '1px solid var(--border-dark)'
              }}
            >
              {analysis.level}
            </span>
          </div>

          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', fontWeight: 800 }}>
            {analysis.score}%
          </span>
        </div>

        {/* Progress Bar */}
        <div
          role="progressbar"
          aria-valuenow={analysis.score}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Password Strength Meter"
          style={{
            height: '14px',
            backgroundColor: '#E0DDD5',
            border: '2px solid var(--border-dark)',
            position: 'relative',
            overflow: 'hidden'
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${analysis.score}%`,
              backgroundColor: analysis.color,
              transition: 'width 0.2s ease, background-color 0.2s ease'
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.4rem', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          <span>Length: {analysis.length} chars</span>
          <span>Estimated Entropy: ~{analysis.estimatedEntropyBits} bits</span>
        </div>
      </div>

      {/* Criteria Checklist */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '0.75rem'
        }}
      >
        {analysis.criteria.map((item) => (
          <div
            key={item.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              padding: '0.65rem 0.85rem',
              backgroundColor: item.met ? 'var(--color-safe-bg)' : '#FFFFFF',
              border: '1px solid var(--border-dark)',
              borderLeft: `4px solid ${item.met ? 'var(--color-safe)' : 'var(--color-danger)'}`
            }}
          >
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '1rem',
                fontWeight: 900,
                color: item.met ? 'var(--color-safe)' : 'var(--color-danger)'
              }}
            >
              {item.met ? '✓' : '✗'}
            </span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#111111' }}>
                {item.label}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                {item.explanation}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Security Feedback & Guidance */}
      {analysis.feedback.length > 0 && (
        <div
          style={{
            backgroundColor: 'var(--bg-secondary)',
            border: '1px solid var(--border-dark)',
            padding: '1rem',
            fontSize: '0.825rem'
          }}
        >
          <strong style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
            💡 Security Recommendation:
          </strong>
          <ul style={{ margin: 0, paddingLeft: '1.25rem', lineHeight: 1.45 }}>
            {analysis.feedback.map((tip, idx) => (
              <li key={idx} style={{ color: 'var(--text-primary)' }}>
                {tip}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
