import React, { useState, useEffect } from 'react';
import { PasswordGeneratorService } from '../services/password-generator.service';
import {
  PasswordGeneratorPreset,
  PasswordGeneratorOptions,
  PassphraseGeneratorOptions,
  PasswordGenerationResult,
  PassphraseGenerationResult
} from '../types/mobile.types';

interface PasswordGeneratorScreenProps {
  onBack?: () => void;
}

export const PasswordGeneratorScreen: React.FC<PasswordGeneratorScreenProps> = ({ onBack }) => {
  const service = PasswordGeneratorService.getInstance();

  const [mode, setMode] = useState<'PASSWORD' | 'PASSPHRASE'>('PASSWORD');
  const [preset, setPreset] = useState<PasswordGeneratorPreset>('STANDARD');

  // Password Options
  const [length, setLength] = useState<number>(20);
  const [useUppercase, setUseUppercase] = useState<boolean>(true);
  const [useLowercase, setUseLowercase] = useState<boolean>(true);
  const [useNumbers, setUseNumbers] = useState<boolean>(true);
  const [useSpecial, setUseSpecial] = useState<boolean>(true);
  const [avoidAmbiguous, setAvoidAmbiguous] = useState<boolean>(false);
  const [avoidSimilar, setAvoidSimilar] = useState<boolean>(false);

  // Passphrase Options
  const [wordCount, setWordCount] = useState<number>(5);
  const [separator, setSeparator] = useState<string>('-');
  const [capitalize, setCapitalize] = useState<boolean>(true);
  const [includeNumber, setIncludeNumber] = useState<boolean>(false);

  // Generated Result
  const [generatedResult, setGeneratedResult] = useState<PasswordGenerationResult | PassphraseGenerationResult | null>(null);
  const [copiedFeedback, setCopiedFeedback] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Sync preset changes
  const applyPreset = (selectedPreset: PasswordGeneratorPreset) => {
    setPreset(selectedPreset);
    const opts = service.getPresetOptions(selectedPreset);
    setLength(opts.length);
    setUseUppercase(opts.useUppercase);
    setUseLowercase(opts.useLowercase);
    setUseNumbers(opts.useNumbers);
    setUseSpecial(opts.useSpecial);
    setAvoidAmbiguous(opts.avoidAmbiguous);
    setAvoidSimilar(opts.avoidSimilar);
  };

  const handleGenerate = () => {
    setErrorMessage(null);
    setCopiedFeedback(false);
    try {
      if (mode === 'PASSWORD') {
        const opts: PasswordGeneratorOptions = {
          length,
          useUppercase,
          useLowercase,
          useNumbers,
          useSpecial,
          avoidAmbiguous,
          avoidSimilar
        };
        const result = service.generatePassword(opts);
        setGeneratedResult(result);
      } else {
        const opts: PassphraseGeneratorOptions = {
          wordCount,
          separator,
          capitalize,
          includeNumber
        };
        const result = service.generatePassphrase(opts);
        setGeneratedResult(result);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to generate secret');
    }
  };

  useEffect(() => {
    handleGenerate();
  }, [mode]);

  const handleCopy = async () => {
    if (!generatedResult?.secret) return;
    const success = await service.copyToClipboard(generatedResult.secret, mode === 'PASSWORD' ? 'Password' : 'Passphrase');
    if (success) {
      setCopiedFeedback(true);
      setTimeout(() => setCopiedFeedback(false), 2500);
    }
  };

  const getStrengthBadge = (strength: string) => {
    switch (strength) {
      case 'VERY_STRONG':
        return { label: 'Very Strong', bg: '#064e3b', text: '#34d399', border: '#059669' };
      case 'STRONG':
        return { label: 'Strong', bg: '#065f46', text: '#6ee7b7', border: '#10b981' };
      case 'MEDIUM':
        return { label: 'Medium', bg: '#78350f', text: '#fde047', border: '#f59e0b' };
      case 'WEAK':
      default:
        return { label: 'Weak', bg: '#7f1d1d', text: '#fca5a5', border: '#ef4444' };
    }
  };

  const badge = generatedResult ? getStrengthBadge(generatedResult.strengthLevel) : null;

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {onBack && (
            <button
              type="button"
              onClick={onBack}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#38bdf8',
                fontSize: '1.25rem',
                cursor: 'pointer',
                padding: '0.25rem 0.5rem'
              }}
            >
              ←
            </button>
          )}
          <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700 }}>🔐 Secure Password Generator</h2>
        </div>
        <span
          style={{
            fontSize: '0.7rem',
            padding: '0.2rem 0.5rem',
            borderRadius: '9999px',
            backgroundColor: '#0369a1',
            color: '#e0f2fe'
          }}
        >
          100% On-Device CSPRNG
        </span>
      </div>

      {/* Mode Switcher */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '0.5rem',
          backgroundColor: '#0f172a',
          padding: '0.25rem',
          borderRadius: '10px'
        }}
      >
        <button
          type="button"
          onClick={() => {
            setMode('PASSWORD');
          }}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '8px',
            cursor: 'pointer',
            fontWeight: mode === 'PASSWORD' ? 700 : 500,
            backgroundColor: mode === 'PASSWORD' ? '#2563eb' : 'transparent',
            color: mode === 'PASSWORD' ? '#ffffff' : '#94a3b8'
          }}
        >
          Password (Chars)
        </button>
        <button
          type="button"
          onClick={() => {
            setMode('PASSPHRASE');
          }}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '8px',
            cursor: 'pointer',
            fontWeight: mode === 'PASSPHRASE' ? 700 : 500,
            backgroundColor: mode === 'PASSPHRASE' ? '#2563eb' : 'transparent',
            color: mode === 'PASSPHRASE' ? '#ffffff' : '#94a3b8'
          }}
        >
          Passphrase (Words)
        </button>
      </div>

      {/* Display Result Card */}
      <div
        style={{
          backgroundColor: '#1e293b',
          borderRadius: '16px',
          padding: '1.25rem',
          border: '1px solid #334155',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            {mode === 'PASSWORD' ? `Length: ${length} chars` : `Word Count: ${wordCount} words`}
          </span>
          {badge && (
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.2rem 0.6rem',
                borderRadius: '6px',
                backgroundColor: badge.bg,
                color: badge.text,
                border: `1px solid ${badge.border}`
              }}
            >
              {badge.label} · {generatedResult?.entropyBits} bits
            </span>
          )}
        </div>

        {/* Secret container */}
        <div
          role="region"
          aria-label="Generated Secret"
          style={{
            backgroundColor: '#0f172a',
            borderRadius: '10px',
            padding: '1rem',
            border: '1px solid #38bdf8',
            fontFamily: 'monospace',
            fontSize: '1.1rem',
            wordBreak: 'break-all',
            color: '#38bdf8',
            userSelect: 'all'
          }}
        >
          {generatedResult?.secret || 'Click Generate to produce secret'}
        </div>

        {/* Action Buttons: Refresh & Copy */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <button
            type="button"
            onClick={handleGenerate}
            style={{
              padding: '0.75rem',
              backgroundColor: '#334155',
              border: '1px solid #475569',
              borderRadius: '10px',
              color: '#f8fafc',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '0.9rem'
            }}
          >
            🔄 Regenerate
          </button>
          <button
            type="button"
            onClick={handleCopy}
            disabled={!generatedResult?.secret}
            style={{
              padding: '0.75rem',
              backgroundColor: copiedFeedback ? '#059669' : '#0284c7',
              border: 'none',
              borderRadius: '10px',
              color: '#ffffff',
              cursor: 'pointer',
              fontWeight: 700,
              fontSize: '0.9rem',
              transition: 'background-color 0.2s'
            }}
          >
            {copiedFeedback ? '✓ Copied (Auto-clear in 60s)' : '📋 Copy Secret'}
          </button>
        </div>

        {/* Entropy Explanation */}
        {generatedResult && (
          <p style={{ margin: 0, fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
            ℹ️ {generatedResult.entropyExplanation}
          </p>
        )}
      </div>

      {errorMessage && (
        <div
          style={{
            backgroundColor: '#7f1d1d',
            color: '#fecaca',
            padding: '0.75rem',
            borderRadius: '8px',
            fontSize: '0.85rem'
          }}
        >
          ⚠️ {errorMessage}
        </div>
      )}

      {/* Controls & Configuration */}
      {mode === 'PASSWORD' ? (
        <div
          style={{
            backgroundColor: '#1e293b',
            borderRadius: '16px',
            padding: '1.25rem',
            border: '1px solid #334155',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem'
          }}
        >
          <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Password Presets</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem' }}>
            {(['STANDARD', 'STRONG', 'VERY_STRONG', 'CUSTOM'] as PasswordGeneratorPreset[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => applyPreset(p)}
                style={{
                  padding: '0.5rem 0.25rem',
                  fontSize: '0.75rem',
                  borderRadius: '8px',
                  border: preset === p ? '1px solid #38bdf8' : '1px solid #475569',
                  backgroundColor: preset === p ? '#0369a1' : '#0f172a',
                  color: preset === p ? '#ffffff' : '#94a3b8',
                  cursor: 'pointer',
                  fontWeight: preset === p ? 700 : 500
                }}
              >
                {p === 'STANDARD' ? 'Standard (20)' : p === 'STRONG' ? 'Strong (32)' : p === 'VERY_STRONG' ? 'Max (48)' : 'Custom'}
              </button>
            ))}
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <label htmlFor="length-slider" style={{ fontSize: '0.85rem', color: '#cbd5e1' }}>Length: {length} characters</label>
              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>12–128</span>
            </div>
            <input
              id="length-slider"
              type="range"
              min={12}
              max={128}
              value={length}
              onChange={(e) => {
                setLength(Number(e.target.value));
                setPreset('CUSTOM');
              }}
              style={{ width: '100%' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useUppercase}
                onChange={(e) => { setUseUppercase(e.target.checked); setPreset('CUSTOM'); }}
              />
              Uppercase Letters (A-Z)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useLowercase}
                onChange={(e) => { setUseLowercase(e.target.checked); setPreset('CUSTOM'); }}
              />
              Lowercase Letters (a-z)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useNumbers}
                onChange={(e) => { setUseNumbers(e.target.checked); setPreset('CUSTOM'); }}
              />
              Numbers (0-9)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useSpecial}
                onChange={(e) => { setUseSpecial(e.target.checked); setPreset('CUSTOM'); }}
              />
              Symbols & Special (!@#$%...)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={avoidSimilar}
                onChange={(e) => { setAvoidSimilar(e.target.checked); setPreset('CUSTOM'); }}
              />
              Avoid Similar Characters (l, 1, I, o, 0, O)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={avoidAmbiguous}
                onChange={(e) => { setAvoidAmbiguous(e.target.checked); setPreset('CUSTOM'); }}
              />
              Avoid Ambiguous Symbols ({'{'} {'}'} [ ] ( ) / \ ' " ` ~)
            </label>
          </div>
        </div>
      ) : (
        <div
          style={{
            backgroundColor: '#1e293b',
            borderRadius: '16px',
            padding: '1.25rem',
            border: '1px solid #334155',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem'
          }}
        >
          <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Passphrase Configuration</h3>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <label htmlFor="word-count-slider" style={{ fontSize: '0.85rem', color: '#cbd5e1' }}>Word Count: {wordCount} words</label>
              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>3–10</span>
            </div>
            <input
              id="word-count-slider"
              type="range"
              min={3}
              max={10}
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label htmlFor="separator-select" style={{ display: 'block', fontSize: '0.85rem', marginBottom: '0.25rem', color: '#cbd5e1' }}>
              Word Separator:
            </label>
            <select
              id="separator-select"
              value={separator}
              onChange={(e) => setSeparator(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                backgroundColor: '#0f172a',
                color: '#f8fafc',
                border: '1px solid #475569',
                borderRadius: '8px'
              }}
            >
              <option value="-">Hyphen (-)</option>
              <option value="_">Underscore (_)</option>
              <option value=" ">Space ( )</option>
              <option value=".">Period (.)</option>
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={capitalize}
                onChange={(e) => setCapitalize(e.target.checked)}
              />
              Capitalize Each Word
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={includeNumber}
                onChange={(e) => setIncludeNumber(e.target.checked)}
              />
              Include Random Number
            </label>
          </div>

          <p style={{ margin: 0, fontSize: '0.75rem', color: '#64748b' }}>
            Dictionary: Bundled 2,048-word standard wordlist (11 bits/word). 100% offline. Zero network transmission.
          </p>
        </div>
      )}

      {/* Security Guidance Note */}
      <div
        style={{
          padding: '0.85rem',
          backgroundColor: '#0f172a',
          borderRadius: '12px',
          border: '1px solid #1e293b',
          fontSize: '0.75rem',
          color: '#94a3b8',
          lineHeight: 1.4
        }}
      >
        <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.2rem' }}>🔒 Zero-Knowledge Privacy Guarantee:</strong>
        Passwords generated here are computed purely in volatile RAM using on-device CSPRNG. Secrets are never saved to disk, logged, or sent over any network. Autofill service integration is deferred to a future platform release.
      </div>
    </div>
  );
};
