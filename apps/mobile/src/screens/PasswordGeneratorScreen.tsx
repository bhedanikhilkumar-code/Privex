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
  const [showSecret, setShowSecret] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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
  }, [mode, length, wordCount, useUppercase, useLowercase, useNumbers, useSpecial, avoidAmbiguous, avoidSimilar, separator, capitalize, includeNumber]);

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
        return { label: 'Very Strong', bg: 'rgba(16, 185, 129, 0.2)', text: '#34d399', border: '#10b981' };
      case 'STRONG':
        return { label: 'Strong', bg: 'rgba(16, 185, 129, 0.2)', text: '#6ee7b7', border: '#059669' };
      case 'MEDIUM':
        return { label: 'Medium', bg: 'rgba(245, 158, 11, 0.2)', text: '#fde047', border: '#f59e0b' };
      case 'WEAK':
      default:
        return { label: 'Weak', bg: 'rgba(239, 68, 68, 0.2)', text: '#fca5a5', border: '#ef4444' };
    }
  };

  const badge = generatedResult ? getStrengthBadge(generatedResult.strengthLevel) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Top Header matching Password Generator.png */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {onBack && (
            <button
              type="button"
              onClick={onBack}
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                backgroundColor: '#111b2e',
                border: '1px solid #27364b',
                color: '#38bdf8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1rem'
              }}
            >
              ←
            </button>
          )}
          <div>
            <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              KEY VAULT
            </span>
            <h1 style={{ margin: '0.1rem 0 0 0', fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              🔐 Secure Password Generator
            </h1>
          </div>
        </div>
        <span
          style={{
            fontSize: '0.7rem',
            padding: '0.25rem 0.65rem',
            borderRadius: '9999px',
            backgroundColor: 'rgba(56, 189, 248, 0.15)',
            color: '#38bdf8',
            border: '1px solid #0284c7',
            fontWeight: 700
          }}
        >
          100% On-Device CSPRNG
        </span>
      </div>

      {/* Mode Switcher matching Password Generator.png tabs & test selectors */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '0.5rem',
          backgroundColor: '#0f172a',
          padding: '0.25rem',
          borderRadius: '12px'
        }}
      >
        <button
          type="button"
          onClick={() => setMode('PASSWORD')}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '10px',
            cursor: 'pointer',
            fontWeight: mode === 'PASSWORD' ? 700 : 500,
            backgroundColor: mode === 'PASSWORD' ? '#2563eb' : 'transparent',
            color: mode === 'PASSWORD' ? '#ffffff' : '#94a3b8',
            fontSize: '0.85rem'
          }}
        >
          Password (Chars)
        </button>
        <button
          type="button"
          onClick={() => setMode('PASSPHRASE')}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '10px',
            cursor: 'pointer',
            fontWeight: mode === 'PASSPHRASE' ? 700 : 500,
            backgroundColor: mode === 'PASSPHRASE' ? '#2563eb' : 'transparent',
            color: mode === 'PASSPHRASE' ? '#ffffff' : '#94a3b8',
            fontSize: '0.85rem'
          }}
        >
          Passphrase (Words)
        </button>
      </div>

      {/* Preset Buttons for Quick Selection */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={() => applyPreset('STANDARD')}
          style={{
            padding: '0.35rem 0.65rem',
            backgroundColor: preset === 'STANDARD' ? '#2563eb' : '#111b2e',
            color: preset === 'STANDARD' ? '#ffffff' : '#94a3b8',
            border: '1px solid #27364b',
            borderRadius: '8px',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Standard (20)
        </button>
        <button
          type="button"
          onClick={() => applyPreset('STRONG')}
          style={{
            padding: '0.35rem 0.65rem',
            backgroundColor: preset === 'STRONG' ? '#2563eb' : '#111b2e',
            color: preset === 'STRONG' ? '#ffffff' : '#94a3b8',
            border: '1px solid #27364b',
            borderRadius: '8px',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Strong (32)
        </button>
        <button
          type="button"
          onClick={() => applyPreset('VERY_STRONG')}
          style={{
            padding: '0.35rem 0.65rem',
            backgroundColor: preset === 'VERY_STRONG' ? '#2563eb' : '#111b2e',
            color: preset === 'VERY_STRONG' ? '#ffffff' : '#94a3b8',
            border: '1px solid #27364b',
            borderRadius: '8px',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Very Strong (64)
        </button>
      </div>

      {errorMessage && (
        <div style={{ padding: '0.5rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', color: '#f87171', borderRadius: '8px', fontSize: '0.8rem' }}>
          {errorMessage}
        </div>
      )}

      {/* Generated Secret Display Card matching Password Generator.png */}
      <div
        style={{
          backgroundColor: '#111b2e',
          borderRadius: '20px',
          padding: '1.25rem',
          border: '1px solid #27364b',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {mode === 'PASSWORD' ? `Length: ${length} chars` : `Word Count: ${wordCount} words`}
          </span>
          {badge && (
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '0.2rem 0.6rem',
                borderRadius: '9999px',
                backgroundColor: badge.bg,
                color: badge.text,
                border: `1px solid ${badge.border}`
              }}
            >
              {badge.label} • {generatedResult?.entropyBits} BITS
            </span>
          )}
        </div>

        {/* Secret Output Container */}
        <div
          role="region"
          aria-label="Generated Secret"
          style={{
            backgroundColor: '#0f172a',
            borderRadius: '12px',
            padding: '1rem',
            border: '1px solid #1e293b',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '0.75rem'
          }}
        >
          <div
            style={{
              fontFamily: 'monospace, "JetBrains Mono", Consolas',
              fontSize: '1.05rem',
              fontWeight: 600,
              wordBreak: 'break-all',
              color: '#38bdf8',
              flex: 1,
              letterSpacing: '0.02em'
            }}
          >
            {showSecret
              ? (generatedResult?.secret || 'Generating...')
              : '••••••••••••••••••••••••'}
          </div>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              type="button"
              onClick={() => setShowSecret(!showSecret)}
              aria-label={showSecret ? 'Hide secret' : 'Show secret'}
              style={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#94a3b8',
                borderRadius: '8px',
                padding: '0.4rem 0.6rem',
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              {showSecret ? '👁️' : '🔒'}
            </button>
            <button
              type="button"
              onClick={handleGenerate}
              aria-label="🔄 Regenerate"
              style={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#38bdf8',
                borderRadius: '8px',
                padding: '0.4rem 0.6rem',
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              🔄 Regenerate
            </button>
          </div>
        </div>

        {/* Copy Button */}
        <button
          type="button"
          onClick={handleCopy}
          style={{
            padding: '0.85rem',
            backgroundColor: copiedFeedback ? '#10b981' : '#2563eb',
            color: '#ffffff',
            fontWeight: 700,
            borderRadius: '12px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.9rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',
            transition: 'background-color 0.2s ease'
          }}
        >
          <span>{copiedFeedback ? '✓ Copied (Auto-clear in 60s)' : '📋 Copy Secret'}</span>
        </button>
      </div>

      {/* Configuration Controls */}
      <div
        style={{
          backgroundColor: '#111b2e',
          borderRadius: '20px',
          padding: '1.25rem',
          border: '1px solid #27364b',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem'
        }}
      >
        {/* Length / Word Count Slider */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc' }}>
              {mode === 'PASSWORD' ? 'Password Length' : 'Word Count'}
            </span>
            <span
              style={{
                fontSize: '0.85rem',
                fontWeight: 800,
                color: '#38bdf8',
                backgroundColor: '#0f172a',
                padding: '0.2rem 0.6rem',
                borderRadius: '6px',
                border: '1px solid #1e293b'
              }}
            >
              {mode === 'PASSWORD' ? length : wordCount}
            </span>
          </div>

          <input
            type="range"
            min={mode === 'PASSWORD' ? 8 : 3}
            max={mode === 'PASSWORD' ? 64 : 12}
            value={mode === 'PASSWORD' ? length : wordCount}
            onChange={(e) => {
              if (mode === 'PASSWORD') {
                setLength(parseInt(e.target.value, 10));
              } else {
                setWordCount(parseInt(e.target.value, 10));
              }
            }}
            style={{
              width: '100%',
              accentColor: '#38bdf8',
              cursor: 'pointer'
            }}
          />
        </div>

        {/* Complexity Rules Switches */}
        {mode === 'PASSWORD' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              COMPLEXITY RULES
            </span>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>Uppercase Letters</span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block' }}>A, B, C, ...</span>
              </div>
              <input
                type="checkbox"
                checked={useUppercase}
                onChange={(e) => setUseUppercase(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>Lowercase Letters</span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block' }}>a, b, c, ...</span>
              </div>
              <input
                type="checkbox"
                checked={useLowercase}
                onChange={(e) => setUseLowercase(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>Numeric Digits</span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block' }}>0 through 9</span>
              </div>
              <input
                type="checkbox"
                checked={useNumbers}
                onChange={(e) => setUseNumbers(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>Special Symbols</span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block' }}>!@#$%^&amp;*</span>
              </div>
              <input
                type="checkbox"
                checked={useSpecial}
                onChange={(e) => setUseSpecial(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Passphrase Configuration
            </span>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label htmlFor="separator-input" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>
                Word Separator:
              </label>
              <input
                id="separator-input"
                type="text"
                value={separator}
                onChange={(e) => setSeparator(e.target.value)}
                style={{
                  width: '40px',
                  textAlign: 'center',
                  padding: '0.2rem',
                  backgroundColor: '#0f172a',
                  border: '1px solid #27364b',
                  borderRadius: '6px',
                  color: '#f8fafc'
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
              <label htmlFor="capitalize-checkbox" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>
                Capitalize Each Word
              </label>
              <input
                id="capitalize-checkbox"
                type="checkbox"
                checked={capitalize}
                onChange={(e) => setCapitalize(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
              <label htmlFor="include-number-checkbox" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>
                Include Random Number
              </label>
              <input
                id="include-number-checkbox"
                type="checkbox"
                checked={includeNumber}
                onChange={(e) => setIncludeNumber(e.target.checked)}
                style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#38bdf8' }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
