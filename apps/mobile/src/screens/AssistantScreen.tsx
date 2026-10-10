import React, { useState, useEffect, useMemo } from 'react';
import { AISecurityAssistant, AssistantInput } from '@private-protection/ml';
import { Verdict, SeverityLevel } from '@private-protection/core';
import { SecureStorageService } from '../services/secure-storage.service';

export const AssistantScreen: React.FC = () => {
  const [readingGrade, setReadingGrade] = useState<6 | 8>(6);
  const [_simulatedTopic, setSimulatedTopic] = useState<string>('PHISHING');
  const [customQuery, setCustomQuery] = useState<string>('');
  const [explanation, setExplanation] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const assistant = useMemo(() => new AISecurityAssistant(), []);

  useEffect(() => {
    SecureStorageService.getSettings()
      .then((settings) => {
        if (settings?.readingGrade === 6 || settings?.readingGrade === 8) {
          setReadingGrade(settings.readingGrade);
        }
      })
      .catch(() => {});
  }, []);

  const handleCustomAnalyze = async () => {
    if (!customQuery.trim()) return;
    setLoading(true);
    try {
      const isUrgent = /(urgent|immediate|account|password|verify|suspend|bitcoin|transfer)/i.test(customQuery);
      const isUrl = /(https?:\/\/|www\.)/i.test(customQuery);

      const assistantInput: AssistantInput = {
        requestId: `assistant-custom-${Date.now()}`,
        verdict: isUrgent || isUrl ? Verdict.SUSPICIOUS : Verdict.ALLOW,
        riskAssessment: {
          overallScore: isUrgent ? 75 : (isUrl ? 55 : 10),
          confidence: 0.92,
          severity: isUrgent ? SeverityLevel.HIGH : (isUrl ? SeverityLevel.MEDIUM : SeverityLevel.NONE),
          primaryThreatFactor: isUrgent ? 'SOCIAL_ENGINEERING' : (isUrl ? 'EXTERNAL_LINK' : 'BENIGN_TEXT'),
          detectorContributions: {}
        },
        evidenceTokens: isUrgent ? [
          { ruleId: 'urgency-cue', category: 'HEURISTIC', description: 'Urgency markers and call-to-action detected in snippet', scoreContribution: 75 }
        ] : [],
        cognitiveReadingGrade: readingGrade,
        targetType: isUrl ? 'URL' : 'MESSAGE',
        untrustedSnippet: customQuery
      };

      const output = await assistant.explain(assistantInput);
      setExplanation(output);
    } catch {
      // Safe fallback
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateExplanation = async (topic: string, grade: 6 | 8) => {
    setLoading(true);

    let assistantInput: AssistantInput;

    if (topic === 'PHISHING') {
      assistantInput = {
        requestId: `test-${Date.now()}`,
        verdict: Verdict.DANGEROUS,
        riskAssessment: {
          overallScore: 92,
          confidence: 0.98,
          severity: SeverityLevel.CRITICAL,
          primaryThreatFactor: 'CREDENTIAL_PHISHING',
          detectorContributions: { Typosquatting: 92 }
        },
        evidenceTokens: [
          { ruleId: 'brand-typosquat', category: 'LEXICAL', description: 'Deceptive brand imitation in domain', scoreContribution: 92 },
          { ruleId: 'insecure-http', category: 'NETWORK', description: 'Password requested over plaintext HTTP', scoreContribution: 80 }
        ],
        cognitiveReadingGrade: grade,
        targetType: 'URL',
        untrustedSnippet: 'http://paypa1-security-verification.com/login'
      };
    } else {
      assistantInput = {
        requestId: `test-${Date.now()}`,
        verdict: Verdict.DANGEROUS,
        riskAssessment: {
          overallScore: 88,
          confidence: 0.95,
          severity: SeverityLevel.CRITICAL,
          primaryThreatFactor: 'CRYPTO_EXTORTION',
          detectorContributions: { UrgencyDetector: 88 }
        },
        evidenceTokens: [
          { ruleId: 'bitcoin-address', category: 'HEURISTIC', description: 'Extortion message demanding cryptocurrency transfer', scoreContribution: 88 }
        ],
        cognitiveReadingGrade: grade,
        targetType: 'MESSAGE',
        untrustedSnippet: 'Transfer 0.5 BTC within 2 hours or your private photos will be exposed.'
      };
    }

    try {
      const output = await assistant.explain(assistantInput);
      setExplanation(output);
    } catch {
      // Safe fallback
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            AI-POWERED PROTECTION INSIGHTS
          </span>
          <h1 style={{ margin: '0.15rem 0 0 0', fontSize: '1.75rem', fontWeight: 800, color: '#f8fafc' }}>
            Security Assistant
          </h1>
        </div>
        <div style={{ width: '38px', height: '38px', borderRadius: '50%', backgroundColor: '#111b2e', border: '1px solid #27364b', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8' }}>
          🕒
        </div>
      </div>

      {/* Intro Assistant Banner Card */}
      <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem', display: 'flex', gap: '0.85rem', alignItems: 'center' }}>
        <div style={{ width: '42px', height: '42px', borderRadius: '10px', backgroundColor: 'rgba(56, 189, 248, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem' }}>
          ✨
        </div>
        <div>
          <strong style={{ fontSize: '0.95rem', color: '#f8fafc', display: 'block' }}>Privex Assistant</strong>
          <span style={{ fontSize: '0.76rem', color: '#94a3b8', lineHeight: 1.35, display: 'block' }}>
            I can explain security verdicts, analyze technical evidence, and provide privacy recommendations.
          </span>
        </div>
      </div>

      {/* Reading Grade & Scenario Controls */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem' }}>
        <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.5rem' }}>
          Cognitive Reading Complexity:
        </label>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <button
            type="button"
            onClick={() => {
              setReadingGrade(6);
              SecureStorageService.saveSettings({ readingGrade: 6 });
            }}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: readingGrade === 6 ? '#38bdf8' : '#0f172a',
              color: readingGrade === 6 ? '#0f172a' : '#f8fafc',
              fontWeight: 700,
              borderRadius: '8px',
              border: '1px solid #334155',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Grade 6 (Simplified)
          </button>
          <button
            type="button"
            onClick={() => {
              setReadingGrade(8);
              SecureStorageService.saveSettings({ readingGrade: 8 });
            }}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: readingGrade === 8 ? '#38bdf8' : '#0f172a',
              color: readingGrade === 8 ? '#0f172a' : '#f8fafc',
              fontWeight: 700,
              borderRadius: '8px',
              border: '1px solid #334155',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Grade 8 (Standard)
          </button>
        </div>

        {/* Custom Security Inquiry Input */}
        <div style={{ marginBottom: '1.25rem' }}>
          <label htmlFor="assistant-input" style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.4rem' }}>
            Ask Assistant or Paste Threat Snippet:
          </label>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              id="assistant-input"
              type="text"
              value={customQuery}
              onChange={(e) => setCustomQuery(e.target.value)}
              placeholder="e.g. Is 'urgent account verify' dangerous?"
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleCustomAnalyze();
                }
              }}
              style={{
                flex: 1,
                padding: '0.75rem 0.9rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '8px',
                color: '#f8fafc',
                fontSize: '0.85rem',
                outline: 'none'
              }}
            />
            <button
              type="button"
              onClick={handleCustomAnalyze}
              disabled={loading || !customQuery.trim()}
              style={{
                padding: '0.75rem 1rem',
                backgroundColor: '#38bdf8',
                color: '#0f172a',
                fontWeight: 700,
                borderRadius: '8px',
                border: 'none',
                cursor: loading || !customQuery.trim() ? 'not-allowed' : 'pointer',
                fontSize: '0.85rem',
                whiteSpace: 'nowrap'
              }}
            >
              Analyze
            </button>
          </div>
        </div>

        <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.5rem' }}>
          Simulate Technical Telemetry Synthesis:
        </label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            onClick={() => {
              setSimulatedTopic('PHISHING');
              handleSimulateExplanation('PHISHING', readingGrade);
            }}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: '#0f172a',
              color: '#38bdf8',
              fontWeight: 600,
              borderRadius: '8px',
              border: '1px solid #38bdf8',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Credential Phishing
          </button>
          <button
            type="button"
            onClick={() => {
              setSimulatedTopic('EXTORTION');
              handleSimulateExplanation('EXTORTION', readingGrade);
            }}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: '#0f172a',
              color: '#f87171',
              fontWeight: 600,
              borderRadius: '8px',
              border: '1px solid #f87171',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Crypto Extortion
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', color: '#94a3b8', padding: '1rem' }}>
          Synthesizing Plain-Language Briefing...
        </div>
      )}

      {explanation && (
        <div style={{ backgroundColor: '#0f172a', border: '1px solid #38bdf8', borderRadius: '16px', padding: '1.25rem' }}>
          <h3 style={{ margin: '0 0 0.5rem 0', color: '#38bdf8', fontSize: '1.1rem' }}>
            {explanation.headline}
          </h3>
          <p style={{ margin: '0 0 0.75rem 0', fontSize: '0.9rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {explanation.summaryParagraph}
          </p>

          <div style={{ marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 600 }}>Identified Risk Factors:</span>
            <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
              {explanation.dangerFactors.map((df: string, i: number) => (
                <li key={i}>{df}</li>
              ))}
            </ul>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 600 }}>Actionable Next Steps:</span>
            <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
              {explanation.recommendedSteps.map((step: string, i: number) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>

          <div style={{ marginTop: '1rem', borderTop: '1px solid #1e293b', paddingTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
            Source: {explanation.modelName || 'On-Device Template Fallback Engine'} • Target: Grade {readingGrade}
          </div>
        </div>
      )}
    </div>
  );
};
