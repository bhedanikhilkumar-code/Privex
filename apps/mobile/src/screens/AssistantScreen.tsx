import React, { useState } from 'react';
import { AISecurityAssistant, AssistantInput } from '@private-protection/ml';
import { Verdict, SeverityLevel } from '@private-protection/core';
import { SecureStorageService } from '../services/secure-storage.service';

export const AssistantScreen: React.FC = () => {
  const [readingGrade, setReadingGrade] = useState<6 | 8>(6);
  const [_simulatedTopic, setSimulatedTopic] = useState<string>('PHISHING');
  const [explanation, setExplanation] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const handleSimulateExplanation = async (topic: string, grade: 6 | 8) => {
    setLoading(true);
    const assistant = new AISecurityAssistant();

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
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
          <span style={{ fontSize: '1.5rem' }}>🤖</span>
          <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#38bdf8' }}>
            On-Device AI Security Assistant
          </h2>
        </div>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Translates technical threat telemetry into jargon-free, actionable guidance directly on your device.
        </p>
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
