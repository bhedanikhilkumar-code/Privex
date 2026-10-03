import React, { useState } from 'react';
import { AISecurityAssistant, AssistantInput } from '@private-protection/ml';
import { Verdict, SeverityLevel, RiskAssessment } from '@private-protection/core';
import { UserPreferences } from '../../scanner/types';

interface AssistantViewProps {
  preferences: UserPreferences;
}

export const AssistantView: React.FC<AssistantViewProps> = ({ preferences }) => {
  const [selectedTopic, setSelectedTopic] = useState<string>('PHISHING');
  const [customSnippet, setCustomSnippet] = useState<string>('');
  const [explanation, setExplanation] = useState<any | null>(null);
  const [isSynthesizing, setIsSynthesizing] = useState<boolean>(false);

  const assistant = new AISecurityAssistant();

  const handleSynthesize = async (topic: string, snippet?: string) => {
    setIsSynthesizing(true);
    try {
      let verdict = Verdict.DANGEROUS;
      let overallScore = 85;
      let severity = SeverityLevel.HIGH;
      let category = 'PHISHING';
      let ruleId = 'credential-harvest';
      let description = 'Detected suspicious request for password credentials';

      if (topic === 'EXTORTION') {
        category = 'EXTORTION';
        ruleId = 'cryptocurrency-blackmail';
        description = 'Detected urgent cryptocurrency demand threatening data destruction';
        overallScore = 95;
        severity = SeverityLevel.CRITICAL;
      } else if (topic === 'INVOICE') {
        category = 'SCAM';
        ruleId = 'tech-support-invoice';
        description = 'Detected fraudulent subscription auto-renewal notification';
        overallScore = 75;
      } else if (topic === 'POSTAL') {
        category = 'DELIVERY_SCAM';
        ruleId = 'postal-redelivery-fee';
        description = 'Detected deceptive package detention notice demanding payment';
        overallScore = 70;
      }

      const demoAssessment: RiskAssessment = {
        overallScore,
        confidence: 0.95,
        severity,
        primaryThreatFactor: category,
        detectorContributions: {},
      };

      const input: AssistantInput = {
        requestId: `assistant-demo-${Date.now()}`,
        verdict,
        riskAssessment: demoAssessment,
        evidenceTokens: [
          {
            ruleId,
            category,
            description,
            scoreContribution: overallScore
          }
        ],
        cognitiveReadingGrade: preferences.cognitiveReadingGrade,
        targetType: 'INTERACTIVE_ASSISTANT',
        untrustedSnippet: snippet || customSnippet || description
      };

      const output = await assistant.explain(input);
      setExplanation(output);
    } finally {
      setIsSynthesizing(false);
    }
  };

  return (
    <section aria-labelledby="assistant-view-heading" style={{ maxWidth: '950px', margin: '0 auto' }}>
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
            ON-DEVICE EXPLAINER
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            EVIDENCE-BASED • READ-ONLY SYNTHESIZER
          </span>
        </div>

        <h2
          id="assistant-view-heading"
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: '2.25rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: '#111111'
          }}
        >
          On-Device AI Security Assistant
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '1rem', maxWidth: '750px', lineHeight: 1.5 }}>
          Unlike cloud-based chatbots, this assistant is an evidence-based security synthesizer running completely
          inside your browser. It strictly interprets structured security signals into plain-language Grade 6 explanations.
        </p>
      </div>

      {/* Security Assistant Boundary Notice */}
      <div
        style={{
          padding: '1.25rem',
          backgroundColor: 'var(--color-accent)',
          border: '2px solid var(--border-dark)',
          boxShadow: 'var(--shadow-brutal)',
          marginBottom: '2rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem'
        }}
      >
        <span style={{ fontSize: '1.75rem' }}>🛡️</span>
        <div style={{ fontSize: '0.875rem', color: '#111111', lineHeight: 1.5 }}>
          <strong style={{ fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Strict Safety Boundary:
          </strong>{' '}
          Assistant operates strictly as a read-only threat interpreter. It has zero authority to downgrade security verdicts or assist in weaponization.
        </div>
      </div>

      {/* Interactive Threat Simulator Section */}
      <div
        style={{
          backgroundColor: '#FFFFFF',
          border: '2px solid var(--border-dark)',
          boxShadow: 'var(--shadow-brutal-lg)',
          padding: '1.75rem',
          marginBottom: '2rem'
        }}
      >
        <div style={{ marginBottom: '1.5rem' }}>
          <label
            htmlFor="topic-selector"
            style={{
              display: 'block',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 800,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              marginBottom: '0.75rem'
            }}
          >
            SELECT SECURITY SCENARIO TO EXPLAIN:
          </label>
          <div id="topic-selector" style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
            {[
              { id: 'PHISHING', label: 'Credential Phishing' },
              { id: 'EXTORTION', label: 'Urgent Extortion' },
              { id: 'INVOICE', label: 'Tech Support Invoice' },
              { id: 'POSTAL', label: 'Postal Delivery Fraud' }
            ].map((topic) => {
              const isSelected = selectedTopic === topic.id;
              return (
                <button
                  key={topic.id}
                  type="button"
                  onClick={() => {
                    setSelectedTopic(topic.id);
                    handleSynthesize(topic.id);
                  }}
                  style={{
                    padding: '0.6rem 1.15rem',
                    backgroundColor: isSelected ? 'var(--color-brand)' : '#FFFFFF',
                    color: isSelected ? '#FFFFFF' : 'var(--text-primary)',
                    border: '2px solid var(--border-dark)',
                    boxShadow: isSelected ? '3px 3px 0px #111111' : '1px 1px 0px #111111',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    textTransform: 'uppercase',
                    cursor: 'pointer'
                  }}
                >
                  {topic.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Untrusted Snippet Input */}
        <div>
          <label
            htmlFor="assistant-custom-input"
            style={{
              display: 'block',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 800,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              marginBottom: '0.5rem'
            }}
          >
            OPTIONAL CONTENT SNIPPET (TESTS ADVERSARIAL CONTAINMENT):
          </label>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              id="assistant-custom-input"
              type="text"
              placeholder="Enter custom suspicious text snippet..."
              value={customSnippet}
              onChange={(e) => setCustomSnippet(e.target.value)}
              style={{
                flex: '1 1 280px',
                padding: '0.85rem 1rem',
                backgroundColor: 'var(--bg-primary)',
                border: '2px solid var(--border-dark)',
                color: 'var(--text-primary)',
                fontSize: '0.95rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            />
            <button
              type="button"
              onClick={() => handleSynthesize(selectedTopic, customSnippet)}
              disabled={isSynthesizing}
              style={{
                padding: '0.85rem 1.5rem',
                backgroundColor: 'var(--color-brand)',
                color: '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: '3px 3px 0px #111111',
                fontWeight: 800,
                fontSize: '0.85rem',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                cursor: 'pointer'
              }}
            >
              {isSynthesizing ? 'Synthesizing...' : 'Synthesize Explanation'}
            </button>
          </div>
        </div>
      </div>

      {/* Synthesized Output Display */}
      {explanation && (
        <article
          style={{
            backgroundColor: '#FFFFFF',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal-xl)',
            padding: '1.75rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.75rem' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-brand)', fontWeight: 800, textTransform: 'uppercase' }}>
              GRADE {preferences.cognitiveReadingGrade} PLAIN-LANGUAGE THREAT BRIEFING
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', backgroundColor: 'var(--bg-secondary)', padding: '0.2rem 0.5rem', border: '1px solid var(--border-dark)', fontWeight: 700 }}>
              ⚡ Synthesized in {explanation.executionTimeMs} ms
            </span>
          </div>

          <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, color: '#111111', margin: 0 }}>
            {explanation.headline}
          </h3>

          <p style={{ fontSize: '0.95rem', color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>
            {explanation.summaryParagraph}
          </p>

          {explanation.dangerFactors.length > 0 && (
            <div style={{ backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--border-dark)', padding: '1rem' }}>
              <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-danger)', textTransform: 'uppercase', display: 'block', marginBottom: '0.35rem' }}>
                Key Threat Indicators:
              </strong>
              <ul style={{ paddingLeft: '1.25rem', margin: 0, fontSize: '0.85rem', color: '#111111', lineHeight: 1.5 }}>
                {explanation.dangerFactors.map((df: string, i: number) => (
                  <li key={i}>{df}</li>
                ))}
              </ul>
            </div>
          )}

          {explanation.recommendedSteps.length > 0 && (
            <div style={{ backgroundColor: 'var(--color-safe-bg)', border: '1px solid var(--border-dark)', padding: '1rem' }}>
              <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-safe)', textTransform: 'uppercase', display: 'block', marginBottom: '0.35rem' }}>
                Recommended Defensive Actions:
              </strong>
              <ul style={{ paddingLeft: '1.25rem', margin: 0, fontSize: '0.85rem', color: '#111111', lineHeight: 1.5 }}>
                {explanation.recommendedSteps.map((step: string, i: number) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          )}

          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)', borderTop: '1px solid #EBE7DE', paddingTop: '0.75rem' }}>
            <span>🔒 Mode: {explanation.inferenceStatus} • Prompt Boundary: 100% Contained</span>
          </div>
        </article>
      )}
    </section>
  );
};
