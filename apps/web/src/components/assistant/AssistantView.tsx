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

      const dummyAssessment: RiskAssessment = {
        overallScore,
        confidence: 0.95,
        severity,
        primaryThreatFactor: category,
        detectorContributions: {},
      };

      const input: AssistantInput = {
        requestId: `assistant-demo-${Date.now()}`,
        verdict,
        riskAssessment: dummyAssessment,
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
    <section aria-labelledby="assistant-view-heading" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 id="assistant-view-heading" style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          On-Device AI Security Assistant
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Unlike cloud-based chatbots, this assistant is an evidence-based security synthesizer running completely
          inside your browser. It strictly interprets structured security signals into plain-language Grade 6 explanations.
        </p>
      </div>

      {/* Security Assistant Boundary Notice */}
      <div
        style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '0.5rem',
          fontSize: '0.8rem',
          color: '#93c5fd',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}
      >
        <span>🛡️</span>
        <span>
          <strong>Strict Safety Boundary:</strong> Assistant operates strictly as a read-only threat interpreter. It has zero authority to downgrade security verdicts or assist in weaponization.
        </span>
      </div>

      {/* Interactive Threat Simulator Tabs */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label htmlFor="topic-selector" style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
          Select Security Scenario to Explain:
        </label>
        <div id="topic-selector" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {[
            { id: 'PHISHING', label: 'Credential Phishing' },
            { id: 'EXTORTION', label: 'Urgent Extortion' },
            { id: 'INVOICE', label: 'Tech Support Invoice' },
            { id: 'POSTAL', label: 'Postal Delivery Fraud' }
          ].map((topic) => (
            <button
              key={topic.id}
              type="button"
              onClick={() => {
                setSelectedTopic(topic.id);
                handleSynthesize(topic.id);
              }}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: selectedTopic === topic.id ? 'var(--color-brand)' : 'var(--bg-card)',
                color: selectedTopic === topic.id ? '#ffffff' : 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.375rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              {topic.label}
            </button>
          ))}
        </div>
      </div>

      {/* Untrusted Snippet Input */}
      <div style={{ marginBottom: '1.5rem' }}>
        <label htmlFor="assistant-custom-input" style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
          Optional Content Snippet (Tests Adversarial Containment):
        </label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            id="assistant-custom-input"
            type="text"
            placeholder="Enter custom suspicious text snippet..."
            value={customSnippet}
            onChange={(e) => setCustomSnippet(e.target.value)}
            style={{
              flex: 1,
              padding: '0.65rem 0.85rem',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.375rem',
              color: 'var(--text-primary)',
              fontSize: '0.9rem'
            }}
          />
          <button
            type="button"
            onClick={() => handleSynthesize(selectedTopic, customSnippet)}
            disabled={isSynthesizing}
            style={{
              padding: '0.65rem 1.25rem',
              backgroundColor: 'var(--color-brand)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '0.375rem',
              fontWeight: 600,
              fontSize: '0.85rem',
              cursor: 'pointer'
            }}
          >
            {isSynthesizing ? 'Synthesizing...' : 'Synthesize Explanation'}
          </button>
        </div>
      </div>

      {/* Synthesized Output Display */}
      {explanation && (
        <article
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '1px solid #3b82f6',
            borderRadius: '0.75rem',
            padding: '1.5rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#93c5fd', fontWeight: 600, textTransform: 'uppercase' }}>
              Grade {preferences.cognitiveReadingGrade} Plain-Language Threat Briefing
            </span>
            <span style={{ fontSize: '0.75rem', color: '#34d399' }}>
              ⚡ Synthesized in {explanation.executionTimeMs} ms
            </span>
          </div>

          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
            {explanation.headline}
          </h3>

          <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            {explanation.summaryParagraph}
          </p>

          {explanation.dangerFactors.length > 0 && (
            <div>
              <strong style={{ fontSize: '0.85rem', color: '#fca5a5' }}>Key Threat Indicators:</strong>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                {explanation.dangerFactors.map((df: string, i: number) => (
                  <li key={i}>{df}</li>
                ))}
              </ul>
            </div>
          )}

          {explanation.recommendedSteps.length > 0 && (
            <div>
              <strong style={{ fontSize: '0.85rem', color: '#6ee7b7' }}>Recommended Defensive Actions:</strong>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                {explanation.recommendedSteps.map((step: string, i: number) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          )}

          <div style={{ fontSize: '0.7rem', color: '#64748b', borderTop: '1px solid var(--border-color)', paddingTop: '0.5rem' }}>
            <span>🔒 Mode: {explanation.inferenceStatus} • Prompt Boundary: 100% Contained</span>
          </div>
        </article>
      )}
    </section>
  );
};
