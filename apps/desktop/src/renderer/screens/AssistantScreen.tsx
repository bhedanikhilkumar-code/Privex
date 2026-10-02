import React, { useState } from 'react';
import { DetectedThreat, DesktopAssistantExplanation } from '../../types/desktop.types';

interface AssistantScreenProps {
  selectedThreat: DetectedThreat | null;
  onExplainThreat: (threat: DetectedThreat, level: 'grade6' | 'grade8') => Promise<DesktopAssistantExplanation>;
}

export const AssistantScreen: React.FC<AssistantScreenProps> = ({
  selectedThreat,
  onExplainThreat
}) => {
  const [cognitiveLevel, setCognitiveLevel] = useState<'grade6' | 'grade8'>('grade6');
  const [explanation, setExplanation] = useState<DesktopAssistantExplanation | null>(null);
  const [loading, setLoading] = useState(false);

  const handleFetchExplanation = async () => {
    if (!selectedThreat) return;
    setLoading(true);
    try {
      const res = await onExplainThreat(selectedThreat, cognitiveLevel);
      setExplanation(res);
    } catch {
      // Fallback
      setExplanation({
        threatTitle: selectedThreat.threatName,
        summary: `This file was blocked because it exhibits suspicious executable signals (${selectedThreat.evidenceFactors.join(', ')}).`,
        explanation: 'The system inspected the header bytes and found indicators common to deceptive files designed to trick users into running hidden software.',
        riskLevel: selectedThreat.severity.toUpperCase(),
        recommendedActions: ['Do not run or open this file', 'Keep the file in the quarantine vault', 'Delete the file if you did not expect it'],
        cognitiveLevel
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>🤖 On-Device AI Security Assistant</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Plain-language threat explanations translated directly on this PC from technical detection evidence
      </p>

      {/* Target Threat Card */}
      {selectedThreat ? (
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontWeight: 'bold', fontSize: '16px', color: '#0f172a' }}>{selectedThreat.fileName}</div>
              <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace' }}>{selectedThreat.filePath}</div>
            </div>
            <span style={{ fontSize: '12px', backgroundColor: '#fee2e2', color: '#991b1b', padding: '3px 8px', borderRadius: '4px', fontWeight: 'bold' }}>
              SCORE: {selectedThreat.riskScore}/100
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginTop: '16px' }}>
            <span style={{ fontSize: '13px', color: '#334155', fontWeight: 600 }}>Reading Level:</span>
            <label style={{ fontSize: '13px', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
              <input
                type="radio"
                name="level"
                value="grade6"
                checked={cognitiveLevel === 'grade6'}
                onChange={() => setCognitiveLevel('grade6')}
              />
              Grade 6 (Plain Language)
            </label>
            <label style={{ fontSize: '13px', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
              <input
                type="radio"
                name="level"
                value="grade8"
                checked={cognitiveLevel === 'grade8'}
                onChange={() => setCognitiveLevel('grade8')}
              />
              Grade 8 (Detailed Technical)
            </label>

            <button
              type="button"
              onClick={handleFetchExplanation}
              disabled={loading}
              style={{
                marginLeft: 'auto',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '8px 16px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {loading ? 'Synthesizing...' : 'Synthesize Explanation'}
            </button>
          </div>
        </div>
      ) : (
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '32px', textAlign: 'center', marginBottom: '20px' }}>
          <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
            Select a detected threat from <strong>Scan Results</strong> or <strong>Quarantine</strong> to view its plain-language AI explanation.
          </p>
        </div>
      )}

      {/* Explanation Briefing Display */}
      {explanation && (
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px' }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', color: '#0f172a' }}>{explanation.threatTitle}</h3>
          <div style={{ fontSize: '14px', color: '#1e293b', lineHeight: 1.5, marginBottom: '16px' }}>
            {explanation.summary}
          </div>

          <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', color: '#334155' }}>Why is this file dangerous?</h4>
          <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#475569', lineHeight: 1.5 }}>
            {explanation.explanation}
          </p>

          <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', color: '#334155' }}>Recommended Actions:</h4>
          <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '13px', color: '#475569', lineHeight: 1.6 }}>
            {explanation.recommendedActions.map((act, i) => (
              <li key={i}>{act}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
