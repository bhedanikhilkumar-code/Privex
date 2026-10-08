import React, { useState } from 'react';
import { FrictionGateModal } from '../components/FrictionGateModal';

interface PrivacyScreenProps {
  onCryptoShred: () => Promise<void>;
}

export const PrivacyScreen: React.FC<PrivacyScreenProps> = ({ onCryptoShred }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [shredComplete, setShredComplete] = useState(false);

  const handleConfirmShred = async () => {
    try {
      await onCryptoShred();
      setShredComplete(true);
    } finally {
      setIsModalOpen(false);
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>👁️ Privacy Guarantees & Cryptographic Erasure</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Foundational Zero-Knowledge data classification and local memory lifecycle
      </p>

      {/* Metrics Card */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>BYTES EXFILTRATED</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#16a34a', marginTop: '4px' }}>0 Bytes</div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Zero cloud telemetry</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>AIR-GAP STATUS</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#0284c7', marginTop: '4px' }}>100% Offline</div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Operates with network disabled</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>USER DATA STORAGE</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#0f172a', marginTop: '4px' }}>Volatile RAM</div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Zero raw file disk retention</div>
        </div>
      </div>

      {/* Principles breakdown */}
      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px', marginBottom: '24px' }}>
        <h4 style={{ margin: '0 0 12px 0', fontSize: '15px', color: '#0f172a' }}>Constitutional Privacy Architecture</h4>
        <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '13px', color: '#475569', lineHeight: 1.8 }}>
          <li><strong>Tier 1 Data Isolation:</strong> Your personal files, photos, code, and documents are inspected purely in volatile RAM and zeroed immediately upon scan completion.</li>
          <li><strong>Zero Cloud AI:</strong> Threat briefings are synthesized locally on this computer via `@private-protection/ml`. No prompt or evidence is sent to external LLM APIs.</li>
          <li><strong>No User Tracking:</strong> Privex contains no user identifiers, usage telemetry beacons, or advertising SDKs.</li>
        </ul>
      </div>

      {/* One-Click Crypto-Shredder */}
      <div style={{ backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', padding: '20px' }}>
        <h4 style={{ margin: '0 0 6px 0', fontSize: '15px', color: '#991b1b' }}>One-Click Cryptographic Erasure (Crypto-Shredder)</h4>
        <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#7f1d1d', lineHeight: 1.5 }}>
          Instantly wipes all local settings, scan history, cached metadata, and overwrites all quarantined threat blobs with random cryptographic noise.
        </p>
        <button
          type="button"
          onClick={() => setIsModalOpen(true)}
          style={{
            backgroundColor: '#dc2626',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            padding: '10px 20px',
            fontWeight: 600,
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          Purge All Data (Crypto-Shred)
        </button>
        {shredComplete && (
          <div style={{ marginTop: '12px', fontSize: '13px', color: '#166534', fontWeight: 600 }}>
            ✅ All local data successfully purged and overwritten.
          </div>
        )}
      </div>

      {/* Friction Gate */}
      <FrictionGateModal
        isOpen={isModalOpen}
        title="Execute Complete Cryptographic Erasure?"
        description="This action will permanently delete all quarantined files, clear all settings, and reset Privex to factory defaults. Quarantined threats cannot be recovered after this action."
        confirmLabel="Permanent Crypto-Shred"
        countdownSeconds={3}
        onConfirm={handleConfirmShred}
        onCancel={() => setIsModalOpen(false)}
      />
    </div>
  );
};
