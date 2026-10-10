import React, { useState } from 'react';
import { QuarantineItem } from '../../types/desktop.types';
import { SecurityBadge } from '../components/SecurityBadge';
import { FrictionGateModal } from '../components/FrictionGateModal';

interface QuarantineScreenProps {
  items: QuarantineItem[];
  onRestore: (item: QuarantineItem) => Promise<void>;
  onDelete: (item: QuarantineItem) => Promise<void>;
  onPurgeAll: () => Promise<void>;
}

export const QuarantineScreen: React.FC<QuarantineScreenProps> = ({
  items,
  onRestore,
  onDelete,
  onPurgeAll
}) => {
  const [selectedRestoreItem, setSelectedRestoreItem] = useState<QuarantineItem | null>(null);
  const [isPurgeModalOpen, setIsPurgeModalOpen] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const handleConfirmRestore = async () => {
    if (!selectedRestoreItem) return;
    try {
      await onRestore(selectedRestoreItem);
      setActionNotice(`Successfully restored '${selectedRestoreItem.fileName}' to disk.`);
    } catch (err: any) {
      setActionNotice(`Restore error: ${err.message}`);
    } finally {
      setSelectedRestoreItem(null);
    }
  };

  const handleConfirmPurgeAll = async () => {
    try {
      await onPurgeAll();
      setActionNotice('All quarantined files permanently destroyed via cryptographic erasure.');
    } catch (err: any) {
      setActionNotice(`Purge error: ${err.message}`);
    } finally {
      setIsPurgeModalOpen(false);
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '22px', color: '#0f172a' }}>🔒 Encrypted Quarantine Vault</h2>
          <p style={{ margin: '4px 0 0 0', color: '#64748b', fontSize: '14px' }}>
            Isolated threats with neutralized executable headers to prevent accidental execution
          </p>
        </div>
        {items.length > 0 && (
          <button
            type="button"
            onClick={() => setIsPurgeModalOpen(true)}
            style={{
              backgroundColor: '#fee2e2',
              color: '#991b1b',
              border: '1px solid #f87171',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Purge All (Crypto-Shred)
          </button>
        )}
      </div>

      {actionNotice && (
        <div style={{ marginBottom: '16px', padding: '10px 14px', backgroundColor: '#f0fdf4', border: '1px solid #86efac', borderRadius: '6px', color: '#166534', fontSize: '13px' }}>
          {actionNotice}
        </div>
      )}

      {items.length === 0 ? (
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '32px', textAlign: 'center' }}>
          <div style={{ fontSize: '32px', marginBottom: '8px' }}>🛡️</div>
          <h3 style={{ margin: '0 0 4px 0', fontSize: '16px', color: '#0f172a' }}>Vault is Empty</h3>
          <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
            No quarantined threat blobs currently isolated.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {items.map((item, index) => (
            <div
              key={item.quarantineId}
              className="motion-card motion-fade-up"
              style={{
                backgroundColor: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                padding: '16px',
                animationDelay: `${Math.min(index * 50, 300)}ms`
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <div>
                  <div style={{ fontWeight: 'bold', fontSize: '15px', color: '#0f172a' }}>{item.fileName}</div>
                  <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace' }}>
                    Original: {item.originalPath}
                  </div>
                </div>
                <SecurityBadge severity={item.severity} size="sm" />
              </div>

              <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '12px' }}>
                Threat: <strong>{item.threatName}</strong> | Size: {Math.round(item.fileSize / 1024)} KB | Quarantined: {new Date(item.quarantinedAt).toLocaleTimeString()}
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setSelectedRestoreItem(item)}
                  className="motion-pressable"
                  style={{
                    backgroundColor: '#f1f5f9',
                    border: '1px solid #cbd5e1',
                    borderRadius: '4px',
                    padding: '6px 12px',
                    fontSize: '12px',
                    cursor: 'pointer'
                  }}
                >
                  Restore to Disk...
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(item)}
                  className="motion-pressable"
                  style={{
                    backgroundColor: '#fee2e2',
                    color: '#991b1b',
                    border: '1px solid #fca5a5',
                    borderRadius: '4px',
                    padding: '6px 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    fontWeight: 500
                  }}
                >
                  Permanent Delete (Shred)
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Restore Friction Gate Modal */}
      {selectedRestoreItem && (
        <FrictionGateModal
          isOpen={true}
          title="Restore Quarantined Threat?"
          description={`Warning: '${selectedRestoreItem.fileName}' was detected as '${selectedRestoreItem.threatName}'. Restoring it will return the file to disk in executable form. Proceed only if you trust this item.`}
          confirmLabel="I Trust This File, Restore"
          countdownSeconds={3}
          onConfirm={handleConfirmRestore}
          onCancel={() => setSelectedRestoreItem(null)}
        />
      )}

      {/* Purge All Modal */}
      <FrictionGateModal
        isOpen={isPurgeModalOpen}
        title="Permanently Destroy All Quarantined Blobs?"
        description="This will execute multi-pass cryptographic byte overwriting on all quarantined files. This action cannot be undone."
        confirmLabel="Permanent Crypto-Shred All"
        countdownSeconds={3}
        onConfirm={handleConfirmPurgeAll}
        onCancel={() => setIsPurgeModalOpen(false)}
      />
    </div>
  );
};
