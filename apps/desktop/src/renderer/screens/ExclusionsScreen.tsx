import React, { useState, useEffect } from 'react';
import {
  ExclusionItem,
  CreateExclusionInput,
  ExclusionType
} from '../../types/desktop.types';

interface ExclusionsScreenProps {
  onRequestFrictionGate: (action: string, onConfirm: () => void) => void;
}

export const ExclusionsScreen: React.FC<ExclusionsScreenProps> = ({ onRequestFrictionGate }) => {
  const [exclusions, setExclusions] = useState<ExclusionItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [type, setType] = useState<ExclusionType>('HASH');
  const [value, setValue] = useState<string>('');
  const [reason, setReason] = useState<string>('');
  const [ttlHours, setTtlHours] = useState<number>(24);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    loadExclusions();
  }, []);

  const loadExclusions = async () => {
    setLoading(true);
    try {
      if (window.desktopSecurity?.getExclusions) {
        const list = await window.desktopSecurity.getExclusions();
        setExclusions(list || []);
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load exclusions: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddExclusion = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;

    setErrorMsg(null);

    // Validate type constraints
    if (type === 'HASH') {
      const cleanHash = value.trim().toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(cleanHash)) {
        setErrorMsg('Invalid SHA-256 hash. Must be exactly 64 hexadecimal characters.');
        return;
      }
    } else if (type === 'PATH') {
      const p = value.trim();
      const forbidden = ['c:\\', 'c:\\windows', 'c:\\windows\\system32'];
      if (forbidden.includes(p.toLowerCase())) {
        setErrorMsg('FORBIDDEN EXCLUSION: Windows critical system directories cannot be excluded.');
        return;
      }
    }

    const input: CreateExclusionInput = {
      type,
      value: value.trim(),
      reason: reason.trim() || 'Manual exclusion by user',
      ttl: ttlHours === 0 ? undefined : (ttlHours === 24 ? '24h' : ttlHours === 168 ? '7d' : ttlHours === 720 ? '30d' : 'permanent')
    };

    // Adding an exclusion lowers security -> Requires Friction Gate
    onRequestFrictionGate(`Add ${type} exclusion for '${value.trim()}'`, async () => {
      try {
        if (window.desktopSecurity?.addExclusion) {
          const added = await window.desktopSecurity.addExclusion(input);
          setExclusions((prev) => [added, ...prev]);
          setValue('');
          setReason('');
          setNotice(`Exclusion successfully added for: ${added.value}`);
        }
      } catch (err: any) {
        setErrorMsg(`Failed to add exclusion: ${err?.message || 'Policy rejected'}`);
      }
    });
  };

  const handleRemove = async (id: string) => {
    try {
      if (window.desktopSecurity?.removeExclusion) {
        await window.desktopSecurity.removeExclusion(id);
        setExclusions((prev) => prev.filter((item) => item.id !== id));
        setNotice('Exclusion removed. Inspection coverage restored.');
      }
    } catch (err: any) {
      setErrorMsg(`Error removing exclusion: ${err?.message}`);
    }
  };

  const handleClearAll = () => {
    onRequestFrictionGate('Clear ALL Exclusions and restore 100% inspection coverage', async () => {
      try {
        if (window.desktopSecurity?.clearAllExclusions) {
          await window.desktopSecurity.clearAllExclusions();
          setExclusions([]);
          setNotice('All exclusions cleared. System has 100% security inspection coverage.');
        }
      } catch (err: any) {
        setErrorMsg(`Error clearing exclusions: ${err?.message}`);
      }
    });
  };

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🚫 Exclusions & False-Positive Manager</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Safely bypass false-positives via SHA-256 hash (recommended), path, or domain with mandatory TTL expiration.
          </p>
        </div>

        {exclusions.length > 0 && (
          <button
            type="button"
            onClick={handleClearAll}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#f8fafc',
              color: '#334155',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Clear All Exclusions
          </button>
        )}
      </div>

      {notice && (
        <div
          role="status"
          style={{
            padding: '12px',
            backgroundColor: '#f0fdf4',
            border: '1px solid #86efac',
            borderRadius: '8px',
            color: '#166534',
            fontSize: '13px'
          }}
        >
          ✅ {notice}
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          style={{
            padding: '12px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '8px',
            color: '#991b1b',
            fontSize: '13px'
          }}
        >
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Add Exclusion Form */}
      <form
        onSubmit={handleAddExclusion}
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px'
        }}
      >
        <div style={{ fontSize: '14px', fontWeight: 700, color: '#0f172a' }}>
          Add New Security Exclusion (Gated by Friction Gate)
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 1fr', gap: '12px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
              Exclusion Type
            </label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as any)}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px'
              }}
            >
              <option value="HASH">SHA-256 Hash (Safest)</option>
              <option value="PATH">Folder / File Path</option>
              <option value="DOMAIN">Web Domain</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
              Value ({type === 'HASH' ? '64-char Hex' : type === 'PATH' ? 'Full Path' : 'Domain'})
            </label>
            <input
              type="text"
              placeholder={
                type === 'HASH'
                  ? 'e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                  : type === 'PATH'
                  ? 'e.g. C:\\MyTools\\debugger.exe'
                  : 'e.g. internal.corp.local'
              }
              value={value}
              onChange={(e) => setValue(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                fontFamily: type === 'HASH' ? 'monospace' : 'inherit',
                boxSizing: 'border-box'
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
              Expiration TTL
            </label>
            <select
              value={ttlHours}
              onChange={(e) => setTtlHours(parseInt(e.target.value, 10))}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px'
              }}
            >
              <option value={24}>24 Hours</option>
              <option value={168}>7 Days</option>
              <option value={720}>30 Days</option>
              <option value={0}>Permanent</option>
            </select>
          </div>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
            Reason / Justification
          </label>
          <input
            type="text"
            placeholder="e.g. False positive on developer debugging utility"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 10px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              boxSizing: 'border-box'
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '4px' }}>
          <button
            type="submit"
            style={{
              padding: '9px 18px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            + Add Exclusion (Opens Gate)
          </button>
        </div>
      </form>

      {/* Active Exclusions Table */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          overflow: 'hidden'
        }}
      >
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #e2e8f0', fontWeight: 700, fontSize: '14px' }}>
          Active Exclusions ({exclusions.length})
        </div>

        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            Loading exclusions...
          </div>
        ) : exclusions.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
            🛡️ Zero exclusions active. 100% inspection coverage is active.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', color: '#475569' }}>
                  <th style={{ padding: '10px 14px' }}>Type</th>
                  <th style={{ padding: '10px 14px' }}>Value</th>
                  <th style={{ padding: '10px 14px' }}>Reason</th>
                  <th style={{ padding: '10px 14px' }}>Expires</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {exclusions.map((item) => (
                  <tr key={item.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td style={{ padding: '10px 14px' }}>
                      <span
                        style={{
                          fontWeight: 700,
                          fontSize: '10px',
                          backgroundColor: '#e2e8f0',
                          padding: '2px 6px',
                          borderRadius: '4px'
                        }}
                      >
                        {item.type.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#0f172a', wordBreak: 'break-all' }}>
                      {item.value}
                    </td>
                    <td style={{ padding: '10px 14px', color: '#64748b' }}>{item.reason}</td>
                    <td style={{ padding: '10px 14px', color: '#64748b' }}>
                      {item.expiresAt ? new Date(item.expiresAt).toLocaleDateString() : 'Permanent'}
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => handleRemove(item.id)}
                        style={{
                          padding: '4px 8px',
                          borderRadius: '4px',
                          border: '1px solid #fecaca',
                          backgroundColor: '#fff1f2',
                          color: '#dc2626',
                          fontSize: '11px',
                          cursor: 'pointer'
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
