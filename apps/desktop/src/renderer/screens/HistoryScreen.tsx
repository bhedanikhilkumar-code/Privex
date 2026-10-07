import React, { useState, useEffect } from 'react';
import {
  AuditLogEntry,
  AuditVerificationResult,
  AuditQueryFilter
} from '../../types/desktop.types';

export const HistoryScreen: React.FC = () => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [chainResult, setChainResult] = useState<AuditVerificationResult | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [exportNotice, setExportNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadLogs();
  }, [categoryFilter, severityFilter]);

  const loadLogs = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      if (window.desktopSecurity?.getAuditLogs) {
        const filter: AuditQueryFilter = {
          limit: 200,
          offset: 0,
          category: categoryFilter !== 'ALL' ? (categoryFilter as any) : undefined,
          severity: severityFilter !== 'ALL' ? (severityFilter as any) : undefined
        };
        const res = await window.desktopSecurity.getAuditLogs(filter);
        setEntries(res.entries || []);
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load audit logs: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      if (window.desktopSecurity?.verifyAuditChain) {
        const res = await window.desktopSecurity.verifyAuditChain();
        setChainResult(res);
      }
    } catch (err: any) {
      setErrorMsg(`Verification error: ${err?.message || 'Cryptographic check failed'}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setExportNotice(null);
    try {
      if (window.desktopSecurity?.exportAuditLogs) {
        const content = await window.desktopSecurity.exportAuditLogs(format);
        // Create an in-memory blob and trigger download
        const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `private-protection-audit-${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setExportNotice(`Sanitized ${format.toUpperCase()} report exported successfully (Tier-1 PII scrubbed).`);
      }
    } catch (err: any) {
      setErrorMsg(`Export failed: ${err?.message || 'Export error'}`);
    }
  };

  const filteredEntries = entries.filter((e) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    const actionMatch = e.action?.toLowerCase().includes(term);
    const categoryMatch = e.category?.toLowerCase().includes(term);
    const metaMatch = JSON.stringify(e.metadata || {}).toLowerCase().includes(term);
    return actionMatch || categoryMatch || metaMatch;
  });

  return (
    <div style={{ padding: '24px', maxWidth: '1040px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header and Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>📜 Forensic Audit Log & Timeline</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Append-only, HMAC-SHA256 hash-chained immutable security timeline.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={handleVerifyChain}
            disabled={verifying}
            style={{
              padding: '8px 14px',
              borderRadius: '6px',
              border: '1px solid #16a34a',
              backgroundColor: '#f0fdf4',
              color: '#166534',
              fontSize: '12px',
              fontWeight: 700,
              cursor: verifying ? 'wait' : 'pointer'
            }}
          >
            {verifying ? 'Verifying Chain...' : '🛡️ Verify HMAC Integrity'}
          </button>

          <button
            type="button"
            onClick={() => handleExport('json')}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#334155',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Export JSON
          </button>

          <button
            type="button"
            onClick={() => handleExport('csv')}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#334155',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Chain Verification Result Card */}
      {chainResult && (
        <div
          role="status"
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            border: `1px solid ${chainResult.isValid ? '#86efac' : '#f87171'}`,
            backgroundColor: chainResult.isValid ? '#f0fdf4' : '#fef2f2',
            color: chainResult.isValid ? '#166534' : '#991b1b',
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <div>
            <strong>
              {chainResult.isValid
                ? `🟢 HMAC Hash Chain Intact — ${chainResult.totalEntries} entries cryptographically sealed.`
                : `🔴 TAMPER DETECTED: Chain integrity broken at Entry #${chainResult.corruptedIndex}!`}
            </strong>
          </div>
          <button
            type="button"
            onClick={() => setChainResult(null)}
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'inherit' }}
          >
            ✕
          </button>
        </div>
      )}

      {exportNotice && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            backgroundColor: '#eff6ff',
            border: '1px solid #bfdbfe',
            color: '#1d4ed8',
            fontSize: '12px'
          }}
        >
          {exportNotice}
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            color: '#991b1b',
            fontSize: '12px'
          }}
        >
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div
        style={{
          display: 'flex',
          gap: '12px',
          alignItems: 'center',
          backgroundColor: '#ffffff',
          padding: '12px',
          borderRadius: '8px',
          border: '1px solid #e2e8f0'
        }}
      >
        <input
          type="text"
          placeholder="Search by action, category, or metadata..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            flex: 1,
            padding: '8px 12px',
            borderRadius: '6px',
            border: '1px solid #cbd5e1',
            fontSize: '13px'
          }}
        />

        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          style={{
            padding: '8px 10px',
            borderRadius: '6px',
            border: '1px solid #cbd5e1',
            fontSize: '13px',
            backgroundColor: '#ffffff'
          }}
        >
          <option value="ALL">All Categories</option>
          <option value="SECURITY">SECURITY</option>
          <option value="ENGINE">ENGINE</option>
          <option value="CONFIG">CONFIG</option>
          <option value="QUARANTINE">QUARANTINE</option>
          <option value="WATCHDOG">WATCHDOG</option>
          <option value="TAMPER">TAMPER</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{
            padding: '8px 10px',
            borderRadius: '6px',
            border: '1px solid #cbd5e1',
            fontSize: '13px',
            backgroundColor: '#ffffff'
          }}
        >
          <option value="ALL">All Severities</option>
          <option value="INFO">INFO</option>
          <option value="WARN">WARN</option>
          <option value="CRITICAL">CRITICAL</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          overflow: 'hidden'
        }}
      >
        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            Loading audit records from encrypted store...
          </div>
        ) : filteredEntries.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
            No audit records found matching the active filter.
          </div>
        ) : (
          <div style={{ overflowX: 'auto', maxHeight: '560px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', color: '#475569' }}>
                  <th style={{ padding: '10px 14px' }}>#</th>
                  <th style={{ padding: '10px 14px' }}>Timestamp</th>
                  <th style={{ padding: '10px 14px' }}>Severity</th>
                  <th style={{ padding: '10px 14px' }}>Category</th>
                  <th style={{ padding: '10px 14px' }}>Action</th>
                  <th style={{ padding: '10px 14px' }}>Metadata / Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntries.map((entry) => {
                  const sevColor =
                    entry.severity === 'CRITICAL'
                      ? '#dc2626'
                      : entry.severity === 'WARN'
                      ? '#d97706'
                      : '#16a34a';

                  return (
                    <tr
                      key={entry.index}
                      style={{ borderBottom: '1px solid #f1f5f9', transition: 'background-color 0.1s' }}
                    >
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#64748b' }}>
                        {entry.index}
                      </td>
                      <td style={{ padding: '10px 14px', whiteSpace: 'nowrap', color: '#334155' }}>
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span
                          style={{
                            fontWeight: 700,
                            color: sevColor,
                            backgroundColor: `${sevColor}15`,
                            padding: '2px 6px',
                            borderRadius: '4px'
                          }}
                        >
                          {entry.severity}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px', fontWeight: 600, color: '#334155' }}>
                        {entry.category}
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#0f172a' }}>
                        {entry.action}
                      </td>
                      <td style={{ padding: '10px 14px', color: '#64748b', wordBreak: 'break-all' }}>
                        {entry.metadata ? JSON.stringify(entry.metadata) : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
