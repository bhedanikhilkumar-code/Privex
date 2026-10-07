import React, { useState, useEffect } from 'react';
import { TrustedApplication } from '../../types/desktop.types';

interface TrustedAppsScreenProps {
  onRequestFrictionGate: (action: string, onConfirm: () => void) => void;
}

export const TrustedAppsScreen: React.FC<TrustedAppsScreenProps> = ({ onRequestFrictionGate }) => {
  const [apps, setApps] = useState<TrustedApplication[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [pathInput, setPathInput] = useState<string>('');
  const [nameInput, setNameInput] = useState<string>('');
  const [shaInput, setShaInput] = useState<string>('');
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadTrustedApps();
  }, []);

  const loadTrustedApps = async () => {
    setLoading(true);
    try {
      if (window.desktopSecurity?.getTrustedApplications) {
        const list = await window.desktopSecurity.getTrustedApplications();
        setApps(list || []);
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load trusted apps: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddApp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pathInput.trim()) return;

    const executablePath = pathInput.trim();
    // Warning if trying to trust script interpreter or shell
    const lower = executablePath.toLowerCase();
    if (lower.endsWith('powershell.exe') || lower.endsWith('cmd.exe') || lower.endsWith('cscript.exe') || lower.endsWith('wscript.exe')) {
      setErrorMsg('SECURITY POLICY: Trusting command shells or script engines inside Protected Folders is forbidden.');
      return;
    }

    const newApp: TrustedApplication = {
      canonicalPath: executablePath,
      sha256: shaInput.trim().toLowerCase() || 'pending-first-execution',
      name: nameInput.trim() || executablePath.split(/[\/\\]/).pop() || 'Application',
      addedAt: Date.now()
    };

    onRequestFrictionGate(`Grant Protected Folder access to application '${newApp.name}'`, async () => {
      try {
        if (window.desktopSecurity?.addTrustedApplication) {
          const updated = await window.desktopSecurity.addTrustedApplication(newApp);
          setApps(updated);
          setPathInput('');
          setNameInput('');
          setShaInput('');
          setNotice(`Trusted application registered: ${newApp.name}`);
        }
      } catch (err: any) {
        setErrorMsg(`Failed to register trusted app: ${err?.message || 'Registration rejected'}`);
      }
    });
  };

  const handleRemove = (executablePath: string) => {
    onRequestFrictionGate(`Revoke Protected Folder trust for '${executablePath}'`, async () => {
      try {
        if (window.desktopSecurity?.removeTrustedApplication) {
          const updated = await window.desktopSecurity.removeTrustedApplication(executablePath);
          setApps(updated);
          setNotice(`Trust revoked for: ${executablePath}`);
        }
      } catch (err: any) {
        setErrorMsg(`Failed to revoke trust: ${err?.message}`);
      }
    });
  };

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🤝 Trusted Applications (Ransomware Shield)</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Applications authorized to perform bulk writes in Protected Folders. Pinned strictly to Canonical Path + SHA-256.
          </p>
        </div>
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

      {/* Add App Form */}
      <form
        onSubmit={handleAddApp}
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
          Register Trusted Binary (Gated by Friction Gate)
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
              Application Friendly Name
            </label>
            <input
              type="text"
              placeholder="e.g. Adobe Photoshop"
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
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

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
              Full Executable Path (.exe)
            </label>
            <input
              type="text"
              placeholder="e.g. C:\Program Files\Adobe\Photoshop.exe"
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
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
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#334155', marginBottom: '4px' }}>
            Pinned SHA-256 Binary Hash (Optional — automatically verified on disk)
          </label>
          <input
            type="text"
            placeholder="64-character SHA-256 hash or leave empty for auto-pin"
            value={shaInput}
            onChange={(e) => setShaInput(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 10px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              fontFamily: 'monospace',
              boxSizing: 'border-box'
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
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
            + Authorize Application
          </button>
        </div>
      </form>

      {/* List of Trusted Applications */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          overflow: 'hidden'
        }}
      >
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #e2e8f0', fontWeight: 700, fontSize: '14px' }}>
          Authorized Applications ({apps.length})
        </div>

        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            Loading trusted applications...
          </div>
        ) : apps.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
            🛡️ Zero custom trusted applications. Only verified Microsoft OS binaries can write to Protected Folders.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', color: '#475569' }}>
                  <th style={{ padding: '10px 14px' }}>Application</th>
                  <th style={{ padding: '10px 14px' }}>Path</th>
                  <th style={{ padding: '10px 14px' }}>Pinned SHA-256</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {apps.map((a) => (
                  <tr key={a.canonicalPath} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td style={{ padding: '10px 14px', fontWeight: 700, color: '#0f172a' }}>
                      {a.name || 'Application'}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#334155', wordBreak: 'break-all' }}>
                      {a.canonicalPath}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#64748b' }}>
                      {a.sha256 ? `${a.sha256.slice(0, 16)}...` : 'Auto-pin'}
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => handleRemove(a.canonicalPath)}
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
                        Revoke Trust
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
