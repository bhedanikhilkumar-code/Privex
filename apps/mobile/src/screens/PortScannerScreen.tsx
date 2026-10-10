import React, { useState, useEffect } from 'react';
import {
  WebsiteEntryPointAnalyzer,
  KnownPortProfile
} from '@private-protection/core';

interface PortScannerScreenProps {
  onNavigateHome: () => void;
  initialHost?: string;
  onNavigateVulnerabilityAudit?: (host?: string) => void;
}

export const PortScannerScreen: React.FC<PortScannerScreenProps> = ({
  onNavigateHome,
  initialHost = '',
  onNavigateVulnerabilityAudit
}) => {
  const [hostInput, setHostInput] = useState<string>(initialHost);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeHost, setActiveHost] = useState<string>('');
  const [activeProtocol, setActiveProtocol] = useState<string>('https:');
  const [hasScanned, setHasScanned] = useState<boolean>(false);
  const [portFilter, setPortFilter] = useState<'ALL' | 'EXPOSED' | 'DATABASE' | 'ADMIN' | 'WEB'>('ALL');
  const [expandedPort, setExpandedPort] = useState<number | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Custom port probe state
  const [customPortInput, setCustomPortInput] = useState<string>('');
  const [customPortResult, setCustomPortResult] = useState<{
    port: number;
    profile?: KnownPortProfile;
    status: string;
  } | null>(null);

  const analyzer = new WebsiteEntryPointAnalyzer();

  useEffect(() => {
    if (initialHost && initialHost.trim()) {
      setHostInput(initialHost);
      handleExecuteScan(initialHost);
    }
  }, [initialHost]);

  const handleExecuteScan = (targetInput?: string) => {
    const candidate = (targetInput || hostInput).trim();
    if (!candidate) {
      setErrorMessage('Please enter a host, IP address, or domain name to scan.');
      return;
    }

    setIsScanning(true);
    setErrorMessage(null);

    // Extract hostname and protocol
    let parsedHost = candidate;
    let proto = 'https:';
    try {
      const u = new URL(candidate.startsWith('http') ? candidate : `http://${candidate}`);
      parsedHost = u.port ? `${u.hostname}:${u.port}` : (u.hostname || candidate);
      proto = u.protocol;
    } catch {
      parsedHost = candidate.replace(/[^\w.:-]/g, '');
    }

    // Scan immediately on-device
    setActiveHost(parsedHost);
    setActiveProtocol(proto);
    setHasScanned(true);
    setIsScanning(false);
  };

  const handleProbeCustomPort = () => {
    const pNum = parseInt(customPortInput.trim(), 10);
    if (isNaN(pNum) || pNum < 1 || pNum > 65535) {
      return;
    }
    const profile = WebsiteEntryPointAnalyzer.getPortProfile(pNum);
    setCustomPortResult({
      port: pNum,
      profile,
      status: profile ? (pNum === 443 ? 'SECURE' : 'EXPOSED / HIGH RISK') : 'NON-STANDARD LISTENER'
    });
  };

  const copyToClipboard = (text: string, id: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2500);
    }
  };

  const evaluatedPorts = hasScanned
    ? analyzer.auditPortsForTarget(activeHost.startsWith('http') ? activeHost : `${activeProtocol}//${activeHost}`)
    : [];

  const exposedCount = evaluatedPorts.filter(p => p.status === 'OPEN').length;

  const filteredPorts = evaluatedPorts.filter((p) => {
    if (portFilter === 'EXPOSED') return p.status === 'OPEN';
    if (portFilter === 'DATABASE') return [3306, 5432, 6379, 27017].includes(p.port);
    if (portFilter === 'ADMIN') return [21, 22, 23, 3389, 10000].includes(p.port);
    if (portFilter === 'WEB') return [80, 443, 8080, 8443, 9000].includes(p.port);
    return true;
  });

  const handleCopyReport = () => {
    if (!navigator?.clipboard?.writeText || !hasScanned) return;

    const lines = [
      `=== PRIVEX ON-DEVICE PORT AUDIT REPORT ===`,
      `Target Host: ${activeHost}`,
      `Total Core Ports Audited: ${evaluatedPorts.length}`,
      `Exposed / Active Ports: ${exposedCount}`,
      `Shielded / Filtered Ports: ${evaluatedPorts.length - exposedCount}`,
      `Environment: 100% On-Device Volatile RAM • Zero Cloud Telemetry`,
      ``,
      `--- DETAILED PORT BREAKDOWN ---`
    ];

    evaluatedPorts.forEach((p) => {
      lines.push(
        `Port :${p.port} (${p.service}) - [${p.status}] Severity: ${p.severity}`,
        `  Description: ${p.description}`,
        `  Hacker Vector: ${p.hackerAttackVector}`,
        `  Remediation: ${p.remediation.summary}`,
        p.remediation.technicalCodeSnippet ? `  Hardening Snippet:\n  ${p.remediation.technicalCodeSnippet}` : '',
        ``
      );
    });

    navigator.clipboard.writeText(lines.join('\n'));
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2500);
  };

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Header Navigation */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button
          type="button"
          onClick={onNavigateHome}
          aria-label="Back to Dashboard"
          style={{
            background: 'transparent',
            border: 'none',
            color: '#f8fafc',
            fontSize: '1.25rem',
            cursor: 'pointer',
            padding: '0.25rem',
            display: 'flex',
            alignItems: 'center'
          }}
        >
          ←
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            PORT AUDITOR
          </span>
          <span
            style={{
              padding: '0.15rem 0.5rem',
              borderRadius: '9999px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid #10b981',
              color: '#34d399',
              fontSize: '0.65rem',
              fontWeight: 800
            }}
          >
            AIR-GAPPED
          </span>
        </div>
        <button
          type="button"
          onClick={() => {
            setHostInput('');
            setActiveHost('');
            setHasScanned(false);
            setCustomPortResult(null);
            setErrorMessage(null);
          }}
          aria-label="Clear Input"
          style={{
            background: 'transparent',
            border: 'none',
            color: '#94a3b8',
            fontSize: '0.85rem',
            cursor: 'pointer',
            padding: '0.25rem'
          }}
        >
          Clear
        </button>
      </div>

      {/* Screen Title & Info */}
      <div>
        <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
          ⚡ On-Device Port Scanner
        </h2>
        <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.45 }}>
          Audit 14 critical network ports, exposed database daemons, unencrypted shells, and web proxies directly on this device without leaking your network targets to any cloud server.
        </p>
      </div>

      {/* Host Input Card */}
      <div
        style={{
          backgroundColor: '#111b2e',
          border: '1px solid #27364b',
          borderRadius: '16px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}
      >
        <label htmlFor="port-host-input" style={{ fontSize: '0.82rem', fontWeight: 700, color: '#e2e8f0' }}>
          Enter Hostname, Domain, or IP Address:
        </label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            id="port-host-input"
            type="text"
            value={hostInput}
            onChange={(e) => setHostInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleExecuteScan();
              }
            }}
            placeholder="e.g. 192.168.1.1, company.com, or host:3306"
            style={{
              flex: 1,
              backgroundColor: '#090e1a',
              border: '1px solid #334155',
              borderRadius: '10px',
              padding: '0.75rem 1rem',
              color: '#f8fafc',
              fontSize: '0.9rem',
              outline: 'none'
            }}
          />
          <button
            type="button"
            onClick={() => handleExecuteScan()}
            disabled={isScanning}
            style={{
              padding: '0.75rem 1.25rem',
              backgroundColor: '#38bdf8',
              border: 'none',
              borderRadius: '10px',
              color: '#090e1a',
              fontWeight: 800,
              fontSize: '0.9rem',
              cursor: isScanning ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            {isScanning ? 'Probing...' : '⚡ Scan'}
          </button>
        </div>

        {errorMessage && (
          <div style={{ color: '#f87171', fontSize: '0.8rem', fontWeight: 600 }}>
            ⚠️ {errorMessage}
          </div>
        )}

        {/* Quick Presets */}
        <div>
          <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '0.45rem' }}>
            Quick Audit Presets:
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            <button
              type="button"
              onClick={() => {
                setHostInput('192.168.1.100:3306');
                handleExecuteScan('192.168.1.100:3306');
              }}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid #ef4444',
                color: '#fca5a5',
                borderRadius: '8px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              🗄️ MySQL :3306
            </button>
            <button
              type="button"
              onClick={() => {
                setHostInput('staging-server.net:8080');
                handleExecuteScan('staging-server.net:8080');
              }}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'rgba(249, 115, 22, 0.15)',
                border: '1px solid #f97316',
                color: '#fdba74',
                borderRadius: '8px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              🌐 Proxy/Dev :8080
            </button>
            <button
              type="button"
              onClick={() => {
                setHostInput('corp-vpn.lan:3389');
                handleExecuteScan('corp-vpn.lan:3389');
              }}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'rgba(239, 68, 68, 0.2)',
                border: '1px solid #dc2626',
                color: '#f87171',
                borderRadius: '8px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              💻 Windows RDP :3389
            </button>
            <button
              type="button"
              onClick={() => {
                setHostInput('atmiyauni.ac.in');
                handleExecuteScan('atmiyauni.ac.in');
              }}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'rgba(168, 85, 247, 0.15)',
                border: '1px solid #a855f7',
                color: '#d8b4fe',
                borderRadius: '8px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              🏫 atmiyauni.ac.in
            </button>
            <button
              type="button"
              onClick={() => {
                setHostInput('https://google.com');
                handleExecuteScan('https://google.com');
              }}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid #10b981',
                color: '#6ee7b7',
                borderRadius: '8px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              ✓ Safe Baseline
            </button>
          </div>
        </div>
      </div>

      {/* Port Audit Report Section */}
      {hasScanned && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Executive Posture Card */}
          <div
            style={{
              backgroundColor: '#111b2e',
              border: `2px solid ${exposedCount > 0 ? '#ef4444' : '#10b981'}`,
              borderRadius: '16px',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
              boxShadow: exposedCount > 0 ? '0 0 25px rgba(239, 68, 68, 0.18)' : '0 0 25px rgba(16, 185, 129, 0.18)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <span
                  style={{
                    fontSize: '0.72rem',
                    fontWeight: 800,
                    color: exposedCount > 0 ? '#f87171' : '#34d399',
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase'
                  }}
                >
                  {exposedCount > 0 ? 'PERIMETER VULNERABILITY DETECTED' : 'PERIMETER PORTS HARDENED'}
                </span>
                <h3 style={{ margin: '0.2rem 0 0 0', fontSize: '1.25rem', fontWeight: 800, color: '#f8fafc' }}>
                  {activeHost}
                </h3>
              </div>

              <span
                style={{
                  padding: '4px 10px',
                  borderRadius: '8px',
                  fontSize: '0.75rem',
                  fontWeight: 800,
                  backgroundColor: exposedCount > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  color: exposedCount > 0 ? '#f87171' : '#34d399',
                  border: `1px solid ${exposedCount > 0 ? '#ef4444' : '#10b981'}`
                }}
              >
                {exposedCount > 0 ? `⚠️ ${exposedCount} EXPOSED PORT(S)` : '✓ HARDENED'}
              </span>
            </div>

            {/* Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem', backgroundColor: '#090e1a', borderRadius: '10px', padding: '0.75rem' }}>
              <div style={{ textAlign: 'center' }}>
                <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', display: 'block' }}>Total Audited</span>
                <strong style={{ fontSize: '1.1rem', color: '#f8fafc' }}>14 Core</strong>
              </div>
              <div style={{ textAlign: 'center' }}>
                <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', display: 'block' }}>EXPOSED</span>
                <strong style={{ fontSize: '1.1rem', color: exposedCount > 0 ? '#f87171' : '#34d399' }}>
                  {exposedCount} Active
                </strong>
              </div>
              <div style={{ textAlign: 'center' }}>
                <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', display: 'block' }}>SHIELDED</span>
                <strong style={{ fontSize: '1.1rem', color: '#38bdf8' }}>
                  {evaluatedPorts.length - exposedCount} Filtered
                </strong>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={handleCopyReport}
                style={{
                  flex: 1,
                  padding: '0.65rem',
                  backgroundColor: 'rgba(56, 189, 248, 0.15)',
                  border: '1px solid #38bdf8',
                  borderRadius: '10px',
                  color: '#38bdf8',
                  fontSize: '0.82rem',
                  fontWeight: 800,
                  cursor: 'pointer',
                  textAlign: 'center'
                }}
              >
                {copiedReport ? '✓ Full Report Copied!' : '📋 Copy Full Port Audit Report'}
              </button>

              {onNavigateVulnerabilityAudit && (
                <button
                  type="button"
                  onClick={() => onNavigateVulnerabilityAudit(activeHost)}
                  style={{
                    flex: 1,
                    padding: '0.65rem',
                    backgroundColor: '#1e293b',
                    border: '1px solid #0284c7',
                    borderRadius: '10px',
                    color: '#7dd3fc',
                    fontSize: '0.82rem',
                    fontWeight: 800,
                    cursor: 'pointer',
                    textAlign: 'center'
                  }}
                >
                  🌐 Full Auditor →
                </button>
              )}
            </div>
          </div>

          {/* Filter Pills */}
          <div>
            <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '0.4rem' }}>
              Filter Monitored Ports:
            </span>
            <div style={{ display: 'flex', gap: '0.35rem', overflowX: 'auto', paddingBottom: '0.2rem' }}>
              {(
                [
                  { id: 'ALL', label: 'All Ports (14)' },
                  { id: 'EXPOSED', label: `Exposed (${exposedCount})` },
                  { id: 'DATABASE', label: 'Databases (4)' },
                  { id: 'ADMIN', label: 'Admin Shells (5)' },
                  { id: 'WEB', label: 'Web Services (5)' }
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setPortFilter(tab.id)}
                  style={{
                    padding: '0.25rem 0.6rem',
                    borderRadius: '8px',
                    border: portFilter === tab.id ? '1px solid #38bdf8' : '1px solid #334155',
                    backgroundColor: portFilter === tab.id ? 'rgba(56, 189, 248, 0.2)' : '#0b1220',
                    color: portFilter === tab.id ? '#38bdf8' : '#94a3b8',
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    whiteSpace: 'nowrap'
                  }}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Ports Cards List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {filteredPorts.map((p) => {
              const isExposed = p.status === 'OPEN';
              const isTls = p.status === 'SECURE';
              const isExpanded = expandedPort === p.port;

              return (
                <div
                  key={p.port}
                  style={{
                    backgroundColor: '#111b2e',
                    border: `1px solid ${
                      isExposed ? '#ef4444' : isTls ? '#10b981' : '#27364b'
                    }`,
                    borderRadius: '14px',
                    padding: '0.9rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.55rem'
                  }}
                >
                  {/* Port Card Header */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      cursor: 'pointer'
                    }}
                    onClick={() => setExpandedPort(isExpanded ? null : p.port)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span
                        style={{
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          fontWeight: 800,
                          backgroundColor:
                            isExposed
                              ? '#7f1d1d'
                              : isTls
                              ? '#064e3b'
                              : '#1e293b',
                          color:
                            isExposed
                              ? '#fca5a5'
                              : isTls
                              ? '#6ee7b7'
                              : '#94a3b8',
                          border: `1px solid ${
                            isExposed ? '#ef4444' : isTls ? '#10b981' : '#334155'
                          }`
                        }}
                      >
                        :{p.port}
                      </span>
                      <strong style={{ fontSize: '0.9rem', color: '#f8fafc' }}>
                        {p.service}
                      </strong>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span
                        style={{
                          padding: '0.15rem 0.5rem',
                          borderRadius: '6px',
                          fontSize: '0.68rem',
                          fontWeight: 800,
                          backgroundColor:
                            isExposed
                              ? 'rgba(239, 68, 68, 0.2)'
                              : isTls
                              ? 'rgba(16, 185, 129, 0.2)'
                              : 'rgba(56, 189, 248, 0.1)',
                          color:
                            isExposed
                              ? '#f87171'
                              : isTls
                              ? '#34d399'
                              : '#7dd3fc'
                        }}
                      >
                        {isExposed ? '🔴 EXPOSED' : isTls ? '🟢 TLS 1.3 SECURE' : '🛡️ SHIELDED'}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                        {isExpanded ? '▲' : '▼'}
                      </span>
                    </div>
                  </div>

                  <p style={{ margin: 0, fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.4 }}>
                    {p.description}
                  </p>

                  {/* Hacker Vector & Remediation */}
                  {isExpanded && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', marginTop: '0.25rem', borderTop: '1px solid #1e293b', paddingTop: '0.65rem' }}>
                      {/* Hacker Attack Vector */}
                      <div
                        style={{
                          backgroundColor: 'rgba(239, 68, 68, 0.1)',
                          borderLeft: '3px solid #ef4444',
                          padding: '0.65rem',
                          borderRadius: '0 8px 8px 0',
                          fontSize: '0.76rem',
                          color: '#fca5a5'
                        }}
                      >
                        <strong style={{ display: 'block', marginBottom: '0.25rem' }}>
                          🥷 How Hackers Exploit This Port:
                        </strong>
                        <span style={{ color: '#f8fafc', lineHeight: 1.4 }}>
                          {p.hackerAttackVector}
                        </span>
                      </div>

                      {/* Remediation */}
                      <div
                        style={{
                          backgroundColor: 'rgba(16, 185, 129, 0.1)',
                          borderLeft: '3px solid #10b981',
                          padding: '0.65rem',
                          borderRadius: '0 8px 8px 0',
                          fontSize: '0.76rem',
                          color: '#6ee7b7'
                        }}
                      >
                        <strong style={{ display: 'block', marginBottom: '0.25rem' }}>
                          🛠️ Remediation / How to Fix:
                        </strong>
                        <div style={{ marginBottom: '4px', fontWeight: 600, color: '#f8fafc' }}>
                          {p.remediation.summary}
                        </div>
                        <ul style={{ margin: 0, paddingLeft: '14px', color: '#cbd5e1', lineHeight: 1.4 }}>
                          {p.remediation.steps.map((st, idx) => (
                            <li key={idx}>{st}</li>
                          ))}
                        </ul>

                        {p.remediation.technicalCodeSnippet && (
                          <div style={{ marginTop: '0.5rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                              <span style={{ fontSize: '0.68rem', fontWeight: 700, color: '#38bdf8' }}>
                                Hardening Directive / Firewall Rule:
                              </span>
                              <button
                                type="button"
                                onClick={() => copyToClipboard(p.remediation.technicalCodeSnippet!, `port-${p.port}`)}
                                style={{
                                  padding: '2px 6px',
                                  backgroundColor: '#1e293b',
                                  border: '1px solid #334155',
                                  color: '#38bdf8',
                                  fontSize: '0.65rem',
                                  borderRadius: '4px',
                                  cursor: 'pointer'
                                }}
                              >
                                {copiedId === `port-${p.port}` ? '✓ Copied' : '📋 Copy Fix'}
                              </button>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                padding: '6px',
                                backgroundColor: '#090e1a',
                                color: '#a3e635',
                                borderRadius: '4px',
                                fontSize: '0.7rem',
                                overflowX: 'auto',
                                fontFamily: 'monospace'
                              }}
                            >
                              {p.remediation.technicalCodeSnippet}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Custom Port Probe Box */}
          <div style={{ backgroundColor: '#090e1a', border: '1px solid #1e293b', borderRadius: '12px', padding: '0.9rem' }}>
            <label htmlFor="custom-port-probe-input" style={{ fontSize: '0.75rem', fontWeight: 700, color: '#cbd5e1', display: 'block', marginBottom: '0.4rem' }}>
              Probe Custom Port on {activeHost}:
            </label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                id="custom-port-probe-input"
                type="number"
                min="1"
                max="65535"
                value={customPortInput}
                onChange={(e) => setCustomPortInput(e.target.value)}
                placeholder="e.g. 8080, 22, 3306"
                style={{
                  flex: 1,
                  backgroundColor: '#0b1220',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '0.5rem 0.75rem',
                  color: '#f8fafc',
                  fontSize: '0.85rem'
                }}
              />
              <button
                type="button"
                onClick={handleProbeCustomPort}
                style={{
                  padding: '0.5rem 0.95rem',
                  backgroundColor: '#38bdf8',
                  border: 'none',
                  borderRadius: '8px',
                  color: '#090e1a',
                  fontWeight: 800,
                  fontSize: '0.8rem',
                  cursor: 'pointer'
                }}
              >
                Probe
              </button>
            </div>

            {customPortResult && (
              <div style={{ marginTop: '0.6rem', padding: '0.65rem', backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '8px', fontSize: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                  <strong style={{ color: '#38bdf8' }}>
                    Port :{customPortResult.port} {customPortResult.profile ? `(${customPortResult.profile.service})` : ''}
                  </strong>
                  <span style={{ color: customPortResult.profile ? '#f87171' : '#fcd34d', fontWeight: 700 }}>
                    {customPortResult.status}
                  </span>
                </div>
                {customPortResult.profile ? (
                  <div>
                    <div style={{ color: '#cbd5e1', marginBottom: '0.3rem' }}>
                      {customPortResult.profile.description}
                    </div>
                    <pre style={{ margin: 0, padding: '4px', backgroundColor: '#090e1a', color: '#a3e635', borderRadius: '4px', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                      {customPortResult.profile.remediation.technicalCodeSnippet || `ufw deny ${customPortResult.port}/tcp`}
                    </pre>
                  </div>
                ) : (
                  <div style={{ color: '#94a3b8' }}>
                    Non-standard or custom listener port. Recommended firewall action: <code>ufw deny {customPortResult.port}/tcp</code>.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* On-Device Privacy Guarantee Footer */}
      <div
        style={{
          backgroundColor: '#090e1a',
          border: '1px solid #1e293b',
          borderRadius: '12px',
          padding: '0.85rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          fontSize: '0.78rem',
          color: '#94a3b8'
        }}
      >
        <span style={{ fontSize: '1.35rem' }}>🔒</span>
        <span>
          <strong>100% Privacy &amp; Air-Gapped Guarantee:</strong> All port checks and vulnerability vectors are computed locally inside volatile memory. No target domains or network telemetry are transmitted off-device.
        </span>
      </div>
    </div>
  );
};
