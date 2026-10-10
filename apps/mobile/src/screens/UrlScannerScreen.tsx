import React, { useState } from 'react';
import { UrlScannerService } from '../services/url-scanner.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import { MobileScanResult } from '../types/mobile.types';
import { ScanResultScreen } from './ScanResultScreen';
import {
  WebsiteEntryPointAnalyzer,
  WebsiteAuditReport,
  ExposedEntryPoint
} from '@private-protection/core';

interface UrlScannerScreenProps {
  scannerService: UrlScannerService;
  onNavigateHome: () => void;
  initialUrl?: string;
  autoScan?: boolean;
}

export const UrlScannerScreen: React.FC<UrlScannerScreenProps> = ({
  scannerService,
  onNavigateHome,
  initialUrl,
  autoScan
}) => {
  const [urlInput, setUrlInput] = useState<string>(initialUrl || '');
  const [activeTab, setActiveTab] = useState<'PHISHING' | 'ATTACK_SURFACE'>('PHISHING');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<MobileScanResult | null>(null);
  const [auditReport, setAuditReport] = useState<WebsiteAuditReport | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const entryPointAnalyzer = new WebsiteEntryPointAnalyzer();

  React.useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      if (autoScan) {
        handleScan(initialUrl);
      }
    }
  }, [initialUrl, autoScan]);

  const handleScan = async (targetUrl?: string) => {
    const candidate = targetUrl || urlInput;
    if (!candidate.trim()) {
      setError('Please provide a URL to scan.');
      return;
    }

    setIsScanning(true);
    setError(null);

    try {
      if (activeTab === 'ATTACK_SURFACE') {
        const report = entryPointAnalyzer.analyzeWebsite(candidate);
        setAuditReport(report);
      } else {
        const settings = await SecureStorageService.getSettings();
        const result = await scannerService.scanUrl(
          candidate,
          settings.readingGrade,
          settings.allowlistDomains
        );

        setScanResult(result);

        // Also run entry point audit for link
        const report = entryPointAnalyzer.analyzeWebsite(candidate);
        setAuditReport(report);

        // Record non-sensitive metadata
        let domainSummary = candidate;
        try {
          const u = new URL(candidate.startsWith('http') ? candidate : `http://${candidate}`);
          domainSummary = u.hostname.substring(0, 15);
        } catch {
          domainSummary = candidate.substring(0, 15);
        }

        await SecureStorageService.recordScan({
          scanId: result.scanId,
          targetType: 'URL',
          sanitizedSummary: domainSummary,
          verdict: result.verdict,
          score: result.overallScore,
          timestamp: Date.now()
        });

        // Dispatch notification if flagged
        await NotificationService.notifyScanResult(result);
      }
    } catch (err: any) {
      setError(err.message || 'Scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2500);
    }
  };

  if (scanResult && activeTab === 'PHISHING') {
    return (
      <ScanResultScreen
        result={scanResult}
        auditReport={auditReport}
        onReset={() => {
          setScanResult(null);
          setAuditReport(null);
          setUrlInput('');
        }}
        onDone={onNavigateHome}
      />
    );
  }

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar with Back navigation & Sentry label */}
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
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          PRIVEX SENTRY
        </span>
        <button
          type="button"
          onClick={() => {
            setUrlInput('');
            setScanResult(null);
            setAuditReport(null);
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

      {/* Screen Title */}
      <div>
        <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
          On-Device URL Scanner &amp; Port Auditor
        </h2>
        <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.82rem', color: '#94a3b8' }}>
          Inspect phishing links, open hacker entry points, exposed database ports, and remediation blueprints.
        </p>
      </div>

      {/* Mode Selector Tabs */}
      <div style={{ display: 'flex', backgroundColor: '#0b1220', border: '1px solid #27364b', borderRadius: '12px', padding: '4px', gap: '4px' }}>
        <button
          type="button"
          onClick={() => setActiveTab('PHISHING')}
          style={{
            flex: 1,
            padding: '8px',
            borderRadius: '8px',
            border: 'none',
            backgroundColor: activeTab === 'PHISHING' ? '#38bdf8' : 'transparent',
            color: activeTab === 'PHISHING' ? '#090e1a' : '#94a3b8',
            fontWeight: 800,
            fontSize: '0.8rem',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          🔗 Phishing &amp; Link Scan
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('ATTACK_SURFACE')}
          style={{
            flex: 1,
            padding: '8px',
            borderRadius: '8px',
            border: 'none',
            backgroundColor: activeTab === 'ATTACK_SURFACE' ? '#38bdf8' : 'transparent',
            color: activeTab === 'ATTACK_SURFACE' ? '#090e1a' : '#94a3b8',
            fontWeight: 800,
            fontSize: '0.8rem',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          🛡️ Open Points &amp; Ports
        </button>
      </div>

      {/* Input Card Container */}
      <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div>
          <label htmlFor="url-input" style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'block', marginBottom: '0.5rem', fontWeight: 600 }}>
            {activeTab === 'ATTACK_SURFACE' ? 'Enter website URL or host with port to audit entry points:' : 'Enter URL to analyze for deception:'}
          </label>
          <div style={{ position: 'relative' }}>
            <span style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', fontSize: '1rem', color: '#64748b' }}>
              🌐
            </span>
            <input
              id="url-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder={activeTab === 'ATTACK_SURFACE' ? 'e.g. target.com:3306 or http://site.com/.env' : 'https://example.com/path...'}
              style={{
                padding: '0.85rem 1rem 0.85rem 2.6rem',
                backgroundColor: '#0b1220',
                border: '1px solid #27364b',
                borderRadius: '12px',
                color: '#f8fafc',
                fontSize: '0.92rem',
                width: '100%',
                boxSizing: 'border-box'
              }}
            />
          </div>
        </div>

        {error && (
          <div style={{ padding: '0.75rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', fontSize: '0.85rem' }}>
            {error}
          </div>
        )}

        <button
          type="button"
          disabled={isScanning}
          onClick={() => handleScan()}
          style={{
            marginTop: '0.25rem',
            padding: '0.85rem',
            backgroundColor: '#38bdf8',
            color: '#0b1220',
            fontWeight: 800,
            borderRadius: '12px',
            border: 'none',
            cursor: isScanning ? 'not-allowed' : 'pointer',
            fontSize: '0.95rem',
            boxShadow: '0 4px 12px rgba(56, 189, 248, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem'
          }}
        >
          🔍 {isScanning ? 'Analyzing On-Device...' : (activeTab === 'ATTACK_SURFACE' ? 'Audit Open Points (Offline)' : 'Scan Link')}
        </button>
      </div>

      {/* Attack Surface Audit Report (Rendered in ATTACK_SURFACE mode or when report is available) */}
      {auditReport && activeTab === 'ATTACK_SURFACE' && (
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase' }}>
                AUDIT REPORT
              </span>
              <h3 style={{ margin: '0.1rem 0 0 0', fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc' }}>
                {auditReport.hostname}
              </h3>
            </div>
            <span
              style={{
                padding: '4px 10px',
                borderRadius: '8px',
                fontSize: '0.75rem',
                fontWeight: 800,
                backgroundColor:
                  auditReport.overallExposureRisk === 'CRITICAL'
                    ? 'rgba(239, 68, 68, 0.2)'
                    : auditReport.overallExposureRisk === 'HIGH'
                    ? 'rgba(249, 115, 22, 0.2)'
                    : auditReport.overallExposureRisk === 'MODERATE'
                    ? 'rgba(234, 179, 8, 0.2)'
                    : 'rgba(16, 185, 129, 0.2)',
                color:
                  auditReport.overallExposureRisk === 'CRITICAL'
                    ? '#f87171'
                    : auditReport.overallExposureRisk === 'HIGH'
                    ? '#fb923c'
                    : auditReport.overallExposureRisk === 'MODERATE'
                    ? '#facc15'
                    : '#34d399',
                border: `1px solid ${
                  auditReport.overallExposureRisk === 'CRITICAL'
                    ? '#ef4444'
                    : auditReport.overallExposureRisk === 'HIGH'
                    ? '#f97316'
                    : auditReport.overallExposureRisk === 'MODERATE'
                    ? '#eab308'
                    : '#10b981'
                }`
              }}
            >
              {auditReport.overallExposureRisk} ({auditReport.openPointsDetected} OPEN)
            </span>
          </div>

          <p style={{ margin: 0, fontSize: '0.8rem', color: '#94a3b8' }}>
            {auditReport.summaryExplanation}
          </p>

          {auditReport.openEntryPoints.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {auditReport.openEntryPoints.map((point: ExposedEntryPoint) => (
                <div
                  key={point.id}
                  style={{
                    backgroundColor: '#0b1220',
                    border: '1px solid #1e293b',
                    borderRadius: '12px',
                    padding: '0.85rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.6rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span
                        style={{
                          fontSize: '0.65rem',
                          fontWeight: 800,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          backgroundColor: point.severity === 'CRITICAL' ? '#7f1d1d' : point.severity === 'HIGH' ? '#7c2d12' : '#713f12',
                          color: '#f8fafc'
                        }}
                      >
                        {point.severity}
                      </span>
                      <strong style={{ fontSize: '0.85rem', color: '#f8fafc' }}>{point.name}</strong>
                    </div>
                    <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                      {point.target}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                    {point.description}
                  </div>

                  {/* Hacker Exploit Mechanism */}
                  <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', padding: '0.6rem', fontSize: '0.75rem', color: '#fca5a5' }}>
                    <strong style={{ display: 'block', marginBottom: '2px' }}>
                      🥷 Hacker Exploitation Vector:
                    </strong>
                    {point.hackerAttackVector}
                  </div>

                  {/* Remediation & Code */}
                  <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '0.6rem', fontSize: '0.75rem', color: '#6ee7b7' }}>
                    <strong style={{ display: 'block', marginBottom: '2px' }}>
                      🛠️ Remediation / How to Fix:
                    </strong>
                    <div style={{ marginBottom: '4px', fontWeight: 600 }}>
                      {point.remediationSolution.summary}
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '14px' }}>
                      {point.remediationSolution.steps.map((st: string, i: number) => (
                        <li key={i} style={{ marginBottom: '2px' }}>{st}</li>
                      ))}
                    </ul>

                    {point.remediationSolution.technicalCodeSnippet && (
                      <div style={{ marginTop: '6px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                          <span style={{ fontSize: '0.7rem', fontWeight: 700 }}>Directive / Command:</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(point.remediationSolution.technicalCodeSnippet!, point.id)}
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
                            {copiedId === point.id ? '✓ Copied' : '📋 Copy'}
                          </button>
                        </div>
                        <pre style={{ margin: 0, padding: '6px', backgroundColor: '#090e1a', color: '#a3e635', borderRadius: '4px', fontSize: '0.7rem', overflowX: 'auto', fontFamily: 'monospace' }}>
                          {point.remediationSolution.technicalCodeSnippet}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', borderRadius: '10px', padding: '0.75rem', fontSize: '0.8rem', color: '#34d399' }}>
              ✓ No dangerous open ports or exposed files found on this domain. Perimeter verified clean.
            </div>
          )}
        </div>
      )}

      {/* Security Protocol Information Cards */}
      <div>
        <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
          Security Protocol
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '12px', padding: '1rem', display: 'flex', gap: '0.85rem', alignItems: 'flex-start' }}>
            <div style={{ padding: '0.5rem', backgroundColor: 'rgba(56, 189, 248, 0.1)', borderRadius: '8px', fontSize: '1.1rem' }}>
              🛡️
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', color: '#f8fafc', display: 'block' }}>On-Device Analysis</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4, display: 'block', marginTop: '0.2rem' }}>
                Analysis runs locally. Privex does not log your browsing history or full URL content.
              </span>
            </div>
          </div>

          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '12px', padding: '1rem', display: 'flex', gap: '0.85rem', alignItems: 'flex-start' }}>
            <div style={{ padding: '0.5rem', backgroundColor: 'rgba(16, 185, 129, 0.1)', borderRadius: '8px', fontSize: '1.1rem' }}>
              ⚡
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', color: '#f8fafc', display: 'block' }}>Offline Threat Intelligence</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4, display: 'block', marginTop: '0.2rem' }}>
                Cross-references against offline cryptographic threat database and port vulnerability signatures.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Test Sample Chips */}
      <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600 }}>Test Scenarios:</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={() => {
              setUrlInput('https://google.com');
              handleScan('https://google.com');
            }}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#34d399',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            ✓ Safe Baseline: https://google.com
          </button>

          <button
            type="button"
            onClick={() => {
              setUrlInput('http://192.168.1.100/login.php');
              handleScan('http://192.168.1.100/login.php');
            }}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f87171',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            🛑 IP Phishing: http://192.168.1.100/login.php
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('ATTACK_SURFACE');
              setUrlInput('http://internal-server.local:3306');
              handleScan('http://internal-server.local:3306');
            }}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#fb923c',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            🛡️ Open Port Attack Surface: http://internal-server.local:3306
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('ATTACK_SURFACE');
              setUrlInput('https://production-app.com/.env');
              handleScan('https://production-app.com/.env');
            }}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f87171',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            🚨 Exposed Secret File: https://production-app.com/.env
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('ATTACK_SURFACE');
              setUrlInput('https://atmiyauni.ac.in/');
              handleScan('https://atmiyauni.ac.in/');
            }}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #7c3aed',
              borderRadius: '8px',
              color: '#c084fc',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            🏫 University Audit Target: https://atmiyauni.ac.in/
          </button>
        </div>
      </div>
    </div>
  );
};
