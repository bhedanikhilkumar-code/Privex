import { describe, it, expect } from 'vitest';
import { WebsiteEntryPointAnalyzer } from '../../analyzers/website-entry-point-analyzer';

describe('WebsiteEntryPointAnalyzer', () => {
  const analyzer = new WebsiteEntryPointAnalyzer();

  it('handles empty or missing input safely', () => {
    const report = analyzer.analyzeWebsite('');
    expect(report.overallExposureRisk).toBe('SECURE');
    expect(report.openPointsDetected).toBe(0);
    expect(report.openEntryPoints).toEqual([]);
    expect(report.isOfflineEvaluation).toBe(true);
  });

  it('detects unencrypted HTTP port 80 exposure and provides remediation', () => {
    const report = analyzer.analyzeWebsite('http://insecure-site.org');
    expect(report.protocol).toBe('http:');
    const point = report.openEntryPoints.find(p => p.id === 'open-port-80-http');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('MEDIUM');
    expect(point?.hackerAttackVector).toContain('Man-in-the-Middle');
    expect(point?.remediationSolution.steps.length).toBeGreaterThan(0);
    expect(point?.remediationSolution.category).toBe('CRYPTO_TLS');
  });

  it('detects exposed MySQL database port :3306', () => {
    const report = analyzer.analyzeWebsite('http://company-internal.com:3306');
    const point = report.openEntryPoints.find(p => p.id === 'open-port-3306');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('CRITICAL');
    expect(point?.hackerAttackVector).toContain('dictionary attacks');
    expect(point?.remediationSolution.steps).toContain('Block external inbound port 3306 on the host firewall.');
  });

  it('detects exposed Redis port :6379 with remote execution warning', () => {
    const report = analyzer.analyzeWebsite('http://192.168.1.10:6379');
    const point = report.openEntryPoints.find(p => p.id === 'open-port-6379');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('CRITICAL');
    expect(point?.hackerAttackVector).toContain('Remote Code Execution');
    expect(point?.remediationSolution.category).toBe('SERVER_HARDENING');
  });

  it('detects exposed RDP port :3389 and flags ransomware vector', () => {
    const report = analyzer.analyzeWebsite('http://workstation.corp.net:3389');
    const point = report.openEntryPoints.find(p => p.id === 'open-port-3389');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('CRITICAL');
    expect(point?.hackerAttackVector).toContain('ransomware');
  });

  it('detects exposed sensitive .env / .git files', () => {
    const report = analyzer.analyzeWebsite('https://example.com/.env');
    const point = report.openEntryPoints.find(p => p.id === 'exposed-sensitive-file-endpoint');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('CRITICAL');
    expect(point?.hackerAttackVector).toContain('harvest database passwords');
    expect(point?.remediationSolution.technicalCodeSnippet).toContain('deny all');
  });

  it('detects exposed admin portal /admin', () => {
    const report = analyzer.analyzeWebsite('https://example.com/admin/login');
    const point = report.openEntryPoints.find(p => p.id === 'exposed-admin-portal');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('HIGH');
    expect(point?.hackerAttackVector).toContain('credential-stuffing');
    expect(point?.remediationSolution.steps.some(s => s.includes('Multi-Factor Authentication'))).toBe(true);
  });

  it('detects actuator / debug endpoints', () => {
    const report = analyzer.analyzeWebsite('https://api.example.com/actuator/env');
    const point = report.openEntryPoints.find(p => p.id === 'exposed-debug-actuator-endpoint');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('HIGH');
    expect(point?.hackerAttackVector).toContain('introspection');
  });

  it('detects open redirect parameters in query strings', () => {
    const report = analyzer.analyzeWebsite('https://example.com/login?redirect=https://evil-phish.com');
    const point = report.openEntryPoints.find(p => p.id === 'open-redirect-parameter');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('MEDIUM');
    expect(point?.hackerAttackVector).toContain('credential harvesting site');
  });

  it('detects injection attack payloads in URL', () => {
    const report = analyzer.analyzeWebsite('https://example.com/search?q=1%20union%20select%20null,password');
    const point = report.openEntryPoints.find(p => p.id === 'url-injection-payload-vector');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('CRITICAL');
  });

  it('computes overall exposure risk and score accurately', () => {
    const criticalReport = analyzer.analyzeWebsite('http://192.168.1.10:3306/.env');
    expect(criticalReport.overallExposureRisk).toBe('CRITICAL');
    expect(criticalReport.exposureScore).toBeGreaterThanOrEqual(60);
    expect(criticalReport.openPointsDetected).toBeGreaterThanOrEqual(2);
  });

  it('retrieves all standard known port profiles for education', () => {
    const profiles = WebsiteEntryPointAnalyzer.getAllKnownPortProfiles();
    expect(profiles.length).toBeGreaterThan(5);
    expect(profiles.some(p => p.port === 80)).toBe(true);
    expect(profiles.some(p => p.port === 22)).toBe(true);
    expect(profiles.some(p => p.port === 3306)).toBe(true);
  });

  it('detects exposed XML-RPC user enumeration vectors', () => {
    const report = analyzer.analyzeWebsite('https://atmiyauni.ac.in/xmlrpc.php');
    const point = report.openEntryPoints.find(p => p.id === 'exposed-xmlrpc-user-enum');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('HIGH');
    expect(point?.hackerAttackVector).toContain('xmlrpc.php');
    expect(point?.remediationSolution.steps.length).toBeGreaterThan(0);
  });

  it('detects exposed file upload and attachment directories', () => {
    const report = analyzer.analyzeWebsite('https://atmiyauni.ac.in/wp-content/uploads/shell.php');
    const point = report.openEntryPoints.find(p => p.id === 'exposed-upload-directory-endpoint');
    expect(point).toBeDefined();
    expect(point?.severity).toBe('HIGH');
    expect(point?.hackerAttackVector).toContain('web shells');
  });
});
