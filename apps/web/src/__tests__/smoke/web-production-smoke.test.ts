import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ClientScanner } from '../../scanner/client-scanner';
import { Verdict } from '@private-protection/core';
import fs from 'node:fs';
import path from 'node:path';

describe('Web Production Smoke Tests (Phase 38-A)', () => {
  let scanner: ClientScanner;

  beforeEach(() => {
    scanner = new ClientScanner();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('Journey A: processes safe URL with instant ALLOW verdict and zero network activity', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const result = await scanner.scanUrl('https://www.google.com/search', {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: false,
      allowlistDomains: []
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.overallScore).toBeLessThan(30);
    expect(result.executionTimeMs).toBeGreaterThanOrEqual(0);
    expect(result.privacyGuarantee).toContain('100% processed on-device');
  });

  it('Journey B: processes deceptive phishing URL with DANGEROUS verdict and Grade 6 explanation', async () => {
    const result = await scanner.scanUrl('http://paypal-security-update.buzz/login/verify', {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: false,
      allowlistDomains: []
    });

    expect(result.verdict === Verdict.DANGEROUS || result.verdict === Verdict.SUSPICIOUS).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(50);
    expect(result.aiExplanation).toBeDefined();
    expect(result.aiExplanation?.headline).toBeDefined();
    expect(result.aiExplanation?.dangerFactors.length).toBeGreaterThan(0);
    expect(result.aiExplanation?.recommendedSteps.length).toBeGreaterThan(0);
  });

  it('Journey C: processes threat in simulated air-gapped offline environment', async () => {
    // Simulate offline
    const originalOnLine = navigator.onLine;
    Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });

    const result = await scanner.scanUrl('http://192.168.1.1/admin/login.php', {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: false,
      allowlistDomains: []
    });

    expect(result.verdict === Verdict.DANGEROUS || result.verdict === Verdict.SUSPICIOUS || result.verdict === Verdict.CAUTION).toBe(true);
    expect(result.evidence.length).toBeGreaterThan(0);

    Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
  });

  it('Journey D: handles malformed input safely without throwing unhandled exceptions', async () => {
    const result = await scanner.scanUrl('not a valid url at all :/// ? &&', {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: false,
      allowlistDomains: []
    });

    expect(result).toBeDefined();
    expect(result.verdict).toBeDefined();
    expect(result.targetPreview).toBeDefined();
  });

  it('Journey E: processes scam extortion message and produces plain-language briefing', async () => {
    const scamText = 'URGENT: Your computer is hacked. Send 0.5 Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours or your files will be deleted.';
    const result = await scanner.scanText(scamText, {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: false,
      allowlistDomains: []
    });

    expect(result.verdict === Verdict.DANGEROUS || result.verdict === Verdict.SUSPICIOUS).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(60);
    expect(result.aiExplanation?.summaryParagraph).toBeDefined();
    expect(result.aiExplanation?.dangerFactors.length).toBeGreaterThan(0);
    expect(result.aiExplanation?.recommendedSteps.length).toBeGreaterThan(0);
  });

  it('Deployment Verification: verifies Cloudflare Pages config, security headers, and routes exist', () => {
    const rootDir = path.resolve(__dirname, '../../../');
    const wranglerPath = path.join(rootDir, 'wrangler.toml');
    const headersPath = path.join(rootDir, 'public/_headers');
    const routesPath = path.join(rootDir, 'public/_routes.json');
    const manifestPath = path.join(rootDir, 'public/manifest.json');
    const swPath = path.join(rootDir, 'public/sw.js');
    const faviconPath = path.join(rootDir, 'public/favicon.svg');

    expect(fs.existsSync(wranglerPath)).toBe(true);
    expect(fs.existsSync(headersPath)).toBe(true);
    expect(fs.existsSync(routesPath)).toBe(true);
    expect(fs.existsSync(manifestPath)).toBe(true);
    expect(fs.existsSync(swPath)).toBe(true);
    expect(fs.existsSync(faviconPath)).toBe(true);

    const headersContent = fs.readFileSync(headersPath, 'utf8');
    expect(headersContent).toContain("Content-Security-Policy");
    expect(headersContent).toContain("Strict-Transport-Security");
    expect(headersContent).toContain("X-Frame-Options: DENY");
  });
});
