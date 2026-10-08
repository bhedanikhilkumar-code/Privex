import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { FullDeviceScanServiceClient } from '../../services/full-device-scan.service';

describe('FullDeviceScanServiceClient (Phase T4)', () => {
  let client: FullDeviceScanServiceClient;

  beforeEach(() => {
    client = new FullDeviceScanServiceClient();
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
    vi.restoreAllMocks();
  });

  describe('Fallback / Web Simulation Mode', () => {
    it('returns isNativeBridgeAvailable as false when window.AndroidSecurityBridge is absent', () => {
      expect(client.isNativeBridgeAvailable()).toBe(false);
    });

    it('executes QUICK_SCAN in fallback mode with truthful coverage description', async () => {
      const job = await client.startDeviceScan('QUICK_SCAN');
      expect(job.type).toBe('STORAGE_SCAN');
      expect(job.state).toBe('COMPLETED');
      expect(job.result).toBeDefined();

      const report = job.result!;
      expect(report.scanMode).toBe('QUICK_SCAN');
      expect(report.coverage.isFullDeviceClaimed).toBe(false);
      expect(report.coverage.coverageDescription).toContain('Quick Scan');
    });

    it('executes FULL_ACCESSIBLE_SCAN in fallback mode with truthful restricted system scope', async () => {
      const job = await client.startDeviceScan('FULL_ACCESSIBLE_SCAN');
      const report = job.result!;
      expect(report.scanMode).toBe('FULL_ACCESSIBLE_SCAN');
      expect(report.coverage.isFullDeviceClaimed).toBe(false);
      expect(report.coverage.coverageDescription).toContain('Protected system directories were truthfully skipped');

      const restricted = report.scopes.find((s: any) => s.scopeId === 'scope_restricted_system');
      expect(restricted).toBeDefined();
      expect(restricted?.accessibilityState).toBe('INACCESSIBLE');
      expect(restricted?.scanStatus).toBe('SKIPPED');
    });

    it('handles mock SAF tree queries', async () => {
      const trees = await client.getPersistedSafTrees();
      expect(Array.isArray(trees)).toBe(true);
    });
  });

  describe('Native AndroidSecurityBridge Integration', () => {
    it('detects native bridge when startDeviceScan is present', () => {
      (window as any).AndroidSecurityBridge = {
        startDeviceScan: vi.fn(),
        getPersistedSafTrees: vi.fn(),
        persistSafTree: vi.fn(),
        releaseSafTree: vi.fn()
      };
      expect(client.isNativeBridgeAvailable()).toBe(true);
    });

    it('delegates startDeviceScan call to native bridge and parses job descriptor', async () => {
      const mockJob = {
        id: 'native_job_123',
        type: 'STORAGE_SCAN',
        state: 'RUNNING',
        progress: 10,
        createdAtMs: 1700000000000
      };

      (window as any).AndroidSecurityBridge = {
        startDeviceScan: vi.fn().mockReturnValue(JSON.stringify(mockJob)),
        getPersistedSafTrees: vi.fn(),
        persistSafTree: vi.fn(),
        releaseSafTree: vi.fn()
      };

      const job = await client.startDeviceScan('FULL_ACCESSIBLE_SCAN');
      expect((window as any).AndroidSecurityBridge.startDeviceScan).toHaveBeenCalledWith('FULL_ACCESSIBLE_SCAN');
      expect(job.id).toBe('native_job_123');
      expect(job.type).toBe('STORAGE_SCAN');
    });

    it('throws SCAN_INIT_FAILED when native bridge returns an error', async () => {
      (window as any).AndroidSecurityBridge = {
        startDeviceScan: vi.fn().mockReturnValue(JSON.stringify({ error: 'PERMISSION_DENIED' })),
        getPersistedSafTrees: vi.fn(),
        persistSafTree: vi.fn(),
        releaseSafTree: vi.fn()
      };

      await expect(client.startDeviceScan('QUICK_SCAN')).rejects.toThrow('SCAN_INIT_FAILED: PERMISSION_DENIED');
    });

    it('delegates persistSafTree and releaseSafTree to bridge', async () => {
      (window as any).AndroidSecurityBridge = {
        startDeviceScan: vi.fn(),
        getPersistedSafTrees: vi.fn().mockReturnValue(JSON.stringify([{ uri: 'content://tree/doc', isValid: true }])),
        persistSafTree: vi.fn().mockReturnValue(true),
        releaseSafTree: vi.fn().mockReturnValue(true)
      };

      const trees = await client.getPersistedSafTrees();
      expect(trees.length).toBe(1);
      expect(trees[0].uri).toBe('content://tree/doc');

      const persisted = await client.persistSafTree('content://tree/doc');
      expect(persisted).toBe(true);
      expect((window as any).AndroidSecurityBridge.persistSafTree).toHaveBeenCalledWith('content://tree/doc');

      const released = await client.releaseSafTree('content://tree/doc');
      expect(released).toBe(true);
      expect((window as any).AndroidSecurityBridge.releaseSafTree).toHaveBeenCalledWith('content://tree/doc');
    });
  });
});
