import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MobileThreatIntelService } from '../../services/mobile-threat-intel.service';

describe('MobileThreatIntelService', () => {
  beforeEach(() => {
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
  });

  it('provides default fallback metadata when native bridge is absent', async () => {
    const status = await MobileThreatIntelService.inspectDatabaseHealth();

    expect(status.isVerified).toBe(true);
    expect(status.activeMetadata.versionSequence).toBe(100);
    expect(status.activeMetadata.installedVersion).toBe('1.0.0-seed');
    expect(status.activeMetadata.isFactorySeed).toBe(true);
    expect(status.activeMetadata.recordsCount).toBe(11);
    expect(status.stalenessState).toBe('FRESH');
  });

  it('correctly reads status from window.AndroidSecurityBridge', async () => {
    const mockBridgeMetadata = {
      database_version: '101',
      version_sequence: '105',
      installed_version: '1.0.5',
      published_at: String(Date.now() - 1000 * 60 * 60 * 24 * 3), // 3 days ago
      last_verified_at: String(Date.now()),
      source_feed: 'OFFICIAL_PRIVEX_INTEL',
      records_count: '250',
      sha256_digest: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      is_factory_seed: 'false',
      status: 'ACTIVE'
    };

    (window as any).AndroidSecurityBridge = {
      getThreatDatabaseMetadata: vi.fn().mockReturnValue(JSON.stringify(mockBridgeMetadata))
    };

    const status = await MobileThreatIntelService.inspectDatabaseHealth();

    expect(status.isVerified).toBe(true);
    expect(status.activeMetadata.installedVersion).toBe('1.0.5');
    expect(status.activeMetadata.versionSequence).toBe(105);
    expect(status.activeMetadata.isFactorySeed).toBe(false);
    expect(status.activeMetadata.recordsCount).toBe(250);
    expect(status.stalenessState).toBe('FRESH');
  });

  it('calculates staleness correctly for AGED, STALE, and EXPIRED_CACHE timestamps', async () => {
    // 10 days ago -> AGED (between 7 and 30 days)
    const agedMetadata = {
      database_version: '101',
      version_sequence: '102',
      installed_version: '1.0.2',
      published_at: String(Date.now() - 1000 * 60 * 60 * 24 * 10),
      last_verified_at: String(Date.now()),
      source_feed: 'OFFICIAL_PRIVEX_INTEL',
      records_count: '150',
      sha256_digest: 'abc',
      is_factory_seed: 'false',
      status: 'ACTIVE'
    };

    (window as any).AndroidSecurityBridge = {
      getThreatDatabaseMetadata: vi.fn().mockReturnValue(JSON.stringify(agedMetadata))
    };

    let status = await MobileThreatIntelService.inspectDatabaseHealth();
    expect(status.stalenessState).toBe('AGED');

    // 45 days ago -> STALE (> 30 days)
    const staleMetadata = {
      ...agedMetadata,
      published_at: String(Date.now() - 1000 * 60 * 60 * 24 * 45)
    };

    (window as any).AndroidSecurityBridge.getThreatDatabaseMetadata = vi.fn().mockReturnValue(JSON.stringify(staleMetadata));
    status = await MobileThreatIntelService.inspectDatabaseHealth();
    expect(status.stalenessState).toBe('STALE');

    // 100 days ago -> EXPIRED_CACHE (> 90 days)
    const expiredMetadata = {
      ...agedMetadata,
      published_at: String(Date.now() - 1000 * 60 * 60 * 24 * 100)
    };

    (window as any).AndroidSecurityBridge.getThreatDatabaseMetadata = vi.fn().mockReturnValue(JSON.stringify(expiredMetadata));
    status = await MobileThreatIntelService.inspectDatabaseHealth();
    expect(status.stalenessState).toBe('EXPIRED_CACHE');
  });

  it('handles applySignedUpdate correctly through native bridge', async () => {
    const mockBridgeResult = {
      success: true,
      code: 'OK',
      message: 'Successfully verified and applied update sequence 105'
    };

    (window as any).AndroidSecurityBridge = {
      applyThreatDatabaseSignedUpdate: vi.fn().mockReturnValue(JSON.stringify(mockBridgeResult))
    };

    const res = await MobileThreatIntelService.applySignedUpdate('{"manifest":{},"payload":{}}');
    expect(res.success).toBe(true);
    expect(res.error).toBe('Successfully verified and applied update sequence 105');
    expect((window as any).AndroidSecurityBridge.applyThreatDatabaseSignedUpdate).toHaveBeenCalledWith(
      '{"manifest":{},"payload":{}}',
      ''
    );
  });

  it('handles applySignedUpdate errors gracefully', async () => {
    (window as any).AndroidSecurityBridge = {
      applyThreatDatabaseSignedUpdate: vi.fn().mockImplementation(() => {
        throw new Error('Bridge execution failed');
      })
    };

    const res = await MobileThreatIntelService.applySignedUpdate('{"manifest":{},"payload":{}}');
    expect(res.success).toBe(false);
    expect(res.error).toContain('Bridge execution failed');
  });

  it('handles rollbackToFactorySeed correctly through native bridge and fallback', async () => {
    // 1. Native bridge success
    (window as any).AndroidSecurityBridge = {
      rollbackThreatDatabaseToFactorySeed: vi.fn().mockReturnValue(true)
    };

    let success = await MobileThreatIntelService.rollbackToFactorySeed();
    expect(success).toBe(true);
    expect((window as any).AndroidSecurityBridge.rollbackThreatDatabaseToFactorySeed).toHaveBeenCalled();

    // 2. Fallback when bridge is absent
    delete (window as any).AndroidSecurityBridge;
    success = await MobileThreatIntelService.rollbackToFactorySeed();
    expect(success).toBe(true);
  });
});
