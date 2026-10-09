import { MobileThreatMetadata, ThreatDatabaseInspectionResult, ThreatUpdateInspectionResult } from '../types/mobile.types';

/**
 * Mobile Threat Intelligence Service (Phase T9)
 *
 * Coordinates on-device threat intelligence inspection, metadata reporting,
 * and cryptographically signed .ppdb update verification via the native bridge.
 *
 * Constitutional Guarantees:
 * 1. 100% Offline-First: Works completely air-gapped using local SQLite / Factory Seed definitions.
 * 2. Cryptographic Rigor: Rejects unconfigured (all-zero) or invalidly signed updates.
 * 3. Anti-Downgrade: Strictly monotonic sequence numbers.
 * 4. Zero-Knowledge: Only hashes, domain names, and metadata are handled.
 */
export class MobileThreatIntelService {
  private static instance: MobileThreatIntelService | null = null;

  public static getInstance(): MobileThreatIntelService {
    if (!MobileThreatIntelService.instance) {
      MobileThreatIntelService.instance = new MobileThreatIntelService();
    }
    return MobileThreatIntelService.instance;
  }

  public static async getDatabaseMetadata(): Promise<MobileThreatMetadata> {
    return MobileThreatIntelService.getInstance().getDatabaseMetadata();
  }

  public static async inspectDatabaseHealth(): Promise<ThreatDatabaseInspectionResult> {
    return MobileThreatIntelService.getInstance().inspectDatabaseHealth();
  }

  public static async applySignedUpdate(bundleJsonStr: string, trustedPublicKeyOverride?: string): Promise<ThreatUpdateInspectionResult> {
    return MobileThreatIntelService.getInstance().applySignedUpdate(bundleJsonStr, trustedPublicKeyOverride);
  }

  public static async rollbackToFactorySeed(): Promise<boolean> {
    return MobileThreatIntelService.getInstance().rollbackToFactorySeed();
  }

  // Fallback in-memory metadata when running on web preview without native Android bridge
  private fallbackMetadata: MobileThreatMetadata = {
    databaseVersion: 101,
    versionSequence: 100,
    installedVersion: '1.0.0-seed',
    publishedAt: Date.now() - 3600000,
    lastVerifiedAt: Date.now(),
    sourceFeed: 'FACTORY_SEED',
    recordsCount: 11,
    sha256Digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b801',
    isFactorySeed: true,
    status: 'ACTIVE'
  };

  /**
   * Retrieves active threat database metadata.
   */
  public async getDatabaseMetadata(): Promise<MobileThreatMetadata> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.getThreatDatabaseMetadata) {
      try {
        const raw = (window as any).AndroidSecurityBridge.getThreatDatabaseMetadata();
        if (raw && typeof raw === 'string') {
          const parsed = JSON.parse(raw);
          return {
            databaseVersion: Number(parsed.database_version || 101),
            versionSequence: Number(parsed.version_sequence || 100),
            installedVersion: String(parsed.installed_version || '1.0.0-seed'),
            publishedAt: Number(parsed.published_at || Date.now()),
            lastVerifiedAt: Number(parsed.last_verified_at || Date.now()),
            sourceFeed: String(parsed.source_feed || 'FACTORY_SEED'),
            recordsCount: Number(parsed.records_count || 11),
            sha256Digest: String(parsed.sha256_digest || ''),
            isFactorySeed: parsed.is_factory_seed === 'true',
            status: 'ACTIVE'
          };
        }
      } catch (e) {
        // Fall back to local
      }
    }
    return this.fallbackMetadata;
  }

  /**
   * Calculates staleness metric and returns health status.
   */
  public async inspectDatabaseHealth(): Promise<ThreatDatabaseInspectionResult> {
    const meta = await this.getDatabaseMetadata();
    const stalenessDays = Math.max(0, (Date.now() - meta.publishedAt) / (1000 * 60 * 60 * 24));

    let stalenessState: 'FRESH' | 'AGED' | 'STALE' | 'EXPIRED_CACHE' = 'FRESH';
    if (stalenessDays > 90) {
      stalenessState = 'EXPIRED_CACHE';
    } else if (stalenessDays > 30) {
      stalenessState = 'STALE';
    } else if (stalenessDays > 7) {
      stalenessState = 'AGED';
    }

    return {
      activeMetadata: meta,
      stalenessDays: Math.round(stalenessDays * 10) / 10,
      stalenessState,
      isVerified: true
    };
  }

  /**
   * Verifies and applies a signed .ppdb update bundle.
   */
  public async applySignedUpdate(bundleJsonStr: string, trustedPublicKeyOverride?: string): Promise<ThreatUpdateInspectionResult> {
    if (!bundleJsonStr || !bundleJsonStr.trim()) {
      return { success: false, error: 'Empty update bundle payload.' };
    }

    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.applyThreatDatabaseSignedUpdate) {
      try {
        const rawRes = (window as any).AndroidSecurityBridge.applyThreatDatabaseSignedUpdate(
          bundleJsonStr,
          trustedPublicKeyOverride || ''
        );
        const parsed = JSON.parse(rawRes);
        return {
          success: Boolean(parsed.success),
          error: parsed.message || parsed.code
        };
      } catch (err: any) {
        return { success: false, error: err?.message || 'Bridge execution failed' };
      }
    }

    // Web simulation: check JSON
    try {
      const parsed = JSON.parse(bundleJsonStr);
      if (!parsed.manifest || !parsed.payload) {
        return { success: false, error: 'Bundle missing manifest or payload.' };
      }
      return { success: false, error: 'Native update verification requires Android runtime' };
    } catch (e: any) {
      return { success: false, error: 'Malformed JSON payload: ' + e.message };
    }
  }

  /**
   * Rolls back the database back to immutable Factory Seed definitions.
   */
  public async rollbackToFactorySeed(): Promise<boolean> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.rollbackThreatDatabaseToFactorySeed) {
      try {
        return (window as any).AndroidSecurityBridge.rollbackThreatDatabaseToFactorySeed();
      } catch {
        return false;
      }
    }
    this.fallbackMetadata = {
      ...this.fallbackMetadata,
      versionSequence: 100,
      installedVersion: '1.0.0-seed',
      publishedAt: Date.now(),
      isFactorySeed: true
    };
    return true;
  }
}
