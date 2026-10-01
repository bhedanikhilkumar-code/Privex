import { ThreatIntel } from './threat-intel';
import { UpdateMetadata } from '../types';

export interface UpdateProvider {
  fetchManifest(): Promise<UpdateMetadata | null>;
  fetchPatch(downloadUrl: string): Promise<string | null>;
}

export interface UpdateResult {
  updated: boolean;
  newVersion: number;
  bytesDownloaded: number;
  error?: string;
}

/**
 * ThreatIntelUpdater — Subsystem 16 Contract
 * Manages background querying, verification, and atomic application of signed OTA diffs.
 * 100% fail-closed and fail-safe; never degrades local protection on network or validation errors.
 */
export class ThreatIntelUpdater {
  private threatIntel: ThreatIntel;
  private trustedPublicKeyHex: string;

  constructor(threatIntel: ThreatIntel, trustedPublicKeyHex?: string) {
    this.threatIntel = threatIntel;
    this.trustedPublicKeyHex = trustedPublicKeyHex || '00'.repeat(32);
  }

  public async checkAndUpdate(
    provider: UpdateProvider,
    options?: { forceCheck?: boolean; trustedPublicKeyHex?: string }
  ): Promise<UpdateResult> {
    const currentVersion = this.threatIntel.getVersion();
    const pubKey = options?.trustedPublicKeyHex || this.trustedPublicKeyHex;

    try {
      // 1. Fetch manifest from provider
      const manifest = await provider.fetchManifest();
      if (!manifest) {
        return {
          updated: false,
          newVersion: currentVersion,
          bytesDownloaded: 0
        };
      }

      // Step 1 check: Monotonic version check before downloading patch
      if (manifest.targetVersion <= currentVersion) {
        return {
          updated: false,
          newVersion: currentVersion,
          bytesDownloaded: 0,
          error: `DowngradeRejectedError: manifest version ${manifest.targetVersion} <= current ${currentVersion}`
        };
      }

      // 2. Fetch patch payload
      const patchData = await provider.fetchPatch(manifest.downloadUrl);
      if (!patchData) {
        return {
          updated: false,
          newVersion: currentVersion,
          bytesDownloaded: 0,
          error: 'NetworkUnavailableError: could not fetch patch payload'
        };
      }

      const bytesDownloaded = Buffer.byteLength(patchData, 'utf-8');

      // 3. Delegate to atomic verification & application pipeline in ThreatIntel
      const applyResult = this.threatIntel.applySignedUpdate(manifest, patchData, pubKey);

      if (!applyResult.success) {
        return {
          updated: false,
          newVersion: currentVersion,
          bytesDownloaded,
          error: applyResult.error
        };
      }

      return {
        updated: true,
        newVersion: this.threatIntel.getVersion(),
        bytesDownloaded
      };
    } catch (err: any) {
      return {
        updated: false,
        newVersion: currentVersion,
        bytesDownloaded: 0,
        error: `UnexpectedUpdateError: ${err?.message || 'unknown error'}`
      };
    }
  }
}
