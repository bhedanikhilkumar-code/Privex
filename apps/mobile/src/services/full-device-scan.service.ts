import {
  DeviceScanMode,
  DeviceScanReport,
  SecurityJobDescriptor
} from '../types/mobile.types';

/**
 * FullDeviceScanServiceClient (Phase T4):
 *
 * Bridges the presentation layer with native Android full device scanning capabilities:
 * - QUICK_SCAN
 * - STANDARD_SCAN
 * - FULL_ACCESSIBLE_SCAN
 *
 * Integrates with AndroidSecurityBridge and provides local mock fallback for browser testing.
 */
export class FullDeviceScanServiceClient {

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge &&
      typeof window.AndroidSecurityBridge.startDeviceScan === 'function'
    );
  }

  /**
   * Initiates a native device scan job. Returns the SecurityJobDescriptor.
   */
  public async startDeviceScan(mode: DeviceScanMode): Promise<SecurityJobDescriptor> {
    if (this.isNativeBridgeAvailable()) {
      try {
        const raw = window.AndroidSecurityBridge!.startDeviceScan!(mode);
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          throw new Error(`SCAN_INIT_FAILED: ${parsed.error}`);
        }
        return parsed as SecurityJobDescriptor;
      } catch (err: any) {
        if (err.message && err.message.startsWith('SCAN_INIT_FAILED')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    // Mock response for Web / testing environments
    return {
      id: `mock_scan_${Date.now()}`,
      type: 'STORAGE_SCAN',
      state: 'COMPLETED',
      progress: 100,
      createdAtMs: Date.now(),
      startedAtMs: Date.now(),
      completedAtMs: Date.now() + 50,
      metadata: { scanMode: mode },
      result: this.createMockScanReport(mode)
    };
  }

  /**
   * Retrieves active persisted SAF tree permissions from native bridge.
   */
  public async getPersistedSafTrees(): Promise<Array<{ uri: string; isValid: boolean }>> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.getPersistedSafTrees === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.getPersistedSafTrees();
        return JSON.parse(raw);
      } catch (err) {
        return [];
      }
    }
    return [];
  }

  /**
   * Grants persistent SAF tree permission for a given URI.
   */
  public async persistSafTree(treeUri: string): Promise<boolean> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.persistSafTree === 'function') {
      return window.AndroidSecurityBridge.persistSafTree(treeUri);
    }
    return true;
  }

  /**
   * Releases persistent SAF tree permission.
   */
  public async releaseSafTree(treeUri: string): Promise<boolean> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.releaseSafTree === 'function') {
      return window.AndroidSecurityBridge.releaseSafTree(treeUri);
    }
    return true;
  }

  private createMockScanReport(mode: DeviceScanMode): DeviceScanReport {
    const isFull = mode === 'FULL_ACCESSIBLE_SCAN';
    return {
      scanMode: mode,
      status: 'SECURE',
      startTimeMs: Date.now() - 200,
      endTimeMs: Date.now(),
      durationMs: 200,
      totalDiscovered: isFull ? 45 : 12,
      totalScanned: isFull ? 44 : 12,
      totalSkipped: isFull ? 1 : 0,
      threatsCount: 0,
      coverage: {
        isFullDeviceClaimed: false,
        coverageDescription: isFull
          ? 'Full Accessible Device Scan: Inspected all accessible MediaStore collections, persistent SAF trees, and applications. Protected system directories were truthfully skipped.'
          : (mode === 'QUICK_SCAN' ? 'Quick Scan: Inspected high-risk downloads, recent files, and user packages.'
          : 'Standard Scan: Inspected user shared storage collections and granted SAF roots.')
      },
      scopes: [
        {
          scopeId: 'scope_downloads',
          displayName: 'Downloads Collection',
          scopeType: 'MEDIASTORE_DOWNLOADS',
          uriOrPath: 'content://media/external/downloads',
          accessibilityState: 'MEDIASTORE_ACCESSIBLE',
          scanStatus: 'COMPLETED',
          filesDiscovered: 12,
          filesScanned: 12,
          filesSkipped: 0,
          threatsFound: 0,
          startTimeMs: Date.now() - 200,
          endTimeMs: Date.now()
        },
        ...(isFull
          ? [
              {
                scopeId: 'scope_restricted_system',
                displayName: 'Restricted System & Private App Storage',
                scopeType: 'RESTRICTED_SYSTEM',
                uriOrPath: '/data/data',
                accessibilityState: 'INACCESSIBLE' as const,
                scanStatus: 'SKIPPED' as const,
                filesDiscovered: 0,
                filesScanned: 0,
                filesSkipped: 1,
                threatsFound: 0,
                startTimeMs: Date.now() - 200,
                endTimeMs: Date.now(),
                errorDetails: 'Android sandboxing restricts access to system and other apps private directories.'
              }
            ]
          : [])
      ],
      threats: []
    };
  }
}
