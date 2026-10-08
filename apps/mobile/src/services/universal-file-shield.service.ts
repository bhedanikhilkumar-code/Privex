import {
  UniversalFileInspectionReport,
  QuarantineResult
} from '../types/mobile.types';

/**
 * UniversalFileShieldService (Phase T3):
 * Bridges file inspection, URI analysis, and secure quarantine vault operations
 * between the TypeScript mobile presentation layer and native AndroidSecurityBridge.
 * Includes graceful offline/browser fallbacks for local test environments.
 */
export class UniversalFileShieldService {

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge &&
      typeof window.AndroidSecurityBridge.inspectFile === 'function'
    );
  }

  /**
   * Inspects a local filesystem path via the native UniversalFileShield engine.
   */
  public async inspectFile(filePath: string): Promise<UniversalFileInspectionReport> {
    if (!filePath || !filePath.trim()) {
      throw new Error('INVALID_FILE_PATH: File path cannot be empty');
    }

    if (this.isNativeBridgeAvailable()) {
      try {
        const raw = window.AndroidSecurityBridge!.inspectFile!(filePath.trim());
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          throw new Error(`FILE_INSPECTION_ERROR: ${parsed.error}`);
        }
        return parsed as UniversalFileInspectionReport;
      } catch (err: any) {
        if (err.message && err.message.startsWith('FILE_INSPECTION_ERROR')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    // Web / mock fallback
    const fileName = filePath.split(/[/\\]/).pop() || 'unknown_file';
    const isEicar = fileName.toLowerCase().includes('eicar');
    const isZipBomb = fileName.toLowerCase().includes('bomb');
    const isDoubleExt = fileName.toLowerCase().endsWith('.pdf.exe') || fileName.toLowerCase().endsWith('.jpg.scr');
    const isThreat = isEicar || isZipBomb || isDoubleExt;

    return {
      fileIdentity: {
        uriString: `file://${filePath}`,
        fileName,
        fileExtension: fileName.split('.').pop() || '',
        detectedMimeType: isThreat ? 'application/x-dosexec' : 'application/pdf',
        sizeBytes: 1024,
        lastModifiedMs: Date.now(),
        sha256: 'mock_sha256_digest',
        sourceCollection: 'LOCAL_STORAGE',
        isExecutable: isThreat
      },
      score: isThreat ? 95 : 5,
      verdict: isThreat ? 'DANGEROUS' : 'ALLOW',
      severity: isThreat ? 'CRITICAL' : 'NONE',
      recommendation: isThreat ? 'QUARANTINE_OR_DELETE' : 'SAFE_TO_OPEN',
      evidence: isThreat
        ? [
            {
              code: isEicar ? 'EICAR_TEST_PAYLOAD' : isZipBomb ? 'ARCHIVE_ZIP_BOMB' : 'DECEPTIVE_DOUBLE_EXTENSION',
              severity: 'CRITICAL',
              weight: 90,
              description: 'Detected threat signature during simulated inspection.'
            }
          ]
        : [],
      timestamp: Date.now()
    };
  }

  /**
   * Inspects a content URI (e.g. from Storage Access Framework or MediaStore).
   */
  public async inspectFileUri(uriString: string, declaredFileName?: string): Promise<UniversalFileInspectionReport> {
    if (!uriString || !uriString.trim()) {
      throw new Error('INVALID_URI: Content URI cannot be empty');
    }

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.inspectFileUri === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.inspectFileUri(uriString.trim(), declaredFileName || '');
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          throw new Error(`FILE_INSPECTION_ERROR: ${parsed.error}`);
        }
        return parsed as UniversalFileInspectionReport;
      } catch (err: any) {
        if (err.message && err.message.startsWith('FILE_INSPECTION_ERROR')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    return this.inspectFile(declaredFileName || 'content_file.dat');
  }

  /**
   * Moves or isolates a threat file into the app-private quarantine vault.
   */
  public async quarantineFile(filePath: string): Promise<QuarantineResult> {
    if (!filePath || !filePath.trim()) {
      throw new Error('INVALID_FILE_PATH: File path cannot be empty');
    }

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.quarantineFile === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.quarantineFile(filePath.trim());
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          return {
            status: 'FAILED',
            error: parsed.error,
            timestamp: Date.now()
          };
        }
        return parsed as QuarantineResult;
      } catch (err: any) {
        return {
          status: 'FAILED',
          error: `NATIVE_BRIDGE_FAILURE: ${err?.message || err}`,
          timestamp: Date.now()
        };
      }
    }

    // Mock response for web/test
    return {
      status: 'QUARANTINED',
      quarantinePath: `/data/user/0/com.privateprotection.mobile/files/private_quarantine_vault/${Date.now()}_quarantined`,
      originalDeleted: true,
      timestamp: Date.now()
    };
  }
}
