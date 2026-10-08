import {
  PackageAuditReport
} from '../types/mobile.types';

/**
 * Service for auditing installed packages and uninstalled APK files (Phase T2 App Installation Shield).
 * Bridges to native AndroidSecurityBridge when running in WebView, or provides local fallback.
 */
export class AppInstallationShieldService {

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge &&
      typeof window.AndroidSecurityBridge.auditPackage === 'function'
    );
  }

  /**
   * Audits an installed Android package.
   */
  public async auditPackage(packageName: string): Promise<PackageAuditReport> {
    if (!packageName || !packageName.trim()) {
      throw new Error('INVALID_PACKAGE_NAME: Package name cannot be empty');
    }

    if (this.isNativeBridgeAvailable()) {
      try {
        const raw = window.AndroidSecurityBridge!.auditPackage!(packageName.trim());
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          throw new Error(`PACKAGE_AUDIT_ERROR: ${parsed.error}`);
        }
        return parsed as PackageAuditReport;
      } catch (err: any) {
        if (err.message && err.message.startsWith('PACKAGE_AUDIT_ERROR')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    // Fallback deterministic simulation for Web/testing environment
    const isSuspicious = packageName.includes('malicious') || packageName.includes('trojan');
    const score = isSuspicious ? 85 : 5;
    const verdict = isSuspicious ? 'DANGEROUS' : 'ALLOW';
    const severity = isSuspicious ? 'CRITICAL' : 'NONE';

    return {
      packageName,
      appLabel: packageName.split('.').pop() || packageName,
      score,
      verdict,
      severity,
      recommendation: isSuspicious ? 'IMMEDIATELY_UNINSTALL' : 'SAFE_TO_RUN',
      isSideloaded: isSuspicious,
      isSystemApp: false,
      timestamp: Date.now(),
      evidence: isSuspicious
        ? [
            {
              code: 'HIGH_RISK_PERMISSIONS',
              severity: 'HIGH',
              weight: 35,
              description: 'Requested sensitive SMS and Accessibility service permissions.'
            }
          ]
        : []
    };
  }

  /**
   * Audits an uninstalled APK file prior to user installation.
   */
  public async auditApkFile(apkFilePath: string): Promise<PackageAuditReport> {
    if (!apkFilePath || !apkFilePath.trim()) {
      throw new Error('INVALID_FILE_PATH: APK file path cannot be empty');
    }

    if (this.isNativeBridgeAvailable()) {
      try {
        const raw = window.AndroidSecurityBridge!.auditApkFile!(apkFilePath.trim());
        const parsed = JSON.parse(raw);
        if (parsed.error) {
          throw new Error(`APK_AUDIT_ERROR: ${parsed.error}`);
        }
        return parsed as PackageAuditReport;
      } catch (err: any) {
        if (err.message && err.message.startsWith('APK_AUDIT_ERROR')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    const isSuspicious = apkFilePath.includes('malicious') || apkFilePath.includes('dropper');
    return {
      packageName: 'com.file.inspection',
      appLabel: apkFilePath.split(/[/\\]/).pop() || 'Archive.apk',
      score: isSuspicious ? 90 : 10,
      verdict: isSuspicious ? 'DANGEROUS' : 'ALLOW',
      severity: isSuspicious ? 'CRITICAL' : 'NONE',
      recommendation: isSuspicious ? 'IMMEDIATELY_UNINSTALL' : 'SAFE_TO_RUN',
      isSideloaded: true,
      isSystemApp: false,
      timestamp: Date.now(),
      apkInspection: {
        isValidZip: true,
        hasDex: true,
        hasAndroidManifest: true,
        hasNativeLibraries: false,
        hasSuspiciousPayloads: isSuspicious,
        uncompressedSizeBytes: 50000,
        fileCount: 15,
        fileSha256: 'mock_sha256',
        suspiciousEntries: isSuspicious ? ['SUSPICIOUS_DROPPER: assets/payload.apk'] : [],
        certEntries: ['META-INF/CERT.RSA']
      }
    };
  }

  /**
   * Triggers the native Android uninstall dialog via ACTION_DELETE Intent.
   */
  public async requestUninstall(packageName: string): Promise<boolean> {
    if (!packageName || !packageName.trim()) {
      return false;
    }

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge!.requestUninstall === 'function') {
      try {
        return !!window.AndroidSecurityBridge!.requestUninstall!(packageName.trim());
      } catch {
        return false;
      }
    }

    // Simulated fallback in browser/test
    return true;
  }
}
