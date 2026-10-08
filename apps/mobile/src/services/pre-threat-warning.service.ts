import {
  PreThreatTargetType,
  WarningConfidenceLevel,
  PreThreatActionType,
  PreThreatWarningPayload,
  PreThreatWarningDecision,
  PreThreatWarningEvidenceItem
} from '../types/mobile.types';

/**
 * PreThreatWarningService (Phase T7):
 *
 * Evidence-backed predictive pre-threat warning coordinator and lifecycle manager:
 * - Bridges to Android native PreThreatWarningCoordinator when available in WebView.
 * - Provides fully deterministic on-device fallback evaluation in web and mock environments.
 * - Enforces evidence-backed triggers, plain-language consequences, and safe defaults.
 * - Coordinates friction-gate delays (5 seconds) for hazardous actions.
 * - Manages active warning state, notification dispatch, and bounded decision history.
 */
export class PreThreatWarningService {
  private static instance: PreThreatWarningService | null = null;

  private activeWarning: PreThreatWarningPayload | null = null;
  private listeners: Set<(warning: PreThreatWarningPayload) => void> = new Set();
  private localDecisionHistory: PreThreatWarningDecision[] = [];
  private lastWarningTimestamps: Map<string, number> = new Map();

  private readonly DEDUPLICATION_WINDOW_MS = 30000;
  private readonly MAX_LOCAL_HISTORY = 100;

  public static getInstance(): PreThreatWarningService {
    if (!PreThreatWarningService.instance) {
      PreThreatWarningService.instance = new PreThreatWarningService();
    }
    return PreThreatWarningService.instance;
  }

  constructor() {
    this.registerWindowEventListener();
  }

  private registerWindowEventListener(): void {
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      window.addEventListener('privateprotection:pre_threat_warning', ((event: CustomEvent) => {
        if (event.detail && event.detail.warning) {
          try {
            const parsed = typeof event.detail.warning === 'string'
              ? JSON.parse(event.detail.warning)
              : event.detail.warning;
            this.setActiveWarning(parsed);
          } catch (e) {
            console.error('Failed to parse pre_threat_warning custom event detail', e);
          }
        }
      }) as EventListener);
    }
  }

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge &&
      typeof window.AndroidSecurityBridge.synthesizePreThreatWarning === 'function'
    );
  }

  /**
   * Synthesizes an evidence-backed pre-threat warning payload from an inspection report.
   */
  public async synthesizeWarning(
    targetType: PreThreatTargetType,
    targetIdentifier: string,
    report: any
  ): Promise<PreThreatWarningPayload | null> {
    if (!targetIdentifier || !report) {
      return null;
    }

    if (this.isNativeBridgeAvailable()) {
      try {
        const reportStr = typeof report === 'string' ? report : JSON.stringify(report);
        const resStr = window.AndroidSecurityBridge!.synthesizePreThreatWarning!(targetType, reportStr);
        const parsed = JSON.parse(resStr);
        if (parsed.error) {
          // Fall back gracefully to local deterministic synthesis
          return this.evaluateFallbackWarning(targetType, targetIdentifier, report);
        }
        return parsed as PreThreatWarningPayload;
      } catch (e) {
        console.warn('Native bridge pre-threat synthesis failed, using fallback', e);
      }
    }

    return this.evaluateFallbackWarning(targetType, targetIdentifier, report);
  }

  /**
   * Deterministic local fallback synthesizer.
   */
  public evaluateFallbackWarning(
    targetType: PreThreatTargetType,
    targetIdentifier: string,
    report: any
  ): PreThreatWarningPayload | null {
    const warningId = `warn-${targetType.toLowerCase()}-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const timestamp = Date.now();

    let riskScore = 0;
    let verdict: 'ALLOW' | 'CAUTION' | 'SUSPICIOUS' | 'DANGEROUS' = 'CAUTION';
    let confidenceLevel: WarningConfidenceLevel = 'HEURISTIC_ANOMALY';
    let whatDetected = 'Heuristic risk indicators identified during on-device inspection.';
    let potentialConsequences = 'Interacting with this content may present security risks.';
    let recommendedAction: PreThreatActionType = 'GO_BACK';
    const supportedChoices: PreThreatActionType[] = [];
    const evidenceDetails: PreThreatWarningEvidenceItem[] = [];

    if (targetType === 'URL') {
      riskScore = report.riskScore ?? report.score ?? 50;
      verdict = (report.verdict || 'SUSPICIOUS').toUpperCase();
      const threatType = report.threatType || 'NONE';

      if (threatType === 'DANGEROUS_SCHEME' || riskScore >= 90) {
        confidenceLevel = 'CONFIRMED_MALWARE';
        whatDetected = `Dangerous executable URI scheme (${report.scheme || 'unknown'}:) detected attempting script or system execution.`;
        potentialConsequences = 'Opening this link may execute unauthorized script code or trigger unintended app actions.';
      } else if (threatType === 'HOMOGLYPH_ATTACK' || threatType === 'PUNYCODE_SPOOF' || threatType === 'CREDENTIAL_HARVESTING' || riskScore >= 70) {
        confidenceLevel = 'STRONG_SUSPICION';
        whatDetected = `Deceptive lookalike domain using internationalized characters to mimic legitimate services (${report.domain || targetIdentifier}).`;
        potentialConsequences = 'Visiting this deceptive site may allow attackers to steal your account passwords or credentials.';
      } else if (threatType === 'SUSPICIOUS_IP_HOST') {
        confidenceLevel = 'HEURISTIC_ANOMALY';
        whatDetected = 'Direct numeric IP address host utilized in place of a verifiable domain identity.';
        potentialConsequences = 'Connecting directly to an unverified IP host bypasses security certificate checks.';
      } else {
        confidenceLevel = 'HEURISTIC_ANOMALY';
        whatDetected = report.explanation || 'Heuristic anomalies identified during on-device lexical analysis.';
        potentialConsequences = 'Visiting this link may expose your browser to fraudulent content or deception.';
      }

      recommendedAction = 'GO_BACK';
      supportedChoices.push('GO_BACK', 'INSPECT_DETAILS', 'CONTINUE_AT_OWN_RISK');

      if (report.indicators && Array.isArray(report.indicators)) {
        for (const ind of report.indicators) {
          evidenceDetails.push({
            code: threatType,
            severity: verdict === 'DANGEROUS' ? 'CRITICAL' : 'HIGH',
            description: ind
          });
        }
      }
    } else if (targetType === 'FILE' || targetType === 'DOWNLOAD') {
      riskScore = report.score ?? 60;
      verdict = (report.verdict || 'SUSPICIOUS').toUpperCase();

      const evidenceArray = report.evidence || [];
      const hasEicar = evidenceArray.some((e: any) => e.code === 'EICAR_TEST_PAYLOAD');
      const hasZipBomb = evidenceArray.some((e: any) => e.code === 'ARCHIVE_ZIP_BOMB' || e.code === 'PATH_TRAVERSAL_DETECTED');
      const hasEmbeddedExec = evidenceArray.some((e: any) => e.code === 'APK_SUSPICIOUS_EMBEDDED_PAYLOAD' || e.code === 'ARCHIVE_EMBEDDED_EXECUTABLES');

      if (hasEicar || hasZipBomb || riskScore >= 90) {
        confidenceLevel = 'CONFIRMED_MALWARE';
        whatDetected = hasEicar
          ? 'Verified malware signature (EICAR standard antivirus test pattern) detected in file headers.'
          : 'Archive contains hazardous directory traversal sequences (../) or compression bomb ratios.';
        potentialConsequences = hasZipBomb
          ? 'Extracting this archive could overwrite protected files or exhaust system storage.'
          : 'Opening this file could execute unauthorized binary code on your device.';
      } else if (hasEmbeddedExec || riskScore >= 70) {
        confidenceLevel = 'STRONG_SUSPICION';
        whatDetected = 'Hidden secondary executable binaries or dynamic scripts detected embedded inside the archive.';
        potentialConsequences = 'Running this file could compromise device security or run unverified background payloads.';
      } else {
        confidenceLevel = 'HEURISTIC_ANOMALY';
        whatDetected = 'Heuristic file anomalies or unverified executable extensions detected in downloaded content.';
        potentialConsequences = 'Running an unverified file from an external source may expose your device to unexpected behavior.';
      }

      recommendedAction = 'DELETE_DOWNLOAD';
      supportedChoices.push('DELETE_DOWNLOAD', 'QUARANTINE', 'INSPECT_DETAILS', 'CONTINUE_AT_OWN_RISK');

      for (const ev of evidenceArray) {
        evidenceDetails.push({
          code: ev.code || 'FILE_ANOMALY',
          severity: ev.severity || 'HIGH',
          description: ev.description || 'Suspicious file characteristic'
        });
      }
    } else if (targetType === 'APP_PACKAGE') {
      riskScore = report.score ?? 65;
      verdict = (report.verdict || 'SUSPICIOUS').toUpperCase();
      const evidenceArray = report.evidence || [];
      const hasPayload = evidenceArray.some((e: any) => e.code === 'APK_SUSPICIOUS_EMBEDDED_PAYLOAD');
      const hasCriticalPerms = evidenceArray.some((e: any) => e.code === 'DANGEROUS_PERMISSIONS_CLUSTER' || e.code === 'EXCESSIVE_PERMISSIONS');

      if (hasPayload || riskScore >= 80) {
        confidenceLevel = 'CONFIRMED_MALWARE';
        whatDetected = `Application package contains embedded dynamic droppers or secondary binaries (${report.appLabel || targetIdentifier}).`;
        potentialConsequences = 'Installing this package could allow unauthorized background processes or keystroke monitoring.';
      } else if (hasCriticalPerms || riskScore >= 50) {
        confidenceLevel = 'STRONG_SUSPICION';
        whatDetected = `Sideloaded application (${report.appLabel || targetIdentifier}) outside Google Play requesting high-risk system permissions.`;
        potentialConsequences = 'Granting sensitive permissions to this unverified app may allow it to access private messages or contacts.';
      } else {
        confidenceLevel = 'HEURISTIC_ANOMALY';
        whatDetected = `Sideloaded application package with unverified installation origin (${report.appLabel || targetIdentifier}).`;
        potentialConsequences = 'Unverified sideloaded apps bypass Google Play Protect verification.';
      }

      recommendedAction = 'CANCEL_INSTALL';
      supportedChoices.push('CANCEL_INSTALL', 'INSPECT_DETAILS', 'CONTINUE_AT_OWN_RISK');

      for (const ev of evidenceArray) {
        evidenceDetails.push({
          code: ev.code || 'PACKAGE_ANOMALY',
          severity: ev.severity || 'HIGH',
          description: ev.description || 'Suspicious package attribute'
        });
      }
    }

    const requiresFrictionGate = verdict === 'DANGEROUS' || riskScore >= 75;
    const frictionGateSeconds = requiresFrictionGate ? 5 : 0;

    return {
      warningId,
      targetType,
      targetIdentifier,
      riskScore,
      verdict,
      confidenceLevel,
      whatDetected,
      potentialConsequences,
      recommendedAction,
      supportedChoices,
      evidenceDetails,
      requiresFrictionGate,
      frictionGateSeconds,
      timestamp
    };
  }

  /**
   * Sets the current active warning and notifies all subscribers.
   */
  public setActiveWarning(warning: PreThreatWarningPayload): boolean {
    const now = Date.now();
    const last = this.lastWarningTimestamps.get(warning.targetIdentifier);
    if (last && now - last < this.DEDUPLICATION_WINDOW_MS) {
      // Deduplicated within window
      return false;
    }
    this.lastWarningTimestamps.set(warning.targetIdentifier, now);
    this.activeWarning = warning;

    // Dispatch native notification if available
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.showPreThreatWarningNotification === 'function') {
      try {
        window.AndroidSecurityBridge.showPreThreatWarningNotification(JSON.stringify(warning));
      } catch (e) {
        console.warn('Failed to dispatch native pre-threat notification', e);
      }
    }

    // Trigger haptics for warning
    if (typeof window !== 'undefined' && window.AndroidSecurityBridge?.triggerWarningHaptics) {
      try {
        window.AndroidSecurityBridge.triggerWarningHaptics(warning.verdict);
      } catch (e) {
        // Non-blocking
      }
    }

    this.notifyListeners(warning);
    return true;
  }

  public getActiveWarning(): PreThreatWarningPayload | null {
    return this.activeWarning;
  }

  public clearActiveWarning(): void {
    this.activeWarning = null;
  }

  public subscribeToWarnings(listener: (warning: PreThreatWarningPayload) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(warning: PreThreatWarningPayload): void {
    this.listeners.forEach((fn) => {
      try {
        fn(warning);
      } catch (err) {
        console.error('Error notifying warning listener', err);
      }
    });
  }

  /**
   * Records a user decision for an active pre-threat warning.
   */
  public async recordDecision(decision: PreThreatWarningDecision): Promise<boolean> {
    if (!decision || !decision.warningId) {
      return false;
    }

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.recordPreThreatWarningDecision === 'function') {
      try {
        const ok = window.AndroidSecurityBridge.recordPreThreatWarningDecision(JSON.stringify(decision));
        if (ok) {
          this.localDecisionHistory.push(decision);
          if (this.localDecisionHistory.length > this.MAX_LOCAL_HISTORY) {
            this.localDecisionHistory.shift();
          }
          return true;
        }
      } catch (e) {
        console.warn('Failed to record decision via native bridge, using local storage', e);
      }
    }

    this.localDecisionHistory.push(decision);
    if (this.localDecisionHistory.length > this.MAX_LOCAL_HISTORY) {
      this.localDecisionHistory.shift();
    }
    return true;
  }

  /**
   * Returns recent pre-threat decisions.
   */
  public async getDecisionHistory(): Promise<PreThreatWarningDecision[]> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.getPreThreatWarningDecisionHistory === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.getPreThreatWarningDecisionHistory();
        return JSON.parse(raw);
      } catch (e) {
        console.warn('Failed to fetch decision history from native bridge', e);
      }
    }
    return [...this.localDecisionHistory];
  }

  public reset(): void {
    this.activeWarning = null;
    this.listeners.clear();
    this.localDecisionHistory = [];
    this.lastWarningTimestamps.clear();
  }
}
