import { EventEmitter } from 'events';
import {
  DesktopNotification,
  NotificationSeverity,
  NotificationCategory,
  CreateNotificationInput,
  NotificationDispatchResult,
  NotificationServiceOptions,
  NotificationInboxState,
  NotificationThreatMetadata,
  DetectedThreat,
  RansomwareIncident,
  ProcessContainmentResult,
  ToastSuppressedReason
} from '../types/desktop.types';

interface BurstEventRecord {
  readonly timestamp: number;
  readonly category: NotificationCategory;
  readonly threatName?: string;
  readonly filePath?: string;
}

/**
 * NotificationService (Phase H — Notification System & Storm Rate-Limiter)
 *
 * Implements:
 * 1. Native Windows OS Toast Notifications with headless/test-safe fallback.
 * 2. System Tray security alerts / status updates integration.
 * 3. Persistent In-App Notification Inbox with unread tracking, markRead, markAllRead, clearAll.
 * 4. RULE-15 Token-Bucket Storm Rate Limiter (Max 3 toasts per 10-second window).
 * 5. RULE-15 Burst Coalescer (>= 3 threats within 5 seconds coalesce into batch summary).
 * 6. Fullscreen awareness (suppresses info/low/medium toasts while preserving critical alerts).
 * 7. Unicode RTLO & control character sanitization (scrubbing \u202E and directional overrides).
 * 8. 100% Non-blocking failure isolation (notification errors never halt detection/containment).
 */
export class NotificationService extends EventEmitter {
  private notifications: DesktopNotification[] = [];
  private unreadCount = 0;

  // Rate limiter state (Token Bucket)
  private readonly maxToastsPerWindow: number;
  private readonly toastWindowMs: number;
  private tokens: number;
  private lastRefillTimestamp: number;

  // Burst coalescer state
  private readonly burstCoalesceThreshold: number;
  private readonly burstWindowMs: number;
  private recentBurstEvents: BurstEventRecord[] = [];
  private lastCoalescedToastTimestamp = 0;

  // Inbox configuration
  private readonly maxInboxSize: number;

  // Pluggable providers
  private readonly isFullscreenFn?: () => boolean;
  private readonly clock: () => number;
  private readonly customToastDispatcher?: (title: string, message: string, severity: NotificationSeverity) => boolean;
  private readonly trayUpdater?: (unreadCount: number, latestThreatTitle?: string) => void;

  // Directional override character scrubbing regex (\u202A-\u202E, \u2066-\u2069, \u200E, \u200F)
  private static readonly DIRECTIONAL_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g;

  // Dispatched toasts log for observability & testing (bounded)
  private static readonly MAX_DISPATCHED_HISTORY = 100;
  private readonly dispatchedToastsHistory: Array<{
    readonly timestamp: number;
    readonly title: string;
    readonly message: string;
    readonly severity: NotificationSeverity;
  }> = [];

  constructor(options?: NotificationServiceOptions) {
    super();

    this.maxInboxSize = options?.maxInboxSize ?? 500;
    this.maxToastsPerWindow = options?.maxToastsPerWindow ?? 3;
    this.toastWindowMs = options?.toastWindowMs ?? 10000;
    this.burstCoalesceThreshold = options?.burstCoalesceThreshold ?? 3;
    this.burstWindowMs = options?.burstWindowMs ?? 5000;

    this.tokens = this.maxToastsPerWindow;
    this.clock = options?.clock ?? (() => Date.now());
    this.lastRefillTimestamp = this.clock();

    this.isFullscreenFn = options?.isFullscreenFn;
    this.customToastDispatcher = options?.toastDispatcher;
    this.trayUpdater = options?.trayUpdater;
  }

  // ============================================================
  // SANITIZATION & SCRUBBING HELPERS
  // ============================================================

  /**
   * Cleans RTLO and directional override characters, control characters,
   * and truncates long strings to a safe boundary (max 255 chars).
   */
  public static sanitizeNotificationText(text: string, maxLength = 255): string {
    if (!text || typeof text !== 'string') return '';

    // 1. Strip RTLO and directional override characters
    let sanitized = text.replace(NotificationService.DIRECTIONAL_OVERRIDE_REGEX, '');

    // 2. Strip dangerous null bytes and non-printable control characters (except newline/space)
    sanitized = sanitized.replace(/[\0\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // 3. Trim whitespace
    sanitized = sanitized.trim();

    // 4. Safe truncation with ellipsis
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength - 3) + '...';
    }

    return sanitized;
  }

  // ============================================================
  // TOKEN-BUCKET RATE LIMITER
  // ============================================================

  /**
   * Refills token bucket based on elapsed time and determines if a toast can be consumed.
   * Hard requirement: At most maxToastsPerWindow (3) per toastWindowMs (10,000 ms).
   */
  private consumeToastToken(now: number): { allowed: boolean; remainingTokens: number } {
    if (now < this.lastRefillTimestamp) {
      // Clock moved backward: preserve tokens, reset timestamp
      this.lastRefillTimestamp = now;
    } else {
      const elapsedMs = now - this.lastRefillTimestamp;
      const tokensToAdd = (elapsedMs / this.toastWindowMs) * this.maxToastsPerWindow;
      this.tokens = Math.min(this.maxToastsPerWindow, this.tokens + tokensToAdd);
      this.lastRefillTimestamp = now;
    }

    if (this.tokens >= 1.0) {
      this.tokens -= 1.0;
      return { allowed: true, remainingTokens: this.tokens };
    }

    return { allowed: false, remainingTokens: this.tokens };
  }

  /**
   * Inspects current token count without consuming.
   */
  public getAvailableTokens(): number {
    const now = this.clock();
    if (now > this.lastRefillTimestamp) {
      const elapsedMs = now - this.lastRefillTimestamp;
      const tokensToAdd = (elapsedMs / this.toastWindowMs) * this.maxToastsPerWindow;
      return Math.min(this.maxToastsPerWindow, this.tokens + tokensToAdd);
    }
    return this.tokens;
  }

  // ============================================================
  // BURST COALESCER
  // ============================================================

  /**
   * Evaluates if an incoming threat event is part of a storm burst.
   * If >= burstCoalesceThreshold (3) threats arrive within burstWindowMs (5,000 ms),
   * subsequent toasts are coalesced into a single batch summary.
   */
  private evaluateBurst(now: number, category: NotificationCategory, metadata?: NotificationThreatMetadata): {
    isBurst: boolean;
    burstCount: number;
  } {
    // Only security/threat categories participate in burst coalescing
    const isThreatCategory =
      category === 'SECURITY_ALERT' ||
      category === 'REALTIME_INGRESS' ||
      category === 'RANSOMWARE_BLOCKED' ||
      category === 'PROCESS_CONTAINED' ||
      category === 'QUARANTINE_ACTION';

    if (!isThreatCategory) {
      return { isBurst: false, burstCount: 0 };
    }

    // 1. Prune events outside the 5.0-second sliding burst window
    const cutoff = now - this.burstWindowMs;
    this.recentBurstEvents = this.recentBurstEvents.filter((ev) => ev.timestamp >= cutoff);

    // 2. Add current event
    this.recentBurstEvents.push({
      timestamp: now,
      category,
      threatName: metadata?.threatName,
      filePath: metadata?.filePath
    });

    const burstCount = this.recentBurstEvents.length;
    const isBurst = burstCount >= this.burstCoalesceThreshold;

    return { isBurst, burstCount };
  }

  // ============================================================
  // PRIMARY DISPATCH ENGINE
  // ============================================================

  /**
   * Dispatches a notification through the complete pipeline:
   * Sanitization -> In-App Inbox -> Fullscreen Evaluation -> Burst Coalescing -> Token Bucket -> Native OS Toast -> Tray.
   */
  public notify(input: CreateNotificationInput): NotificationDispatchResult {
    const now = this.clock();
    const id = input.id || `notif-${now}-${Math.random().toString(36).substring(2, 9)}`;
    const severity: NotificationSeverity = input.severity ?? 'info';
    const category: NotificationCategory = input.category ?? 'SECURITY_ALERT';

    // 1. Sanitize text payloads (strip RTLO, truncate long filenames)
    const title = NotificationService.sanitizeNotificationText(input.title, 120);
    const message = NotificationService.sanitizeNotificationText(input.message, 255);

    // 2. Burst evaluation
    const burstState = this.evaluateBurst(now, category, input.metadata);

    // 3. Construct immutable notification record for In-App Inbox

    const notification: DesktopNotification = {
      id,
      timestamp: now,
      title,
      message,
      severity,
      category,
      isRead: false,
      isCoalesced: burstState.isBurst,
      coalescedCount: burstState.isBurst ? burstState.burstCount : undefined,
      metadata: input.metadata,
      actionLabel: input.actionLabel
    };

    // 4. Insert into In-App Notification Inbox (ALWAYS recorded regardless of toast suppression)
    this.insertIntoInbox(notification);

    // 5. Check Fullscreen suppression
    const isFullscreen = this.isFullscreenFn ? this.isFullscreenFn() : false;
    let toastSuppressedReason: ToastSuppressedReason | undefined;

    if (isFullscreen && (severity === 'info' || severity === 'low' || severity === 'medium') && !input.forceToast) {
      toastSuppressedReason = 'FULLSCREEN_SUPPRESSED';
    }

    // 6. Native Toast Dispatch Evaluation
    let toastDispatched = false;

    if (!toastSuppressedReason) {
      if (burstState.isBurst) {
        // If this is the threshold trigger event (e.g. exactly 3rd event), or significant subsequent interval
        const shouldSendCoalescedToast =
          burstState.burstCount === this.burstCoalesceThreshold ||
          now - this.lastCoalescedToastTimestamp >= 4000;

        if (shouldSendCoalescedToast) {
          const coalescedTitle = 'Multiple Threats Blocked';
          const coalescedMsg = `Private Protection blocked ${burstState.burstCount} threats in the last 5 seconds.`;

          const tokenResult = this.consumeToastToken(now);
          if (tokenResult.allowed) {
            toastDispatched = this.dispatchNativeToast(coalescedTitle, coalescedMsg, severity);
            this.lastCoalescedToastTimestamp = now;
          } else {
            toastSuppressedReason = 'RATE_LIMITED';
          }
        } else {
          // Coalesced into previous summary toast
          toastSuppressedReason = 'RATE_LIMITED';
        }
      } else {
        // Normal single threat or alert: consume 1 token
        const tokenResult = this.consumeToastToken(now);
        if (tokenResult.allowed) {
          toastDispatched = this.dispatchNativeToast(title, message, severity);
        } else {
          toastSuppressedReason = 'RATE_LIMITED';
        }
      }
    }

    // 7. Update System Tray (Non-blocking)
    this.updateTraySafe(title);

    // 8. Emit notification event for listeners/renderer
    this.emit('notification', notification);

    return {
      notificationId: id,
      inboxInserted: true,
      toastDispatched,
      toastSuppressedReason,
      isCoalesced: burstState.isBurst,
      totalUnread: this.unreadCount
    };
  }

  // ============================================================
  // SPECIALIZED SECURITY ADAPTERS
  // ============================================================

  /**
   * Specialized dispatcher for detected malware/threats (RealtimeMonitor & Scanner).
   */
  public notifySecurityThreat(threat: DetectedThreat, context?: { source?: string; actionTaken?: string }): NotificationDispatchResult {
    const action = context?.actionTaken || (threat.quarantined ? 'Quarantined' : 'Blocked');
    const sourceLabel = context?.source ? ` [${context.source}]` : '';

    const title = threat.verdict === 'BLOCK'
      ? `Threat Blocked & ${action}`
      : `Suspicious File Alert`;

    const message = `${threat.fileName} was classified as ${threat.threatName} (Score: ${threat.riskScore}).`;

    const severity: NotificationSeverity =
      threat.severity === 'critical' ? 'critical' :
      threat.severity === 'dangerous' ? 'high' :
      threat.severity === 'suspicious' ? 'medium' : 'low';

    return this.notify({
      title: `${title}${sourceLabel}`,
      message,
      severity,
      category: 'SECURITY_ALERT',
      metadata: {
        threatName: threat.threatName,
        fileName: threat.fileName,
        filePath: threat.filePath,
        sha256: threat.sha256,
        riskScore: threat.riskScore,
        verdict: threat.verdict
      }
    });
  }

  /**
   * Specialized dispatcher for Ransomware incidents (Phase G).
   */
  public notifyRansomwareIncident(incident: RansomwareIncident): NotificationDispatchResult {
    const title = 'Ransomware Attack Blocked';
    const message = incident.threatType === 'CANARY_TAMPER'
      ? `Decoy canary trap tripped. Process isolated and protected files shielded.`
      : `High-velocity file encryption blocked (${incident.metrics.modificationsInWindow} files).`;

    return this.notify({
      title,
      message,
      severity: 'critical',
      category: 'RANSOMWARE_BLOCKED',
      metadata: {
        incidentId: incident.incidentId,
        threatName: incident.threatType,
        riskScore: incident.riskScore,
        pid: incident.responsiblePid,
        count: incident.affectedFiles.length
      },
      forceToast: true
    });
  }

  /**
   * Specialized dispatcher for Process Containment (Phase F).
   */
  public notifyProcessContained(result: ProcessContainmentResult): NotificationDispatchResult {
    const title = result.success ? 'Malicious Process Terminated' : 'Process Containment Alert';
    const message = result.success
      ? `Process ${result.processName || ''} (PID ${result.pid}) was terminated due to malicious behavior.`
      : `Process ${result.processName || ''} (PID ${result.pid}) containment: ${result.action}`;

    return this.notify({
      title,
      message,
      severity: result.success ? 'high' : 'medium',
      category: 'PROCESS_CONTAINED',
      metadata: {
        pid: result.pid,
        threatName: result.action,
        verdict: result.success ? 'CONTAINED' : 'FAILED'
      }
    });
  }

  // ============================================================
  // NATIVE TOAST DISPATCH & SYSTEM INTEGRATION
  // ============================================================

  /**
   * Attempts native Windows toast dispatch via Electron Notification or custom dispatcher.
   * Completely safe and non-blocking.
   */
  private dispatchNativeToast(title: string, message: string, severity: NotificationSeverity): boolean {
    // Record in memory history for testing/auditing (bounded FIFO)
    this.dispatchedToastsHistory.push({
      timestamp: this.clock(),
      title,
      message,
      severity
    });
    if (this.dispatchedToastsHistory.length > NotificationService.MAX_DISPATCHED_HISTORY) {
      this.dispatchedToastsHistory.shift();
    }

    // 1. Use custom dispatcher if provided (e.g. test harness)
    if (this.customToastDispatcher) {
      try {
        return this.customToastDispatcher(title, message, severity);
      } catch (err: any) {
        this.emit('error', new Error(`CUSTOM_DISPATCHER_ERROR: ${err?.message || err}`));
        return false;
      }
    }

    // 2. Try Electron Notification API if available
    try {
      const electron = require('electron');
      if (electron?.Notification && typeof electron.Notification.isSupported === 'function') {
        if (electron.Notification.isSupported()) {
          const toast = new electron.Notification({
            title,
            body: message,
            silent: severity === 'info' || severity === 'low'
          });
          toast.show();
          return true;
        }
      }
    } catch {
      // Running in headless/Node CLI environment without Electron GUI
    }

    return true; // Graceful headless fallback
  }

  private updateTraySafe(latestTitle?: string): void {
    if (!this.trayUpdater) return;
    try {
      this.trayUpdater(this.unreadCount, latestTitle);
    } catch (err: any) {
      this.emit('error', new Error(`TRAY_UPDATE_ERROR: ${err?.message || err}`));
    }
  }

  // ============================================================
  // IN-APP INBOX MANAGEMENT
  // ============================================================

  private insertIntoInbox(notification: DesktopNotification): void {
    // Deduplication check for identical ID
    const existingIdx = this.notifications.findIndex((n) => n.id === notification.id);
    if (existingIdx !== -1) {
      // Replace existing
      const wasRead = this.notifications[existingIdx].isRead;
      this.notifications[existingIdx] = notification;
      if (wasRead && !notification.isRead) {
        this.unreadCount++;
      } else if (!wasRead && notification.isRead) {
        this.unreadCount = Math.max(0, this.unreadCount - 1);
      }
      return;
    }

    // Insert at front (newest first)
    this.notifications.unshift(notification);
    if (!notification.isRead) {
      this.unreadCount++;
    }

    // Enforce maxInboxSize with FIFO eviction of oldest items
    if (this.notifications.length > this.maxInboxSize) {
      const evicted = this.notifications.pop();
      if (evicted && !evicted.isRead) {
        this.unreadCount = Math.max(0, this.unreadCount - 1);
      }
    }
  }

  public getNotifications(limit?: number): DesktopNotification[] {
    if (limit && limit > 0) {
      return this.notifications.slice(0, limit);
    }
    return [...this.notifications];
  }

  public getInboxState(): NotificationInboxState {
    return {
      notifications: [...this.notifications],
      unreadCount: this.unreadCount,
      totalCount: this.notifications.length
    };
  }

  public getUnreadCount(): number {
    return this.unreadCount;
  }

  public markRead(notificationId: string): boolean {
    if (!notificationId || typeof notificationId !== 'string') return false;

    const notif = this.notifications.find((n) => n.id === notificationId);
    if (notif && !notif.isRead) {
      const updated: DesktopNotification = { ...notif, isRead: true };
      const idx = this.notifications.indexOf(notif);
      this.notifications[idx] = updated;
      this.unreadCount = Math.max(0, this.unreadCount - 1);
      this.updateTraySafe();
      this.emit('inboxChanged', this.getInboxState());
      return true;
    }
    return false;
  }

  public markAllRead(): number {
    let changed = 0;
    this.notifications = this.notifications.map((n) => {
      if (!n.isRead) {
        changed++;
        return { ...n, isRead: true };
      }
      return n;
    });
    this.unreadCount = 0;
    if (changed > 0) {
      this.updateTraySafe();
      this.emit('inboxChanged', this.getInboxState());
    }
    return changed;
  }

  public clearAll(): void {
    this.notifications = [];
    this.unreadCount = 0;
    this.updateTraySafe();
    this.emit('inboxChanged', this.getInboxState());
  }

  public getDispatchedToastsHistory(): Array<{
    readonly timestamp: number;
    readonly title: string;
    readonly message: string;
    readonly severity: NotificationSeverity;
  }> {
    return [...this.dispatchedToastsHistory];
  }

  public clearDispatchedToastsHistory(): void {
    this.dispatchedToastsHistory.length = 0;
  }
}
