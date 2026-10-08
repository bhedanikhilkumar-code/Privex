/**
 * REUSABLE SECURITY EVENT & ALERT SYSTEM
 *
 * Provides standardized cybersecurity event structures, notification triggers,
 * and pub-sub state for real-time threat monitoring and user alerts.
 */

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export type SecurityEventType =
  | 'HIGH_REQUEST_ACTIVITY'
  | 'UNKNOWN_THIRD_PARTY'
  | 'SUSPICIOUS_REQUEST'
  | 'REPEATED_REQUEST'
  | 'ACCOUNT_SECURITY_ALERT'
  | 'PASSWORD_SECURITY_WARNING';

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  domain?: string;
  requestCount?: number;
  timeWindow?: number; // ms
  timestamp: string;
  message: string;
  metadata?: Record<string, any>;
  dismissed?: boolean;
}

export class SecurityEventManager {
  private static instance: SecurityEventManager | null = null;
  private events: SecurityEvent[] = [];
  private listeners: Set<(events: SecurityEvent[]) => void> = new Set();
  private maxEvents = 100;

  private constructor() {
    // Seed with a default informational baseline event
    this.events = [
      {
        id: 'evt_init',
        type: 'ACCOUNT_SECURITY_ALERT',
        severity: 'low',
        timestamp: new Date().toISOString(),
        message: 'Local security engine initialized. Real-time RAM monitoring active.',
        dismissed: true
      }
    ];
  }

  public static getInstance(): SecurityEventManager {
    if (!SecurityEventManager.instance) {
      SecurityEventManager.instance = new SecurityEventManager();
    }
    return SecurityEventManager.instance;
  }

  public getEvents(): SecurityEvent[] {
    return [...this.events];
  }

  public getActiveAlerts(): SecurityEvent[] {
    return this.events.filter((e) => !e.dismissed && (e.severity === 'high' || e.severity === 'critical' || e.severity === 'medium'));
  }

  public subscribe(listener: (events: SecurityEvent[]) => void): () => void {
    this.listeners.add(listener);
    listener(this.getEvents());
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    const list = this.getEvents();
    this.listeners.forEach((fn) => fn(list));
  }

  public addEvent(eventData: Omit<SecurityEvent, 'id' | 'timestamp' | 'dismissed'> & { id?: string; timestamp?: string }): SecurityEvent {
    // Deduplication check for repeated events within 3 seconds
    const existing = this.events.find(
      (e) => e.type === eventData.type && e.domain === eventData.domain && Date.now() - new Date(e.timestamp).getTime() < 3000
    );
    if (existing) {
      return existing;
    }

    const newEvent: SecurityEvent = {
      id: eventData.id || `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      type: eventData.type,
      severity: eventData.severity,
      domain: eventData.domain,
      requestCount: eventData.requestCount,
      timeWindow: eventData.timeWindow,
      timestamp: eventData.timestamp || new Date().toISOString(),
      message: eventData.message,
      metadata: eventData.metadata,
      dismissed: false
    };

    this.events.unshift(newEvent);
    if (this.events.length > this.maxEvents) {
      this.events.length = this.maxEvents;
    }

    this.notify();
    return newEvent;
  }

  public dismissEvent(id: string): void {
    const found = this.events.find((e) => e.id === id);
    if (found) {
      found.dismissed = true;
      this.notify();
    }
  }

  public dismissAllAlerts(): void {
    this.events.forEach((e) => {
      e.dismissed = true;
    });
    this.notify();
  }

  public clearAllEvents(): void {
    this.events = [];
    this.notify();
  }
}

export const securityEventManager = SecurityEventManager.getInstance();
