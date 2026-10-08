import { useState, useEffect, useCallback } from 'react';
import {
  requestMonitor,
  MonitoredRequest,
  NetworkMonitorConfig
} from '../lib/security/request-monitor';
import {
  securityEventManager,
  SecurityEvent
} from '../lib/security/security-events';

export function useSecurityMonitor() {
  const [requests, setRequests] = useState<MonitoredRequest[]>(() => requestMonitor.getHistory());
  const [events, setEvents] = useState<SecurityEvent[]>(() => securityEventManager.getEvents());
  const [config, setConfig] = useState<NetworkMonitorConfig>(() => requestMonitor.getConfig());

  useEffect(() => {
    // Start non-intrusive fetch interception
    requestMonitor.startInterception();

    const unsubRequests = requestMonitor.subscribe((updatedRequests) => {
      setRequests(updatedRequests);
    });

    const unsubEvents = securityEventManager.subscribe((updatedEvents) => {
      setEvents(updatedEvents);
    });

    return () => {
      unsubRequests();
      unsubEvents();
    };
  }, []);

  const dismissAlert = useCallback((id: string) => {
    securityEventManager.dismissEvent(id);
  }, []);

  const dismissAllAlerts = useCallback(() => {
    securityEventManager.dismissAllAlerts();
  }, []);

  const clearRequests = useCallback(() => {
    requestMonitor.clearHistory();
  }, []);

  const clearEvents = useCallback(() => {
    securityEventManager.clearAllEvents();
  }, []);

  const updateConfig = useCallback((newConfig: Partial<NetworkMonitorConfig>) => {
    requestMonitor.updateConfig(newConfig);
    setConfig(requestMonitor.getConfig());
  }, []);

  /**
   * Safe simulator to test first-party, third-party, and suspicious network traffic.
   */
  const simulateRequest = useCallback((url: string, method = 'GET', status = 200) => {
    return requestMonitor.recordRequest({
      url,
      method,
      status,
      responseTimeMs: Math.floor(Math.random() * 45) + 5
    });
  }, []);

  /**
   * Simulates a rapid burst of requests to demonstrate overload detection.
   */
  const simulateBurstRequests = useCallback((domain: string, count = 52) => {
    for (let i = 0; i < count; i++) {
      requestMonitor.recordRequest({
        url: `https://${domain}/api/v1/data?req=${i + 1}`,
        method: 'GET',
        status: 200,
        responseTimeMs: Math.floor(Math.random() * 20) + 1
      });
    }
  }, []);

  const activeAlerts = events.filter((e) => !e.dismissed && (e.severity === 'high' || e.severity === 'critical' || e.severity === 'medium'));

  return {
    requests,
    events,
    activeAlerts,
    config,
    updateConfig,
    dismissAlert,
    dismissAllAlerts,
    clearRequests,
    clearEvents,
    simulateRequest,
    simulateBurstRequests
  };
}
