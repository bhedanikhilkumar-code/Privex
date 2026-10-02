import { describe, it, expect } from 'vitest';
import { NetworkMonitorService } from '../../services/network-monitor.service';

describe('NetworkMonitorService (Network Visibility)', () => {
  const service = new NetworkMonitorService();

  it('reports genuine local network posture without claiming fake firewall capabilities', async () => {
    const report = await service.getNetworkPosture();
    expect(report.activeInterfacesCount).toBeGreaterThanOrEqual(1);
    expect(report.firewallStatus).toBe('OS_NATIVE_FIREWALL_DELEGATED');
    expect(report.notice).toContain('Packet filtering is delegated to the native OS firewall');
  });
});
