import { describe, it, expect } from 'vitest';
import { NetworkMonitorService, NetworkCommandRunner } from '../../services/network-monitor.service';

class MockNetworkCommandRunner implements NetworkCommandRunner {
  public netstatTcpOutput = '';
  public netstatUdpOutput = '';
  public firewallOutput = '';

  public async exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    if (command === 'netstat') {
      if (args.includes('TCP')) {
        return { stdout: this.netstatTcpOutput, stderr: '' };
      }
      if (args.includes('UDP')) {
        return { stdout: this.netstatUdpOutput, stderr: '' };
      }
    }
    if (command === 'netsh') {
      return { stdout: this.firewallOutput, stderr: '' };
    }
    throw new Error(`Command not recognized: ${command}`);
  }
}

describe('NetworkMonitorService (Phase K — Network Socket & Firewall Auditing)', () => {
  it('parses address and port formats (IPv4, bracketed IPv6, and wildcards) correctly', () => {
    expect(NetworkMonitorService.parseAddressPort('192.168.1.50:443')).toEqual({
      address: '192.168.1.50',
      port: 443
    });
    expect(NetworkMonitorService.parseAddressPort('[fe80::1]:8080')).toEqual({
      address: 'fe80::1',
      port: 8080
    });
    expect(NetworkMonitorService.parseAddressPort('0.0.0.0:0')).toEqual({
      address: '0.0.0.0',
      port: 0
    });
    expect(NetworkMonitorService.parseAddressPort('*:*')).toEqual({
      address: '*',
      port: 0
    });
  });

  it('parses netstat TCP and UDP output with owning PID and states', () => {
    const mockRunner = new MockNetworkCommandRunner();
    const service = new NetworkMonitorService(mockRunner);

    const netstatTcp = [
      'Active Connections',
      '',
      '  Proto  Local Address          Foreign Address        State           PID',
      '  TCP    127.0.0.1:52341        127.0.0.1:52342        ESTABLISHED     1234',
      '  TCP    192.168.1.100:49152    142.250.190.46:443     ESTABLISHED     4568',
      '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888'
    ].join('\r\n');

    const connections = service.parseNetstatOutput(netstatTcp);
    expect(connections.length).toBe(3);
    expect(connections[0].protocol).toBe('TCP');
    expect(connections[0].localAddress).toBe('127.0.0.1');
    expect(connections[0].localPort).toBe(52341);
    expect(connections[0].remoteAddress).toBe('127.0.0.1');
    expect(connections[0].remotePort).toBe(52342);
    expect(connections[0].state).toBe('ESTABLISHED');
    expect(connections[0].pid).toBe(1234);
    expect(connections[0].isRemoteMalicious).toBe(false);
  });

  it('correlates remote endpoints with ThreatIntel and detects malicious C2 connections', () => {
    const mockRunner = new MockNetworkCommandRunner();
    const service = new NetworkMonitorService(mockRunner);

    // 198.51.100.23 is in the seeded ThreatIntel test blocklist
    const netstatOutput = [
      '  Proto  Local Address          Foreign Address        State           PID',
      '  TCP    192.168.1.100:54321    198.51.100.23:4444     ESTABLISHED     6789'
    ].join('\r\n');

    const connections = service.parseNetstatOutput(netstatOutput);
    expect(connections.length).toBe(1);
    expect(connections[0].isRemoteMalicious).toBe(true);
    expect(connections[0].riskScore).toBe(100);
    expect(connections[0].threatName).toBeDefined();
    expect(connections[0].threatIndicators.some((i) => i.includes('threat intelligence'))).toBe(true);
  });

  it('detects high-risk suspicious C2 ports (e.g. 4444, 1337) without false hard-blocking benign IPs', () => {
    const mockRunner = new MockNetworkCommandRunner();
    const service = new NetworkMonitorService(mockRunner);

    // Unlisted remote IP on Metasploit C2 port 4444
    const netstatOutput = [
      '  Proto  Local Address          Foreign Address        State           PID',
      '  TCP    192.168.1.100:55555    203.0.113.50:4444      ESTABLISHED     9999'
    ].join('\r\n');

    const connections = service.parseNetstatOutput(netstatOutput);
    expect(connections.length).toBe(1);
    expect(connections[0].isSuspiciousPort).toBe(true);
    expect(connections[0].riskScore).toBe(45);
    expect(connections[0].threatIndicators.some((i) => i.includes('4444'))).toBe(true);
  });

  it('parses Windows Defender Firewall profile states (Domain, Private, Public)', () => {
    const mockRunner = new MockNetworkCommandRunner();
    const service = new NetworkMonitorService(mockRunner);

    const netshOutput = [
      'Domain Profile Settings:',
      '----------------------------------------------------------------------',
      'State                                 ON',
      'Firewall Policy                       BlockInbound,AllowOutbound',
      '',
      'Private Profile Settings:',
      '----------------------------------------------------------------------',
      'State                                 ON',
      'Firewall Policy                       BlockInbound,AllowOutbound',
      '',
      'Public Profile Settings:',
      '----------------------------------------------------------------------',
      'State                                 OFF',
      'Firewall Policy                       BlockInbound,AllowOutbound'
    ].join('\r\n');

    const firewallState = service.parseFirewallOutput(netshOutput);
    expect(firewallState.domainProfile).toBe('ON');
    expect(firewallState.privateProfile).toBe('ON');
    expect(firewallState.publicProfile).toBe('OFF');
    expect(firewallState.isFirewallActive).toBe(true);
  });

  it('handles firewall command failures gracefully with diagnostic state', () => {
    const mockRunner = new MockNetworkCommandRunner();
    const service = new NetworkMonitorService(mockRunner);

    const firewallState = service.parseFirewallOutput('');
    expect(firewallState.domainProfile).toBe('UNKNOWN');
    expect(firewallState.privateProfile).toBe('UNKNOWN');
    expect(firewallState.publicProfile).toBe('UNKNOWN');
    expect(firewallState.isFirewallActive).toBe(false);
    expect(firewallState.rawDiagnostic).toBe('EMPTY_OUTPUT');
  });

  it('collects complete network posture report end-to-end', async () => {
    const mockRunner = new MockNetworkCommandRunner();
    mockRunner.netstatTcpOutput = [
      '  Proto  Local Address          Foreign Address        State           PID',
      '  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       1200',
      '  TCP    192.168.1.10:50000     198.51.100.23:4444     ESTABLISHED     3400'
    ].join('\r\n');
    mockRunner.netstatUdpOutput = [
      '  Proto  Local Address          Foreign Address        State           PID',
      '  UDP    0.0.0.0:5353           *:*                                    900'
    ].join('\r\n');
    mockRunner.firewallOutput = [
      'Domain Profile Settings:\r\nState ON\r\nPrivate Profile Settings:\r\nState ON\r\nPublic Profile Settings:\r\nState ON'
    ].join('\r\n');

    const service = new NetworkMonitorService(mockRunner);
    const posture = await service.getNetworkPosture();

    expect(posture.activeInterfacesCount).toBeGreaterThanOrEqual(1);
    expect(posture.firewallStatus.isFirewallActive).toBe(true);
    expect(posture.connections.length).toBe(3);
    expect(posture.maliciousSocketsCount).toBe(1);
    expect(posture.suspiciousSocketsCount).toBe(1);
    expect(posture.notice).toContain('100% offline');
  });
});
