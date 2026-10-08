import * as os from 'os';
import * as child_process from 'child_process';
import { ThreatIntel } from '@private-protection/core';
import {
  NetworkPostureReport,
  NetworkSocketConnection,
  FirewallProfileState
} from '../types/desktop.types';

export type { NetworkPostureReport, NetworkSocketConnection, FirewallProfileState };

export interface NetworkCommandRunner {
  exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }>;
}

export class DefaultNetworkCommandRunner implements NetworkCommandRunner {
  public async exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      child_process.execFile(
        command,
        args,
        {
          timeout: 2000,
          maxBuffer: 2 * 1024 * 1024,
          windowsHide: true
        },
        (err, stdout, stderr) => {
          if (err) {
            reject(err);
          } else {
            resolve({ stdout, stderr });
          }
        }
      );
    });
  }
}

/**
 * Real Windows Network Posture & Active Socket Threat Monitor (Phase K).
 *
 * Inspects active TCP/UDP sockets (netstat -ano), correlates remote endpoints against
 * local ThreatIntel and suspicious C2 ports, audits Windows Defender Firewall profiles
 * (netsh advfirewall), and reports network security posture 100% offline.
 */
export class NetworkMonitorService {
  private static readonly SUSPICIOUS_C2_PORTS = new Set([
    4444, // Metasploit Default C2
    1337, // Elite / Custom RAT
    6667, // IRC Botnet C2
    31337, // Back Orifice
    8088, // Custom HTTP Proxy C2
    9001, // Tor / Custom Relay
    9999 // Generic Reverse Shell
  ]);

  private runner: NetworkCommandRunner;

  constructor(runner?: NetworkCommandRunner) {
    this.runner = runner || new DefaultNetworkCommandRunner();
  }

  /**
   * Parses host and port from an address string (e.g. "192.168.1.50:443" or "[::1]:8080" or "*:*").
   */
  public static parseAddressPort(addrStr: string): { address: string; port: number } {
    if (!addrStr || typeof addrStr !== 'string') {
      return { address: '', port: 0 };
    }

    const trimmed = addrStr.trim();
    if (trimmed === '*:*' || trimmed === '*' || trimmed === '0.0.0.0:0' || trimmed === '[::]:0') {
      return { address: trimmed.split(':')[0] || '*', port: 0 };
    }

    // Bracketed IPv6: [fe80::1]:8080
    if (trimmed.startsWith('[')) {
      const closeBracket = trimmed.indexOf(']');
      if (closeBracket !== -1) {
        const address = trimmed.slice(1, closeBracket);
        const portStr = trimmed.slice(closeBracket + 2);
        const port = parseInt(portStr, 10);
        return { address, port: isNaN(port) ? 0 : port };
      }
    }

    // IPv4 or plain host: 192.168.1.50:443
    const lastColon = trimmed.lastIndexOf(':');
    if (lastColon !== -1) {
      const address = trimmed.slice(0, lastColon);
      const portStr = trimmed.slice(lastColon + 1);
      const port = parseInt(portStr, 10);
      return { address, port: isNaN(port) ? 0 : port };
    }

    return { address: trimmed, port: 0 };
  }

  /**
   * Parses raw `netstat -ano` output into structured NetworkSocketConnection entries.
   */
  public parseNetstatOutput(rawOutput: string): NetworkSocketConnection[] {
    if (!rawOutput || typeof rawOutput !== 'string') return [];

    const lines = rawOutput.split(/\r?\n/);
    const connections: NetworkSocketConnection[] = [];
    const intel = ThreatIntel.getSharedInstance();

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;

      const tokens = line.split(/\s+/);
      if (tokens.length < 4) continue;

      const proto = tokens[0].toUpperCase();
      if (proto !== 'TCP' && proto !== 'UDP') continue;

      let localRaw = '';
      let remoteRaw = '';
      let state = 'UNKNOWN';
      let pidStr = '0';

      if (proto === 'TCP') {
        if (tokens.length >= 5) {
          localRaw = tokens[1];
          remoteRaw = tokens[2];
          state = tokens[3].toUpperCase();
          pidStr = tokens[4];
        } else if (tokens.length === 4) {
          localRaw = tokens[1];
          remoteRaw = tokens[2];
          pidStr = tokens[3];
          state = 'ESTABLISHED';
        }
      } else {
        // UDP format: UDP  Local Address  Foreign Address  PID
        localRaw = tokens[1];
        remoteRaw = tokens[2];
        state = 'NONE';
        pidStr = tokens[3] || '0';
      }

      const pid = parseInt(pidStr, 10);
      if (isNaN(pid)) continue;

      const local = NetworkMonitorService.parseAddressPort(localRaw);
      const remote = NetworkMonitorService.parseAddressPort(remoteRaw);

      const threatIndicators: string[] = [];
      let isRemoteMalicious = false;
      let isSuspiciousPort = false;
      let threatName: string | undefined;
      let riskScore = 0;

      // Check if remote IP is in ThreatIntel blocklist
      const isLoopbackOrWildcard =
        remote.address === '*' ||
        remote.address === '0.0.0.0' ||
        remote.address === '127.0.0.1' ||
        remote.address === '::1' ||
        remote.address === '::';

      if (!isLoopbackOrWildcard && remote.address) {
        const intelResult = intel.checkUrl(`http://${remote.address}`);
        if (intelResult.isMalicious) {
          isRemoteMalicious = true;
          riskScore = 100;
          threatName = intelResult.threatName || 'KNOWN_MALICIOUS_C2_IP';
          threatIndicators.push(`Remote IP matches threat intelligence blocklist (${remote.address})`);
        }
      }

      // Check suspicious C2 ports
      if (NetworkMonitorService.SUSPICIOUS_C2_PORTS.has(remote.port) && !isLoopbackOrWildcard) {
        isSuspiciousPort = true;
        if (riskScore < 45) riskScore = 45;
        threatIndicators.push(`Connection to suspicious/high-risk C2 port: :${remote.port}`);
      }

      connections.push({
        protocol: proto as 'TCP' | 'UDP',
        localAddress: local.address,
        localPort: local.port,
        remoteAddress: remote.address,
        remotePort: remote.port,
        state,
        pid,
        isRemoteMalicious,
        isSuspiciousPort,
        ...(threatName ? { threatName } : {}),
        riskScore,
        threatIndicators
      });
    }

    return connections;
  }

  /**
   * Parses `netsh advfirewall show allprofiles` output into structured FirewallProfileState.
   */
  public parseFirewallOutput(rawOutput: string): FirewallProfileState {
    if (!rawOutput || typeof rawOutput !== 'string') {
      return {
        domainProfile: 'UNKNOWN',
        privateProfile: 'UNKNOWN',
        publicProfile: 'UNKNOWN',
        isFirewallActive: false,
        rawDiagnostic: 'EMPTY_OUTPUT'
      };
    }

    let domainProfile: 'ON' | 'OFF' | 'UNKNOWN' = 'UNKNOWN';
    let privateProfile: 'ON' | 'OFF' | 'UNKNOWN' = 'UNKNOWN';
    let publicProfile: 'ON' | 'OFF' | 'UNKNOWN' = 'UNKNOWN';

    const domainMatch = rawOutput.match(/Domain Profile Settings:[\s\S]*?State\s+([A-Za-z]+)/i);
    if (domainMatch) {
      domainProfile = domainMatch[1].toUpperCase() === 'ON' ? 'ON' : 'OFF';
    }

    const privateMatch = rawOutput.match(/Private Profile Settings:[\s\S]*?State\s+([A-Za-z]+)/i);
    if (privateMatch) {
      privateProfile = privateMatch[1].toUpperCase() === 'ON' ? 'ON' : 'OFF';
    }

    const publicMatch = rawOutput.match(/Public Profile Settings:[\s\S]*?State\s+([A-Za-z]+)/i);
    if (publicMatch) {
      publicProfile = publicMatch[1].toUpperCase() === 'ON' ? 'ON' : 'OFF';
    }

    const isFirewallActive =
      domainProfile === 'ON' || privateProfile === 'ON' || publicProfile === 'ON';

    return {
      domainProfile,
      privateProfile,
      publicProfile,
      isFirewallActive,
      rawDiagnostic:
        domainProfile === 'UNKNOWN' && privateProfile === 'UNKNOWN' && publicProfile === 'UNKNOWN'
          ? 'UNRECOGNIZED_FORMAT'
          : undefined
    };
  }

  /**
   * Collects complete, genuine local network posture without making external network requests.
   */
  public async getNetworkPosture(): Promise<NetworkPostureReport> {
    const interfaces = os.networkInterfaces();
    const resultInterfaces: Array<{
      name: string;
      address: string;
      family: 'IPv4' | 'IPv6';
      isInternal: boolean;
    }> = [];

    let hasExternal = false;

    for (const [name, netList] of Object.entries(interfaces)) {
      if (!netList) continue;
      for (const net of netList) {
        resultInterfaces.push({
          name,
          address: net.address,
          family: net.family,
          isInternal: net.internal
        });
        if (!net.internal && (net.family === 'IPv4' || net.family === 'IPv6')) {
          hasExternal = true;
        }
      }
    }

    let connections: NetworkSocketConnection[] = [];
    let firewallStatus: FirewallProfileState = {
      domainProfile: 'UNKNOWN',
      privateProfile: 'UNKNOWN',
      publicProfile: 'UNKNOWN',
      isFirewallActive: false
    };

    // 1. Query Active Sockets (netstat -ano)
    try {
      const tcpOut = await this.runner.exec('netstat', ['-ano', '-p', 'TCP']);
      const parsedTcp = this.parseNetstatOutput(tcpOut.stdout);
      connections.push(...parsedTcp);
    } catch {
      // Graceful fallback if netstat is restricted
    }

    try {
      const udpOut = await this.runner.exec('netstat', ['-ano', '-p', 'UDP']);
      const parsedUdp = this.parseNetstatOutput(udpOut.stdout);
      connections.push(...parsedUdp);
    } catch {
      // Graceful fallback if UDP query is restricted
    }

    // 2. Query Windows Defender Firewall state (netsh advfirewall show allprofiles)
    try {
      const firewallOut = await this.runner.exec('netsh', ['advfirewall', 'show', 'allprofiles']);
      firewallStatus = this.parseFirewallOutput(firewallOut.stdout);
    } catch (err: any) {
      firewallStatus = {
        domainProfile: 'UNKNOWN',
        privateProfile: 'UNKNOWN',
        publicProfile: 'UNKNOWN',
        isFirewallActive: false,
        rawDiagnostic: err?.message || 'FIREWALL_QUERY_FAILED'
      };
    }

    const maliciousSocketsCount = connections.filter((c) => c.isRemoteMalicious).length;
    const suspiciousSocketsCount = connections.filter((c) => c.isSuspiciousPort).length;

    return {
      interfaces: resultInterfaces,
      activeInterfacesCount: resultInterfaces.length,
      hasExternalConnectivity: hasExternal,
      firewallStatus,
      connections,
      maliciousSocketsCount,
      suspiciousSocketsCount,
      notice:
        'Privex evaluates network connections locally against ThreatIntel blocklists and C2 heuristics. All operations run 100% offline.'
    };
  }
}
