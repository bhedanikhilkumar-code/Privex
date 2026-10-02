import * as os from 'os';

export interface NetworkInterfaceInfo {
  name: string;
  address: string;
  family: 'IPv4' | 'IPv6';
  isInternal: boolean;
}

export interface NetworkPostureReport {
  interfaces: NetworkInterfaceInfo[];
  activeInterfacesCount: number;
  hasExternalConnectivity: boolean;
  firewallStatus: string;
  notice: string;
}

export class NetworkMonitorService {
  /**
   * Reports genuine local network posture without claiming fake packet-level firewall filtering.
   */
  public async getNetworkPosture(): Promise<NetworkPostureReport> {
    const interfaces = os.networkInterfaces();
    const result: NetworkInterfaceInfo[] = [];

    let hasExternal = false;

    for (const [name, netList] of Object.entries(interfaces)) {
      if (!netList) continue;
      for (const net of netList) {
        result.push({
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

    return {
      interfaces: result,
      activeInterfacesCount: result.length,
      hasExternalConnectivity: hasExternal,
      firewallStatus: 'OS_NATIVE_FIREWALL_DELEGATED',
      notice: 'Private Protection monitors domain and URL threats at the application layer. Packet filtering is delegated to the native OS firewall.'
    };
  }
}
