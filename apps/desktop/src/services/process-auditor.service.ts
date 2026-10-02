import * as child_process from 'child_process';
import { ProcessInfo } from '../types/desktop.types';

export class ProcessAuditorService {
  /**
   * Enumerates active processes and audits their executable names and locations.
   * STRICT INVARIANT: Read-only audit. Never autonomously terminates processes.
   */
  public async auditRunningProcesses(): Promise<ProcessInfo[]> {
    if (process.platform === 'win32') {
      return this.auditWindowsProcesses();
    }
    return this.auditPosixProcesses();
  }

  private auditWindowsProcesses(): Promise<ProcessInfo[]> {
    return new Promise((resolve) => {
      // Execute tasklist without shell interpolation
      child_process.execFile('tasklist', ['/FO', 'CSV', '/NH'], (err, stdout) => {
        if (err || !stdout) {
          resolve([]);
          return;
        }

        const lines = stdout.split('\r\n').filter((line) => line.trim().length > 0);
        const processes: ProcessInfo[] = [];

        for (const line of lines) {
          // Format: "Image Name","PID","Session Name","Session#","Mem Usage"
          const parts = line.split('","').map((p) => p.replace(/^"|"$/g, ''));
          if (parts.length >= 2) {
            const processName = parts[0];
            const pid = parseInt(parts[1], 10) || 0;

            const isSuspicious = this.isProcessNameSuspicious(processName);
            processes.push({
              pid,
              processName,
              executablePath: processName,
              isSuspicious: isSuspicious.suspicious,
              reason: isSuspicious.reason
            });
          }
        }

        resolve(processes);
      });
    });
  }

  private auditPosixProcesses(): Promise<ProcessInfo[]> {
    return new Promise((resolve) => {
      child_process.execFile('ps', ['-A', '-o', 'pid,comm'], (err, stdout) => {
        if (err || !stdout) {
          resolve([]);
          return;
        }

        const lines = stdout.split('\n').slice(1).filter((l) => l.trim().length > 0);
        const processes: ProcessInfo[] = [];

        for (const line of lines) {
          const trimmed = line.trim();
          const match = trimmed.match(/^(\d+)\s+(.+)$/);
          if (match) {
            const pid = parseInt(match[1], 10);
            const processName = match[2];
            const isSuspicious = this.isProcessNameSuspicious(processName);

            processes.push({
              pid,
              processName,
              executablePath: processName,
              isSuspicious: isSuspicious.suspicious,
              reason: isSuspicious.reason
            });
          }
        }

        resolve(processes);
      });
    });
  }

  /**
   * Checks if process name exhibits double extensions, disguised document names, or known suspicious patterns.
   */
  public isProcessNameSuspicious(procName: string): { suspicious: boolean; reason?: string } {
    const lower = procName.toLowerCase();

    // Check for double extension disguised process (e.g. invoice.pdf.exe)
    const parts = lower.split('.');
    if (parts.length >= 3) {
      return {
        suspicious: true,
        reason: 'Process exhibits double-extension disguise pattern'
      };
    }

    // Check for known deceptive system spoofer names
    const suspiciousNames = ['svchost32.exe', 'lsasss.exe', 'explorer_update.exe', 'powershell_stealth.exe'];
    if (suspiciousNames.includes(lower)) {
      return {
        suspicious: true,
        reason: 'Process name mimics a critical Windows system executable'
      };
    }

    return { suspicious: false };
  }
}
