import * as child_process from 'child_process';
import * as fs from 'fs';
import { ProcessInfo, ProcessContainmentResult } from '../types/desktop.types';
import { BehaviorEngineService } from './behavior-engine.service';
import { FileAnalyzer } from '../core/file-analyzer';

export interface ProcessAuditorOptions {
  readonly behaviorEngine?: BehaviorEngineService;
  readonly scanBinaryOnDisk?: boolean;
  readonly dryRunContainment?: boolean;
  readonly processQueryProvider?: () => Promise<Array<Partial<ProcessInfo> & { pid: number; processName: string }>>;
}

export interface ContainProcessOptions {
  readonly force?: boolean;
  readonly dryRun?: boolean;
  readonly reason?: string;
}

/**
 * ProcessAuditorService (Phase F — Process Lineage + LOLBin Monitoring)
 *
 * Discovers active user-mode processes, traces parent-child PID lineage via
 * BehaviorEngineService, evaluates LOLBin and masquerade threats, and safely
 * contains confirmed malicious non-system processes under strict RULE-09 governance.
 */
export class ProcessAuditorService {
  private readonly behaviorEngine: BehaviorEngineService;
  private readonly scanBinaryOnDisk: boolean;
  private readonly dryRunContainment: boolean;
  private readonly customQueryProvider?: () => Promise<Array<Partial<ProcessInfo> & { pid: number; processName: string }>>;

  constructor(options?: ProcessAuditorOptions) {
    this.behaviorEngine = options?.behaviorEngine || new BehaviorEngineService();
    this.scanBinaryOnDisk = options?.scanBinaryOnDisk ?? false;
    this.dryRunContainment = options?.dryRunContainment ?? false;
    this.customQueryProvider = options?.processQueryProvider;
  }

  public getBehaviorEngine(): BehaviorEngineService {
    return this.behaviorEngine;
  }

  /**
   * Enumerates active processes, enriches with parent PID & command line,
   * updates the lineage graph, and evaluates each against the behavioral catalog.
   */
  public async auditRunningProcesses(): Promise<ProcessInfo[]> {
    let rawProcesses: Array<Partial<ProcessInfo> & { pid: number; processName: string }>;

    if (this.customQueryProvider) {
      rawProcesses = await this.customQueryProvider();
    } else if (process.platform === 'win32') {
      rawProcesses = await this.queryWindowsProcesses();
    } else {
      rawProcesses = await this.queryPosixProcesses();
    }

    // Register full process snapshot into BehaviorEngine lineage graph
    this.behaviorEngine.updateProcessTable(rawProcesses);

    const enrichedProcesses: ProcessInfo[] = [];

    for (const proc of rawProcesses) {
      const evaluation = this.behaviorEngine.evaluateProcess({
        pid: proc.pid,
        ppid: proc.ppid,
        processName: proc.processName,
        executablePath: proc.executablePath,
        commandLine: proc.commandLine,
        sha256: proc.sha256,
        isSigned: proc.isSigned,
        signer: proc.signer
      });

      let onDiskAnalysisRisk = 0;
      let onDiskSha256 = proc.sha256;

      // Optional on-disk binary inspection through FileAnalyzer / CleanFileCache
      if (this.scanBinaryOnDisk && proc.executablePath && fs.existsSync(proc.executablePath)) {
        try {
          const fileResult = await FileAnalyzer.analyzeFile(proc.executablePath);
          onDiskAnalysisRisk = fileResult.riskScore;
          onDiskSha256 = fileResult.sha256;
        } catch {
          // Inaccessible file or permission restricted
        }
      }

      const combinedScore = Math.max(evaluation.riskScore, onDiskAnalysisRisk);
      const isSuspicious = combinedScore >= 50;

      enrichedProcesses.push({
        pid: proc.pid,
        ppid: proc.ppid,
        processName: proc.processName,
        parentName:
          evaluation.lineageChain.length > 1
            ? evaluation.lineageChain[evaluation.lineageChain.length - 2]
            : undefined,
        executablePath: proc.executablePath || proc.processName,
        commandLine: proc.commandLine,
        sanitizedCommandLine: evaluation.sanitizedCommandLine,
        sha256: onDiskSha256,
        isSigned: proc.isSigned,
        signer: proc.signer,
        creationDate: proc.creationDate || Date.now(),
        isSuspicious,
        reason: isSuspicious ? evaluation.evidenceFactors.join('; ') : undefined,
        riskScore: combinedScore,
        verdict: evaluation.verdict,
        engineVerdict: evaluation.engineVerdict,
        severity: evaluation.severity,
        threatName: evaluation.threatName,
        evidenceFactors: evaluation.evidenceFactors,
        isLolbin: evaluation.isLolbin,
        lineageChain: evaluation.lineageChain,
        isProtectedSystemProcess: evaluation.isProtectedSystemProcess
      });
    }

    return enrichedProcesses;
  }

  // ============================================================
  // PROCESS CONTAINMENT (RULE-09 & USER-MODE ARREST)
  // ============================================================

  /**
   * Safely contains/terminates a confirmed malicious non-system process.
   * STRICT INVARIANT (RULE-09): Hard-rejects PID 0, PID 4, and critical OS processes.
   */
  public async containProcess(
    pid: number,
    options?: ContainProcessOptions
  ): Promise<ProcessContainmentResult> {
    const now = Date.now();

    // 1. RULE-09: Hard check on kernel & idle PIDs
    if (pid === 0) {
      return {
        success: false,
        pid: 0,
        processName: 'System Idle Process',
        action: 'REJECTED_PROTECTED',
        reason: 'RULE-09: Cannot terminate system idle process (PID 0).',
        containedAt: now
      };
    }
    if (pid === 4) {
      return {
        success: false,
        pid: 4,
        processName: 'System',
        action: 'REJECTED_PROTECTED',
        reason: 'RULE-09: Cannot terminate Windows NT kernel System process (PID 4).',
        containedAt: now
      };
    }

    // 2. Query process details from lineage graph or live OS
    const lineage = this.behaviorEngine.getLineage(pid, 1);
    const procNode = lineage[0];
    const procName = procNode?.processName || '';
    const execPath = procNode?.executablePath || '';

    if (this.behaviorEngine.isProtectedSystemProcess(pid, procName, execPath)) {
      // Allow kill only if path is confirmed masquerading outside System32
      const isMasquerade = this.behaviorEngine.isPathMasquerading(procName, execPath);
      if (!isMasquerade) {
        return {
          success: false,
          pid,
          processName: procName,
          action: 'REJECTED_PROTECTED',
          reason: `RULE-09: Process '${procName}' (PID ${pid}) is a protected Windows operating system component.`,
          containedAt: now
        };
      }
    }

    // 3. Dry-run containment check
    if (this.dryRunContainment || options?.dryRun) {
      return {
        success: true,
        pid,
        processName: procName,
        action: 'TERMINATED',
        reason: 'Dry-run containment: termination simulated successfully.',
        containedAt: now
      };
    }

    // 4. Terminate target process safely
    try {
      if (process.platform === 'win32') {
        await new Promise<void>((resolve, reject) => {
          child_process.execFile('taskkill', ['/PID', String(pid), '/T', '/F'], (err) => {
            if (err) {
              // Taskkill error code 128 indicates process not found
              const errStr = String(err);
              if (errStr.includes('not found') || (err as any).code === 128) {
                resolve();
              } else {
                reject(err);
              }
            } else {
              resolve();
            }
          });
        });
      } else {
        process.kill(pid, 'SIGKILL');
      }

      return {
        success: true,
        pid,
        processName: procName,
        action: 'TERMINATED',
        reason: options?.reason || 'Malicious process terminated per EngineVerdict containment policy',
        containedAt: now
      };
    } catch (err: any) {
      if (err?.code === 'ESRCH') {
        return {
          success: true,
          pid,
          processName: procName,
          action: 'NOT_FOUND',
          reason: 'Process already exited prior to termination signal',
          containedAt: now
        };
      }

      if (err?.code === 'EPERM' || String(err).includes('Access is denied')) {
        return {
          success: false,
          pid,
          processName: procName,
          action: 'FAILED',
          reason: 'Access denied: insufficient administrative privilege to terminate process',
          containedAt: now
        };
      }

      return {
        success: false,
        pid,
        processName: procName,
        action: 'FAILED',
        reason: err?.message || 'Process termination failed',
        containedAt: now
      };
    }
  }

  // ============================================================
  // OS PROCESS DISCOVERY IMPLEMENTATIONS
  // ============================================================

  private queryWindowsProcesses(): Promise<Array<Partial<ProcessInfo> & { pid: number; processName: string }>> {
    return new Promise((resolve) => {
      // PowerShell Get-CimInstance query extracting PID, PPID, Name, ExecutablePath, CommandLine
      const psCommand =
        'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress';

      child_process.execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCommand], { timeout: 3000 }, (err, stdout) => {
        if (!err && stdout && stdout.trim().startsWith('[')) {
          try {
            const data = JSON.parse(stdout);
            if (Array.isArray(data)) {
              const processes = data.map((item: any) => ({
                pid: Number(item.ProcessId) || 0,
                ppid: Number(item.ParentProcessId) || undefined,
                processName: String(item.Name || 'unknown'),
                executablePath: item.ExecutablePath ? String(item.ExecutablePath) : String(item.Name || ''),
                commandLine: item.CommandLine ? String(item.CommandLine) : undefined
              }));
              resolve(processes);
              return;
            }
          } catch {
            // Fall through to tasklist fallback
          }
        }

        // Fallback: tasklist /FO CSV /V /NH
        child_process.execFile('tasklist', ['/FO', 'CSV', '/NH'], { timeout: 2000 }, (tErr, tStdout) => {
          if (tErr || !tStdout) {
            resolve([]);
            return;
          }

          const lines = tStdout.split('\r\n').filter((line) => line.trim().length > 0);
          const processes: Array<Partial<ProcessInfo> & { pid: number; processName: string }> = [];

          for (const line of lines) {
            const parts = line.split('","').map((p) => p.replace(/^"|"$/g, ''));
            if (parts.length >= 2) {
              const processName = parts[0];
              const pid = parseInt(parts[1], 10) || 0;
              processes.push({
                pid,
                processName,
                executablePath: processName
              });
            }
          }

          resolve(processes);
        });
      });
    });
  }

  private queryPosixProcesses(): Promise<Array<Partial<ProcessInfo> & { pid: number; processName: string }>> {
    return new Promise((resolve) => {
      child_process.execFile('ps', ['-A', '-o', 'pid,ppid,comm,args'], { timeout: 2000 }, (err, stdout) => {
        if (err || !stdout) {
          resolve([]);
          return;
        }

        const lines = stdout.split('\n').slice(1).filter((l) => l.trim().length > 0);
        const processes: Array<Partial<ProcessInfo> & { pid: number; processName: string }> = [];

        for (const line of lines) {
          const match = line.trim().match(/^(\d+)\s+(\d+)\s+([^\s]+)\s*(.*)$/);
          if (match) {
            const pid = parseInt(match[1], 10);
            const ppid = parseInt(match[2], 10);
            const processName = match[3];
            const commandLine = match[4] || processName;

            processes.push({
              pid,
              ppid,
              processName,
              executablePath: processName,
              commandLine
            });
          }
        }

        resolve(processes);
      });
    });
  }

  // Backward compatibility helper
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

    const evaluation = this.behaviorEngine.evaluateProcess({
      pid: 9999,
      processName: procName
    });
    return {
      suspicious: evaluation.riskScore >= 50,
      reason: evaluation.evidenceFactors.length > 0 ? evaluation.evidenceFactors.join('; ') : undefined
    };
  }
}
