import * as child_process from 'child_process';
import * as fs from 'fs';
import { ProcessInfo, ProcessContainmentResult, ContainProcessOptions } from '../types/desktop.types';
import { BehaviorEngineService } from './behavior-engine.service';
import { FileAnalyzer } from '../core/file-analyzer';

export interface ProcessAuditorOptions {
  readonly behaviorEngine?: BehaviorEngineService;
  readonly scanBinaryOnDisk?: boolean;
  readonly dryRunContainment?: boolean;
  readonly processQueryProvider?: () => Promise<Array<Partial<ProcessInfo> & { pid: number; processName: string }>>;
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
    this.scanBinaryOnDisk = options?.scanBinaryOnDisk ?? true;
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
        isProtectedSystemProcess: evaluation.isProtectedSystemProcess,
        authorization: evaluation.authorization
      });
    }

    return enrichedProcesses;
  }

  // ============================================================
  // PROCESS CONTAINMENT (RULE-09 & USER-MODE ARREST)
  // ============================================================

  /**
   * Queries the live operating system for process existence and identity (SEC-F-05 TOCTOU revalidation).
   */
  public async getProcessIdentity(pid: number): Promise<{
    exists: boolean;
    processName?: string;
    creationTime?: number;
    executablePath?: string;
  }> {
    if (this.customQueryProvider) {
      try {
        const list = await this.customQueryProvider();
        const match = list.find((p) => p.pid === pid);
        if (!match) return { exists: false };
        return {
          exists: true,
          processName: match.processName,
          creationTime: match.creationDate
            ? typeof match.creationDate === 'number'
              ? match.creationDate
              : (match.creationDate as any).getTime?.()
            : undefined,
          executablePath: match.executablePath
        };
      } catch {
        return { exists: false };
      }
    }

    if (process.platform === 'win32') {
      return new Promise((resolve) => {
        const psCommand = `Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}" | Select-Object ProcessId,Name,ExecutablePath,CreationDate | ConvertTo-Json -Compress`;
        child_process.execFile(
          'powershell',
          ['-NoProfile', '-NonInteractive', '-Command', psCommand],
          { timeout: 2000 },
          (err, stdout) => {
            if (err || !stdout || !stdout.trim().startsWith('{')) {
              // Tasklist fallback
              child_process.execFile('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { timeout: 1500 }, (tErr, tStdout) => {
                if (tErr || !tStdout || !tStdout.includes(String(pid))) {
                  resolve({ exists: false });
                  return;
                }
                const parts = tStdout.split('","').map((p) => p.replace(/^"|"$/g, ''));
                resolve({
                  exists: true,
                  processName: parts[0] || undefined
                });
              });
              return;
            }

            try {
              const data = JSON.parse(stdout);
              let creationTime: number | undefined;
              if (data.CreationDate) {
                const parsed = new Date(data.CreationDate).getTime();
                if (!isNaN(parsed)) creationTime = parsed;
              }
              resolve({
                exists: true,
                processName: data.Name,
                creationTime,
                executablePath: data.ExecutablePath
              });
            } catch {
              resolve({ exists: false });
            }
          }
        );
      });
    }

    // POSIX fallback
    return new Promise((resolve) => {
      child_process.execFile('ps', ['-p', String(pid), '-o', 'comm='], { timeout: 1500 }, (err, stdout) => {
        if (err || !stdout || stdout.trim().length === 0) {
          resolve({ exists: false });
          return;
        }
        resolve({
          exists: true,
          processName: stdout.trim()
        });
      });
    });
  }

  /**
   * Safely contains/terminates a confirmed malicious non-system process.
   * STRICT INVARIANTS:
   * 1. RULE-09: Hard-rejects PID 0, PID 4, and critical OS processes.
   * 2. SEC-F-01: Requires authoritative ProcessContainmentAuthorization issued by BehaviorEngine.
   * 3. SEC-F-05: Revalidates process identity & creation timestamp immediately before kill.
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

    // 2. Query process details from lineage graph
    const lineage = this.behaviorEngine.getLineage(pid, 1);
    const procNode = lineage[0];
    const procNameFromGraph = procNode?.processName || '';
    const execPathFromGraph = procNode?.executablePath || '';

    // Check system process protection from lineage graph FIRST (RULE-09)
    if (this.behaviorEngine.isProtectedSystemProcess(pid, procNameFromGraph, execPathFromGraph)) {
      const isMasquerade = this.behaviorEngine.isPathMasquerading(procNameFromGraph, execPathFromGraph);
      if (!isMasquerade) {
        return {
          success: false,
          pid,
          processName: procNameFromGraph,
          action: 'REJECTED_PROTECTED',
          reason: `RULE-09: Process '${procNameFromGraph}' (PID ${pid}) is a protected Windows operating system component.`,
          containedAt: now
        };
      }
    }

    // 3. SEC-F-01: Reject calls without authorization token immediately
    if (!options?.authorizationId || !options?.token) {
      return {
        success: false,
        pid,
        processName: procNameFromGraph,
        action: 'REJECTED_UNAUTHORIZED',
        reason: 'Containment authorization required: missing authorizationId or single-use token.',
        containedAt: now
      };
    }

    // 4. Query live OS identity for TOCTOU revalidation
    const liveIdentity = await this.getProcessIdentity(pid);
    const procName = liveIdentity.processName || procNameFromGraph;
    const execPath = liveIdentity.executablePath || execPathFromGraph;

    // Check system process protection again with live identity
    if (this.behaviorEngine.isProtectedSystemProcess(pid, procName, execPath)) {
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

    // 5. SEC-F-01 & SEC-F-05: Enforce mandatory authorization and revalidate identity
    const authValidation = this.behaviorEngine.validateAndConsumeAuthorization(
      options?.authorizationId,
      options?.token,
      pid,
      liveIdentity.creationTime ?? options?.expectedCreationTime,
      procName
    );

    if (!authValidation.valid) {
      return {
        success: false,
        pid,
        processName: procName,
        action: authValidation.action as any,
        reason: authValidation.reason,
        containedAt: now,
        authorizationId: options?.authorizationId
      };
    }

    // 6. Pre-containment TOCTOU OS existence check
    if (!liveIdentity.exists && !options?.dryRun && !this.dryRunContainment) {
      return {
        success: true,
        pid,
        processName: procName,
        action: 'NOT_FOUND',
        reason: `Process PID ${pid} not found: process has already terminated.`,
        containedAt: now,
        authorizationId: options?.authorizationId
      };
    }

    // 4. Dry-run containment check
    if (this.dryRunContainment || options?.dryRun) {
      return {
        success: true,
        pid,
        processName: procName,
        action: 'TERMINATED',
        reason: 'Dry-run containment: termination simulated successfully.',
        containedAt: now,
        authorizationId: options?.authorizationId
      };
    }

    // 5. Terminate target process safely
    try {
      if (process.platform === 'win32') {
        await new Promise<void>((resolve, reject) => {
          child_process.execFile('taskkill', ['/PID', String(pid), '/T', '/F'], (err) => {
            if (err) {
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
        containedAt: now,
        authorizationId: options?.authorizationId
      };
    } catch (err: any) {
      if (err?.code === 'ESRCH') {
        return {
          success: true,
          pid,
          processName: procName,
          action: 'NOT_FOUND',
          reason: 'Process already exited prior to termination signal',
          containedAt: now,
          authorizationId: options?.authorizationId
        };
      }

      if (err?.code === 'EPERM' || String(err).includes('Access is denied')) {
        return {
          success: false,
          pid,
          processName: procName,
          action: 'FAILED',
          reason: 'Access denied: insufficient administrative privilege to terminate process',
          containedAt: now,
          authorizationId: options?.authorizationId
        };
      }

      return {
        success: false,
        pid,
        processName: procName,
        action: 'FAILED',
        reason: err?.message || 'Process termination failed',
        containedAt: now,
        authorizationId: options?.authorizationId
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
