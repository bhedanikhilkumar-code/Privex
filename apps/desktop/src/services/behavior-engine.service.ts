import * as path from 'path';
import {
  Evidence,
  DetectorType,
  DetectorLayer,
  SeverityLevel,
  RiskScorer,
  ProcessAnalyzer
} from '@private-protection/core';
import { ProcessInfo, ProcessLineageNode, ThreatSeverity } from '../types/desktop.types';

export interface BehaviorEngineOptions {
  readonly maxTrackedProcesses?: number;
  readonly maxLineageDepth?: number;
  readonly ttlMs?: number;
}

export interface ProcessBehaviorEvaluation {
  readonly pid: number;
  readonly processName: string;
  readonly executablePath: string;
  readonly commandLine?: string;
  readonly sanitizedCommandLine?: string;
  readonly riskScore: number;
  readonly confidence: number;
  readonly severity: ThreatSeverity;
  readonly verdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';
  readonly engineVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' | 'CONTAIN_PROCESS';
  readonly threatName: string;
  readonly evidenceFactors: string[];
  readonly evidence: Evidence[];
  readonly isLolbin: boolean;
  readonly isProtectedSystemProcess: boolean;
  readonly lineageChain: string[];
}

/**
 * BehaviorEngineService (Phase F — Component 03)
 *
 * Correlates runtime process metadata, parent-child lineage anomalies,
 * Living-off-the-Land Binary (LOLBin) command lines, and path masquerading
 * into structured Evidence tokens scored exclusively via the canonical RiskScorer.
 *
 * INVARIANTS:
 * 1. Read-only behavioral analysis — never executes or evaluates code.
 * 2. 100% offline air-gapped processing in bounded volatile memory.
 * 3. Evidence-only producer: canonical RiskScorer / EngineVerdict remains the sole authority.
 * 4. Zero AI decision authority.
 * 5. PID-reuse resilient via compound instance keys.
 */
export class BehaviorEngineService {
  private readonly maxTrackedProcesses: number;
  private readonly maxLineageDepth: number;
  private readonly ttlMs: number;

  // Bounded process storage: instanceKey -> ProcessLineageNode
  private readonly processGraph = new Map<string, ProcessLineageNode>();
  // Active PID -> latest instanceKey mapping (PID reuse protection)
  private readonly pidToInstanceKey = new Map<number, string>();

  private instanceCounter = 0;
  private readonly riskScorer: RiskScorer;

  // ============================================================
  // CANONICAL LOLBIN CATALOG & SYSTEM DIRECTORIES
  // ============================================================

  public static readonly KNOWN_LOLBINS = new Set([
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'rundll32.exe',
    'regsvr32.exe',
    'reg.exe',
    'certutil.exe',
    'bitsadmin.exe',
    'msiexec.exe',
    'installutil.exe',
    'cmstp.exe',
    'msbuild.exe',
    'vssadmin.exe',
    'wmic.exe',
    'schtasks.exe',
    'hh.exe',
    'bash.exe',
    'wsl.exe',
    'at.exe',
    'sc.exe',
    'net.exe',
    'net1.exe',
    'regasm.exe',
    'regsvcs.exe',
    'forfiles.exe',
    'pcalua.exe',
    'scriptrunner.exe'
  ]);

  public static readonly CRITICAL_SYSTEM_PROCESSES = new Set([
    'system',
    'smss.exe',
    'csrss.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'lsm.exe',
    'winlogon.exe',
    'svchost.exe',
    'explorer.exe'
  ]);

  public static readonly DOCUMENT_PARENTS = new Set([
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'acrord32.exe',
    'acrobat.exe',
    'mspub.exe',
    'visio.exe'
  ]);

  public static readonly BROWSER_PARENTS = new Set([
    'chrome.exe',
    'msedge.exe',
    'firefox.exe',
    'brave.exe',
    'opera.exe'
  ]);

  public static readonly SCRIPT_INTERPRETERS = new Set([
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'rundll32.exe',
    'regsvr32.exe',
    'certutil.exe',
    'bitsadmin.exe'
  ]);

  private static readonly USER_WRITABLE_DIR_PATTERNS = [
    /\\appdata\\local\\temp\\/i,
    /\\windows\\temp\\/i,
    /\\users\\[^\\]+\\downloads\\/i,
    /\\users\\public\\/i,
    /\\programdata\\[^\\]*$/i,
    /\/tmp\//i,
    /\/var\/tmp\//i,
    /\\temp\\/i
  ];

  private static readonly SYSTEM_DIR_PATTERNS = [
    /^[a-z]:\\windows\\system32(?:\\|$)/i,
    /^[a-z]:\\windows\\syswow64(?:\\|$)/i,
    /^[a-z]:\\windows\\winsxs(?:\\|$)/i,
    /^[a-z]:\\windows\\systemapps(?:\\|$)/i
  ];

  // ============================================================
  // SUSPICIOUS COMMAND-LINE REGEX PATTERNS (PURE INSPECTION)
  // ============================================================

  private static readonly CLI_PATTERNS: Array<{
    ruleId: string;
    name: string;
    regex: RegExp;
    score: number;
    severity: SeverityLevel;
    threatName: string;
    isCriticalOverride?: boolean;
    description: (match: string) => string;
  }> = [
    {
      ruleId: 'behav-ps1-encoded-command',
      name: 'PowerShell Encoded Command Execution',
      regex: /(?:-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{8,}/i,
      score: 85,
      severity: SeverityLevel.CRITICAL,
      threatName: 'POWERSHELL_ENCODED_COMMAND',
      isCriticalOverride: true,
      description: () => 'PowerShell invoked with Base64 encoded payload to evade static string analysis.'
    },
    {
      ruleId: 'behav-ps1-hidden-bypass',
      name: 'PowerShell Hidden Window and ExecutionPolicy Bypass',
      regex: /(?:-w(?:indowstyle)?\s+hidden.*-ep\s+bypass|-ep\s+bypass.*-w(?:indowstyle)?\s+hidden|-w\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass)/i,
      score: 78,
      severity: SeverityLevel.HIGH,
      threatName: 'POWERSHELL_HIDDEN_BYPASS',
      description: () => 'PowerShell invoked with hidden window and ExecutionPolicy bypass flags.'
    },
    {
      ruleId: 'behav-ps1-hidden-download-cradle',
      name: 'Hidden PowerShell Remote Download Cradle',
      regex: /(?:downloadstring|downloadfile|invoke-webrequest|iwr\s+|curl\s+|wget\s+)/i,
      score: 88,
      severity: SeverityLevel.CRITICAL,
      threatName: 'POWERSHELL_DOWNLOAD_CRADLE',
      isCriticalOverride: true,
      description: () => 'PowerShell invoked with remote network download cradle payload.'
    },
    {
      ruleId: 'behav-ransomware-shadow-delete',
      name: 'Volume Shadow Copy Deletion (Ransomware Inhibitor)',
      regex: /(?:delete\s+shadows|resize\s+shadowstorage)/i,
      score: 95,
      severity: SeverityLevel.CRITICAL,
      threatName: 'VSSADMIN_SHADOW_DELETION',
      isCriticalOverride: true,
      description: () => 'Utility attempted deletion of volume shadow copies to prevent system recovery.'
    },
    {
      ruleId: 'behav-certutil-urlcache-download',
      name: 'Certutil Ingress Tool Transfer / Download',
      regex: /certutil(?:\.exe)?\s+.*(?:-urlcache|-split)/i,
      score: 82,
      severity: SeverityLevel.HIGH,
      threatName: 'CERTUTIL_INGRESS_TRANSFER',
      description: () => 'Certutil certificate utility abused as an ingress file download mechanism.'
    },
    {
      ruleId: 'behav-bitsadmin-transfer',
      name: 'Bitsadmin Background File Download',
      regex: /bitsadmin(?:\.exe)?\s+.*\/transfer/i,
      score: 78,
      severity: SeverityLevel.HIGH,
      threatName: 'BITSADMIN_INGRESS_TRANSFER',
      description: () => 'Bitsadmin background copy manager abused to stage remote payloads.'
    },
    {
      ruleId: 'behav-mshta-remote-script',
      name: 'Mshta Remote Scriptlet Execution',
      regex: /mshta(?:\.exe)?\s+.*(?:http|javascript:|vbscript:)/i,
      score: 85,
      severity: SeverityLevel.CRITICAL,
      threatName: 'MSHTA_REMOTE_SCRIPT',
      isCriticalOverride: true,
      description: () => 'HTML Application host (mshta.exe) invoked with remote URL or inline script protocol.'
    },
    {
      ruleId: 'behav-regsvr32-squiblydoo',
      name: 'Regsvr32 Remote Scriptlet (Squiblydoo)',
      regex: /regsvr32(?:\.exe)?\s+.*(?:\/i:http|\/i:https|scrobj\.dll)/i,
      score: 90,
      severity: SeverityLevel.CRITICAL,
      threatName: 'REGSVR32_SQUIBLYDOO',
      isCriticalOverride: true,
      description: () => 'Regsvr32 utility abused to execute remote COM scriptlet bypassing AppLocker.'
    },
    {
      ruleId: 'behav-rundll32-inline-script',
      name: 'Rundll32 Script Protocol / Temp Execution',
      regex: /rundll32(?:\.exe)?\s+.*(?:javascript:|mshtml|appdata|temp)/i,
      score: 85,
      severity: SeverityLevel.HIGH,
      threatName: 'RUNDLL32_SCRIPT_ABUSE',
      description: () => 'Rundll32 invoked with inline script protocol or target DLL in temp folder.'
    },
    {
      ruleId: 'behav-piped-interpreter-chain',
      name: 'Piped Shell Interpreter Chaining',
      regex: /\|\s*(?:powershell|pwsh|cmd)(?:\.exe)?/i,
      score: 80,
      severity: SeverityLevel.HIGH,
      threatName: 'PIPED_SHELL_CHAIN',
      description: () => 'Commands piped directly to command interpreter to conceal execution stream.'
    },
    {
      ruleId: 'behav-installutil-uninstall-bypass',
      name: 'InstallUtil Uninstall Proxy Execution',
      regex: /installutil(?:\.exe)?\s+.*\/u\s+/i,
      score: 75,
      severity: SeverityLevel.HIGH,
      threatName: 'INSTALLUTIL_PROXY_EXECUTION',
      description: () => 'InstallUtil abused to execute unmanaged payload via /U uninstall handler.'
    },
    {
      ruleId: 'behav-cmstp-profile-install',
      name: 'CMSTP INF Profile Execution (UAC Bypass)',
      regex: /cmstp(?:\.exe)?\s+.*(?:\/s|\/au|\/ni)/i,
      score: 80,
      severity: SeverityLevel.HIGH,
      threatName: 'CMSTP_INF_EXECUTION',
      description: () => 'Microsoft Connection Manager Profile Installer invoked with silent INF script.'
    },
    {
      ruleId: 'behav-msbuild-inline-task',
      name: 'MSBuild Inline Task / Project Execution',
      regex: /msbuild(?:\.exe)?\s+.*(?:\.csproj|\.xml|\.proj)/i,
      score: 70,
      severity: SeverityLevel.HIGH,
      threatName: 'MSBUILD_INLINE_TASK',
      description: () => 'MSBuild invoked on untrusted project file to execute inline C# compilation.'
    }
  ];

  constructor(options?: BehaviorEngineOptions) {
    this.maxTrackedProcesses = options?.maxTrackedProcesses ?? 1024;
    this.maxLineageDepth = options?.maxLineageDepth ?? 10;
    this.ttlMs = options?.ttlMs ?? 300000; // 5 minutes default
    this.riskScorer = new RiskScorer();
  }

  // ============================================================
  // PROCESS LINEAGE GRAPH & PID-REUSE SAFE TRACKING
  // ============================================================

  /**
   * Registers or updates a process in the lineage graph.
   * Handles PID reuse by creating a unique monotonic instanceKey.
   */
  public registerProcess(info: {
    pid: number;
    ppid?: number;
    processName?: string;
    name?: string;
    executablePath?: string;
    commandLine?: string;
    creationDate?: Date;
    creationTime?: number;
    sha256?: string;
    isSigned?: boolean;
    signer?: string;
  }): ProcessLineageNode {
    const pid = info.pid;
    const processName = info.processName || info.name || 'unknown';
    const now = info.creationTime || (info.creationDate ? info.creationDate.getTime() : Date.now());
    this.instanceCounter++;
    const instanceKey = `${pid}:${now}:${this.instanceCounter}`;

    const sanitizedCommandLine = ProcessAnalyzer.sanitizeCommandLine(info.commandLine);
    const lowerName = processName.toLowerCase();
    const isLolbin = BehaviorEngineService.KNOWN_LOLBINS.has(lowerName);
    const isProtected = this.isProtectedSystemProcess(pid, lowerName, info.executablePath);

    const node: ProcessLineageNode = {
      pid,
      ppid: info.ppid,
      processName,
      executablePath: info.executablePath,
      commandLine: info.commandLine,
      sanitizedCommandLine,
      creationTime: now,
      sha256: info.sha256,
      isSigned: info.isSigned,
      signer: info.signer,
      isLolbin,
      isProtectedSystemProcess: isProtected,
      instanceKey
    };

    // If active PID already mapped, previous process terminated/reused
    this.pidToInstanceKey.set(pid, instanceKey);
    this.processGraph.set(instanceKey, node);

    // Enforce bounded memory invariants
    this.pruneOldEntries();

    return node;
  }

  /**
   * Alias for registerProcess.
   */
  public recordProcess(info: {
    pid: number;
    ppid?: number;
    processName?: string;
    name?: string;
    executablePath?: string;
    commandLine?: string;
    creationDate?: Date;
    creationTime?: number;
    sha256?: string;
    isSigned?: boolean;
    signer?: string;
  }): ProcessLineageNode {
    return this.registerProcess(info);
  }

  /**
   * Sanitizes command line arguments to redact credentials and tokens.
   */
  public sanitizeCommandLine(commandLine?: string): string {
    return ProcessAnalyzer.sanitizeCommandLine(commandLine) || '';
  }

  /**
   * Updates state with an entire table snapshot of running processes.
   */
  public updateProcessTable(processes: Array<Partial<ProcessInfo> & { pid: number; processName: string }>): void {
    for (const proc of processes) {
      this.registerProcess({
        pid: proc.pid,
        ppid: proc.ppid,
        processName: proc.processName,
        executablePath: proc.executablePath,
        commandLine: proc.commandLine,
        creationTime: proc.creationDate,
        sha256: proc.sha256,
        isSigned: proc.isSigned,
        signer: proc.signer
      });
    }
  }

  /**
   * Retrieves full lineage ancestor chain for a PID, safely bounded to maxLineageDepth.
   * Cycle-detection via Set prevents infinite loops on corrupt PPID trees.
   */
  public getLineage(pid: number, maxDepth = this.maxLineageDepth): ProcessLineageNode[] {
    const chain: ProcessLineageNode[] = [];
    const visited = new Set<string>();

    let currentKey = this.pidToInstanceKey.get(pid);
    let depth = 0;

    while (currentKey && depth < maxDepth) {
      if (visited.has(currentKey)) {
        break; // Cycle detected, terminate loop safely
      }
      visited.add(currentKey);

      const node = this.processGraph.get(currentKey);
      if (!node) break;

      chain.push(node);
      depth++;

      if (node.ppid === undefined || node.ppid <= 0 || node.ppid === node.pid) {
        break;
      }

      currentKey = this.pidToInstanceKey.get(node.ppid);
    }

    return chain;
  }

  /**
   * Returns current count of tracked processes in memory graph.
   */
  public getTrackedProcessCount(): number {
    return this.processGraph.size;
  }

  /**
   * Retrieves active process node by PID.
   */
  public getProcessByPid(pid: number): ProcessLineageNode | undefined {
    const key = this.pidToInstanceKey.get(pid);
    return key ? this.processGraph.get(key) : undefined;
  }

  /**
   * Prunes oldest entries when process graph capacity exceeds limits or entries expire.
   */
  private pruneOldEntries(): void {
    const now = Date.now();

    // 1. Remove expired entries
    if (this.processGraph.size > this.maxTrackedProcesses / 2) {
      for (const [key, node] of this.processGraph.entries()) {
        if (now - node.creationTime > this.ttlMs) {
          this.processGraph.delete(key);
          if (this.pidToInstanceKey.get(node.pid) === key) {
            this.pidToInstanceKey.delete(node.pid);
          }
        }
      }
    }

    // 2. FIFO shed if still exceeding max capacity
    while (this.processGraph.size > this.maxTrackedProcesses) {
      const oldestKey = this.processGraph.keys().next().value;
      if (!oldestKey) break;
      const oldNode = this.processGraph.get(oldestKey);
      if (oldNode && this.pidToInstanceKey.get(oldNode.pid) === oldestKey) {
        this.pidToInstanceKey.delete(oldNode.pid);
      }
      this.processGraph.delete(oldestKey);
    }
  }

  // ============================================================
  // HEURISTIC CHECKS & PATH VALIDATION
  // ============================================================

  /**
   * Checks whether a binary name or path corresponds to a known Living-off-the-Land binary.
   */
  public isLolbin(binaryOrPath: string): boolean {
    const base = path.basename(binaryOrPath).toLowerCase();
    return BehaviorEngineService.KNOWN_LOLBINS.has(base);
  }

  public isProtectedSystemProcess(pid: number, processName: string, executablePath?: string): boolean {
    if (pid === 0 || pid === 4) return true;

    const lowerName = processName.toLowerCase();
    if (BehaviorEngineService.CRITICAL_SYSTEM_PROCESSES.has(lowerName)) {
      if (!executablePath) return pid < 1000; // Low system PIDs
      return this.isLegitimateSystemPath(executablePath);
    }
    return false;
  }

  public isLegitimateSystemPath(filePath: string): boolean {
    if (!filePath) return false;
    const normalized = path.resolve(filePath).toLowerCase();
    return BehaviorEngineService.SYSTEM_DIR_PATTERNS.some((rx) => rx.test(normalized));
  }

  public isUserWritablePath(filePath: string): boolean {
    if (!filePath) return false;
    const normalized = path.resolve(filePath).toLowerCase();
    return BehaviorEngineService.USER_WRITABLE_DIR_PATTERNS.some((rx) => rx.test(normalized));
  }

  public isPathMasquerading(processName: string, executablePath?: string): boolean {
    if (!executablePath) return false;
    const lowerName = processName.toLowerCase();

    // If binary name is a critical system executable (e.g. svchost.exe, lsass.exe, csrss.exe)
    // but its executable path is NOT in Windows\System32, SysWOW64, or WinSxS:
    if (BehaviorEngineService.CRITICAL_SYSTEM_PROCESSES.has(lowerName) && lowerName !== 'explorer.exe') {
      return !this.isLegitimateSystemPath(executablePath);
    }
    return false;
  }

  // ============================================================
  // MULTI-SIGNAL BEHAVIORAL EVALUATION
  // ============================================================

  /**
   * Evaluates a process node against LOLBin catalog, argument patterns,
   * path masquerade rules, and parent-child lineage anomaly rules.
   * All evidence is mapped to canonical Evidence tokens and scored through RiskScorer.
   */
  public evaluateProcess(info: {
    pid: number;
    ppid?: number;
    processName?: string;
    name?: string;
    executablePath?: string;
    commandLine?: string;
    creationDate?: Date;
    creationTime?: number;
    sha256?: string;
    isSigned?: boolean;
    signer?: string;
  }): ProcessBehaviorEvaluation {
    const node = this.registerProcess(info);
    const evidence: Evidence[] = [];
    const evidenceFactors: string[] = [];
    let threatName = 'PROCESS_BENIGN';

    const lowerProcName = node.processName.toLowerCase();
    const executablePath = node.executablePath || '';
    const cli = node.commandLine || '';
    const isProtected = node.isProtectedSystemProcess ?? false;

    // Lineage lookup
    const lineage = this.getLineage(node.pid);
    const lineageNames = lineage.map((n) => n.processName);
    const parentNode = lineage.length > 1 ? lineage[1] : undefined;
    const parentName = parentNode ? parentNode.processName.toLowerCase() : '';

    // ------------------------------------------------------------
    // 1. Path Masquerading Check (svchost / lsass outside System32)
    // ------------------------------------------------------------
    if (this.isPathMasquerading(node.processName, executablePath)) {
      const desc = `Critical system binary '${node.processName}' executing outside legitimate system directory (${executablePath}).`;
      evidenceFactors.push(desc);
      threatName = 'SYSTEM_BINARY_PATH_MASQUERADE';
      evidence.push({
        ruleId: 'behav-system-path-masquerade',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
        source: 'BEHAVIOR_ENGINE',
        name: 'System Binary Path Masquerade',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.CRITICAL,
        weight: 95,
        scoreContribution: 95,
        confidence: 0.98,
        isCriticalOverride: true
      });
    }

    // ------------------------------------------------------------
    // 2. Double Extension Disguise (e.g. invoice.pdf.exe)
    // ------------------------------------------------------------
    const nameParts = lowerProcName.split('.');
    if (nameParts.length >= 3) {
      const desc = `Process '${node.processName}' exhibits a deceptive double-extension disguise pattern.`;
      evidenceFactors.push(desc);
      if (threatName === 'PROCESS_BENIGN') threatName = 'DECEPTIVE_DOUBLE_EXTENSION';
      evidence.push({
        ruleId: 'behav-double-extension-disguise',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
        source: 'BEHAVIOR_ENGINE',
        name: 'Double-Extension Disguised Process',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.HIGH,
        weight: 75,
        scoreContribution: 75,
        confidence: 0.9
      });
    }

    // ------------------------------------------------------------
    // 3. User-Writable Directory Execution for Non-System Executables
    // ------------------------------------------------------------
    if (this.isUserWritablePath(executablePath) && !this.isLegitimateSystemPath(executablePath)) {
      const desc = `Process '${node.processName}' executing from user-writable directory (${executablePath}).`;
      evidenceFactors.push(desc);
      evidence.push({
        ruleId: 'behav-writable-dir-execution',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
        source: 'BEHAVIOR_ENGINE',
        name: 'Execution From User-Writable Directory',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.MEDIUM,
        weight: 35,
        scoreContribution: 35,
        confidence: 0.8
      });
    }

    // ------------------------------------------------------------
    // 4. Parent-Child Lineage Anomalies
    // ------------------------------------------------------------
    if (parentName) {
      // (a) Document application spawned script interpreter / shell
      if (
        BehaviorEngineService.DOCUMENT_PARENTS.has(parentName) &&
        (BehaviorEngineService.SCRIPT_INTERPRETERS.has(lowerProcName) || node.isLolbin)
      ) {
        const desc = `Suspicious parent-child process chain: office/document application '${parentNode?.processName}' spawned interpreter '${node.processName}'.`;
        evidenceFactors.push(desc);
        threatName = 'OFFICE_SHELL_SPAWN';
        evidence.push({
          ruleId: 'behav-office-spawns-shell',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
          source: 'BEHAVIOR_ENGINE',
          name: 'Document Reader Spawned Shell Interpreter',
          description: desc,
          reason: desc,
          severityLevel: SeverityLevel.CRITICAL,
          weight: 90,
          scoreContribution: 90,
          confidence: 0.95,
          isCriticalOverride: true
        });
      }

      // (b) Web Browser spawned script interpreter / shell
      if (
        BehaviorEngineService.BROWSER_PARENTS.has(parentName) &&
        (BehaviorEngineService.SCRIPT_INTERPRETERS.has(lowerProcName) || node.isLolbin)
      ) {
        const desc = `Suspicious parent-child process chain: browser '${parentNode?.processName}' spawned utility '${node.processName}'.`;
        evidenceFactors.push(desc);
        if (threatName === 'PROCESS_BENIGN') threatName = 'BROWSER_SHELL_SPAWN';
        evidence.push({
          ruleId: 'behav-browser-spawns-lolbin',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
          source: 'BEHAVIOR_ENGINE',
          name: 'Web Browser Spawned Shell or LOLBin',
          description: desc,
          reason: desc,
          severityLevel: SeverityLevel.HIGH,
          weight: 85,
          scoreContribution: 85,
          confidence: 0.95,
          isCriticalOverride: true
        });
      }

      // (c) Chained Interpreters (e.g. cmd.exe -> powershell.exe -> mshta.exe)
      if (
        BehaviorEngineService.SCRIPT_INTERPRETERS.has(parentName) &&
        BehaviorEngineService.SCRIPT_INTERPRETERS.has(lowerProcName)
      ) {
        const desc = `Chained command interpreter execution: '${parentNode?.processName}' spawned '${node.processName}'.`;
        evidenceFactors.push(desc);
        if (threatName === 'PROCESS_BENIGN') threatName = 'CHAINED_INTERPRETER_EXECUTION';
        evidence.push({
          ruleId: 'behav-chained-interpreter',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
          source: 'BEHAVIOR_ENGINE',
          name: 'Chained Command Interpreter Execution',
          description: desc,
          reason: desc,
          severityLevel: SeverityLevel.HIGH,
          weight: 75,
          scoreContribution: 75,
          confidence: 0.85
        });
      }

      // (d) User-writable binary spawned LOLBin
      if (
        parentNode &&
        parentNode.executablePath &&
        this.isUserWritablePath(parentNode.executablePath) &&
        node.isLolbin
      ) {
        const desc = `User-writable executable '${parentNode.processName}' spawned LOLBin '${node.processName}'.`;
        evidenceFactors.push(desc);
        if (threatName === 'PROCESS_BENIGN') threatName = 'WRITABLE_BINARY_SPAWNS_LOLBIN';
        evidence.push({
          ruleId: 'behav-writable-spawns-lolbin',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
          source: 'BEHAVIOR_ENGINE',
          name: 'User-Writable Executable Spawned LOLBin',
          description: desc,
          reason: desc,
          severityLevel: SeverityLevel.HIGH,
          weight: 75,
          scoreContribution: 75,
          confidence: 0.85
        });
      }
    }

    // ------------------------------------------------------------
    // 5. Command-Line Argument Inspection (Pure Regex Analysis)
    // ------------------------------------------------------------
    if (cli) {
      for (const pattern of BehaviorEngineService.CLI_PATTERNS) {
        if (pattern.regex.test(cli)) {
          const desc = pattern.description(cli);
          evidenceFactors.push(desc);
          if (threatName === 'PROCESS_BENIGN') threatName = pattern.threatName;
          evidence.push({
            ruleId: pattern.ruleId,
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.BEHAVIORAL_ENGINE,
            source: 'BEHAVIOR_ENGINE',
            name: pattern.name,
            description: desc,
            reason: desc,
            severityLevel: pattern.severity,
            weight: pattern.score,
            scoreContribution: pattern.score,
            confidence: 0.95,
            isCriticalOverride: pattern.isCriticalOverride
          });
        }
      }
    }

    // ------------------------------------------------------------
    // 6. Canonical Risk Scoring via RiskScorer
    // ------------------------------------------------------------
    const scoreResult = this.riskScorer.calculateScore(evidence, 0, {
      inputType: 'PROCESS'
    });

    const finalScore = scoreResult.score;

    // Decision & Action mapping strictly aligned with Phase B contracts
    const engineVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' | 'CONTAIN_PROCESS' =
      finalScore >= 85 && !isProtected
        ? 'CONTAIN_PROCESS'
        : finalScore >= 70
        ? 'BLOCK'
        : finalScore >= 50
        ? 'WARN'
        : finalScore >= 20
        ? 'INFORM'
        : 'ALLOW';

    const verdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' =
      engineVerdict === 'CONTAIN_PROCESS' ? 'BLOCK' : (scoreResult.verdict as any) || 'ALLOW';

    const severity: ThreatSeverity =
      finalScore >= 85
        ? 'critical'
        : finalScore >= 70
        ? 'dangerous'
        : finalScore >= 50
        ? 'suspicious'
        : finalScore >= 20
        ? 'low'
        : 'safe';

    if (evidenceFactors.length === 0) {
      evidenceFactors.push('Process execution inspected; no anomalous behavior or suspicious arguments detected.');
    }

    return {
      pid: node.pid,
      processName: node.processName,
      executablePath,
      commandLine: node.commandLine,
      sanitizedCommandLine: node.sanitizedCommandLine,
      riskScore: finalScore,
      confidence: scoreResult.confidence,
      severity,
      verdict,
      engineVerdict,
      threatName,
      evidenceFactors,
      evidence,
      isLolbin: node.isLolbin ?? false,
      isProtectedSystemProcess: isProtected,
      lineageChain: [...lineageNames].reverse()
    };
  }
}
