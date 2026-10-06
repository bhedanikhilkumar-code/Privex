import { describe, it, expect, beforeEach } from 'vitest';
import * as child_process from 'child_process';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';

describe('ProcessAuditorService (Phase F — Process Auditing & Containment)', () => {
  let auditor: ProcessAuditorService;
  let behaviorEngine: BehaviorEngineService;

  beforeEach(() => {
    behaviorEngine = new BehaviorEngineService();
    auditor = new ProcessAuditorService({ behaviorEngine });
  });

  describe('1. Suspicious Name & Double Extension Detection', () => {
    it('identifies deceptive double-extension process names', () => {
      const check1 = auditor.isProcessNameSuspicious('invoice.pdf.exe');
      expect(check1.suspicious).toBe(true);
      expect(check1.reason).toContain('double-extension');

      const check2 = auditor.isProcessNameSuspicious('chrome.exe');
      expect(check2.suspicious).toBe(false);

      const check3 = auditor.isProcessNameSuspicious('svchost32.exe');
      expect(check3.suspicious).toBe(true);
      expect(check3.reason).toContain('system executable');
    });
  });

  describe('2. Process Audit with Mock Query Provider (AV-BEHAVIOR-001)', () => {
    it('enriches process table with behavioral and lineage intelligence', async () => {
      const mockRawProcesses = [
        {
          pid: 100,
          ppid: 0,
          processName: 'System',
          executablePath: 'C:\\Windows\\System32\\ntoskrnl.exe',
          commandLine: ''
        },
        {
          pid: 1000,
          ppid: 500,
          processName: 'WINWORD.EXE',
          executablePath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
          commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" doc.docx'
        },
        {
          pid: 1001,
          ppid: 1000,
          processName: 'cmd.exe',
          executablePath: 'C:\\Windows\\System32\\cmd.exe',
          commandLine: 'cmd.exe /c powershell.exe -enc SQBFAFgA...'
        },
        {
          pid: 2000,
          ppid: 1,
          processName: 'svchost.exe',
          executablePath: 'C:\\Users\\Public\\svchost.exe',
          commandLine: 'C:\\Users\\Public\\svchost.exe'
        }
      ];

      const testAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => mockRawProcesses
      });

      const audited = await testAuditor.auditRunningProcesses();
      expect(audited.length).toBe(4);

      // Check System process
      const systemProc = audited.find(p => p.pid === 100);
      expect(systemProc).toBeDefined();
      expect(systemProc?.isProtectedSystemProcess).toBe(true);
      expect(systemProc?.engineVerdict).not.toBe('CONTAIN_PROCESS');

      // Check WINWORD.EXE
      const wordProc = audited.find(p => p.pid === 1000);
      expect(wordProc).toBeDefined();

      // Check malicious child cmd.exe
      const cmdProc = audited.find(p => p.pid === 1001);
      expect(cmdProc).toBeDefined();
      expect(cmdProc?.isLolbin).toBe(true);
      expect(cmdProc?.parentName).toBe('WINWORD.EXE');
      expect(cmdProc?.riskScore).toBeGreaterThanOrEqual(85);
      expect(cmdProc?.verdict).toBe('BLOCK');
      expect(cmdProc?.engineVerdict).toBe('CONTAIN_PROCESS');
      expect(cmdProc?.evidenceFactors?.some(f => f.includes('office'))).toBe(true);

      // Check masqueraded svchost.exe
      const masqProc = audited.find(p => p.pid === 2000);
      expect(masqProc).toBeDefined();
      expect(masqProc?.riskScore).toBeGreaterThanOrEqual(85);
      expect(masqProc?.engineVerdict).toBe('CONTAIN_PROCESS');
      expect(masqProc?.evidenceFactors?.some(f => f.toLowerCase().includes('outside legitimate system directory'))).toBe(true);
    });
  });

  describe('3. Process Containment & RULE-09 Immunity (AV-BEHAVIOR-003)', () => {
    it('hard-rejects containment of critical OS process PID 0 and PID 4', async () => {
      const res0 = await auditor.containProcess(0);
      expect(res0.action).toBe('REJECTED_PROTECTED');
      expect(res0.pid).toBe(0);

      const res4 = await auditor.containProcess(4);
      expect(res4.action).toBe('REJECTED_PROTECTED');
      expect(res4.pid).toBe(4);
    });

    it('hard-rejects containment of critical Windows core system binaries', async () => {
      const protectedNames = [
        'smss.exe',
        'csrss.exe',
        'wininit.exe',
        'services.exe',
        'lsass.exe',
        'lsm.exe',
        'winlogon.exe',
        'svchost.exe'
      ];

      for (let i = 0; i < protectedNames.length; i++) {
        const pid = 5000 + i;
        const name = protectedNames[i];
        // Inject into behavior graph as system32 binary
        behaviorEngine.recordProcess({
          pid,
          processName: name,
          executablePath: `C:\\Windows\\System32\\${name}`
        });

        const res = await auditor.containProcess(pid);
        expect(res.action).toBe('REJECTED_PROTECTED');
        expect(res.processName).toBe(name);
      }
    });

    it('returns NOT_FOUND or TERMINATED when attempting to contain non-existent PID', async () => {
      // 999999 is extraordinarily unlikely to exist
      const res = await auditor.containProcess(999999);
      expect(['NOT_FOUND', 'TERMINATED']).toContain(res.action);
    });

    it('supports dryRun containment without killing processes', async () => {
      // Register a mock non-system process
      behaviorEngine.recordProcess({
        pid: 65432,
        processName: 'test_miner.exe',
        executablePath: 'C:\\temp\\test_miner.exe'
      });

      const res = await auditor.containProcess(65432, { dryRun: true });
      expect(res.action).toBe('TERMINATED');
      expect(res.reason).toContain('Dry-run');
    });

    it('successfully terminates a real non-system child process', async () => {
      // Spawn a lightweight idle process
      const child = child_process.spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
        stdio: 'ignore'
      });

      expect(child.pid).toBeDefined();
      const pid = child.pid!;

      try {
        const res = await auditor.containProcess(pid);
        expect(res.action).toBe('TERMINATED');
        expect(res.pid).toBe(pid);

        // Verify the child process is terminated
        let isAlive = true;
        try {
          process.kill(pid, 0); // signal 0 tests for existence
        } catch {
          isAlive = false;
        }
        expect(isAlive).toBe(false);
      } finally {
        try {
          child.kill('SIGKILL');
        } catch {
          // already dead
        }
      }
    });
  });

  describe('4. Performance SLA & Responsiveness', () => {
    it('executes process posture audit well within SLA (<500ms)', async () => {
      const mockRawProcesses = Array.from({ length: 50 }, (_, i) => ({
        pid: 10000 + i,
        ppid: 1000,
        processName: `worker_${i}.exe`,
        executablePath: `C:\\Program Files\\App\\worker_${i}.exe`,
        commandLine: `worker_${i}.exe --id ${i}`
      }));

      const testAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => mockRawProcesses
      });

      const start = Date.now();
      const results = await testAuditor.auditRunningProcesses();
      const elapsed = Date.now() - start;

      expect(results.length).toBe(50);
      expect(elapsed).toBeLessThan(500);
    });
  });
});
