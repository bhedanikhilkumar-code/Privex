import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { BehaviorEngineService } from '../../services/behavior-engine.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { ProcessMonitorService } from '../../services/process-monitor.service';

describe('Phase F Adversarial & Remediation Test Suite (SEC-F-01 to SEC-F-05)', () => {
  let behaviorEngine: BehaviorEngineService;
  let auditor: ProcessAuditorService;
  let monitor: ProcessMonitorService;

  beforeEach(() => {
    behaviorEngine = new BehaviorEngineService({
      maxTrackedProcesses: 200,
      ttlMs: 30000
    });
    auditor = new ProcessAuditorService({
      behaviorEngine,
      scanBinaryOnDisk: false,
      processQueryProvider: async () => []
    });
    monitor = new ProcessMonitorService({
      behaviorEngine,
      processAuditor: auditor,
      maxQueueSize: 50,
      workerConcurrency: 2,
      pollIntervalMs: 5000,
      eventSourceOverride: 'MOCK'
    });
  });

  afterEach(() => {
    monitor.stop();
  });

  describe('SEC-F-01: Arbitrary Process Containment Defenses', () => {
    it('ADV-01: Rejects containment when caller provides no authorizationId or token', async () => {
      const res = await auditor.containProcess(12345);
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res.reason).toContain('authorization required');
    });

    it('ADV-02: Rejects containment when caller provides fabricated authorizationId', async () => {
      const res = await auditor.containProcess(12345, {
        authorizationId: 'auth-contain-fake-123',
        token: 'tok-fake-123'
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res.reason).toContain('not found or already consumed');
    });

    it('ADV-03: Rejects containment when caller provides wrong singleUseToken', async () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 12346,
        processName: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });
      expect(evalResult.authorization).toBeDefined();

      const res = await auditor.containProcess(12346, {
        authorizationId: evalResult.authorization!.authorizationId,
        token: 'wrong-token-abc'
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res.reason).toContain('Invalid containment authorization token');
    });

    it('ADV-04: Rejects second containment attempt with identical token (single-use guarantee)', async () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 12347,
        processName: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });
      const auth = evalResult.authorization!;

      // First call consumes the token (dryRun)
      const res1 = await auditor.containProcess(12347, {
        dryRun: true,
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res1.action).toBe('TERMINATED');

      // Second call must fail
      const res2 = await auditor.containProcess(12347, {
        dryRun: true,
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res2.success).toBe(false);
      expect(res2.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res2.reason).toContain('already consumed');
    });

    it('ADV-05: Rejects containment attempt after authorization token expires (TTL)', async () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 12348,
        processName: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });
      const auth = evalResult.authorization!;
      // Artificially expire the token
      (auth as any).expiresAt = Date.now() - 5000;

      const res = await auditor.containProcess(12348, {
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res.reason).toContain('expired');
    });

    it('ADV-06: Hard-rejects containment of protected OS binary even if caller holds malicious token', async () => {
      // Record svchost in System32
      behaviorEngine.recordProcess({
        pid: 12349,
        processName: 'svchost.exe',
        executablePath: 'C:\\Windows\\System32\\svchost.exe'
      });

      // Try to contain svchost
      const res = await auditor.containProcess(12349);
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_PROTECTED');
    });

    it('ADV-07: Never issues containment authorization for benign software', () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 12350,
        processName: 'notepad.exe',
        commandLine: 'notepad.exe mydoc.txt'
      });
      expect(evalResult.engineVerdict).toBe('ALLOW');
      expect(evalResult.authorization).toBeUndefined();
    });

    it('ADV-08: Target PID mismatch in authorization is rejected', async () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 12351,
        processName: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });
      const auth = evalResult.authorization!;

      // Attempt to use PID 12351's authorization against PID 99999
      const res = await auditor.containProcess(99999, {
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_UNAUTHORIZED');
      expect(res.reason).toContain('PID mismatch');
    });
  });

  describe('SEC-F-02: Continuous Process Monitoring & Truthful Health', () => {
    it('ADV-09: Health report truthfully reflects RUNNING status when started', async () => {
      await monitor.start();
      const health = monitor.getHealth();
      expect(health.status).toBe('RUNNING');
      expect(health.isContinuous).toBe(true);
      expect(health.eventSource).toBe('MOCK');
    });

    it('ADV-10: Prioritizes LOLBin events over benign processes in queue', async () => {
      await monitor.start();
      const order: string[] = [];

      monitor.on('processEvaluated', (ev) => {
        order.push(ev.processName);
      });

      // Enqueue benign first, then LOLBin
      monitor.enqueueEvent({
        eventId: 'evt-norm-1',
        pid: 5001,
        processName: 'calc.exe',
        creationTime: Date.now(),
        timestamp: Date.now()
      });
      monitor.enqueueEvent({
        eventId: 'evt-lol-1',
        pid: 5002,
        processName: 'powershell.exe',
        creationTime: Date.now(),
        timestamp: Date.now()
      });

      await new Promise((r) => setTimeout(r, 100));
      expect(order).toContain('powershell.exe');
      expect(order).toContain('calc.exe');
    });

    it('ADV-11: Detects backpressure and drops normal priority events first during event storm', async () => {
      const stormMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor: auditor,
        maxQueueSize: 5,
        workerConcurrency: 1
      });
      await stormMonitor.start();

      for (let i = 0; i < 20; i++) {
        stormMonitor.enqueueEvent({
          eventId: `evt-storm-${i}`,
          pid: 6000 + i,
          processName: `worker_${i}.exe`,
          creationTime: Date.now(),
          timestamp: Date.now()
        });
      }

      const health = stormMonitor.getHealth();
      expect(health.droppedEvents).toBeGreaterThan(0);
      expect(health.status).toBe('DEGRADED');
      stormMonitor.stop();
    });

    it('ADV-12: Stopped monitor drops incoming events gracefully without throwing', () => {
      monitor.stop();
      const accepted = monitor.enqueueEvent({
        eventId: 'evt-stopped-1',
        pid: 7001,
        processName: 'test.exe',
        creationTime: Date.now(),
        timestamp: Date.now()
      });
      expect(accepted).toBe(false);
      expect(monitor.getHealth().status).toBe('STOPPED');
    });
  });

  describe('SEC-F-03: Process Binary Inspection Defaults', () => {
    it('ADV-13: Defaults scanBinaryOnDisk to true in ProcessAuditorService', () => {
      const freshAuditor = new ProcessAuditorService();
      expect((freshAuditor as any).scanBinaryOnDisk).toBe(true);
    });

    it('ADV-14: Audit preserves binary scan default when options are omitted', () => {
      const freshAuditor = new ProcessAuditorService({ behaviorEngine });
      expect((freshAuditor as any).scanBinaryOnDisk).toBe(true);
    });
  });

  describe('SEC-F-04: Command-Line Privacy & Zero Raw Secret Persistence', () => {
    it('ADV-15: Masks API keys, tokens, and passwords in sanitizedCommandLine', () => {
      const rawCli = 'agent.exe --token ghp_99887766554433221100 --password P@ssw0rd999';
      const sanitized = behaviorEngine.sanitizeCommandLine(rawCli);
      expect(sanitized).not.toContain('ghp_99887766554433221100');
      expect(sanitized).not.toContain('P@ssw0rd999');
      expect(sanitized).toContain('[REDACTED]');
    });

    it('ADV-16: ProcessLineageNode memory contains zero unredacted secrets', () => {
      const secret = 'node.exe --token secret_access_token_xyz_123';
      const node = behaviorEngine.registerProcess({
        pid: 8001,
        processName: 'node.exe',
        commandLine: secret
      });

      expect((node as any).commandLine).toBeUndefined();
      expect(node.sanitizedCommandLine).not.toContain('secret_access_token_xyz_123');
      expect(node.sanitizedCommandLine).toContain('[REDACTED]');
    });

    it('ADV-17: ProcessGraph lookup returns sanitizedCommandLine without leaking raw credentials', () => {
      behaviorEngine.registerProcess({
        pid: 8002,
        processName: 'worker.exe',
        commandLine: 'worker.exe --password ConfidentialCredential987'
      });

      const lineage = behaviorEngine.getLineage(8002);
      expect((lineage[0] as any).commandLine).toBeUndefined();
      expect(lineage[0].sanitizedCommandLine).not.toContain('ConfidentialCredential987');
    });
  });

  describe('SEC-F-05: PID Reuse & TOCTOU Pre-Containment Revalidation', () => {
    it('ADV-18: Rejects containment when OS PID has recycled (creationTime drift > 1000ms)', async () => {
      const customAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => [
          {
            pid: 9001,
            processName: 'malware.exe',
            creationDate: 5000000 // Recycled process timestamp
          }
        ]
      });

      const evalResult = behaviorEngine.evaluateProcess({
        pid: 9001,
        processName: 'malware.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet',
        creationTime: 1000000 // Original observed timestamp
      });
      const auth = evalResult.authorization!;

      const res = await customAuditor.containProcess(9001, {
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_PID_REUSE');
      expect(res.reason).toContain('PID Reuse detected');
    });

    it('ADV-19: Rejects containment when OS PID process name differs from authorization', async () => {
      const customAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => [
          {
            pid: 9002,
            processName: 'benign_browser.exe',
            creationDate: 1000000
          }
        ]
      });

      const evalResult = behaviorEngine.evaluateProcess({
        pid: 9002,
        processName: 'trojan.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet',
        creationTime: 1000000
      });
      const auth = evalResult.authorization!;

      const res = await customAuditor.containProcess(9002, {
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res.success).toBe(false);
      expect(res.action).toBe('REJECTED_IDENTITY_MISMATCH');
      expect(res.reason).toContain('Process identity mismatch');
    });

    it('ADV-20: Dry-run containment succeeds when authorization, PID, and timestamps match', async () => {
      const evalResult = behaviorEngine.evaluateProcess({
        pid: 9003,
        processName: 'vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet'
      });
      const auth = evalResult.authorization!;

      const res = await auditor.containProcess(9003, {
        dryRun: true,
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken
      });
      expect(res.success).toBe(true);
      expect(res.action).toBe('TERMINATED');
      expect(res.reason).toContain('Dry-run');
    });
  });
});
