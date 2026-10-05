import { describe, it, expect } from 'vitest';
import { ProcessAuditorService } from '../../services/process-auditor.service';

describe('ProcessAuditorService (Process Posture Audit)', () => {
  const auditor = new ProcessAuditorService();

  it('audits running processes without terminating them', async () => {
    const procs = await auditor.auditRunningProcesses();
    expect(Array.isArray(procs)).toBe(true);
  }, 30000);

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
