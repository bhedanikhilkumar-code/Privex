import { describe, it, expect } from 'vitest';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';

describe('PersistenceAuditorService (Startup Auditing)', () => {
  const auditor = new PersistenceAuditorService();

  it('audits startup persistence locations safely in read-only mode', async () => {
    const items = await auditor.auditStartupLocations();
    expect(Array.isArray(items)).toBe(true);
  });

  it('detects suspicious automated script files in persistence entries', () => {
    const check1 = auditor.checkPersistenceEntry('updater.vbs');
    expect(check1.suspicious).toBe(true);
    expect(check1.reason).toContain('Automated script');

    const check2 = auditor.checkPersistenceEntry('clean_app.exe');
    expect(check2.suspicious).toBe(false);

    const check3 = auditor.checkPersistenceEntry('document.pdf.bat');
    expect(check3.suspicious).toBe(true);
  });
});
