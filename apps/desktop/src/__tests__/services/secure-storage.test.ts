import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SecureStorageService } from '../../services/secure-storage.service';

describe('SecureStorageService (AES-256-GCM Settings & Crypto-Shredder)', () => {
  let tempDir: string;
  let storage: SecureStorageService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-storage-test-'));
    storage = new SecureStorageService(tempDir);
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('reads default settings when no settings file exists', () => {
    const settings = storage.getSettings();
    expect(settings.realtimeShieldEnabled).toBe(true);
    expect(settings.scanLargeFilesLimitMb).toBe(50);
  });

  it('encrypts and persists settings using AES-256-GCM', () => {
    storage.saveSettings({ scanLargeFilesLimitMb: 100, realtimeShieldEnabled: false });

    // File on disk must NOT be plaintext JSON
    const encPath = path.join(tempDir, 'settings.enc');
    expect(fs.existsSync(encPath)).toBe(true);
    const rawContent = fs.readFileSync(encPath, 'utf8');
    expect(rawContent).not.toContain('scanLargeFilesLimitMb');
    expect(rawContent).toContain('iv');
    expect(rawContent).toContain('tag');

    // Decrypts accurately
    const loaded = storage.getSettings();
    expect(loaded.scanLargeFilesLimitMb).toBe(100);
    expect(loaded.realtimeShieldEnabled).toBe(false);
  });

  it('crypto-shredder completely purges all local storage and configuration', () => {
    storage.saveSettings({ scanLargeFilesLimitMb: 75 });
    storage.purgeAllData();

    // Re-loaded settings reset to default
    const reset = storage.getSettings();
    expect(reset.scanLargeFilesLimitMb).toBe(50);
  });
});
