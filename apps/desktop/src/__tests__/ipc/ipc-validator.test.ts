import { describe, it, expect } from 'vitest';
import { IpcValidator } from '../../ipc/ipc-validator';

describe('IpcValidator (IPC Parameter Hardening & Traversal Defense)', () => {
  it('validates and resolves clean canonical filesystem paths', () => {
    const valid = IpcValidator.validatePath('./src');
    expect(valid).toBeDefined();
    expect(typeof valid).toBe('string');
  });

  it('rejects path strings containing dangerous shell metacharacters', () => {
    expect(() => IpcValidator.validatePath('C:\\Downloads\\test.exe | del /f')).toThrow(
      'SECURITY_VIOLATION'
    );
    expect(() => IpcValidator.validatePath('C:\\test;rmdir /s /q')).toThrow(
      'SECURITY_VIOLATION'
    );
    expect(() => IpcValidator.validatePath('C:\\test&whoami')).toThrow(
      'SECURITY_VIOLATION'
    );
    expect(() => IpcValidator.validatePath('C:\\test`id`')).toThrow(
      'SECURITY_VIOLATION'
    );
  });

  it('rejects parent directory traversal segments (..)', () => {
    expect(() => IpcValidator.validatePath('C:\\Users\\Public\\..\\..\\Windows\\System32')).toThrow(
      'SECURITY_VIOLATION: Relative parent directory traversal (..) is prohibited.'
    );
    expect(() => IpcValidator.validatePath('../../etc/passwd')).toThrow(
      'SECURITY_VIOLATION: Relative parent directory traversal (..) is prohibited.'
    );
  });

  it('rejects remote UNC network share paths', () => {
    expect(() => IpcValidator.validatePath('\\\\192.168.1.99\\malicious_share\\payload.exe')).toThrow(
      'SECURITY_VIOLATION: Remote UNC network paths are prohibited.'
    );
    expect(() => IpcValidator.validatePath('//evil-smb-server/share/dropper.exe')).toThrow(
      'SECURITY_VIOLATION: Remote UNC network paths are prohibited.'
    );
  });

  it('rejects path strings containing embedded null bytes', () => {
    expect(() => IpcValidator.validatePath('C:\\test\0.exe')).toThrow('Null byte detected');
  });

  it('validates scan target arrays and enforces target count bounds', () => {
    const targets = IpcValidator.validateScanTargets(['./src']);
    expect(targets.length).toBe(1);

    expect(() => IpcValidator.validateScanTargets([])).toThrow('INVALID_TARGETS');
    expect(() => IpcValidator.validateScanTargets(new Array(33).fill('./src'))).toThrow(
      'INVALID_TARGETS'
    );
    expect(() => IpcValidator.validateScanTargets(['../secret'])).toThrow(
      'SECURITY_VIOLATION'
    );
  });

  it('validates trusted Electron renderer sender origins and blocks external origins', () => {
    expect(() => IpcValidator.validateSenderOrigin('file:///C:/app/dist/renderer/index.html')).not.toThrow();
    expect(() => IpcValidator.validateSenderOrigin('app://private-protection/index.html')).not.toThrow();
    expect(() => IpcValidator.validateSenderOrigin('http://localhost:5173/')).not.toThrow();
    expect(() => IpcValidator.validateSenderOrigin('http://127.0.0.1:3000/')).not.toThrow();

    expect(() => IpcValidator.validateSenderOrigin('https://evil-phishing.example.com')).toThrow(
      'SECURITY_VIOLATION: Untrusted renderer origin rejected'
    );
    expect(() => IpcValidator.validateSenderOrigin('')).toThrow(
      'SECURITY_VIOLATION: Missing or untrusted IPC sender origin.'
    );
  });

  it('validates alphanumeric identifiers with mandatory prefixes', () => {
    const id = IpcValidator.validateId('quarantine-12345', 'quarantine-');
    expect(id).toBe('quarantine-12345');

    expect(() => IpcValidator.validateId('malicious-id;DROP TABLE', 'quarantine-')).toThrow(
      'SECURITY_VIOLATION'
    );
    expect(() => IpcValidator.validateId('wrong-prefix-123', 'quarantine-')).toThrow(
      'INVALID_ID'
    );
  });

  it('validates cognitive levels for the AI assistant', () => {
    expect(IpcValidator.validateCognitiveLevel('grade8')).toBe('grade8');
    expect(IpcValidator.validateCognitiveLevel('grade6')).toBe('grade6');
    expect(IpcValidator.validateCognitiveLevel('invalid')).toBe('grade6');
  });
});
