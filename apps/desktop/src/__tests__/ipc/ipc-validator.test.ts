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

  it('rejects path strings containing embedded null bytes', () => {
    expect(() => IpcValidator.validatePath('C:\\test\0.exe')).toThrow('Null byte detected');
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
