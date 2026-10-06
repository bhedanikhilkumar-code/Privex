import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  RemovableMediaService,
  RemovableMediaCommandRunner
} from '../../services/removable-media.service';

class MockRemovableCommandRunner implements RemovableMediaCommandRunner {
  public mockStdout = '';
  public mockStderr = '';
  public shouldFail = false;

  public async exec(_command: string, _args: string[]): Promise<{ stdout: string; stderr: string }> {
    if (this.shouldFail) {
      throw new Error('Command failed: execution error');
    }
    return { stdout: this.mockStdout, stderr: this.mockStderr };
  }
}

describe('RemovableMediaService (Phase M — Windows USB & Removable Media Protection)', () => {
  let tempDir: string;
  let mockRunner: MockRemovableCommandRunner;
  let service: RemovableMediaService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-removable-test-'));
    mockRunner = new MockRemovableCommandRunner();
    service = new RemovableMediaService({
      commandRunner: mockRunner,
      autoScanOnMount: false
    });
  });

  afterEach(() => {
    service.stopMonitoring();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('correctly discovers Windows DriveType=2 removable USB volumes with real byte capacity', async () => {
    mockRunner.mockStdout = JSON.stringify([
      {
        DeviceID: 'E:',
        VolumeName: 'SANDISK_USB',
        FileSystem: 'FAT32',
        Size: 32000000000,
        FreeSpace: 28000000000,
        DriveType: 2,
        VolumeSerialNumber: 'A1B2C3D4'
      },
      {
        DeviceID: 'C:',
        VolumeName: 'WINDOWS_OS',
        FileSystem: 'NTFS',
        Size: 500000000000,
        FreeSpace: 120000000000,
        DriveType: 3, // FIXED internal drive
        VolumeSerialNumber: 'F9E8D7C6'
      }
    ]);

    const drives = await service.getMountedDrives();
    // Must contain E: (DriveType=2) and strictly exclude C: (DriveType=3)
    expect(drives.length).toBe(1);
    expect(drives[0].mountPoint).toBe('E:\\');
    expect(drives[0].label).toBe('SANDISK_USB');
    expect(drives[0].totalBytes).toBe(32000000000);
    expect(drives[0].freeBytes).toBe(28000000000);
    expect(drives[0].driveType).toBe('REMOVABLE');
    expect(drives[0].isRemovable).toBe(true);
    expect(drives[0].fileSystem).toBe('FAT32');
    expect(drives[0].volumeSerialNumber).toBe('A1B2C3D4');
  });

  it('safely handles empty or malformed WMI responses without throwing unhandled errors', async () => {
    mockRunner.mockStdout = 'Not Valid JSON Output';
    const drives = await service.getMountedDrives();
    expect(Array.isArray(drives)).toBe(true);
    expect(drives.length).toBe(0);
  });

  it('safely handles command failure without crashing', async () => {
    mockRunner.shouldFail = true;
    const drives = await service.getMountedDrives();
    expect(Array.isArray(drives)).toBe(true);
    expect(drives.length).toBe(0);
  });

  it('starts monitoring, detects newly attached removable media and emits driveAttached event', async () => {
    let driveProviderCount = 0;
    const customService = new RemovableMediaService({
      driveProvider: async () => {
        driveProviderCount++;
        if (driveProviderCount === 1) {
          return [];
        }
        return [
          {
            mountPoint: tempDir,
            label: 'TEST_FLASH_DRIVE',
            totalBytes: 16000000000,
            freeBytes: 14000000000,
            driveType: 'REMOVABLE',
            isRemovable: true
          }
        ];
      },
      autoScanOnMount: false
    });

    const attachedDrives: any[] = [];
    customService.on('driveAttached', (drive) => {
      attachedDrives.push(drive);
    });

    customService.startMonitoring(50);
    await new Promise((resolve) => setTimeout(resolve, 150));
    customService.stopMonitoring();

    expect(attachedDrives.length).toBe(1);
    expect(attachedDrives[0].label).toBe('TEST_FLASH_DRIVE');
  });

  it('performs root quick-triage on completely clean USB root with ALLOW verdict', async () => {
    // Create clean benign files
    fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'Welcome to this USB drive.', 'utf-8');
    fs.writeFileSync(path.join(tempDir, 'data.csv'), 'id,name\n1,alice', 'utf-8');

    const result = await service.scanRemovableDriveRoot(tempDir);
    expect(result.threatsFound).toBe(0);
    expect(result.verdict).toBe('ALLOW');
    expect(result.severity).toBe('safe');
    expect(result.riskScore).toBe(0);
    expect(result.totalRootItemsScanned).toBe(2);
  });

  it('performs root quick-triage detecting autorun.inf threat and flags BLOCK verdict', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'autorun.inf'),
      '[autorun]\r\nopen=wscript.exe //e:vbs worm.vbs\r\naction=Open Folder',
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tempDir, 'worm.vbs'),
      'WScript.Echo "malicious script payload"',
      'utf-8'
    );

    const result = await service.scanRemovableDriveRoot(tempDir);
    expect(result.threatsFound).toBeGreaterThanOrEqual(1);
    expect(result.verdict).toBe('BLOCK');
    expect(result.severity).toBe('critical');
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.autorun?.hasAutorun).toBe(true);
    expect(result.autorun?.isSuspicious).toBe(true);
  });

  it('rejects invalid or non-existent mount paths with clear descriptive errors', async () => {
    await expect(service.scanRemovableDriveRoot(path.join(tempDir, 'missing-drive-path'))).rejects.toThrow(
      /REMOVABLE_DRIVE_NOT_FOUND/
    );
  });
});
