const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const desktopRoot = path.resolve(__dirname, '..');
const releaseDir = path.join(desktopRoot, 'release');
const appDistDir = path.join(releaseDir, 'PrivateProtection-win32-x64');
const installerSrcDir = path.join(__dirname, 'installer-src');

const cscPath = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest('hex');
}

async function buildInstaller() {
  console.log('=== BUILDING WINDOWS CONSUMER INSTALLER ===');

  if (!fs.existsSync(appDistDir)) {
    console.log('[Installer] Packaged desktop app not found, running build-desktop.js --package first...');
    execSync('node scripts/build-desktop.js --package', { cwd: desktopRoot, stdio: 'inherit' });
  }

  if (!fs.existsSync(cscPath)) {
    throw new Error(`C# Compiler csc.exe not found at ${cscPath}`);
  }

  const payloadZip = path.join(releaseDir, 'payload.zip');
  if (!fs.existsSync(payloadZip)) {
    console.log('[Installer] Creating payload.zip from packaged Electron distribution...');
    const psZipCmd = `powershell -NoProfile -Command "Compress-Archive -Path '${appDistDir}/*' -DestinationPath '${payloadZip}' -Force"`;
    execSync(psZipCmd, { stdio: 'inherit' });
  } else {
    console.log('[Installer] Reusing existing payload.zip...');
  }

  const payloadStat = fs.statSync(payloadZip);
  console.log(`[Installer] Payload compressed: ${(payloadStat.size / (1024 * 1024)).toFixed(2)} MB`);

  const tempDir = path.join(releaseDir, 'installer-temp');
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });

  // 1. Compile Uninstaller
  console.log('[Installer] Compiling uninstaller executable (uninstaller.exe)...');
  const uninstallerCs = path.join(installerSrcDir, 'Uninstaller.cs');
  const uninstallerExe = path.join(tempDir, 'uninstaller.exe');
  const uninstallerCmd = `"${cscPath}" /nologo /target:winexe /platform:x64 /optimize+ /out:"${uninstallerExe}" /r:System.Windows.Forms.dll "${uninstallerCs}"`;
  execSync(uninstallerCmd, { stdio: 'inherit' });
  console.log('✓ Uninstaller compiled successfully.');

  const pkgJson = JSON.parse(fs.readFileSync(path.resolve(desktopRoot, 'package.json'), 'utf8'));
  const version = pkgJson.version || '0.1.1';

  // 2. Compile Installer with embedded payload.zip and uninstaller.exe
  console.log(`[Installer] Compiling standalone Windows consumer installer (PrivateProtection-Setup-${version}.exe)...`);
  const installerCs = path.join(installerSrcDir, 'Installer.cs');
  const setupExe = path.join(releaseDir, `PrivateProtection-Setup-${version}.exe`);

  const installerCmd = `"${cscPath}" /nologo /target:winexe /platform:x64 /optimize+ /out:"${setupExe}" /resource:"${payloadZip}" /resource:"${uninstallerExe}" /r:System.Windows.Forms.dll /r:System.IO.Compression.FileSystem.dll /r:System.IO.Compression.dll "${installerCs}"`;
  execSync(installerCmd, { stdio: 'inherit' });

  const setupStat = fs.statSync(setupExe);
  const setupSha256 = sha256File(setupExe);
  console.log(`✓ Standalone Windows installer generated: ${setupExe}`);
  console.log(`  Size: ${(setupStat.size / (1024 * 1024)).toFixed(2)} MB (${setupStat.size} bytes)`);
  console.log(`  SHA-256: ${setupSha256}`);

  // Cleanup temp files
  fs.rmSync(tempDir, { recursive: true, force: true });

  // Update installer manifest
  const manifest = {
    productName: 'Private Protection Desktop Security',
    version: version,
    platform: 'win32',
    arch: 'x64',
    installerType: 'Single-File Native Windows Setup (NSIS-compatible /S silent install)',
    builtAt: new Date().toISOString(),
    installer: {
      fileName: `PrivateProtection-Setup-${version}.exe`,
      path: setupExe,
      sizeBytes: setupStat.size,
      sha256: setupSha256
    }
  };

  fs.writeFileSync(
    path.join(releaseDir, 'INSTALLER_MANIFEST.json'),
    JSON.stringify(manifest, null, 2),
    'utf8'
  );
  console.log('✓ Wrote INSTALLER_MANIFEST.json');
}

buildInstaller().catch((err) => {
  console.error('[Installer Build Failed]', err);
  process.exit(1);
});
