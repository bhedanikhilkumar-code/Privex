import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const releaseDir = path.resolve(rootDir, 'release');

if (!fs.existsSync(releaseDir)) {
  fs.mkdirSync(releaseDir, { recursive: true });
}

console.log('=== PACKAGING RELEASE ARTIFACTS ===');

function calculateSha256(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

const rootPkg = JSON.parse(fs.readFileSync(path.resolve(rootDir, 'package.json'), 'utf8'));
const version = rootPkg.version || '0.1.1';

// 1. Extension Package
const extDist = path.resolve(rootDir, 'apps/extension/dist');
const extZip = path.resolve(releaseDir, `private-protection-extension-${version}.zip`);

if (fs.existsSync(extDist)) {
  console.log('Packaging Browser Extension artifact...');
  if (fs.existsSync(extZip)) fs.unlinkSync(extZip);
  // Cross-platform zip creation via PowerShell or tar
  if (process.platform === 'win32') {
    execSync(`powershell -NoProfile -Command "Compress-Archive -Path '${extDist}/*' -DestinationPath '${extZip}' -Force"`);
  } else {
    execSync(`cd "${extDist}" && zip -r "${extZip}" ./*`);
  }
  const extSha = calculateSha256(extZip);
  const extSize = fs.statSync(extZip).size;
  console.log(`✓ Browser Extension packaged: ${path.basename(extZip)} (${extSize} bytes)`);
  console.log(`  SHA-256: ${extSha}`);
} else {
  console.error('Error: Extension dist directory does not exist. Run npm run build first.');
}

// 2. Web Application Package
const webDist = path.resolve(rootDir, 'apps/web/dist');
const webZip = path.resolve(releaseDir, `private-protection-web-${version}.zip`);

if (fs.existsSync(webDist)) {
  console.log('Packaging Web Application artifact...');
  if (fs.existsSync(webZip)) fs.unlinkSync(webZip);
  if (process.platform === 'win32') {
    execSync(`powershell -NoProfile -Command "Compress-Archive -Path '${webDist}/*' -DestinationPath '${webZip}' -Force"`);
  } else {
    execSync(`cd "${webDist}" && zip -r "${webZip}" ./*`);
  }
  const webSha = calculateSha256(webZip);
  const webSize = fs.statSync(webZip).size;
  console.log(`✓ Web Application packaged: ${path.basename(webZip)} (${webSize} bytes)`);
  console.log(`  SHA-256: ${webSha}`);
} else {
  console.error('Error: Web dist directory does not exist. Run npm run build first.');
}

// 3. Mobile Android Package
const releaseApk = path.resolve(rootDir, 'apps/mobile/android/app/build/outputs/apk/release/app-release.apk');
const debugApk = path.resolve(rootDir, 'apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk');
const releaseAab = path.resolve(rootDir, 'apps/mobile/android/app/build/outputs/bundle/release/app-release.aab');

const finalApkDest = path.resolve(releaseDir, `private-protection-mobile-${version}.apk`);
const finalAabDest = path.resolve(releaseDir, `private-protection-mobile-${version}.aab`);

if (fs.existsSync(releaseApk)) {
  console.log('Packaging Mobile Android Release APK artifact...');
  fs.copyFileSync(releaseApk, finalApkDest);
  const apkSha = calculateSha256(finalApkDest);
  const apkSize = fs.statSync(finalApkDest).size;
  console.log(`✓ Mobile Release APK packaged: ${path.basename(finalApkDest)} (${apkSize} bytes)`);
  console.log(`  SHA-256: ${apkSha}`);
} else if (fs.existsSync(debugApk)) {
  console.log('Packaging Mobile Android Debug APK fallback artifact...');
  fs.copyFileSync(debugApk, finalApkDest);
  const apkSha = calculateSha256(finalApkDest);
  const apkSize = fs.statSync(finalApkDest).size;
  console.log(`✓ Mobile Debug APK packaged: ${path.basename(finalApkDest)} (${apkSize} bytes)`);
  console.log(`  SHA-256: ${apkSha}`);
}

if (fs.existsSync(releaseAab)) {
  console.log('Packaging Mobile Android Release AAB artifact...');
  fs.copyFileSync(releaseAab, finalAabDest);
  const aabSha = calculateSha256(finalAabDest);
  const aabSize = fs.statSync(finalAabDest).size;
  console.log(`✓ Mobile Release AAB packaged: ${path.basename(finalAabDest)} (${aabSize} bytes)`);
  console.log(`  SHA-256: ${aabSha}`);
}

// 4. Desktop Packages
const desktopExe = path.resolve(rootDir, 'apps/desktop/release/PrivateProtection-win32-x64/PrivateProtection.exe');
const desktopPortableDest = path.resolve(releaseDir, `PrivateProtection-${version}-win-x64.exe`);
const desktopInstallerSrc = path.resolve(rootDir, `apps/desktop/release/PrivateProtection-Setup-${version}.exe`);
const desktopInstallerDest = path.resolve(releaseDir, `PrivateProtection-Setup-${version}.exe`);

if (fs.existsSync(desktopExe)) {
  console.log('Packaging Desktop Portable Executable artifact...');
  fs.copyFileSync(desktopExe, desktopPortableDest);
  const exeSha = calculateSha256(desktopPortableDest);
  const exeSize = fs.statSync(desktopPortableDest).size;
  console.log(`✓ Desktop Portable Executable packaged: ${path.basename(desktopPortableDest)} (${exeSize} bytes)`);
  console.log(`  SHA-256: ${exeSha}`);
}

if (fs.existsSync(desktopInstallerSrc)) {
  console.log('Packaging Desktop Consumer Installer artifact...');
  fs.copyFileSync(desktopInstallerSrc, desktopInstallerDest);
  const instSha = calculateSha256(desktopInstallerDest);
  const instSize = fs.statSync(desktopInstallerDest).size;
  console.log(`✓ Desktop Consumer Installer packaged: ${path.basename(desktopInstallerDest)} (${instSize} bytes)`);
  console.log(`  SHA-256: ${instSha}`);
}

// 5. Generate SHA256SUMS.txt
const sumsFile = path.resolve(releaseDir, 'SHA256SUMS.txt');
const lines = [];

const artifacts = [
  { path: extZip, name: path.basename(extZip) },
  { path: webZip, name: path.basename(webZip) },
  { path: finalApkDest, name: path.basename(finalApkDest) },
  { path: finalAabDest, name: path.basename(finalAabDest) },
  { path: desktopPortableDest, name: path.basename(desktopPortableDest) },
  { path: desktopInstallerDest, name: path.basename(desktopInstallerDest) }
];

for (const artifact of artifacts) {
  if (fs.existsSync(artifact.path)) {
    const sha = calculateSha256(artifact.path);
    lines.push(`${sha}  ${artifact.name}`);
  }
}

fs.writeFileSync(sumsFile, lines.join('\n') + '\n', 'utf8');
console.log(`\n✓ Generated ${path.basename(sumsFile)}:`);
console.log(fs.readFileSync(sumsFile, 'utf8'));
console.log('Release packaging completed successfully.');
