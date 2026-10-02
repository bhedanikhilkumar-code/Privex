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

// 1. Extension Package
const extDist = path.resolve(rootDir, 'apps/extension/dist');
const extZip = path.resolve(releaseDir, 'private-protection-extension-0.1.0.zip');

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
const webZip = path.resolve(releaseDir, 'private-protection-web-0.1.0.zip');

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

// 3. Generate SHA256SUMS.txt
const sumsFile = path.resolve(releaseDir, 'SHA256SUMS.txt');
const lines = [];

const apkFile = path.resolve(rootDir, 'apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk');
const desktopExe = path.resolve(rootDir, 'apps/desktop/release/PrivateProtection-win32-x64/PrivateProtection.exe');

const artifacts = [
  { path: extZip, name: path.basename(extZip) },
  { path: webZip, name: path.basename(webZip) },
  { path: apkFile, name: 'private-protection-mobile-0.1.0.apk' },
  { path: desktopExe, name: 'PrivateProtection-0.1.0-win-x64.exe' }
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
