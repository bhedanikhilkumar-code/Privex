import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const sumsPath = path.resolve(rootDir, 'release/SHA256SUMS.txt');

const lines = fs.readFileSync(sumsPath, 'utf8').trim().split('\n');
console.log('=== VERIFYING RELEASE ARTIFACTS AND CHECKSUMS ===\n');

let allPassed = true;

for (const line of lines) {
  if (!line.trim()) continue;
  const [expectedHash, fileName] = line.trim().split(/\s+/);
  const filePath = path.resolve(rootDir, 'release', fileName);

  if (fs.existsSync(filePath)) {
    const actualHash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
    const size = fs.statSync(filePath).size;
    const match = actualHash.toLowerCase() === expectedHash.toLowerCase();
    if (!match) allPassed = false;

    console.log(`[${match ? 'PASS' : 'FAIL'}] ${fileName}`);
    console.log(`  Size:     ${size} bytes`);
    console.log(`  Expected: ${expectedHash}`);
    console.log(`  Actual:   ${actualHash}\n`);
  } else {
    console.log(`[MISSING] ${fileName} not found at ${filePath}\n`);
    allPassed = false;
  }
}

if (allPassed) {
  console.log('✓ All release artifacts are 100% verified against SHA256SUMS.txt');
  process.exit(0);
} else {
  console.error('✗ Some release artifacts failed verification!');
  process.exit(1);
}
