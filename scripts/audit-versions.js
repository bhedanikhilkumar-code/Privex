import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const pkgs = [
  'package.json',
  'packages/core/package.json',
  'packages/ml/package.json',
  'packages/ui/package.json',
  'apps/web/package.json',
  'apps/mobile/package.json',
  'apps/desktop/package.json',
  'apps/extension/package.json'
];

console.log('=== AUDITING WORKSPACE PACKAGE VERSIONS ===');
let consistent = true;
const rootPkg = JSON.parse(fs.readFileSync(path.resolve(rootDir, 'package.json'), 'utf8'));
const targetVersion = rootPkg.version || '0.1.2';

for (const rel of pkgs) {
  const full = path.resolve(rootDir, rel);
  const data = JSON.parse(fs.readFileSync(full, 'utf8'));
  console.log(`${rel.padEnd(30)} -> ${data.name.padEnd(32)} v${data.version}`);
  if (data.version !== targetVersion) {
    consistent = false;
  }
}

if (consistent) {
  console.log(`\n✓ All packages are consistent at version ${targetVersion}`);
} else {
  console.error(`\n✗ Inconsistent versions detected!`);
  process.exit(1);
}
