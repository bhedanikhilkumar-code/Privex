import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sourceDir = path.resolve(__dirname, '../dist');
const targetDir = path.resolve(__dirname, '../android/app/src/main/assets');

if (!fs.existsSync(sourceDir)) {
  console.error(`[copy-assets] Source directory does not exist: ${sourceDir}`);
  console.error('[copy-assets] Please run "vite build" first.');
  process.exit(1);
}

// Ensure target directory exists and is clean
if (fs.existsSync(targetDir)) {
  fs.rmSync(targetDir, { recursive: true, force: true });
}
fs.mkdirSync(targetDir, { recursive: true });

// Copy all files recursively from dist to assets
function copyFolderRecursiveSync(source, target) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }

  const files = fs.readdirSync(source);
  for (const file of files) {
    const curSource = path.join(source, file);
    const curTarget = path.join(target, file);
    if (fs.lstatSync(curSource).isDirectory()) {
      copyFolderRecursiveSync(curSource, curTarget);
    } else {
      fs.copyFileSync(curSource, curTarget);
    }
  }
}

copyFolderRecursiveSync(sourceDir, targetDir);

// Verify index.html exists in target
const targetIndex = path.join(targetDir, 'index.html');
if (!fs.existsSync(targetIndex)) {
  console.error(`[copy-assets] ERROR: index.html missing from target assets: ${targetIndex}`);
  process.exit(1);
}

const copiedFiles = fs.readdirSync(targetDir);
console.log(`[copy-assets] Successfully copied ${copiedFiles.length} top-level entries into ${targetDir}`);
console.log(`[copy-assets] Verified: ${targetIndex} exists (${fs.statSync(targetIndex).size} bytes)`);
