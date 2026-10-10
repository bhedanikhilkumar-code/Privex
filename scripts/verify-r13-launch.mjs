import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks)
        });
      });
    }).on('error', reject);
  });
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function verifyR13Launch() {
  console.log('============================================================');
  console.log('R13 — PUBLIC LAUNCH + DISTRIBUTION VERIFICATION SUITE');
  console.log('============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // 1. Production Website Verification
  console.log('--- 1. PUBLIC WEBSITE (R13-A) ---');
  const webRes = await get('https://privex.pages.dev/');
  assert(webRes.status === 200, 'Web URL resolves with HTTP 200');
  assert(webRes.headers['strict-transport-security'] !== undefined, 'HSTS header enforced on Cloudflare Pages');
  assert(webRes.headers['content-security-policy'] !== undefined, 'Content-Security-Policy header enforced');
  
  const html = webRes.body.toString('utf-8');
  assert(html.includes('Privex'), 'HTML includes brand title');
  assert(html.includes('vite') || html.includes('assets/index'), 'Production bundled assets referenced');

  // 2. Direct Public Downloads Verification
  console.log('\n--- 2. DIRECT PUBLIC DOWNLOADS (R13-B, R13-C, R13-E) ---');
  
  // SHA256SUMS.txt
  const sumsRes = await get('https://privex.pages.dev/downloads/SHA256SUMS.txt');
  assert(sumsRes.status === 200, 'Public SHA256SUMS.txt accessible (HTTP 200)');
  const localSums = fs.readFileSync(path.join(process.cwd(), 'release', 'SHA256SUMS.txt'), 'utf-8');
  assert(sumsRes.body.toString('utf-8').trim() === localSums.trim(), 'Public SHA256SUMS.txt matches local release manifest exactly');

  // Android APK
  console.log('Downloading public Android APK from production edge CDN...');
  const apkRes = await get('https://privex.pages.dev/downloads/private-protection-mobile-0.1.0.apk');
  assert(apkRes.status === 200, 'Public Android APK accessible (HTTP 200)');
  assert(apkRes.headers['content-type'] === 'application/vnd.android.package-archive', 'APK content-type is valid android package');
  assert(apkRes.body.length === 1032677, `APK size matches exact byte count (1,032,677 bytes, got ${apkRes.body.length})`);
  const apkHash = sha256(apkRes.body);
  assert(apkHash === '95ee838e739e69feed4f007c431cb6a7e74304f6751e17a38c6e21269fcdb5b5', `APK SHA-256 verified (${apkHash})`);

  // Extension ZIP
  console.log('Downloading public Extension ZIP from production edge CDN...');
  const zipRes = await get('https://privex.pages.dev/downloads/private-protection-extension-0.1.0.zip');
  assert(zipRes.status === 200, 'Public Extension ZIP accessible (HTTP 200)');
  assert(zipRes.headers['content-type'] === 'application/zip', 'Extension content-type is application/zip');
  assert(zipRes.body.length === 100161, `Extension size matches exact byte count (100,161 bytes, got ${zipRes.body.length})`);
  const zipHash = sha256(zipRes.body);
  assert(zipHash === 'd0f42ab50db530b752cffd3b6e39a6f3a1e23f888e145375fe4b8cc5c67b25dc', `Extension SHA-256 verified (${zipHash})`);

  // 3. Local Release Artifacts Checksum Consistency (R13-J)
  console.log('\n--- 3. CHECKSUM & RELEASE ARTIFACT CONSISTENCY (R13-J, R13-I) ---');
  const manifestLines = localSums.trim().split(/\r?\n/).filter(l => l.trim().length > 0);
  for (const line of manifestLines) {
    const [expectedHash, filename] = line.split(/\s+/);
    const filePath = path.join(process.cwd(), 'release', filename);
    assert(fs.existsSync(filePath), `Release artifact file exists: ${filename}`);
    const actualBuf = fs.readFileSync(filePath);
    const actualHash = sha256(actualBuf);
    assert(actualHash === expectedHash, `${filename} hash matches SHA256SUMS.txt exactly (${actualHash})`);
  }

  // 4. README Link Integrity (R13-H)
  console.log('\n--- 4. LINK INTEGRITY & DOCUMENTATION VERIFICATION (R13-H, R13-G) ---');
  const readmeContent = fs.readFileSync(path.join(process.cwd(), 'README.md'), 'utf-8');
  
  // Check relative release links exist
  const relativeLinks = [
    'release/private-protection-mobile-0.1.0.apk',
    'release/PrivateProtection-Setup-0.1.0.exe',
    'release/PrivateProtection-0.1.0-win-x64.exe',
    'release/private-protection-extension-0.1.0.zip',
    'release/SHA256SUMS.txt'
  ];
  for (const rel of relativeLinks) {
    const full = path.join(process.cwd(), rel);
    assert(fs.existsSync(full), `README relative link points to real existing file: ${rel}`);
  }

  // Check First-Time User Q&A in README
  assert(readmeContent.includes('Does Privex require a backend server?'), 'README answers: Backend requirement');
  assert(readmeContent.includes('Does Privex require the cloud?'), 'README answers: Cloud requirement');
  assert(readmeContent.includes('Does my browsing history, messages, or files ever leave my device?'), 'README answers: Privacy & data handling');
  assert(readmeContent.includes('100% Offline Air-Gapped Test'), 'README answers: Offline functionality');
  assert(readmeContent.includes('Older / Budget Android Devices'), 'README answers: Low-resource / budget device support');

  console.log('\n============================================================');
  console.log(`VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('============================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

verifyR13Launch().catch(err => {
  console.error('Fatal Verification Error:', err);
  process.exit(1);
});
