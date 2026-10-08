import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = process.cwd();

console.log('================================================================');
console.log('PRIVEX — SECURITY & SECRETS AUDIT (PHASE R2-A)');
console.log('================================================================\n');

// 1. Audit .gitignore
console.log('--- 1. AUDITING .gitignore RULES ---');
const gitignorePath = path.join(ROOT, '.gitignore');
const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
const gitignoreLines = gitignoreContent.split('\n').map(l => l.trim()).filter(Boolean);

const requiredExclusions = [
  '.env',
  '.env.local',
  '.env.*',
  '.wrangler',
  '*.pem',
  '*.key'
];

const missingPatterns = [];
for (const pattern of requiredExclusions) {
  const covered = gitignoreLines.some(line => line === pattern || (pattern === '.env.local' && gitignoreLines.includes('.env.*')));
  if (!covered) {
    missingPatterns.push(pattern);
  }
}

if (missingPatterns.length > 0) {
  console.log(`[ACTION REQUIRED] .gitignore is missing explicit patterns: ${missingPatterns.join(', ')}`);
} else {
  console.log('[PASS] .gitignore contains all required environment and secret exclusions.');
}

// 2. Scan for any on-disk secret or environment files (ignoring node_modules, .git, etc.)
console.log('\n--- 2. SCANNING FILESYSTEM FOR ACCIDENTAL SECRET/ENV FILES ---');
function findFiles(dir, matchRegex, ignoreDirs = ['node_modules', '.git', 'dist', 'coverage']) {
  let results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoreDirs.includes(entry.name)) {
        results = results.concat(findFiles(path.join(dir, entry.name), matchRegex, ignoreDirs));
      }
    } else {
      if (matchRegex.test(entry.name)) {
        results.push(path.relative(ROOT, path.join(dir, entry.name)));
      }
    }
  }
  return results;
}

const sensitiveFileRegex = /^(\.env.*|\.wrangler.*|.*\.(pem|key|p8|p12|keystore|jks)|id_rsa.*)$/i;
const foundFiles = findFiles(ROOT, sensitiveFileRegex);
console.log(`Discovered sensitive filenames on disk: ${foundFiles.length}`);
for (const f of foundFiles) {
  console.log(`  Found: ${f}`);
}

// 3. Scan git commit history for secret patterns
console.log('\n--- 3. SCANNING GIT COMMIT HISTORY & DIFFS ---');
const secretPatterns = [
  { name: 'Private Key Block', regex: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY/i },
  { name: 'Cloudflare API Token', regex: /(CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[:=]\s*["']?[a-zA-Z0-9_-]{35,}["']?/i },
  { name: 'Cloudflare Global Key', regex: /(CLOUDFLARE_AUTH_KEY|CF_AUTH_KEY)\s*[:=]\s*["']?[a-f0-9]{37}["']?/i },
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', regex: /aws_secret_access_key\s*[:=]\s*["']?[a-zA-Z0-9\/+=]{40}["']?/i },
  { name: 'GitHub Personal Token', regex: /gh[pousr]_[A-Za-z0-9_]{36}/ },
  { name: 'GitHub Fine-grained PAT', regex: /github_pat_[a-zA-Z0-9_]{50,}/ },
  { name: 'Bearer Token Literal', regex: /["']?Bearer\s+[a-zA-Z0-9_\-\.]{25,}["']?/i },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z]{10,}/ },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{20,}/ }
];

const gitLog = execSync('git log -p', { maxBuffer: 100 * 1024 * 1024 }).toString('utf8');
const logLines = gitLog.split('\n');

let leaksInHistory = [];
for (let i = 0; i < logLines.length; i++) {
  const line = logLines[i];
  if (!line.startsWith('+')) continue;
  // Ignore CI scanning scripts / docs that mention the patterns defensively
  if (line.includes('if grep -rEI') || line.includes('SCAN_SECRET') || line.includes('BEGIN (RSA |EC )?PRIVATE KEY')) continue;
  if (line.includes('intent-classifier.ts') && line.includes('private key')) continue; // Threat detection heuristic
  if (line.includes('intent-evaluation-dataset.json')) continue; // Synthetic threat sample
  if (line.includes('<your-cloudflare-token>') || line.includes('<your-cloudflare-account-id>')) continue; // Doc placeholders

  for (const pat of secretPatterns) {
    if (pat.regex.test(line)) {
      leaksInHistory.push({ pattern: pat.name, line: line.substring(0, 50) });
    }
  }
}

if (leaksInHistory.length > 0) {
  console.log(`[ALERT] Found ${leaksInHistory.length} potential leaks in git history!`);
  for (const leak of leaksInHistory) {
    console.log(`  Pattern: ${leak.pattern} - Match: ${leak.line}...`);
  }
} else {
  console.log('[PASS] Full git commit history clean: 0 secret leaks detected across all commits.');
}

// 4. Scan currently tracked files in git worktree
console.log('\n--- 4. SCANNING CURRENT TRACKED WORKSPACE CODEBASE ---');
const trackedFiles = execSync('git ls-files', { encoding: 'utf8' }).split('\n').map(s => s.trim()).filter(Boolean);

let trackedLeaks = [];
for (const file of trackedFiles) {
  // Skip binary files or known harmless files
  if (file.endsWith('.png') || file.endsWith('.ico') || file.endsWith('.svg') || file.endsWith('.wasm')) continue;
  if (!fs.existsSync(file)) continue;

  const content = fs.readFileSync(file, 'utf8');
  for (const pat of secretPatterns) {
    if (pat.regex.test(content)) {
      // Filter out benign references (docs, threat definitions, scripts)
      if (file.includes('ci.yml') || file.includes('audit-secrets.js')) continue;
      if (file.includes('intent-classifier.ts') || file.includes('intent-evaluation-dataset.json')) continue;
      if (content.includes('<your-cloudflare-token>')) continue;
      
      trackedLeaks.push({ file, pattern: pat.name });
    }
  }
}

if (trackedLeaks.length > 0) {
  console.log(`[ALERT] Found ${trackedLeaks.length} potential leaks in tracked files!`);
  for (const leak of trackedLeaks) {
    console.log(`  File: ${leak.file} - Pattern: ${leak.pattern}`);
  }
} else {
  console.log('[PASS] Tracked files clean: 0 secret leaks detected across all source/doc files.');
}

// 5. Audit Cloudflare configuration & workflows
console.log('\n--- 5. AUDITING CLOUDFLARE SCRIPTS & WORKFLOWS ---');
const deployWorkflowPath = path.join(ROOT, '.github', 'workflows', 'deploy-pages.yml');
if (fs.existsSync(deployWorkflowPath)) {
  const content = fs.readFileSync(deployWorkflowPath, 'utf8');
  const hasSecretsContext = content.includes('${{ secrets.CLOUDFLARE_API_TOKEN }}') && content.includes('${{ secrets.CLOUDFLARE_ACCOUNT_ID }}');
  const hasHardcodedToken = /apiToken:\s*[^$\s\n]+/i.test(content) && !content.includes('apiToken: ${{');
  
  if (hasSecretsContext && !hasHardcodedToken) {
    console.log('[PASS] .github/workflows/deploy-pages.yml uses parameterized secrets (${{ secrets.* }}). No tokens exposed.');
  } else {
    console.log('[FAIL] .github/workflows/deploy-pages.yml may have hardcoded tokens!');
  }
}

const wranglerTomlPath = path.join(ROOT, 'apps', 'web', 'wrangler.toml');
if (fs.existsSync(wranglerTomlPath)) {
  const content = fs.readFileSync(wranglerTomlPath, 'utf8');
  const hasSecretVars = /(api_token|auth_key|secret|password)\s*=/i.test(content);
  if (!hasSecretVars) {
    console.log('[PASS] apps/web/wrangler.toml contains only public routing configuration. No secrets exposed.');
  } else {
    console.log('[FAIL] apps/web/wrangler.toml contains sensitive variable assignments!');
  }
}
