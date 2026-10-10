import fs from 'node:fs';
import path from 'node:path';
import git from 'isomorphic-git';
import http from 'isomorphic-git/http/node';

const rootDir = process.cwd();
const remoteUrl = 'https://github.com/bhedanikhilkumar-code/Privex.git';
const token = process.env.GITHUB_TOKEN || process.argv[2];

async function fetchLatestSha() {
  const res = await fetch('https://api.github.com/repos/bhedanikhilkumar-code/Privex/commits/main', {
    headers: { 'User-Agent': 'Node-Fetch' }
  });
  const data = await res.json();
  return data.sha;
}

async function main() {
  if (!token) {
    console.error('No GITHUB_TOKEN provided!');
    process.exit(1);
  }

  console.log('[GIT] Fetching latest commit SHA from remote main branch...');
  const parentSha = await fetchLatestSha();
  console.log('[GIT] Remote main HEAD is:', parentSha);

  console.log('[GIT] Reading status matrix for current changes...');
  const statusMatrix = await git.statusMatrix({
    fs,
    dir: rootDir,
    filter: (filePath) => {
      if (filePath.startsWith('node_modules/') || 
          filePath.startsWith('dist/') || 
          filePath.startsWith('.git/') ||
          filePath.startsWith('coverage/')) {
        return false;
      }
      return true;
    }
  });

  let stagedCount = 0;
  for (const [filepath, head, workdir, stage] of statusMatrix) {
    if (workdir !== stage) {
      if (workdir === 0) {
        await git.remove({ fs, dir: rootDir, filepath });
      } else {
        await git.add({ fs, dir: rootDir, filepath });
      }
      stagedCount++;
    }
  }

  console.log(`[GIT] Staged ${stagedCount} files.`);

  const commitMsg = `feat(web): add light/dark/night mode theme switcher and remove engine metrics box

- Remove telemetry status box (ENGINE: v0.1.1 | RAM: 42MB | LATENCY: <1ms) from Header.tsx
- Implement 3-way segmented ThemeToggle component (Light, Dark, AMOLED Night)
- Add theme persistence via localStorage ('privex_theme') and document root 'data-theme' synchronization
- Define neo-brutalist CSS custom properties for Light, Dark, and Night modes in index.html
- Adapt Navigation, App, SettingsView, ResultCard, UrlScannerView, and TextScannerView to dynamic theme tokens
- Add comprehensive unit and integration tests covering theme toggling, persistence, and accessibility (100% pass)`;

  console.log('[GIT] Creating commit on top of parent:', parentSha);
  const sha = await git.commit({
    fs,
    dir: rootDir,
    message: commitMsg,
    parent: [parentSha],
    author: {
      name: 'bhedanikhilkumar-code',
      email: 'bhedanikhilkumar@users.noreply.github.com'
    }
  });

  console.log('[GIT] Created commit:', sha);

  console.log('[GIT] Fast-forward pushing to GitHub origin main...');
  const pushResult = await git.push({
    fs,
    http,
    dir: rootDir,
    remote: 'origin',
    ref: 'main',
    force: false,
    onAuth: () => ({ username: token })
  });

  console.log('[GIT] Push result:', pushResult);
  console.log('✅ PUSH SUCCESSFUL! All old commits preserved and new commit appended on top!');
}

main().catch(err => {
  console.error('[GIT ERROR]', err);
  process.exit(1);
});
