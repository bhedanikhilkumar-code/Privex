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

  const commitMsg = `chore(ui): remove local on-device processing indicator

- Removed the static '100% Local On-Device Processing' div from Header.tsx as requested.
- No changes to underlying functions or logic.`;

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
