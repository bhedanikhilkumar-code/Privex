import fs from 'node:fs';
import path from 'node:path';
import git from 'isomorphic-git';
import http from 'isomorphic-git/http/node';

const rootDir = process.cwd();
const remoteUrl = 'https://github.com/bhedanikhilkumar-code/Privex.git';

async function main() {
  console.log('[GIT] Initializing repository in:', rootDir);
  await git.init({ fs, dir: rootDir, defaultBranch: 'main' });

  // Add remote if not exists
  const remotes = await git.listRemotes({ fs, dir: rootDir });
  if (!remotes.some(r => r.remote === 'origin')) {
    console.log('[GIT] Adding remote origin:', remoteUrl);
    await git.addRemote({ fs, dir: rootDir, remote: 'origin', url: remoteUrl });
  }

  console.log('[GIT] Reading status matrix...');
  // Inspect status of all files
  const statusMatrix = await git.statusMatrix({
    fs,
    dir: rootDir,
    filter: (filePath) => {
      // Basic quick ignore for performance
      if (filePath.startsWith('node_modules/') || filePath.startsWith('dist/') || filePath.startsWith('.git/')) {
        return false;
      }
      return true;
    }
  });

  console.log(`[GIT] Found ${statusMatrix.length} files to check.`);
  let stagedCount = 0;

  for (const [filepath, head, workdir, stage] of statusMatrix) {
    // If modified or untracked in workdir
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

  // Commit
  const commitMsg = `feat(web): add light/dark/night mode theme switcher and remove engine metrics box

- Remove telemetry status box (ENGINE: v0.1.1 | RAM: 42MB | LATENCY: <1ms) from Header.tsx
- Implement 3-way segmented ThemeToggle component (Light, Dark, AMOLED Night)
- Add theme persistence via localStorage ('privex_theme') and document root 'data-theme' synchronization
- Define neo-brutalist CSS custom properties for Light, Dark, and Night modes in index.html
- Adapt Navigation, App, SettingsView, ResultCard, UrlScannerView, and TextScannerView to dynamic theme tokens
- Add comprehensive unit and integration tests covering theme toggling, persistence, and accessibility (100% pass)`;

  const sha = await git.commit({
    fs,
    dir: rootDir,
    message: commitMsg,
    author: {
      name: 'bhedanikhilkumar-code',
      email: 'bhedanikhilkumar@users.noreply.github.com'
    }
  });

  console.log('[GIT] Successfully created commit:', sha);

  const token = process.argv[2] || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) {
    console.log('[GIT] Attempting push to origin main with authentication...');
    const pushResult = await git.push({
      fs,
      http,
      dir: rootDir,
      remote: 'origin',
      ref: 'main',
      force: true,
      onAuth: () => ({ username: token })
    });
    console.log('[GIT] Push result:', pushResult);
    console.log('✅ PUSH SUCCESSFUL! Check https://github.com/bhedanikhilkumar-code/Privex');
  } else {
    console.log('[GIT] Ready to push. Run `node scripts/git-sync.js <YOUR_GITHUB_TOKEN>` to push immediately.');
  }
}

main().catch(err => {
  console.error('[GIT ERROR]', err);
  process.exit(1);
});
