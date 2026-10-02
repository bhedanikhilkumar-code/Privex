const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const desktopRoot = path.resolve(__dirname, '..');
const distDir = path.join(desktopRoot, 'dist');
const releaseDir = path.join(desktopRoot, 'release', 'PrivateProtection-win32-x64');

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest('hex');
}

async function buildBundles() {
  console.log('[Desktop Build] Cleaning dist directory...');
  fs.rmSync(distDir, { recursive: true, force: true });
  fs.mkdirSync(path.join(distDir, 'main'), { recursive: true });
  fs.mkdirSync(path.join(distDir, 'preload'), { recursive: true });
  fs.mkdirSync(path.join(distDir, 'renderer'), { recursive: true });

  console.log('[Desktop Build] Bundling Electron Main Process (electron-main.cjs)...');
  await esbuild.build({
    entryPoints: [path.join(desktopRoot, 'src/main/electron-main.ts')],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    external: ['electron'],
    outfile: path.join(distDir, 'main/electron-main.cjs'),
    sourcemap: false,
    minify: false
  });

  console.log('[Desktop Build] Bundling Electron Preload Bridge (electron-preload.cjs)...');
  await esbuild.build({
    entryPoints: [path.join(desktopRoot, 'src/preload/electron-preload.ts')],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    external: ['electron'],
    outfile: path.join(distDir, 'preload/electron-preload.cjs'),
    sourcemap: false,
    minify: false
  });

  console.log('[Desktop Build] Bundling React Renderer UI (renderer.js)...');
  await esbuild.build({
    entryPoints: [path.join(desktopRoot, 'src/renderer/main.tsx')],
    bundle: true,
    platform: 'browser',
    target: ['chrome120'],
    format: 'iife',
    outfile: path.join(distDir, 'renderer/renderer.js'),
    define: {
      'process.env.NODE_ENV': '"production"'
    },
    sourcemap: false,
    minify: true
  });

  fs.copyFileSync(
    path.join(desktopRoot, 'index.html'),
    path.join(distDir, 'renderer/index.html')
  );

  console.log('[Desktop Build] Compiled bundles ready in apps/desktop/dist/');
}

function packageWindowsRelease() {
  console.log('[Desktop Package] Creating Windows x64 portable desktop application...');
  const electronDist = path.dirname(require('electron'));
  if (!fs.existsSync(electronDist)) {
    throw new Error(`Electron binary distribution not found at ${electronDist}`);
  }

  fs.rmSync(releaseDir, { recursive: true, force: true });
  fs.cpSync(electronDist, releaseDir, { recursive: true });

  // Rename electron.exe -> PrivateProtection.exe
  const origExe = path.join(releaseDir, 'electron.exe');
  const targetExe = path.join(releaseDir, 'PrivateProtection.exe');
  if (fs.existsSync(origExe)) {
    fs.renameSync(origExe, targetExe);
  }

  // Remove default_app.asar so Electron boots our packaged resources/app directly
  const defaultAppAsar = path.join(releaseDir, 'resources', 'default_app.asar');
  if (fs.existsSync(defaultAppAsar)) {
    fs.rmSync(defaultAppAsar, { force: true });
  }

  const appResourcesDir = path.join(releaseDir, 'resources', 'app');
  fs.mkdirSync(appResourcesDir, { recursive: true });
  fs.cpSync(distDir, path.join(appResourcesDir, 'dist'), { recursive: true });

  const appPackageJson = {
    name: 'private-protection-desktop',
    productName: 'Private Protection Desktop Security',
    version: '1.0.0',
    private: true,
    main: 'dist/main/electron-main.cjs'
  };
  fs.writeFileSync(
    path.join(appResourcesDir, 'package.json'),
    JSON.stringify(appPackageJson, null, 2),
    'utf8'
  );

  const exeStat = fs.statSync(targetExe);
  const exeSha256 = sha256File(targetExe);

  const manifest = {
    productName: 'Private Protection Desktop Security',
    version: '1.0.0',
    platform: 'win32',
    arch: 'x64',
    builtAt: new Date().toISOString(),
    executable: {
      fileName: 'PrivateProtection.exe',
      relativePath: 'apps/desktop/release/PrivateProtection-win32-x64/PrivateProtection.exe',
      sizeBytes: exeStat.size,
      sha256: exeSha256
    },
    bundles: {
      main: {
        path: 'resources/app/dist/main/electron-main.cjs',
        sizeBytes: fs.statSync(path.join(appResourcesDir, 'dist/main/electron-main.cjs')).size,
        sha256: sha256File(path.join(appResourcesDir, 'dist/main/electron-main.cjs'))
      },
      preload: {
        path: 'resources/app/dist/preload/electron-preload.cjs',
        sizeBytes: fs.statSync(path.join(appResourcesDir, 'dist/preload/electron-preload.cjs')).size,
        sha256: sha256File(path.join(appResourcesDir, 'dist/preload/electron-preload.cjs'))
      },
      rendererJs: {
        path: 'resources/app/dist/renderer/renderer.js',
        sizeBytes: fs.statSync(path.join(appResourcesDir, 'dist/renderer/renderer.js')).size,
        sha256: sha256File(path.join(appResourcesDir, 'dist/renderer/renderer.js'))
      },
      rendererHtml: {
        path: 'resources/app/dist/renderer/index.html',
        sizeBytes: fs.statSync(path.join(appResourcesDir, 'dist/renderer/index.html')).size,
        sha256: sha256File(path.join(appResourcesDir, 'dist/renderer/index.html'))
      }
    }
  };

  const manifestPath = path.join(releaseDir, 'ARTIFACT_MANIFEST.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log('[Desktop Package] Release artifact packaged successfully:');
  console.log(JSON.stringify(manifest, null, 2));
}

async function run() {
  await buildBundles();
  if (process.argv.includes('--package')) {
    packageWindowsRelease();
  }
}

run().catch((err) => {
  console.error('[Desktop Build Failed]', err);
  process.exit(1);
});
