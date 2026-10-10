const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-gpu');

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: 512,
    height: 512,
    show: false,
    frame: false,
    transparent: true,
    webPreferences: {
      offscreen: true
    }
  });

  const svgPath = path.resolve(__dirname, '../privex-logo.svg');
  const svgContent = fs.readFileSync(svgPath, 'utf8');
  
  // HTML wrapper that renders SVG centered on transparent background
  const html = `<!DOCTYPE html>
  <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { width: 100vw; height: 100vh; display: flex; align-items: center; justify-content: center; background: transparent; overflow: hidden; }
        svg { width: 100%; height: 100%; max-width: 100%; max-height: 100%; object-fit: contain; }
      </style>
    </head>
    <body>
      ${svgContent}
    </body>
  </html>`;

  await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  
  // Render targets
  const targets = [
    { size: 16, dest: 'apps/extension/public/icons/icon-16.png' },
    { size: 32, dest: 'apps/extension/public/icons/icon-32.png' },
    { size: 48, dest: 'apps/extension/public/icons/icon-48.png' },
    { size: 128, dest: 'apps/extension/public/icons/icon-128.png' },
    { size: 192, dest: 'apps/web/public/icon-192.png' },
    { size: 512, dest: 'apps/web/public/icon-512.png' },
    { size: 256, dest: 'apps/desktop/icon.png' },
    { size: 48, dest: 'apps/mobile/android/app/src/main/res/mipmap-mdpi/ic_launcher.png' },
    { size: 72, dest: 'apps/mobile/android/app/src/main/res/mipmap-hdpi/ic_launcher.png' },
    { size: 96, dest: 'apps/mobile/android/app/src/main/res/mipmap-xhdpi/ic_launcher.png' },
    { size: 144, dest: 'apps/mobile/android/app/src/main/res/mipmap-xxhdpi/ic_launcher.png' },
    { size: 192, dest: 'apps/mobile/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png' }
  ];

  for (const t of targets) {
    win.setSize(t.size, t.size);
    // Wait a brief moment for repaint
    await new Promise(r => setTimeout(r, 150));
    const image = await win.webContents.capturePage();
    const pngBuf = image.toPNG();
    const destFull = path.resolve(__dirname, '..', t.dest);
    fs.mkdirSync(path.dirname(destFull), { recursive: true });
    fs.writeFileSync(destFull, pngBuf);
    console.log(`Rendered: ${t.dest} (${t.size}x${t.size}, ${pngBuf.length} bytes)`);
  }

  app.quit();
});
