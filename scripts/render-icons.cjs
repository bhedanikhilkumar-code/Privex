const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-gpu');

app.whenReady().then(async () => {
  // Capture at 512x512 resolution offscreen with transparent canvas
  const win = new BrowserWindow({
    width: 512,
    height: 512,
    show: false,
    frame: false,
    transparent: true,
    backgroundColor: '#00000000',
    webPreferences: {
      offscreen: true
    }
  });

  const svgPath = path.resolve(__dirname, '../privex-icon.svg');
  const svgContent = fs.readFileSync(svgPath, 'utf8');

  // HTML wrapper with strictly transparent background, no margin, no padding, 100% vector fit
  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      html, body {
        width: 100vw;
        height: 100vh;
        background: transparent !important;
        background-color: transparent !important;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      svg {
        width: 100%;
        height: 100%;
        background: transparent !important;
      }
    </style>
  </head>
  <body>
    ${svgContent}
  </body>
</html>`;

  await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  // Allow layout and font rendering
  await new Promise(r => setTimeout(r, 400));

  const masterCapture = await win.webContents.capturePage();
  console.log('Captured master image size:', masterCapture.getSize());

  // Render targets across mobile, desktop, extension, and web
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
    const resized = masterCapture.resize({
      width: t.size,
      height: t.size,
      quality: 'best'
    });
    const pngBuf = resized.toPNG();
    const destFull = path.resolve(__dirname, '..', t.dest);
    fs.mkdirSync(path.dirname(destFull), { recursive: true });
    fs.writeFileSync(destFull, pngBuf);
    console.log(`Rendered: ${t.dest} (${t.size}x${t.size}, ${pngBuf.length} bytes)`);
  }

  app.quit();
});
