import { defineConfig, build as viteBuild } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

import fs from 'fs';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'flatten-html-and-bundle-content',
      async closeBundle() {
        const outDir = path.resolve(__dirname, 'dist');
        const pairs = [
          ['src/popup/popup.html', 'popup.html'],
          ['src/options/options.html', 'options.html'],
          ['src/warning/interstitial.html', 'interstitial.html']
        ];
        for (const [src, dest] of pairs) {
          const srcPath = path.resolve(outDir, src);
          const destPath = path.resolve(outDir, dest);
          if (fs.existsSync(srcPath)) {
            fs.copyFileSync(srcPath, destPath);
          }
        }

        // Bundle content.ts as a self-contained classic script (IIFE) for MV3 content_scripts
        await viteBuild({
          configFile: false,
          resolve: {
            alias: {
              crypto: path.resolve(__dirname, './src/shared/shims/crypto-shim.ts'),
              buffer: path.resolve(__dirname, './src/shared/shims/buffer-shim.ts'),
              '@': path.resolve(__dirname, './src')
            }
          },
          build: {
            outDir: 'dist',
            emptyOutDir: false,
            copyPublicDir: false,
            rollupOptions: {
              input: {
                content: path.resolve(__dirname, 'src/content/content.ts')
              },
              output: {
                format: 'iife',
                entryFileNames: 'content.js',
                inlineDynamicImports: true
              }
            }
          }
        });
      }
    }
  ],
  resolve: {
    alias: {
      crypto: path.resolve(__dirname, './src/shared/shims/crypto-shim.ts'),
      buffer: path.resolve(__dirname, './src/shared/shims/buffer-shim.ts'),
      '@': path.resolve(__dirname, './src')
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        background: path.resolve(__dirname, 'src/background/background.ts'),
        popup: path.resolve(__dirname, 'src/popup/popup.html'),
        options: path.resolve(__dirname, 'src/options/options.html'),
        interstitial: path.resolve(__dirname, 'src/warning/interstitial.html')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return '[name].js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    }
  }
});

