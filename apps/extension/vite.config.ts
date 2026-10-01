import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
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
        content: path.resolve(__dirname, 'src/content/content.ts'),
        popup: path.resolve(__dirname, 'src/popup/popup.html'),
        options: path.resolve(__dirname, 'src/options/options.html'),
        interstitial: path.resolve(__dirname, 'src/warning/interstitial.html')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background' || chunkInfo.name === 'content') {
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
