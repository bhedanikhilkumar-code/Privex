import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  base: './',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      'crypto': path.resolve(__dirname, './src/shims/crypto-shim.ts'),
      'buffer': path.resolve(__dirname, './src/shims/buffer-shim.ts'),
    },
  },
  define: {
    'process.env': {},
  },
  build: {
    target: 'es2020',
    outDir: 'dist',
    emptyOutDir: true,
  },
});
