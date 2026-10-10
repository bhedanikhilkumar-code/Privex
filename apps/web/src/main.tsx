import React from 'react';
import ReactDOM from 'react-dom/client';
import '@private-protection/ui/motion.css';
import { App } from './app/App';

const rootElement = document.getElementById('root');
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}

// Register PWA Service Worker for offline application shell caching
if (typeof window !== 'undefined' && 'serviceWorker' in navigator && process.env.NODE_ENV === 'production') {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then(() => {
        // SW registered
      })
      .catch(() => {
        // SW registration failed
      });
  });
}
