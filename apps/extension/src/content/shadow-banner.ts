import { escapeHtml } from '../shared/formatters';

export class ShadowBanner {
  private static hostElement: HTMLElement | null = null;

  public static showInsecurePasswordWarning(formActionUrl?: string): void {
    if (this.hostElement && document.documentElement.contains(this.hostElement)) return;
    this.hostElement = null;

    const host = document.createElement('div');
    host.id = 'private-protection-shield-host';
    host.style.all = 'initial';
    this.hostElement = host;

    // Attach CLOSED shadow root: host page scripts cannot inspect or modify inner DOM
    const shadow = host.attachShadow({ mode: 'closed' });

    const safeUrl = escapeHtml(formActionUrl || 'unencrypted HTTP server');

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          display: block;
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 2147483647;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        @keyframes bannerSlideDown {
          0% {
            transform: translateY(-100%);
            opacity: 0;
          }
          100% {
            transform: translateY(0);
            opacity: 1;
          }
        }
        .banner {
          background-color: #7f1d1d;
          color: #fef2f2;
          padding: 12px 24px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 2px solid #ef4444;
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
          font-size: 14px;
          animation: bannerSlideDown 240ms cubic-bezier(0.22, 1, 0.36, 1) both;
          transition: transform 180ms ease-in, opacity 180ms ease-in;
        }
        @media (prefers-reduced-motion: reduce) {
          .banner {
            animation: none !important;
            transition: none !important;
            transform: none !important;
          }
        }
        .content {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .icon {
          font-size: 20px;
        }
        .title {
          font-weight: 700;
          margin-bottom: 2px;
        }
        .desc {
          color: #fca5a5;
          font-size: 12px;
        }
        .btn-dismiss {
          background-color: rgba(255, 255, 255, 0.15);
          color: #ffffff;
          border: 1px solid rgba(255, 255, 255, 0.3);
          border-radius: 4px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          font-weight: 600;
        }
        .btn-dismiss:hover {
          background-color: rgba(255, 255, 255, 0.25);
        }
      </style>
      <div class="banner" role="alert" aria-live="assertive">
        <div class="content">
          <div class="icon">⚠️</div>
          <div>
            <div class="title">INSECURE CREDENTIAL TRANSMISSION DETECTED</div>
            <div class="desc">A password field on this page transmits data over unencrypted HTTP (${safeUrl}). Do not enter passwords here.</div>
          </div>
        </div>
        <button id="dismiss-btn" class="btn-dismiss" type="button">Dismiss Warning</button>
      </div>
    `;

    const dismissBtn = shadow.getElementById('dismiss-btn');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.remove();
      });
    }

    if (document.body) {
      document.body.prepend(host);
    } else {
      document.documentElement.appendChild(host);
    }
  }

  public static remove(): void {
    if (this.hostElement) {
      if (this.hostElement.parentNode) {
        this.hostElement.parentNode.removeChild(this.hostElement);
      }
      this.hostElement = null;
    }
  }
}
