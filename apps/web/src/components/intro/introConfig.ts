/**
 * PRIVEX CINEMATIC INTRO CONFIGURATION (5-SECOND MASTER RUNTIME)
 */

export interface IntroConfig {
  brandName: string;
  tagline: string;
  storageKey: string;
  totalDurationMs: number;
  scenes: {
    scene1: {
      durationMs: number;
      caption: string;
    };
    scene2: {
      durationMs: number;
      caption: string;
      warningLabel: string;
      requestFlow: string[];
    };
    scene3: {
      durationMs: number;
      caption: string;
      statusItems: Array<{ label: string; status: string; color: string }>;
    };
    scene4: {
      durationMs: number;
      brandName: string;
      tagline: string;
    };
  };
}

export const INTRO_CONFIG: IntroConfig = {
  brandName: 'PRIVEX',
  tagline: 'Your Digital Space. Your Control.',
  storageKey: 'privexIntroSeen',
  // Exactly 5 seconds total runtime
  totalDurationMs: 5000,
  scenes: {
    scene1: {
      durationMs: 1400, // 0.0s - 1.4s: Everyday Connected Life
      caption: 'Your digital world is always connected.'
    },
    scene2: {
      durationMs: 1400, // 1.4s - 2.8s: Unusual Activity Intercepted
      caption: 'Suspicious background activity intercepted.',
      warningLabel: 'UNUSUAL NETWORK TRAFFIC',
      requestFlow: ['REQUEST', 'REQUEST', 'UNKNOWN HOST']
    },
    scene3: {
      durationMs: 1200, // 2.8s - 4.0s: On-Device Shield Engaged
      caption: 'On-device privacy shield isolates the threat in volatile RAM.',
      statusItems: [
        { label: 'Sandbox Isolation', status: 'ACTIVE', color: '#00E5FF' },
        { label: 'Cloud Persistence', status: 'ZERO', color: '#D7FF3F' },
        { label: 'Protection Verdict', status: 'SHIELDED', color: '#10B981' }
      ]
    },
    scene4: {
      durationMs: 1000, // 4.0s - 5.0s: PRIVEX Brand Reveal & Seamless Entry
      brandName: 'PRIVEX',
      tagline: 'Your Digital Space. Your Control.'
    }
  }
};
