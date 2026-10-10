import React from 'react';

export interface IntroCharacterSvgProps {
  scene: 1 | 2 | 3 | 4;
}

export const IntroCharacterSvg: React.FC<IntroCharacterSvgProps> = ({ scene }) => {
  // Screen light color dynamic switch based on active story scene
  const isScene2 = scene === 2;
  const isScene3 = scene === 3;
  const isScene4 = scene === 4;

  const screenGlowColor = isScene2
    ? '#F59E0B' // Amber warning glow
    : isScene3
    ? '#00E5FF' // Electric cyan protection glow
    : isScene4
    ? '#7C4DFF' // Digital purple reveal
    : '#38BDF8'; // Azure blue normal browsing

  const screenGlowOpacity = isScene2 ? 0.35 : isScene3 ? 0.45 : 0.22;

  return (
    <svg
      className="privex-char-svg"
      viewBox="0 0 960 540"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Illustration of person using laptop in a secure digital space"
    >
      <defs>
        {/* Dynamic Screen Glow Gradient */}
        <radialGradient
          id="screenBeamGradient"
          cx="480"
          cy="340"
          r="260"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor={screenGlowColor} stopOpacity={screenGlowOpacity * 1.5} />
          <stop offset="60%" stopColor={screenGlowColor} stopOpacity={screenGlowOpacity * 0.4} />
          <stop offset="100%" stopColor={screenGlowColor} stopOpacity="0" />
        </radialGradient>

        {/* Ambient Room Gradient */}
        <radialGradient id="roomBackdrop" cx="480" cy="270" r="480" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0E162B" />
          <stop offset="70%" stopColor="#070B14" />
          <stop offset="100%" stopColor="#04070D" />
        </radialGradient>

        {/* Desk Surface Gradient */}
        <linearGradient id="deskSurface" x1="160" y1="380" x2="800" y2="440" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1E2538" />
          <stop offset="50%" stopColor="#151B2B" />
          <stop offset="100%" stopColor="#0F1420" />
        </linearGradient>

        {/* Lamp Light Cone */}
        <linearGradient id="lampCone" x1="220" y1="180" x2="220" y2="390" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFE4A0" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#FFE4A0" stopOpacity="0" />
        </linearGradient>

        {/* Hoodie Material Gradient */}
        <linearGradient id="hoodieGrad" x1="420" y1="260" x2="600" y2="440" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1E293B" />
          <stop offset="100%" stopColor="#0F172A" />
        </linearGradient>

        {/* Laptop Metallic Chassis */}
        <linearGradient id="laptopChassis" x1="380" y1="280" x2="480" y2="420" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#64748B" />
          <stop offset="50%" stopColor="#334155" />
          <stop offset="100%" stopColor="#1E293B" />
        </linearGradient>

        {/* Laptop Display Bezel */}
        <linearGradient id="screenDisplay" x1="390" y1="250" x2="470" y2="370" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0B132B" />
          <stop offset="100%" stopColor="#070B14" />
        </linearGradient>

        {/* Skin Tone Shadow */}
        <linearGradient id="faceShading" x1="480" y1="160" x2="520" y2="230" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#F6C49C" />
          <stop offset="100%" stopColor="#E2A676" />
        </linearGradient>

        {/* Hair Texture */}
        <linearGradient id="hairGrad" x1="480" y1="110" x2="540" y2="180" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#2D211A" />
          <stop offset="60%" stopColor="#191310" />
          <stop offset="100%" stopColor="#0D0A08" />
        </linearGradient>
      </defs>

      {/* 1. ROOM ENVIRONMENT & AMBIENCE */}
      <rect width="960" height="540" fill="url(#roomBackdrop)" />

      {/* Architectural Window / Minimal Grid in Background */}
      <g opacity="0.15">
        <rect x="120" y="80" width="200" height="240" rx="4" stroke="#00E5FF" strokeWidth="1.5" />
        <line x1="220" y1="80" x2="220" y2="320" stroke="#00E5FF" strokeWidth="1" />
        <line x1="120" y1="200" x2="320" y2="200" stroke="#00E5FF" strokeWidth="1" />
      </g>

      {/* Modern Desk Lamp on Left */}
      <g>
        {/* Lamp Base & Neck */}
        <path d="M190 390 L250 390 L245 385 L195 385 Z" fill="#334155" />
        <path d="M220 385 Q210 260 250 200" stroke="#475569" strokeWidth="4" strokeLinecap="round" fill="none" />
        {/* Lamp Head */}
        <path d="M245 195 L275 210 L265 225 L235 210 Z" fill="#64748B" />
        {/* Downward Warm Ambient Light Cone */}
        <polygon points="255,218 160,395 350,395 270,222" fill="url(#lampCone)" />
      </g>

      {/* Coffee Ceramic Mug on Desk */}
      <g>
        <rect x="260" y="360" width="24" height="30" rx="4" fill="#3B82F6" opacity="0.8" />
        <path d="M284 366 Q294 375 284 384" stroke="#3B82F6" strokeWidth="2.5" fill="none" opacity="0.8" />
        {/* Coffee Vapor Steam */}
        <path
          className="anim-steam"
          d="M268 355 Q274 345 268 335 T272 320"
          stroke="rgba(255, 255, 255, 0.4)"
          strokeWidth="1.5"
          strokeLinecap="round"
          fill="none"
        />
      </g>

      {/* 2. DESK WORK SURFACE */}
      <path
        d="M100 400 L860 400 L880 440 L80 440 Z"
        fill="url(#deskSurface)"
        stroke="#0F172A"
        strokeWidth="2"
      />
      {/* Subtle Chamfer Edge Highlight */}
      <line x1="80" y1="400" x2="880" y2="400" stroke="rgba(255, 255, 255, 0.12)" strokeWidth="1.5" />

      {/* 3. DYNAMIC SCREEN LIGHT BEAM (Casts onto character & desk) */}
      <ellipse
        cx="460"
        cy="330"
        rx="260"
        ry="160"
        fill="url(#screenBeamGradient)"
        style={{ transition: 'fill 0.6s ease' }}
      />

      {/* 4. THE LAPTOP DEVICE */}
      <g id="privex-laptop">
        {/* Base / Keyboard Deck in Perspective */}
        <path
          d="M370 380 L520 380 L545 408 L345 408 Z"
          fill="url(#laptopChassis)"
          stroke="#1E293B"
          strokeWidth="1.5"
        />
        {/* Trackpad */}
        <rect x="425" y="394" width="40" height="10" rx="1.5" fill="#1E293B" opacity="0.7" />
        {/* Keyboard Backlit Deck */}
        <path
          d="M375 384 L515 384 L525 393 L365 393 Z"
          fill="#0F172A"
          stroke="rgba(0, 229, 255, 0.2)"
          strokeWidth="0.5"
        />

        {/* Display Panel (Tilted slightly open) */}
        <path
          d="M370 380 L380 250 L510 250 L520 380 Z"
          fill="url(#laptopChassis)"
          stroke="#475569"
          strokeWidth="1.5"
        />
        {/* Screen Display Glass */}
        <path
          d="M376 376 L385 256 L505 256 L514 376 Z"
          fill="url(#screenDisplay)"
        />

        {/* Dynamic Display Content Inside Screen */}
        {scene === 1 && (
          /* Normal web browsing: clean cards & tab bar */
          <g opacity="0.85">
            <rect x="388" y="260" width="112" height="8" rx="2" fill="#1E293B" />
            <circle cx="394" cy="264" r="2" fill="#EF4444" />
            <circle cx="400" cy="264" r="2" fill="#F59E0B" />
            <circle cx="406" cy="264" r="2" fill="#10B981" />
            <rect x="388" y="274" width="50" height="20" rx="3" fill="#1E293B" />
            <rect x="444" y="274" width="56" height="20" rx="3" fill="#1E293B" />
            <rect x="388" y="300" width="112" height="60" rx="3" fill="#151E33" />
            <line x1="394" y1="315" x2="480" y2="315" stroke="#38BDF8" strokeWidth="2" strokeLinecap="round" />
            <line x1="394" y1="325" x2="460" y2="325" stroke="#64748B" strokeWidth="1.5" strokeLinecap="round" />
            <line x1="394" y1="335" x2="440" y2="335" stroke="#64748B" strokeWidth="1.5" strokeLinecap="round" />
          </g>
        )}

        {scene === 2 && (
          /* Unusual Activity Display: Amber alerts & node traffic */
          <g>
            <rect x="388" y="260" width="112" height="106" rx="2" fill="#1B1408" />
            <rect x="394" y="270" width="100" height="22" rx="3" fill="rgba(245, 158, 11, 0.2)" stroke="#F59E0B" strokeWidth="1" />
            <text x="444" y="285" fill="#F59E0B" fontSize="8" fontWeight="800" fontFamily="monospace" textAnchor="middle">
              ! UNUSUAL ACTIVITY
            </text>
            <line x1="398" y1="310" x2="490" y2="310" stroke="#F59E0B" strokeWidth="1.5" strokeDasharray="3 2" />
            <circle cx="404" cy="310" r="3" fill="#F59E0B" />
            <circle cx="444" cy="310" r="3" fill="#F59E0B" />
            <circle cx="484" cy="310" r="3" fill="#EF4444" />
            <text x="444" y="335" fill="#EF4444" fontSize="7" fontFamily="monospace" textAnchor="middle">
              INCOMING UNKNOWN IP
            </text>
          </g>
        )}

        {scene === 3 && (
          /* Protection Active: Cyan shield barrier and security diagnostics */
          <g>
            <rect x="388" y="260" width="112" height="106" rx="2" fill="#081826" />
            <path d="M444 275 L460 282 L460 300 Q444 314 444 314 Q428 300 428 282 Z" fill="#00E5FF" fillOpacity="0.25" stroke="#00E5FF" strokeWidth="1.5" />
            <text x="444" y="297" fill="#00E5FF" fontSize="9" fontWeight="800" fontFamily="sans-serif" textAnchor="middle">
              ✓
            </text>
            <text x="444" y="330" fill="#00E5FF" fontSize="7.5" fontWeight="700" fontFamily="monospace" textAnchor="middle">
              SHIELD ENGAGED
            </text>
            <text x="444" y="342" fill="#A78BFA" fontSize="6.5" fontFamily="monospace" textAnchor="middle">
              ZERO-CLOUD ISOLATION
            </text>
          </g>
        )}

        {scene === 4 && (
          /* Brand Final state */
          <g>
            <rect x="388" y="260" width="112" height="106" rx="2" fill="#0A1128" />
            <circle cx="444" cy="310" r="16" fill="#00E5FF" fillOpacity="0.2" stroke="#00E5FF" strokeWidth="1.5" />
            <text x="444" y="314" fill="#FFFFFF" fontSize="8" fontWeight="bold" fontFamily="monospace" textAnchor="middle">
              PRIVEX
            </text>
          </g>
        )}
      </g>

      {/* 5. THE ANIMATED HUMAN CHARACTER */}
      <g
        id="privex-character"
        className={`anim-breathe ${isScene2 ? 'anim-head-react' : ''}`}
      >
        {/* Upper Body / Hoodie Back & Shoulders */}
        <path
          d="M510 260 Q560 280 610 380 L620 440 L450 440 L465 370 Q480 290 510 260 Z"
          fill="url(#hoodieGrad)"
          stroke="#0F172A"
          strokeWidth="1.5"
        />

        {/* Hoodie Cyan Piping Trim on Shoulder */}
        <path
          d="M516 268 Q555 285 595 370"
          stroke="rgba(0, 229, 255, 0.35)"
          strokeWidth="1.5"
          strokeLinecap="round"
          fill="none"
        />

        {/* Neck */}
        <path
          d="M516 215 L534 215 L530 265 L514 265 Z"
          fill="#E2A676"
        />
        {/* Neck Shading Under Jaw */}
        <polygon points="516,215 534,215 532,232 516,228" fill="#D49060" opacity="0.6" />

        {/* Head Base */}
        <path
          d="M485 160 Q485 125 515 125 Q545 125 545 160 Q545 205 522 215 Q492 212 485 160 Z"
          fill="url(#faceShading)"
        />

        {/* Ear */}
        <ellipse cx="536" cy="172" rx="5" ry="8" fill="#E2A676" />
        <path d="M536 168 Q534 172 536 176" stroke="#C27A48" strokeWidth="1" fill="none" />

        {/* Eye (Expressive with Blinking and Reaction) */}
        <g id="character-eye">
          {/* Eye Socket Sclera */}
          <ellipse cx="498" cy="168" rx="6" ry="4" fill="#FFFFFF" opacity="0.9" />
          {/* Iris & Pupil */}
          <circle cx={isScene2 ? 496 : 497} cy="168" r="2.8" fill="#1E293B" />
          <circle cx={isScene2 ? 495 : 496} cy="167" r="0.9" fill="#FFFFFF" />

          {/* Eyelid (Performs natural blink animation) */}
          <path
            className="anim-blink"
            d="M492 164 Q498 162 504 164 Q498 172 492 164 Z"
            fill="#E2A676"
          />
        </g>

        {/* Eyebrow (Raises in Scene 2 when unusual activity occurs) */}
        <path
          className={isScene2 ? 'anim-eyebrow-alert' : ''}
          d={
            isScene2
              ? 'M490 156 Q498 152 506 157' // Arched alert eyebrow
              : 'M491 160 Q498 158 505 161' // Calm focused eyebrow
          }
          stroke="#2D211A"
          strokeWidth="2"
          strokeLinecap="round"
          fill="none"
        />

        {/* Nose & Mouth (Subtle natural profile lines) */}
        <path d="M486 168 L483 178 L488 181" stroke="#D49060" strokeWidth="1.2" strokeLinecap="round" fill="none" />
        <path
          d={isScene2 ? 'M488 196 Q493 197 498 196' : 'M489 195 Q495 197 500 195'}
          stroke="#C27A48"
          strokeWidth="1.5"
          strokeLinecap="round"
          fill="none"
        />

        {/* Styled Modern Haircut (Layered with highlights) */}
        <path
          d="M482 152 Q480 120 515 112 Q550 114 550 148 Q540 142 530 144 Q520 135 500 138 Q488 142 482 152 Z"
          fill="url(#hairGrad)"
        />
        {/* Hair Front Fringe */}
        <path
          d="M482 145 Q496 136 512 144 Q498 148 488 156 Z"
          fill="#1C1410"
        />
        {/* Soft Ambient Rim Light on Hair */}
        <path
          d="M500 115 Q525 115 542 130"
          stroke="rgba(0, 229, 255, 0.4)"
          strokeWidth="1.5"
          strokeLinecap="round"
          fill="none"
        />

        {/* Arms and Hands Resting on Desk / Typing */}
        <g id="character-arms">
          {/* Right Arm & Forearm */}
          <path
            d="M560 320 Q540 370 480 390 L440 394 L440 386 L490 380 Q530 360 550 310 Z"
            fill="#1E293B"
            stroke="#0F172A"
            strokeWidth="1"
          />
          {/* Right Hand on Keyboard (Natural Micro-Typing) */}
          <g className={!isScene2 ? 'anim-typing-right' : ''}>
            <ellipse cx="440" cy="390" rx="9" ry="5" fill="#F6C49C" />
            {/* Fingers resting naturally over keys */}
            <path d="M433 392 L426 394" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
            <path d="M434 390 L424 391" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
            <path d="M435 388 L427 387" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
          </g>

          {/* Left Arm & Forearm (Front perspective) */}
          <path
            d="M485 340 Q450 370 380 392 L350 395 L352 388 L390 382 Q440 360 475 330 Z"
            fill="#182234"
            stroke="#0F172A"
            strokeWidth="1"
          />
          {/* Left Hand on Keyboard (Natural Micro-Typing) */}
          <g className={!isScene2 ? 'anim-typing-left' : ''}>
            <ellipse cx="355" cy="392" rx="9" ry="5" fill="#F6C49C" />
            {/* Left Fingers resting over keys */}
            <path d="M358 393 L366 394" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
            <path d="M359 391 L369 391" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
            <path d="M358 388 L367 387" stroke="#E2A676" strokeWidth="2" strokeLinecap="round" />
          </g>
        </g>
      </g>
    </svg>
  );
};
