/**
 * PASSWORD SECURITY & STRENGTH EVALUATOR
 *
 * CONSTITUTIONAL PRIVACY MANDATE:
 * - 100% Client-Side Execution in Volatile RAM.
 * - NEVER sends, logs, stores, or transmits passwords to any server, storage, or external API.
 * - Zero telemetry or console exposure of user passwords.
 */

export type PasswordStrengthLevel = 'VERY WEAK' | 'WEAK' | 'MEDIUM' | 'STRONG' | 'VERY STRONG';

export interface PasswordCriteriaCheck {
  id: string;
  label: string;
  met: boolean;
  explanation: string;
}

export interface PasswordSecurityAnalysis {
  score: number; // 0 to 100
  level: PasswordStrengthLevel;
  color: string;
  length: number;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumbers: boolean;
  hasSpecial: boolean;
  hasRepeatedChars: boolean;
  hasSequentialChars: boolean;
  isCommonPassword: boolean;
  criteria: PasswordCriteriaCheck[];
  feedback: string[];
  estimatedEntropyBits: number;
}

export interface PasswordGeneratorOptions {
  length: number;
  useUppercase: boolean;
  useLowercase: boolean;
  useNumbers: boolean;
  useSpecial: boolean;
  avoidAmbiguous: boolean;
  avoidSimilar: boolean;
}

const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
  '111111', '1234567', 'dragon', 'welcome', '123123', 'admin', 'football',
  'monkey', 'letmein', 'shadow', 'master', '666666', 'sunshine', 'princess',
  'superman', 'trustno1', 'iloveyou', 'starwars', 'killer', 'test', 'login',
  'access', 'pass123', 'welcome1', 'admin123', 'administrator', 'secret',
  'pass', 'root', 'guest', 'system', 'changeme', 'user', 'default'
]);

const SEQUENTIAL_PATTERNS = [
  'abcdefghijklmnopqrstuvwxyz',
  '0123456789',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm'
];

/**
 * Checks for sequences of length 3 or more (e.g. "abc", "321", "qwe")
 */
function detectSequentialSequences(pwd: string): boolean {
  const lower = pwd.toLowerCase();
  if (lower.length < 3) return false;

  for (const seq of SEQUENTIAL_PATTERNS) {
    const reversed = seq.split('').reverse().join('');
    for (let i = 0; i < lower.length - 2; i++) {
      const triplet = lower.substring(i, i + 3);
      if (seq.includes(triplet) || reversed.includes(triplet)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Checks for excessive repetition (e.g. "aaa", "111", or repeated chunks "ababab")
 */
function detectRepetitivePatterns(pwd: string): boolean {
  if (pwd.length < 3) return false;

  // 3 or more consecutive identical characters
  if (/(.)\1{2,}/.test(pwd)) {
    return true;
  }

  // Repeated 2-character sequences (e.g., "abab")
  if (pwd.length >= 4 && /(..)\1+/.test(pwd)) {
    return true;
  }

  return false;
}

/**
 * Evaluates password security client-side.
 * Never leaks the password string.
 */
export function analyzePasswordSecurity(password: string): PasswordSecurityAnalysis {
  const length = password.length;
  if (length === 0) {
    return {
      score: 0,
      level: 'VERY WEAK',
      color: 'var(--color-danger)',
      length: 0,
      hasUppercase: false,
      hasLowercase: false,
      hasNumbers: false,
      hasSpecial: false,
      hasRepeatedChars: false,
      hasSequentialChars: false,
      isCommonPassword: false,
      criteria: [
        { id: 'length', label: '12+ characters', met: false, explanation: 'Longer passwords resist brute-force attacks exponentially better.' },
        { id: 'uppercase', label: 'Uppercase letters (A-Z)', met: false, explanation: 'Adds variety to character entropy.' },
        { id: 'lowercase', label: 'Lowercase letters (a-z)', met: false, explanation: 'Standard mixed-case composition.' },
        { id: 'numbers', label: 'Numbers (0-9)', met: false, explanation: 'Expands the character search space.' },
        { id: 'special', label: 'Special characters (!@#$%...)', met: false, explanation: 'Significantly increases combinatorial complexity.' },
        { id: 'patterns', label: 'No obvious repetition or patterns', met: true, explanation: 'Avoids dictionary and sequential heuristics.' }
      ],
      feedback: ['Enter a password to evaluate its security strength.'],
      estimatedEntropyBits: 0
    };
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  const hasRepeatedChars = detectRepetitivePatterns(password);
  const hasSequentialChars = detectSequentialSequences(password);
  const lowerPwd = password.toLowerCase().trim();
  const isCommonPassword = COMMON_PASSWORDS.has(lowerPwd);

  // Pool size calculation for Shannon entropy estimation
  let poolSize = 0;
  if (hasLowercase) poolSize += 26;
  if (hasUppercase) poolSize += 26;
  if (hasNumbers) poolSize += 10;
  if (hasSpecial) poolSize += 33;
  if (poolSize === 0) poolSize = 1;

  const rawEntropy = length * Math.log2(poolSize);

  // Scoring algorithm (0-100)
  let score = 0;

  // Length points
  if (length >= 16) score += 40;
  else if (length >= 12) score += 30;
  else if (length >= 8) score += 18;
  else score += length * 2;

  // Character variety points
  let varietyCount = 0;
  if (hasUppercase) varietyCount++;
  if (hasLowercase) varietyCount++;
  if (hasNumbers) varietyCount++;
  if (hasSpecial) varietyCount++;

  score += varietyCount * 12; // up to 48 points

  // Bonus for combination of length & full variety
  if (length >= 12 && varietyCount === 4) score += 12;

  // Deductions
  if (isCommonPassword) {
    score = Math.min(score, 10);
  } else {
    if (hasRepeatedChars) score = Math.max(5, score - 18);
    if (hasSequentialChars) score = Math.max(5, score - 15);
    if (varietyCount === 1 && length > 0) score = Math.min(score, 25);
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  // Strength Level & Color
  let level: PasswordStrengthLevel;
  let color: string;

  if (score >= 85) {
    level = 'VERY STRONG';
    color = 'var(--color-safe)';
  } else if (score >= 65) {
    level = 'STRONG';
    color = 'var(--color-safe)';
  } else if (score >= 45) {
    level = 'MEDIUM';
    color = 'var(--color-caution)';
  } else if (score >= 25) {
    level = 'WEAK';
    color = 'var(--color-danger)';
  } else {
    level = 'VERY WEAK';
    color = 'var(--color-danger)';
  }

  const feedback: string[] = [];
  if (isCommonPassword) {
    feedback.push('This is an extremely common, easily crackable password found in public breach databases.');
  }
  if (length < 8) {
    feedback.push('Password is critically short. Modern attackers crack passwords under 8 characters in seconds.');
  } else if (length < 12) {
    feedback.push('Consider increasing password length to at least 12-16 characters for robust protection.');
  }

  if (varietyCount < 3) {
    feedback.push('Mix uppercase letters, numbers, and symbols to maximize character variety.');
  }

  if (hasRepeatedChars) {
    feedback.push('Avoid repeating identical characters or repeated word fragments.');
  }

  if (hasSequentialChars) {
    feedback.push('Avoid sequential runs such as "123", "abc", or keyboard walking patterns like "qwerty".');
  }

  if (feedback.length === 0) {
    feedback.push('Excellent password composition! High entropy and zero obvious weak patterns.');
  }

  const criteria: PasswordCriteriaCheck[] = [
    {
      id: 'length',
      label: '12+ characters',
      met: length >= 12,
      explanation: length >= 12 ? 'Length exceeds recommended threshold' : `Currently ${length} characters (12+ recommended)`
    },
    {
      id: 'uppercase',
      label: 'Uppercase letters (A-Z)',
      met: hasUppercase,
      explanation: hasUppercase ? 'Uppercase characters present' : 'Add at least one capital letter'
    },
    {
      id: 'lowercase',
      label: 'Lowercase letters (a-z)',
      met: hasLowercase,
      explanation: hasLowercase ? 'Lowercase characters present' : 'Add at least one lowercase letter'
    },
    {
      id: 'numbers',
      label: 'Numbers (0-9)',
      met: hasNumbers,
      explanation: hasNumbers ? 'Numeric digits present' : 'Add numeric digits (0-9)'
    },
    {
      id: 'special',
      label: 'Special characters (!@#$%...)',
      met: hasSpecial,
      explanation: hasSpecial ? 'Symbols and punctuation present' : 'Add special symbols (!@#$%^&*)'
    },
    {
      id: 'patterns',
      label: 'No obvious repetition or patterns',
      met: !hasRepeatedChars && !hasSequentialChars && !isCommonPassword,
      explanation: !hasRepeatedChars && !hasSequentialChars && !isCommonPassword
        ? 'No sequential or repeating patterns detected'
        : 'Sequential or repeating patterns detected'
    }
  ];

  return {
    score,
    level,
    color,
    length,
    hasUppercase,
    hasLowercase,
    hasNumbers,
    hasSpecial,
    hasRepeatedChars,
    hasSequentialChars,
    isCommonPassword,
    criteria,
    feedback,
    estimatedEntropyBits: Math.round(rawEntropy)
  };
}

/**
 * Generates a cryptographically strong random password using window.crypto.getRandomValues().
 * CONSTITUTIONAL RULE: Math.random() is strictly forbidden.
 */
export function generateSecurePassword(options: PasswordGeneratorOptions): string {
  const {
    length = 16,
    useUppercase = true,
    useLowercase = true,
    useNumbers = true,
    useSpecial = true,
    avoidAmbiguous = false,
    avoidSimilar = false
  } = options;

  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let numberChars = '0123456789';
  let specialChars = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  if (avoidSimilar) {
    // Exclude similar looking characters: l, 1, I, o, 0, O
    upperChars = upperChars.replace(/[IO]/g, '');
    lowerChars = lowerChars.replace(/[lo]/g, '');
    numberChars = numberChars.replace(/[01]/g, '');
  }

  if (avoidAmbiguous) {
    // Exclude ambiguous symbols: { } [ ] ( ) / \ ' " ` ~ , ; : . < >
    specialChars = specialChars.replace(/[{}\[\]()\/\\'"`~,;:.<>]/g, '');
  }

  const pools: string[] = [];
  if (useUppercase && upperChars.length > 0) pools.push(upperChars);
  if (useLowercase && lowerChars.length > 0) pools.push(lowerChars);
  if (useNumbers && numberChars.length > 0) pools.push(numberChars);
  if (useSpecial && specialChars.length > 0) pools.push(specialChars);

  if (pools.length === 0) {
    // Default fallback if all turned off
    pools.push(lowerChars || 'abcdefghijklmnopqrstuvwxyz');
  }

  const allAvailableChars = pools.join('');
  const passwordChars: string[] = [];

  // Helper for cryptographically secure random integers in [0, max - 1]
  const getSecureRandomInt = (max: number): number => {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      const buffer = new Uint32Array(1);
      window.crypto.getRandomValues(buffer);
      return buffer[0] % max;
    }
    // Node environment fallback for testing
    if (typeof globalThis !== 'undefined' && (globalThis as any).crypto && (globalThis as any).crypto.getRandomValues) {
      const buffer = new Uint32Array(1);
      (globalThis as any).crypto.getRandomValues(buffer);
      return buffer[0] % max;
    }
    throw new Error('Cryptographically secure random number generator is unavailable.');
  };

  // Guarantee at least one character from each enabled category
  for (const pool of pools) {
    passwordChars.push(pool[getSecureRandomInt(pool.length)]);
  }

  // Fill the remaining length
  const remainingLength = Math.max(0, length - passwordChars.length);
  for (let i = 0; i < remainingLength; i++) {
    passwordChars.push(allAvailableChars[getSecureRandomInt(allAvailableChars.length)]);
  }

  // Cryptographically shuffle the array (Fisher-Yates)
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(i + 1);
    const temp = passwordChars[i];
    passwordChars[i] = passwordChars[j];
    passwordChars[j] = temp;
  }

  return passwordChars.join('');
}
