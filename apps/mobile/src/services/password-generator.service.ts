import { UnbiasedRandom } from '../lib/unbiased-random';
import { PASSPHRASE_WORDLIST } from '../lib/passphrase-wordlist';
import {
  PasswordGeneratorOptions,
  PassphraseGeneratorOptions,
  PasswordGenerationResult,
  PassphraseGenerationResult,
  PasswordGeneratorPreset
} from '../types/mobile.types';

/**
 * Character sets for password generation.
 */
const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz';
const DIGIT_CHARS = '0123456789';
const SPECIAL_CHARS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

// Ambiguous characters: symbols easily mistaken or causing shell/escaping issues
const AMBIGUOUS_SYMBOLS_REGEX = /[{}\[\]()\/\\'"`~,;:.<>]/g;
// Similar characters: l, 1, I, o, 0, O
const SIMILAR_UPPER_REGEX = /[IO]/g;
const SIMILAR_LOWER_REGEX = /[lo]/g;
const SIMILAR_DIGIT_REGEX = /[01]/g;

export class PasswordGeneratorService {
  private static instance: PasswordGeneratorService | null = null;

  public static getInstance(): PasswordGeneratorService {
    if (!PasswordGeneratorService.instance) {
      PasswordGeneratorService.instance = new PasswordGeneratorService();
    }
    return PasswordGeneratorService.instance;
  }

  /**
   * Return predefined options for a given preset.
   */
  public getPresetOptions(preset: PasswordGeneratorPreset): PasswordGeneratorOptions {
    switch (preset) {
      case 'STANDARD':
        return {
          length: 20,
          useUppercase: true,
          useLowercase: true,
          useNumbers: true,
          useSpecial: true,
          avoidAmbiguous: false,
          avoidSimilar: false
        };
      case 'STRONG':
        return {
          length: 32,
          useUppercase: true,
          useLowercase: true,
          useNumbers: true,
          useSpecial: true,
          avoidAmbiguous: false,
          avoidSimilar: false
        };
      case 'VERY_STRONG':
        return {
          length: 48,
          useUppercase: true,
          useLowercase: true,
          useNumbers: true,
          useSpecial: true,
          avoidAmbiguous: false,
          avoidSimilar: false
        };
      case 'CUSTOM':
      default:
        return {
          length: 24,
          useUppercase: true,
          useLowercase: true,
          useNumbers: true,
          useSpecial: true,
          avoidAmbiguous: false,
          avoidSimilar: false
        };
    }
  }

  /**
   * Generates a cryptographically strong character password with zero modulo bias.
   * Guarantees representation of all selected character pools.
   */
  public generatePassword(options: PasswordGeneratorOptions): PasswordGenerationResult {
    const length = Math.max(12, Math.min(128, Math.floor(options.length || 20)));

    let upper = options.useUppercase ? UPPERCASE_CHARS : '';
    let lower = options.useLowercase ? LOWERCASE_CHARS : '';
    let numbers = options.useNumbers ? DIGIT_CHARS : '';
    let special = options.useSpecial ? SPECIAL_CHARS : '';

    if (options.avoidSimilar) {
      upper = upper.replace(SIMILAR_UPPER_REGEX, '');
      lower = lower.replace(SIMILAR_LOWER_REGEX, '');
      numbers = numbers.replace(SIMILAR_DIGIT_REGEX, '');
    }

    if (options.avoidAmbiguous) {
      special = special.replace(AMBIGUOUS_SYMBOLS_REGEX, '');
    }

    const enabledPools: string[] = [];
    if (upper.length > 0) enabledPools.push(upper);
    if (lower.length > 0) enabledPools.push(lower);
    if (numbers.length > 0) enabledPools.push(numbers);
    if (special.length > 0) enabledPools.push(special);

    if (enabledPools.length === 0) {
      throw new Error('At least one character group must be selected.');
    }

    const combinedPool = enabledPools.join('');
    const poolSize = combinedPool.length;

    // Pick at least 1 character from each enabled pool to guarantee representation
    const chars: string[] = [];
    for (const pool of enabledPools) {
      const idx = UnbiasedRandom.nextInt(pool.length);
      chars.push(pool[idx]);
    }

    // Fill the remainder
    const remainingCount = length - chars.length;
    for (let i = 0; i < remainingCount; i++) {
      const idx = UnbiasedRandom.nextInt(combinedPool.length);
      chars.push(combinedPool[idx]);
    }

    // Fisher-Yates unbiased shuffle
    UnbiasedRandom.shuffle(chars);
    const secret = chars.join('');

    // Entropy calculation: L * log2(N)
    const entropyBits = Math.round(length * Math.log2(poolSize));
    const strengthLevel = this.calculatePasswordStrength(entropyBits);
    const entropyExplanation = this.formatEntropyExplanation(entropyBits, 'PASSWORD');

    return {
      secret,
      length,
      poolSize,
      entropyBits,
      entropyExplanation,
      strengthLevel,
      mode: 'PASSWORD',
      characterGroups: {
        hasUppercase: upper.length > 0 && /[A-Z]/.test(secret),
        hasLowercase: lower.length > 0 && /[a-z]/.test(secret),
        hasNumbers: numbers.length > 0 && /[0-9]/.test(secret),
        hasSpecial: special.length > 0
      }
    };
  }

  /**
   * Generates a cryptographically strong passphrase from local 2,048-word dictionary.
   */
  public generatePassphrase(options?: Partial<PassphraseGeneratorOptions>): PassphraseGenerationResult {
    const wordCount = Math.max(3, Math.min(10, Math.floor(options?.wordCount ?? 5)));
    const separator = options?.separator !== undefined ? options.separator : '-';
    const capitalize = options?.capitalize ?? false;
    const includeNumber = options?.includeNumber ?? false;

    const wordlistSize = PASSPHRASE_WORDLIST.length; // 2048
    if (wordlistSize !== 2048) {
      throw new Error(`Corrupted wordlist size: ${wordlistSize}. Expected 2048.`);
    }

    const selectedWords: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      const idx = UnbiasedRandom.nextInt(wordlistSize);
      let word = PASSPHRASE_WORDLIST[idx];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      selectedWords.push(word);
    }

    if (includeNumber) {
      const randomDigit = UnbiasedRandom.nextInt(10);
      const randomWordIdx = UnbiasedRandom.nextInt(selectedWords.length);
      selectedWords[randomWordIdx] += randomDigit.toString();
    }

    const secret = selectedWords.join(separator);

    // Passphrase entropy: C * log2(W) where W is 2048 (11 bits/word)
    // Plus ~3.3 bits if a random single-digit number is appended to a word
    let entropyBits = Math.round(wordCount * Math.log2(wordlistSize));
    if (includeNumber) {
      entropyBits += Math.round(Math.log2(10));
    }
    if (capitalize) {
      // 1 bit per capitalized word
      entropyBits += wordCount;
    }

    const strengthLevel = this.calculatePassphraseStrength(entropyBits);
    const entropyExplanation = this.formatEntropyExplanation(entropyBits, 'PASSPHRASE');

    return {
      secret,
      wordCount,
      wordlistSize,
      entropyBits,
      entropyExplanation,
      strengthLevel,
      mode: 'PASSPHRASE',
      separator
    };
  }

  /**
   * Copies sensitive secret to clipboard with protection and transient feedback.
   * If running under Android Bridge, delegates to native method which marks EXTRA_IS_SENSITIVE.
   */
  public async copyToClipboard(secret: string, label: string = 'Password'): Promise<boolean> {
    if (!secret) return false;

    // Check Android native bridge first
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.copySensitiveToClipboard) {
      try {
        const success = (window as any).AndroidSecurityBridge.copySensitiveToClipboard(label, secret);
        if (success) {
          return true;
        }
      } catch (e) {
        // Fall back to web clipboard
      }
    }

    // Web clipboard fallback
    if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(secret);
        return true;
      } catch (err) {
        // Fall back to execCommand
      }
    }

    if (typeof document !== 'undefined') {
      try {
        const textarea = document.createElement('textarea');
        textarea.value = secret;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      } catch (e) {
        return false;
      }
    }

    return false;
  }

  private calculatePasswordStrength(entropyBits: number): 'WEAK' | 'MEDIUM' | 'STRONG' | 'VERY_STRONG' {
    if (entropyBits < 60) return 'WEAK';
    if (entropyBits < 80) return 'MEDIUM';
    if (entropyBits < 120) return 'STRONG';
    return 'VERY_STRONG';
  }

  private calculatePassphraseStrength(entropyBits: number): 'WEAK' | 'MEDIUM' | 'STRONG' | 'VERY_STRONG' {
    if (entropyBits < 45) return 'WEAK';
    if (entropyBits < 65) return 'MEDIUM';
    if (entropyBits < 90) return 'STRONG';
    return 'VERY_STRONG';
  }

  private formatEntropyExplanation(entropyBits: number, mode: 'PASSWORD' | 'PASSPHRASE'): string {
    const modeDesc = mode === 'PASSWORD' 
      ? 'Character combinations search space' 
      : 'Dictionary word combinations search space';
    return `${entropyBits} bits of entropy (${modeDesc}). Note: Entropy measures mathematical search-space uncertainty against brute-force attacks; it does not protect against phishing or malware keystroke logging.`;
  }
}
