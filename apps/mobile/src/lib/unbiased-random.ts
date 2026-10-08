/**
 * Cryptographically Secure Unbiased Random Integer Sampling
 * 
 * Invariant: Rejection sampling threshold algorithm to ensure zero modulo bias.
 * Formula:
 * For range [0, bound - 1], let limit = 2^32 - (2^32 % bound).
 * If random integer r >= limit, reject and resample.
 * Return r % bound.
 */

export class UnbiasedRandom {
  private static readonly TWO_POW_32 = 4294967296;

  /**
   * Generates a cryptographically secure random integer in [0, bound - 1]
   * with zero modulo bias.
   * 
   * @param bound Positive integer upper limit (exclusive)
   */
  public static nextInt(bound: number): number {
    if (bound <= 0 || !Number.isInteger(bound)) {
      throw new Error(`Invalid bound for unbiased random: ${bound}. Must be a positive integer.`);
    }
    if (bound === 1) {
      return 0;
    }

    // limit = 2^32 - (2^32 % bound)
    const limit = UnbiasedRandom.TWO_POW_32 - (UnbiasedRandom.TWO_POW_32 % bound);

    const buf = new Uint32Array(1);
    const cryptoObj = UnbiasedRandom.getCrypto();

    while (true) {
      cryptoObj.getRandomValues(buf);
      const val = buf[0];
      if (val < limit) {
        return val % bound;
      }
      // Rejection sampling discard, loop to sample again
    }
  }

  /**
   * Shuffles an array in place using unbiased Fisher-Yates shuffle.
   */
  public static shuffle<T>(array: T[]): T[] {
    for (let i = array.length - 1; i > 0; i--) {
      const j = UnbiasedRandom.nextInt(i + 1);
      const temp = array[i];
      array[i] = array[j];
      array[j] = temp;
    }
    return array;
  }

  private static getCrypto(): Crypto {
    if (typeof window !== 'undefined' && window.crypto && typeof window.crypto.getRandomValues === 'function') {
      return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
      return globalThis.crypto;
    }
    throw new Error('Cryptographically secure random number generator (CSPRNG) is unavailable in this environment.');
  }
}
