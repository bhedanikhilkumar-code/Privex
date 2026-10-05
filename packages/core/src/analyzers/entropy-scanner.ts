/**
 * High-Performance Shannon Entropy Scanner with Precomputed LUT (Layer 4 / Phase C)
 *
 * Implements:
 * 1. Precomputed ENTROPY_LUT[4097] for ultra-fast frequency-to-entropy mapping.
 * 2. Sliding-window entropy scan to defeat null-byte padding attacks.
 * 3. Section entropy analysis for PE binary sections.
 */

export interface SlidingWindowEntropyResult {
  readonly maxEntropy: number;
  readonly minEntropy: number;
  readonly avgEntropy: number;
  readonly highEntropyChunkCount: number; // chunks exceeding threshold (e.g. 7.2)
  readonly totalWindows: number;
  readonly isPackedOrEncrypted: boolean;
}

// Precomputed table of c * log2(c) for c in [0, 4096]
// Entropy of a window of size N is: (N * log2(N) - SUM(c_i * log2(c_i))) / N
const LUT_SIZE = 4097;
const ENTROPY_N_LOG2_N = new Float64Array(LUT_SIZE);

for (let c = 1; c < LUT_SIZE; c++) {
  ENTROPY_N_LOG2_N[c] = c * Math.log2(c);
}

export class EntropyScanner {
  public static readonly HIGH_ENTROPY_THRESHOLD = 7.2;
  public static readonly VERY_HIGH_ENTROPY_THRESHOLD = 7.6; // Packed / Encrypted
  public static readonly DEFAULT_WINDOW_SIZE = 2048;
  public static readonly DEFAULT_STEP_SIZE = 512;

  /**
   * Fast whole-buffer Shannon entropy calculation (0.0 to 8.0).
   * Uses ENTROPY_N_LOG2_N LUT for window sizes <= 4096, or direct formula for larger.
   */
  public static calculateEntropy(buffer: Uint8Array | number[]): number {
    if (!buffer || buffer.length === 0) return 0;
    const len = buffer.length;
    if (len === 1) return 0;

    const freq = new Uint32Array(256);
    for (let i = 0; i < len; i++) {
      freq[buffer[i] & 0xff]++;
    }

    if (len < LUT_SIZE) {
      // Fast path using LUT
      let sumCLogC = 0;
      for (let i = 0; i < 256; i++) {
        const count = freq[i];
        if (count > 0) {
          sumCLogC += ENTROPY_N_LOG2_N[count];
        }
      }
      const totalNLogN = ENTROPY_N_LOG2_N[len];
      const entropy = (totalNLogN - sumCLogC) / len;
      return Math.round(entropy * 1000) / 1000;
    }

    // Large buffer fallback
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      const count = freq[i];
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }
    return Math.round(entropy * 1000) / 1000;
  }

  /**
   * Sliding-window entropy scan.
   * Catches high-entropy encrypted/compressed payloads even when surrounded
   * by low-entropy filler or null-byte padding.
   */
  public static scanSlidingWindow(
    buffer: Uint8Array | number[],
    windowSize: number = EntropyScanner.DEFAULT_WINDOW_SIZE,
    stepSize: number = EntropyScanner.DEFAULT_STEP_SIZE,
    threshold: number = EntropyScanner.HIGH_ENTROPY_THRESHOLD
  ): SlidingWindowEntropyResult {
    if (!buffer || buffer.length === 0) {
      return {
        maxEntropy: 0,
        minEntropy: 0,
        avgEntropy: 0,
        highEntropyChunkCount: 0,
        totalWindows: 0,
        isPackedOrEncrypted: false
      };
    }

    const totalLen = buffer.length;
    const effectiveWindow = Math.min(totalLen, Math.min(windowSize, 4096));

    if (totalLen <= effectiveWindow) {
      const singleEntropy = this.calculateEntropy(buffer);
      return {
        maxEntropy: singleEntropy,
        minEntropy: singleEntropy,
        avgEntropy: singleEntropy,
        highEntropyChunkCount: singleEntropy >= threshold ? 1 : 0,
        totalWindows: 1,
        isPackedOrEncrypted: singleEntropy >= threshold
      };
    }

    let maxEntropy = 0;
    let minEntropy = 8.0;
    let sumEntropy = 0;
    let highEntropyCount = 0;
    let windows = 0;

    const actualStep = Math.max(64, stepSize);

    for (let offset = 0; offset + effectiveWindow <= totalLen; offset += actualStep) {
      const slice = buffer instanceof Uint8Array
        ? buffer.subarray(offset, offset + effectiveWindow)
        : buffer.slice(offset, offset + effectiveWindow);

      const ent = this.calculateEntropy(slice);
      if (ent > maxEntropy) maxEntropy = ent;
      if (ent < minEntropy) minEntropy = ent;
      sumEntropy += ent;
      if (ent >= threshold) highEntropyCount++;
      windows++;
    }

    const avgEntropy = windows > 0 ? Math.round((sumEntropy / windows) * 1000) / 1000 : 0;
    const isPackedOrEncrypted =
      maxEntropy >= EntropyScanner.VERY_HIGH_ENTROPY_THRESHOLD ||
      (windows > 0 && highEntropyCount / windows >= 0.40);

    return {
      maxEntropy: Math.round(maxEntropy * 1000) / 1000,
      minEntropy: minEntropy === 8.0 ? 0 : Math.round(minEntropy * 1000) / 1000,
      avgEntropy,
      highEntropyChunkCount: highEntropyCount,
      totalWindows: windows,
      isPackedOrEncrypted
    };
  }
}
