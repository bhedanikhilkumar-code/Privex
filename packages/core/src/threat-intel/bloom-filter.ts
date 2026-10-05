import * as crypto from 'crypto';

export interface BloomFilterOptions {
  expectedElements?: number;
  targetFalsePositiveRate?: number;
  sizeBits?: number;
  hashCount?: number;
}

/**
 * Production-Grade Binary Bloom Filter for Local Threat Intelligence
 * Conforms to docs/OFFLINE_ARCHITECTURE.md and docs/INTERFACE_CONTRACTS.md (Subsystem 6)
 *
 * Mathematical Properties:
 * - Optimal bit size m = ceil(- (n * ln(p)) / (ln(2)^2))
 * - Optimal hash count k = round((m / n) * ln(2))
 * - Double hashing (Kirsch-Mitzenmacher optimization): g_i(x) = (h1(x) + i * h2(x)) mod m
 * - Zero False Negatives Guarantee: if element was added, has() strictly returns true
 * - Measured False Positive Rate: P_fp = (setBits / m)^k
 */
export class BloomFilter {
  private bits: Uint8Array;
  private m: number; // Total bits
  private k: number; // Hash functions count
  private n: number; // Expected element capacity
  private count: number = 0; // Number of elements inserted
  private setBitsCount: number = 0; // Counter for set bits

  constructor(options?: BloomFilterOptions | number, targetFalsePositiveRate?: number) {
    const opts: BloomFilterOptions =
      typeof options === 'number'
        ? { expectedElements: options, targetFalsePositiveRate }
        : options || {};
    const n = Math.max(10, opts.expectedElements ?? 100000);
    const p = Math.max(0.00001, Math.min(0.1, opts.targetFalsePositiveRate ?? 0.001));

    this.n = n;

    if (opts.sizeBits && opts.hashCount) {
      this.m = opts.sizeBits;
      this.k = opts.hashCount;
    } else {
      // Optimal m: - (n * ln(p)) / (ln(2)^2)
      const ln2Squared = Math.LN2 * Math.LN2;
      this.m = Math.ceil(-(n * Math.log(p)) / ln2Squared);
      // Ensure m is at least 64 bits and divisible by 8 for clean byte alignment
      this.m = Math.max(64, Math.ceil(this.m / 8) * 8);

      // Optimal k: (m / n) * ln(2)
      this.k = Math.max(2, Math.min(16, Math.round((this.m / n) * Math.LN2)));
    }

    const byteLength = Math.ceil(this.m / 8);
    this.bits = new Uint8Array(byteLength);
  }

  public get capacity(): number {
    return this.n;
  }

  public get sizeBits(): number {
    return this.m;
  }

  public get hashCount(): number {
    return this.k;
  }

  public get elementCount(): number {
    return this.count;
  }

  /**
   * Adds an element (string or buffer) to the Bloom filter.
   */
   public add(item: string | Uint8Array): void {
    const [h1, h2] = this.hash(item);
    const m = this.m;
    const bits = this.bits;

    for (let i = 0; i < this.k; i++) {
      // Kirsch-Mitzenmacher: (h1 + i * h2) mod m
      // Safe integer arithmetic: h1, h2 < 2^32, k <= 16 -> h1 + i * h2 <= 7.3e10 << Number.MAX_SAFE_INTEGER
      const bitIndex = (h1 + i * h2) % m;
      const byteIndex = bitIndex >>> 3;
      const bitMask = 1 << (bitIndex & 7);

      if ((bits[byteIndex] & bitMask) === 0) {
        bits[byteIndex] |= bitMask;
        this.setBitsCount++;
      }
    }

    this.count++;
  }

  /**
   * Checks whether an element is probably in the Bloom filter.
   * If returns false: 100% guaranteed NOT in the filter (zero false negatives).
   * If returns true: element is probably in the filter (bounded false positive rate).
   * NOTE: A Bloom filter positive is a candidate signal only, NOT a final malicious verdict.
   */
  public has(item: string | Uint8Array): boolean {
    if (item === null || item === undefined) return false;
    const [h1, h2] = this.hash(item);
    const m = this.m;
    const bits = this.bits;

    for (let i = 0; i < this.k; i++) {
      const bitIndex = (h1 + i * h2) % m;
      const byteIndex = bitIndex >>> 3;
      const bitMask = 1 << (bitIndex & 7);

      if ((bits[byteIndex] & bitMask) === 0) {
        return false;
      }
    }

    return true;
  }

  /**
   * Calculates the current empirical false positive probability:
   * P_fp = (setBits / m)^k
   */
  public getFalsePositiveRate(): number {
    if (this.setBitsCount === 0 || this.m === 0) return 0.0;
    const bitDensity = this.setBitsCount / this.m;
    return Math.min(1.0, Math.pow(bitDensity, this.k));
  }

  /**
   * Clears the Bloom filter.
   */
  public clear(): void {
    this.bits.fill(0);
    this.count = 0;
    this.setBitsCount = 0;
  }

  /**
   * Serializes the Bloom filter to binary Uint8Array with a 16-byte header:
   * [0..3]: Magic 'BLOM' (0x42, 0x4C, 0x4F, 0x4D)
   * [4]: Version (1)
   * [5]: Hash count k (uint8)
   * [6..7]: Reserved (0x00, 0x00)
   * [8..11]: Size in bits m (uint32le)
   * [12..15]: Element count (uint32le)
   * [16..]: Raw bit array bytes
   */
  public serialize(): Uint8Array {
    const headerSize = 16;
    const out = new Uint8Array(headerSize + this.bits.length);

    // Magic 'BLOM'
    out[0] = 0x42;
    out[1] = 0x4c;
    out[2] = 0x4f;
    out[3] = 0x4d;

    // Version
    out[4] = 0x01;
    // k
    out[5] = this.k & 0xff;
    // Reserved
    out[6] = 0x00;
    out[7] = 0x00;

    // m (uint32le)
    out[8] = this.m & 0xff;
    out[9] = (this.m >> 8) & 0xff;
    out[10] = (this.m >> 16) & 0xff;
    out[11] = (this.m >> 24) & 0xff;

    // count (uint32le)
    out[12] = this.count & 0xff;
    out[13] = (this.count >> 8) & 0xff;
    out[14] = (this.count >> 16) & 0xff;
    out[15] = (this.count >> 24) & 0xff;

    // Bit bytes
    out.set(this.bits, headerSize);
    return out;
  }

  /**
   * Deserializes a binary Uint8Array into a BloomFilter instance.
   */
  public static deserialize(buffer: Uint8Array): BloomFilter {
    if (buffer.length < 16) {
      throw new Error('InvalidBloomFilterError: buffer too short for header');
    }

    // Verify magic 'BLOM'
    if (buffer[0] !== 0x42 || buffer[1] !== 0x4c || buffer[2] !== 0x4f || buffer[3] !== 0x4d) {
      throw new Error('InvalidBloomFilterError: magic bytes mismatch');
    }

    const version = buffer[4];
    if (version !== 0x01) {
      throw new Error(`InvalidBloomFilterError: unsupported version ${version}`);
    }

    const k = buffer[5];
    const m = (buffer[8] | (buffer[9] << 8) | (buffer[10] << 16) | (buffer[11] << 24)) >>> 0;
    const count = (buffer[12] | (buffer[13] << 8) | (buffer[14] << 16) | (buffer[15] << 24)) >>> 0;

    const expectedBitBytes = Math.ceil(m / 8);
    if (buffer.length - 16 < expectedBitBytes) {
      throw new Error('InvalidBloomFilterError: truncated bit data');
    }

    const filter = new BloomFilter({ sizeBits: m, hashCount: k, expectedElements: count });
    filter.n = count;
    filter.bits.set(buffer.subarray(16, 16 + expectedBitBytes));
    filter.count = count;

    // Recount set bits
    let setBits = 0;
    for (let i = 0; i < filter.bits.length; i++) {
      let b = filter.bits[i];
      while (b > 0) {
        setBits += b & 1;
        b >>= 1;
      }
    }
    filter.setBitsCount = setBits;

    return filter;
  }

  /**
   * Fast-path validation that a string is a 64-character hexadecimal SHA-256 digest.
   */
  public static isSha256Hex(str: string): boolean {
    if (typeof str !== 'string' || str.length !== 64) return false;
    for (let i = 0; i < 64; i++) {
      const c = str.charCodeAt(i);
      const isDigit = c >= 48 && c <= 57;
      const isLowerHex = c >= 97 && c <= 102;
      const isUpperHex = c >= 65 && c <= 70;
      if (!isDigit && !isLowerHex && !isUpperHex) {
        return false;
      }
    }
    return true;
  }

  private static parseHexByte(str: string, offset: number): number {
    const c0 = str.charCodeAt(offset);
    const c1 = str.charCodeAt(offset + 1);
    const n0 = c0 <= 57 ? c0 - 48 : c0 <= 70 ? c0 - 55 : c0 - 87;
    const n1 = c1 <= 57 ? c1 - 48 : c1 <= 70 ? c1 - 55 : c1 - 87;
    return ((n0 << 4) | n1) & 0xff;
  }

  /**
   * Computes two independent 32-bit unsigned hashes for Kirsch-Mitzenmacher double hashing.
   * Phase B Step 5 Optimization: If `item` is already a 64-char SHA-256 hex digest,
   * extracts [h1, h2] directly from the first 8 digest bytes in O(1) with zero heap allocations
   * instead of hashing the hex string a second time.
   */
  private hash(item: string | Uint8Array): [number, number] {
    if (typeof item === 'string' && BloomFilter.isSha256Hex(item)) {
      const b0 = BloomFilter.parseHexByte(item, 0);
      const b1 = BloomFilter.parseHexByte(item, 2);
      const b2 = BloomFilter.parseHexByte(item, 4);
      const b3 = BloomFilter.parseHexByte(item, 6);
      const h1 = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;

      const b4 = BloomFilter.parseHexByte(item, 8);
      const b5 = BloomFilter.parseHexByte(item, 10);
      const b6 = BloomFilter.parseHexByte(item, 12);
      const b7 = BloomFilter.parseHexByte(item, 14);
      const h2 = ((b4 | (b5 << 8) | (b6 << 16) | (b7 << 24)) | 1) >>> 0;

      return [h1, h2];
    }

    const buf = typeof item === 'string' ? Buffer.from(item, 'utf-8') : Buffer.from(item);
    const digest = crypto.createHash('sha256').update(buf).digest();

    // First 4 bytes as h1
    const h1 = digest.readUInt32LE(0);
    // Next 4 bytes as h2 (ensure non-zero and odd for full period cycle)
    const h2 = (digest.readUInt32LE(4) | 1) >>> 0;

    return [h1, h2];
  }
}
