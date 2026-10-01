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

  constructor(options?: BloomFilterOptions) {
    const n = Math.max(10, options?.expectedElements ?? 100000);
    const p = Math.max(0.00001, Math.min(0.1, options?.targetFalsePositiveRate ?? 0.001));

    this.n = n;

    if (options?.sizeBits && options?.hashCount) {
      this.m = options.sizeBits;
      this.k = options.hashCount;
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
    let newlySet = false;

    for (let i = 0; i < this.k; i++) {
      // Kirsch-Mitzenmacher: (h1 + i * h2) mod m
      // Use unsigned 32-bit arithmetic
      const bitIndex = Number((BigInt(h1) + BigInt(i) * BigInt(h2)) % BigInt(this.m));
      const byteIndex = bitIndex >> 3;
      const bitMask = 1 << (bitIndex & 7);

      if ((this.bits[byteIndex] & bitMask) === 0) {
        this.bits[byteIndex] |= bitMask;
        this.setBitsCount++;
        newlySet = true;
      }
    }

    this.count++;
  }

  /**
   * Checks whether an element is probably in the Bloom filter.
   * If returns false: 100% guaranteed NOT in the filter (zero false negatives).
   * If returns true: element is probably in the filter (bounded false positive rate).
   */
  public has(item: string | Uint8Array): boolean {
    const [h1, h2] = this.hash(item);

    for (let i = 0; i < this.k; i++) {
      const bitIndex = Number((BigInt(h1) + BigInt(i) * BigInt(h2)) % BigInt(this.m));
      const byteIndex = bitIndex >> 3;
      const bitMask = 1 << (bitIndex & 7);

      if ((this.bits[byteIndex] & bitMask) === 0) {
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
   * Computes two independent 32-bit unsigned hashes from SHA-256 for Kirsch-Mitzenmacher double hashing.
   */
  private hash(item: string | Uint8Array): [number, number] {
    const buf = typeof item === 'string' ? Buffer.from(item, 'utf-8') : Buffer.from(item);
    const digest = crypto.createHash('sha256').update(buf).digest();

    // First 4 bytes as h1
    const h1 = digest.readUInt32LE(0);
    // Next 4 bytes as h2 (ensure non-zero and odd for full period cycle)
    const h2 = (digest.readUInt32LE(4) | 1) >>> 0;

    return [h1, h2];
  }
}
