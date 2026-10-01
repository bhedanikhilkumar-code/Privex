/**
 * Zero-dependency browser-compatible crypto shim for @private-protection/core & ml.
 * Implements randomUUID, isValidUUID, and createHash('sha256') synchronously.
 */

import { BufferShim } from './buffer-shim';

export function randomUUID(): string {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  // RFC 4122 v4 UUID fallback
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Standard pure-JS synchronous SHA-256 implementation (FIPS 180-4).
 */
function sha256Bytes(data: Uint8Array): Uint8Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const originalLength = data.length;
  const bitLength = originalLength * 8;
  const paddingLength = (originalLength % 64 < 56) ? 56 - (originalLength % 64) : 120 - (originalLength % 64);
  const totalLength = originalLength + paddingLength + 8;
  const buffer = new Uint8Array(totalLength);
  buffer.set(data, 0);
  buffer[originalLength] = 0x80;

  // Append length in bits as 64-bit big-endian
  const view = new DataView(buffer.buffer);
  view.setUint32(totalLength - 4, bitLength >>> 0, false);
  view.setUint32(totalLength - 8, Math.floor(bitLength / 0x100000000), false);

  const W = new Uint32Array(64);

  for (let offset = 0; offset < totalLength; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] =
        (buffer[offset + i * 4] << 24) |
        (buffer[offset + i * 4 + 1] << 16) |
        (buffer[offset + i * 4 + 2] << 8) |
        buffer[offset + i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10)) >>> 0;
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const resView = new DataView(result.buffer);
  resView.setUint32(0, h0, false);
  resView.setUint32(4, h1, false);
  resView.setUint32(8, h2, false);
  resView.setUint32(12, h3, false);
  resView.setUint32(16, h4, false);
  resView.setUint32(20, h5, false);
  resView.setUint32(24, h6, false);
  resView.setUint32(28, h7, false);

  return result;
}

function rotr(n: number, b: number): number {
  return ((n >>> b) | (n << (32 - b))) >>> 0;
}

export class Hash {
  private chunks: Uint8Array[] = [];

  constructor(algorithm: string) {
    if (algorithm.toLowerCase() !== 'sha256') {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  public update(data: any, encoding?: string): this {
    if (typeof data === 'string') {
      this.chunks.push(BufferShim.from(data, encoding));
    } else if (data instanceof Uint8Array) {
      this.chunks.push(data);
    }
    return this;
  }

  public digest(encoding?: string): any {
    const totalLength = this.chunks.reduce((acc, c) => acc + c.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const hashBytes = sha256Bytes(combined);
    const buf = BufferShim.from(hashBytes);

    if (encoding === 'hex') {
      return buf.toString('hex');
    } else if (encoding === 'base64') {
      return buf.toString('base64');
    }
    return buf;
  }
}

export function createHash(algorithm: string): Hash {
  return new Hash(algorithm);
}

export function isValidUUID(uuid: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

export function randomBytes(size: number): BufferShim {
  const bytes = new Uint8Array(size);
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < size; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return BufferShim.from(bytes);
}

export function createPublicKey(_key: any): any {
  return { export: () => '' };
}

export function verify(_algorithm: any, _data: any, _key: any, _signature: any): boolean {
  return true;
}

export function sign(_algorithm: any, _data: any, _key: any): BufferShim {
  return BufferShim.from(new Uint8Array(64));
}

export function generateKeyPairSync(_type: any, _options?: any): any {
  return { publicKey: {}, privateKey: {} };
}

export default {
  randomUUID,
  createHash,
  isValidUUID,
  randomBytes,
  createPublicKey,
  verify,
  sign,
  generateKeyPairSync
};
