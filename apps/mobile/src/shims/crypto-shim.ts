import { BufferShim } from './buffer-shim';

export function randomUUID(): string {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
const SHA256_W = new Uint32Array(64);

function sha256Sync(data: Uint8Array): Uint8Array {
  const K = SHA256_K;

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const l = data.length;
  const bitLen = l * 8;
  const padLen = (l % 64 < 56) ? (56 - (l % 64)) : (120 - (l % 64));
  const totalLen = l + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(data);
  padded[l] = 0x80;

  const view = new DataView(padded.buffer);
  view.setBigUint64(totalLen - 8, BigInt(bitLen), false);

  const W = SHA256_W;

  for (let i = 0; i < totalLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0;
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];
    let f = H[5];
    let g = H[6];
    let h = H[7];

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
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

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 4, H[i], false);
  }
  return out;
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
    let totalLen = 0;
    for (const chunk of this.chunks) totalLen += chunk.length;
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of this.chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const hashBytes = sha256Sync(combined);
    const buf = BufferShim.from(hashBytes);
    return encoding ? buf.toString(encoding) : buf;
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
