import * as crypto from 'crypto';

export function uuidv4(): string {
  return crypto.randomUUID();
}

export function isValidUUID(str: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return typeof str === 'string' && uuidRegex.test(str);
}

export function sha256(data: string | Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  
  const charCounts = new Map<string, number>();
  for (const char of str) {
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }
  
  let entropy = 0;
  const len = str.length;
  for (const count of charCounts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

export function levenshteinDistance(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(null));

  for (let i = 0; i <= a.length; i += 1) {
    matrix[0][i] = i;
  }

  for (let j = 0; j <= b.length; j += 1) {
    matrix[j][0] = j;
  }

  for (let j = 1; j <= b.length; j += 1) {
    for (let i = 1; i <= a.length; i += 1) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1, // insertion
        matrix[j - 1][i] + 1, // deletion
        matrix[j - 1][i - 1] + indicator // substitution
      );
    }
  }

  return matrix[b.length][a.length];
}

// SPKI header prefix for raw 32-byte Ed25519 public key in DER format
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Verifies an Ed25519 cryptographic signature.
 * @param data Message payload as string or buffer
 * @param signatureHex 64-byte hex signature (128 hex chars)
 * @param publicKeyHex 32-byte hex public key (64 hex chars) or SPKI DER hex
 */
export function verifyEd25519Signature(
  data: string | Uint8Array,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    if (!signatureHex || !publicKeyHex) return false;
    const cleanSig = signatureHex.trim();
    const cleanPub = publicKeyHex.trim();
    if (cleanSig.length !== 128) return false;

    const sigBuf = Buffer.from(cleanSig, 'hex');
    let pubKeyObj: crypto.KeyObject;

    if (cleanPub.length === 64) {
      // Raw 32-byte public key: construct DER SPKI
      const derBuf = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(cleanPub, 'hex')]);
      pubKeyObj = crypto.createPublicKey({ key: derBuf, format: 'der', type: 'spki' });
    } else {
      // Full DER or PEM format
      pubKeyObj = crypto.createPublicKey({
        key: Buffer.from(cleanPub, 'hex'),
        format: 'der',
        type: 'spki'
      });
    }

    const dataBuf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
    return crypto.verify(null, dataBuf, pubKeyObj, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Signs data with an Ed25519 private key (used for test fixtures & authoring).
 */
export function signEd25519(
  data: string | Uint8Array,
  privateKey: crypto.KeyObject | string
): string {
  const dataBuf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  const sig = crypto.sign(null, dataBuf, privateKey);
  return sig.toString('hex');
}

/**
 * Generates an Ed25519 keypair for cryptographic testing and verification.
 */
export function generateEd25519KeyPair(): {
  publicKeyHex: string;
  privateKey: crypto.KeyObject;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  // Raw 32-byte public key is at offset 12 in the 44-byte DER SPKI
  const rawHex = der.subarray(12).toString('hex');
  return { publicKeyHex: rawHex, privateKey };
}

export const CryptoUtils = {
  generateUUID: uuidv4,
  isValidUUID,
  sha256,
  calculateEntropy,
  shannonEntropy: calculateEntropy,
  levenshteinDistance,
  verifyEd25519Signature,
  signEd25519,
  generateEd25519KeyPair
};
