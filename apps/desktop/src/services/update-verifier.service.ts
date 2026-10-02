import * as crypto from 'crypto';
import { verifyEd25519Signature } from '@private-protection/core';

export interface UpdatePackageManifest {
  version: string;
  versionSequence: number;
  publishedAt: number;
  sha256: string;
  signature: string; // Ed25519 signature in hex
}

export class UpdateVerifierService {
  // Public Root Key embedded into the binary for Ed25519 signature verification
  private rootPublicKeyHex: string;
  private currentVersionSequence: number;

  constructor(
    rootPublicKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    currentVersionSequence = 100
  ) {
    this.rootPublicKeyHex = rootPublicKeyHex;
    this.currentVersionSequence = currentVersionSequence;
  }

  /**
   * Verifies an inbound update manifest against integrity, authenticity, and anti-downgrade policies.
   */
  public verifyUpdateManifest(
    manifest: UpdatePackageManifest,
    payloadBytes: Buffer
  ): { valid: boolean; reason?: string } {
    // 1. Anti-Downgrade Monotonic Version Verification
    if (manifest.versionSequence <= this.currentVersionSequence) {
      return {
        valid: false,
        reason: `ANTI_DOWNGRADE_REJECT: Update sequence ${manifest.versionSequence} <= current ${this.currentVersionSequence}`
      };
    }

    // 2. Hash Integrity Verification
    const computedHash = crypto.createHash('sha256').update(payloadBytes).digest('hex');
    if (computedHash.toLowerCase() !== manifest.sha256.toLowerCase()) {
      return {
        valid: false,
        reason: `HASH_MISMATCH: Computed payload hash ${computedHash} != manifest ${manifest.sha256}`
      };
    }

    // 3. Ed25519 Signature Verification
    if (!this.rootPublicKeyHex || !manifest.signature) {
      return {
        valid: false,
        reason: 'SIGNATURE_INVALID: Update package signature or public key is missing'
      };
    }

    const isVerified = verifyEd25519Signature(
      manifest.sha256,
      manifest.signature,
      this.rootPublicKeyHex
    );

    if (!isVerified) {
      return {
        valid: false,
        reason: 'SIGNATURE_INVALID: Cryptographic Ed25519 signature verification failed'
      };
    }

    return { valid: true };
  }
}
