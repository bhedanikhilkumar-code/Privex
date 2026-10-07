import * as fs from 'fs';
import * as crypto from 'crypto';
import {
  verifyEd25519Signature,
  signEd25519
} from '@private-protection/core';
import {
  PpdbBundle,
  PpdbManifest,
  PpdbPayload,
  UpdateVerificationResult
} from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';

/**
 * Pinned Production Ed25519 Root Public Key (32-byte raw hex representation)
 * This cryptographic trust anchor is embedded directly into the binary distribution.
 */
export const PRODUCTION_ROOT_PUBLIC_KEY =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export interface UpdateVerifierOptions {
  readonly rootPublicKeyHex?: string;
  readonly currentVersionSequence?: number;
}

/**
 * UpdateVerifierService (Phase O — Threat Intelligence & Cryptographically Signed Updates)
 *
 * Enforces strict cryptographic integrity, authenticity, and anti-downgrade guarantees
 * for offline and OTA threat intelligence database (.ppdb) updates.
 *
 * Trust Model Invariants:
 * 1. Canonical Signed Message: `${manifest.version}:${manifest.versionSequence}:${manifest.publishedAt}:${manifest.sha256}`
 * 2. Signature Algorithm: Pure Ed25519 verification against pinned Root Public Key.
 * 3. Monotonic Anti-Downgrade: incoming.versionSequence <= currentVersionSequence is strictly REJECTED.
 * 4. Payload SHA-256 Digest Verification: exact byte matching.
 * 5. Strict Schema Validation: rejection of prototype pollution, unknown formats, and malformed fields.
 */
export class UpdateVerifierService {
  private readonly rootPublicKeyHex: string;
  private currentVersionSequence: number;

  public static readonly MAX_BUNDLE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB max
  public static readonly MAX_MANIFEST_SIZE_BYTES = 64 * 1024; // 64 KB max

  constructor(
    rootPublicKeyHex?: string,
    currentVersionSequence = 100
  ) {
    this.rootPublicKeyHex =
      rootPublicKeyHex && rootPublicKeyHex.trim().length === 64
        ? rootPublicKeyHex.trim()
        : PRODUCTION_ROOT_PUBLIC_KEY;
    this.currentVersionSequence = currentVersionSequence;
  }

  public getRootPublicKey(): string {
    return this.rootPublicKeyHex;
  }

  public getCurrentVersionSequence(): number {
    return this.currentVersionSequence;
  }

  public setCurrentVersionSequence(seq: number): void {
    if (typeof seq === 'number' && Number.isInteger(seq) && seq > 0) {
      this.currentVersionSequence = seq;
    }
  }

  /**
   * Constructs the strict, unambiguous canonical signed message string.
   * Format: `${manifest.version}:${manifest.versionSequence}:${manifest.publishedAt}:${manifest.sha256}`
   */
  public static computeCanonicalMessage(manifest: PpdbManifest): string {
    return `${manifest.version}:${manifest.versionSequence}:${manifest.publishedAt}:${manifest.sha256}`;
  }

  /**
   * Converts payload to a canonical Buffer representation for SHA-256 hashing.
   */
  public static getPayloadBuffer(payload: PpdbPayload | string | unknown): Buffer {
    if (Buffer.isBuffer(payload)) {
      return payload;
    }
    if (typeof payload === 'string') {
      return Buffer.from(payload, 'utf8');
    }
    if (typeof payload === 'object' && payload !== null) {
      return Buffer.from(JSON.stringify(payload), 'utf8');
    }
    return Buffer.alloc(0);
  }

  /**
   * Validates manifest structure and property constraints.
   */
  public static validateManifestSchema(raw: unknown): {
    valid: boolean;
    reason?: string;
    code?: string;
    manifest?: PpdbManifest;
  } {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { valid: false, code: 'SCHEMA_INVALID', reason: 'SCHEMA_INVALID: Manifest must be a non-null JSON object.' };
    }

    const obj = raw as Record<string, unknown>;

    // Prototype pollution checks
    if (
      Object.prototype.hasOwnProperty.call(obj, '__proto__') ||
      Object.prototype.hasOwnProperty.call(obj, 'constructor') ||
      Object.prototype.hasOwnProperty.call(obj, 'prototype')
    ) {
      return { valid: false, code: 'SECURITY_VIOLATION', reason: 'SECURITY_VIOLATION: Forbidden prototype properties detected.' };
    }

    // version
    if (
      typeof obj.version !== 'string' ||
      !obj.version.trim() ||
      obj.version.length > 64 ||
      !/^[a-zA-Z0-9.\-_+]+$/.test(obj.version)
    ) {
      return { valid: false, code: 'SCHEMA_INVALID', reason: 'SCHEMA_INVALID: Version must be a valid alphanumeric string (max 64 chars).' };
    }

    // versionSequence
    if (
      typeof obj.versionSequence !== 'number' ||
      !Number.isInteger(obj.versionSequence) ||
      obj.versionSequence <= 0 ||
      obj.versionSequence > 2147483647
    ) {
      return { valid: false, code: 'SCHEMA_INVALID', reason: 'SCHEMA_INVALID: versionSequence must be a positive 32-bit integer.' };
    }

    // publishedAt
    if (
      typeof obj.publishedAt !== 'number' ||
      !Number.isFinite(obj.publishedAt) ||
      obj.publishedAt <= 0
    ) {
      return { valid: false, code: 'TIMESTAMP_INVALID', reason: 'TIMESTAMP_INVALID: publishedAt must be a valid positive timestamp.' };
    }

    // Clock drift check: rejection if publishedAt > 5 minutes in future
    if (obj.publishedAt > Date.now() + 5 * 60 * 1000) {
      return { valid: false, code: 'TIMESTAMP_INVALID', reason: 'TIMESTAMP_INVALID: publishedAt cannot be in the future beyond 5 minutes.' };
    }

    // sha256
    if (
      typeof obj.sha256 !== 'string' ||
      obj.sha256.length !== 64 ||
      !/^[0-9a-fA-F]{64}$/.test(obj.sha256)
    ) {
      return { valid: false, code: 'SCHEMA_INVALID', reason: 'SCHEMA_INVALID: sha256 must be a 64-character hex digest.' };
    }

    // signature
    if (
      typeof obj.signature !== 'string' ||
      obj.signature.length !== 128 ||
      !/^[0-9a-fA-F]{128}$/.test(obj.signature)
    ) {
      return { valid: false, code: 'SCHEMA_INVALID', reason: 'SCHEMA_INVALID: signature must be a 128-character Ed25519 hex string.' };
    }

    const manifest: PpdbManifest = {
      version: obj.version.trim(),
      versionSequence: obj.versionSequence,
      publishedAt: obj.publishedAt,
      sha256: obj.sha256.toLowerCase(),
      signature: obj.signature.toLowerCase()
    };

    return { valid: true, code: 'UPDATE_OK', manifest };
  }

  /**
   * Verifies payload digest against manifest SHA-256.
   */
  public static verifyPayloadHash(
    payloadData: Buffer | string | object,
    expectedSha256: string
  ): { valid: boolean; computedHash: string } {
    const buf = UpdateVerifierService.getPayloadBuffer(payloadData);
    const computedHash = crypto.createHash('sha256').update(buf).digest('hex').toLowerCase();
    const cleanExpected = expectedSha256.toLowerCase().trim();
    return {
      valid: computedHash === cleanExpected,
      computedHash
    };
  }

  /**
   * Verifies Ed25519 signature of canonical message.
   */
  public verifySignature(
    canonicalMessage: string,
    signatureHex: string,
    publicKeyHex?: string
  ): boolean {
    const key = (publicKeyHex || this.rootPublicKeyHex).trim();
    if (!key || key.length !== 64) return false;
    return verifyEd25519Signature(canonicalMessage, signatureHex, key);
  }

  /**
   * Complete verification of a manifest and payload buffer.
   */
  public verifyUpdateManifest(
    manifest: PpdbManifest | unknown,
    payloadBytesOrObj: Buffer | string | object,
    options?: { currentSequence?: number } | number
  ): { valid: boolean; code?: string; reason?: string; manifest?: PpdbManifest } {
    // 1. Schema Validation
    const schemaRes = UpdateVerifierService.validateManifestSchema(manifest);
    if (!schemaRes.valid || !schemaRes.manifest) {
      return { valid: false, code: schemaRes.code || 'SCHEMA_INVALID', reason: schemaRes.reason };
    }
    const validatedManifest = schemaRes.manifest;

    // 2. Anti-Downgrade Monotonic Version Verification
    const currentSeq = typeof options === 'number'
      ? options
      : (options?.currentSequence ?? this.currentVersionSequence);

    if (validatedManifest.versionSequence <= currentSeq) {
      return {
        valid: false,
        code: 'ANTI_DOWNGRADE_REJECT',
        reason: `ANTI_DOWNGRADE_REJECT: Update sequence (${validatedManifest.versionSequence}) must be strictly greater than current (${currentSeq})`,
        manifest: validatedManifest
      };
    }

    // 3. Hash Integrity Verification
    const hashRes = UpdateVerifierService.verifyPayloadHash(
      payloadBytesOrObj,
      validatedManifest.sha256
    );
    if (!hashRes.valid) {
      return {
        valid: false,
        code: 'HASH_MISMATCH',
        reason: `HASH_MISMATCH: Calculated payload SHA-256 does not match manifest (${hashRes.computedHash} != ${validatedManifest.sha256})`,
        manifest: validatedManifest
      };
    }

    // 4. Canonical Signed Message Construction & Ed25519 Verification
    const canonicalMessage = UpdateVerifierService.computeCanonicalMessage(validatedManifest);
    const isSigValid = this.verifySignature(canonicalMessage, validatedManifest.signature);

    if (!isSigValid) {
      return {
        valid: false,
        code: 'SIGNATURE_INVALID',
        reason: 'SIGNATURE_INVALID: Cryptographic signature check failed — invalid Ed25519 signature',
        manifest: validatedManifest
      };
    }

    return { valid: true, code: 'UPDATE_OK', manifest: validatedManifest };
  }

  /**
   * Parses and completely verifies an offline .ppdb bundle from file path or in-memory object.
   */
  public verifyBundle(
    bundleOrPath: unknown,
    options?: { currentSequence?: number } | number
  ): UpdateVerificationResult & { bundle?: PpdbBundle } {
    let bundle: PpdbBundle;

    if (typeof bundleOrPath === 'string') {
      try {
        const validatedPath = IpcValidator.validatePath(bundleOrPath);
        if (!fs.existsSync(validatedPath)) {
          return { valid: false, code: 'FILE_NOT_FOUND', reason: `FILE_NOT_FOUND: Update bundle does not exist at ${validatedPath}` };
        }

        const stat = fs.statSync(validatedPath);
        if (stat.size > UpdateVerifierService.MAX_BUNDLE_SIZE_BYTES) {
          return {
            valid: false,
            code: 'BUNDLE_TOO_LARGE',
            reason: `BUNDLE_TOO_LARGE: Bundle file size ${stat.size} exceeds maximum limit (${UpdateVerifierService.MAX_BUNDLE_SIZE_BYTES} bytes)`
          };
        }

        const rawContent = fs.readFileSync(validatedPath, 'utf8');
        bundle = JSON.parse(rawContent);
      } catch (err: any) {
        return { valid: false, code: 'BUNDLE_READ_ERROR', reason: `BUNDLE_READ_ERROR: ${err.message || 'Failed to read update bundle file'}` };
      }
    } else if (typeof bundleOrPath === 'object' && bundleOrPath !== null) {
      bundle = bundleOrPath as PpdbBundle;
    } else {
      return { valid: false, code: 'INVALID_INPUT', reason: 'INVALID_INPUT: Bundle must be a valid file path string or object.' };
    }

    if (!bundle || typeof bundle !== 'object' || bundle.format !== 'PPDB1') {
      return { valid: false, code: 'FORMAT_INVALID', reason: 'FORMAT_INVALID: Update bundle must declare format "PPDB1".' };
    }

    if (!bundle.manifest || !bundle.payload) {
      return { valid: false, code: 'STRUCTURE_INVALID', reason: 'STRUCTURE_INVALID: Bundle must contain manifest and payload.' };
    }

    const manifestRes = this.verifyUpdateManifest(bundle.manifest, bundle.payload, options);
    if (!manifestRes.valid) {
      return {
        valid: false,
        code: manifestRes.code,
        reason: manifestRes.reason,
        manifest: manifestRes.manifest,
        payload: bundle.payload
      };
    }

    return {
      valid: true,
      code: 'UPDATE_OK',
      manifest: manifestRes.manifest,
      payload: bundle.payload,
      bundle
    };
  }

  /**
   * Helper to verify a bundle directly from disk file path.
   */
  public verifyBundleFile(
    filePath: string,
    options?: { currentSequence?: number } | number
  ): UpdateVerificationResult & { bundle?: PpdbBundle } {
    return this.verifyBundle(filePath, options);
  }

  /**
   * Factory function for building and signing authentic .ppdb bundles.
   * Supports both object options and positional arguments.
   */
  public static createSignedBundle(
    paramOrVersion: {
      version: string;
      versionSequence: number;
      publishedAt?: number;
      payload: PpdbPayload | string | any;
      privateKey: crypto.KeyObject | string;
    } | string,
    versionSequence?: number,
    publishedAt?: number,
    payload?: PpdbPayload | string | any,
    privateKey?: crypto.KeyObject | string,
    _publicKeyHex?: string
  ): PpdbBundle {
    let version: string;
    let seq: number;
    let pubAt: number;
    let pld: any;
    let privKey: crypto.KeyObject | string;

    if (typeof paramOrVersion === 'object' && paramOrVersion !== null) {
      version = paramOrVersion.version;
      seq = paramOrVersion.versionSequence;
      pubAt = paramOrVersion.publishedAt ?? Date.now();
      pld = paramOrVersion.payload;
      privKey = paramOrVersion.privateKey;
    } else {
      version = paramOrVersion;
      seq = versionSequence!;
      pubAt = publishedAt ?? Date.now();
      pld = payload!;
      privKey = privateKey!;
    }

    const payloadBuf = UpdateVerifierService.getPayloadBuffer(pld);
    const sha256 = crypto.createHash('sha256').update(payloadBuf).digest('hex');

    const rawManifest: PpdbManifest = {
      version,
      versionSequence: seq,
      publishedAt: pubAt,
      sha256,
      signature: ''
    };

    const canonicalMessage = UpdateVerifierService.computeCanonicalMessage(rawManifest);
    const signature = signEd25519(canonicalMessage, privKey);

    const manifest: PpdbManifest = {
      ...rawManifest,
      signature
    };

    return {
      format: 'PPDB1',
      manifest,
      payload: pld,
      signature
    };
  }
}
