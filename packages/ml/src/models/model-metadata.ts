import * as crypto from 'crypto';
import { ModelMetadata } from '../types';

export class ModelIntegrityVerifier {
  /**
   * Maximum permitted file size for local classifier models (50 MB)
   */
  public static readonly MAX_MODEL_SIZE_BYTES = 50 * 1024 * 1024;

  /**
   * Validates model binary buffer against its cryptographic metadata.
   */
  public static verifyModelBuffer(
    buffer: Uint8Array | Buffer,
    expectedMetadata: ModelMetadata
  ): { valid: boolean; error?: string } {
    if (!buffer || buffer.length === 0) {
      return { valid: false, error: 'EmptyModelBufferError: model payload contains 0 bytes' };
    }

    // 1. Size constraint enforcement
    if (buffer.length > this.MAX_MODEL_SIZE_BYTES) {
      return {
        valid: false,
        error: `ModelSizeExceededError: buffer length ${buffer.length} exceeds maximum allowed size of ${this.MAX_MODEL_SIZE_BYTES} bytes`
      };
    }

    if (expectedMetadata.sizeBytes > 0 && buffer.length !== expectedMetadata.sizeBytes) {
      return {
        valid: false,
        error: `ModelSizeMismatchError: buffer length ${buffer.length} does not match metadata expected size ${expectedMetadata.sizeBytes}`
      };
    }

    // 2. Cryptographic SHA-256 digest validation
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    if (hash.toLowerCase() !== expectedMetadata.sha256.toLowerCase()) {
      return {
        valid: false,
        error: `ModelChecksumMismatchError: computed sha256 ${hash} != expected ${expectedMetadata.sha256}`
      };
    }

    // 3. Format & Magic Byte Verification
    if (expectedMetadata.format === 'ONNX') {
      // ONNX files use protobuf encoding.
      // Must not be empty and must start with valid protobuf field or header structure
      if (buffer.length < 8) {
        return { valid: false, error: 'CorruptedModelError: truncated ONNX file header' };
      }
    } else if (expectedMetadata.format === 'TFLITE') {
      // TFLite flatbuffer magic bytes: at offset 4: 'TFL3'
      if (buffer.length < 8) {
        return { valid: false, error: 'CorruptedModelError: truncated TFLite file header' };
      }
      const magic = Buffer.from(buffer.subarray(4, 8)).toString('ascii');
      if (magic !== 'TFL3') {
        return { valid: false, error: `InvalidFormatError: expected TFLite magic 'TFL3', received '${magic}'` };
      }
    }

    return { valid: true };
  }
}
