import * as crypto from 'crypto';
import { ModelMetadata } from '../types';

export class ModelIntegrityVerifier {
  /**
   * Maximum permitted file size for local classifier models (50 MB)
   */
  public static readonly MAX_MODEL_SIZE_BYTES = 50 * 1024 * 1024;

  /**
   * Validates metadata structure, dimensions, types, and constraints.
   */
  public static validateMetadata(metadata: ModelMetadata): { valid: boolean; error?: string } {
    if (!metadata) {
      return { valid: false, error: 'InvalidMetadataError: metadata object is null or undefined' };
    }

    // 1. Model ID
    if (!metadata.modelId || typeof metadata.modelId !== 'string') {
      return { valid: false, error: `InvalidModelIdError: modelId is required` };
    }

    // 2. Version (semver or dotted notation like 1.0 or 0.1.0-test-fixture)
    if (!metadata.version || typeof metadata.version !== 'string' || !/^\d+(\.\d+)*(-[a-zA-Z0-9\.\-_]+)?$/.test(metadata.version)) {
      return { valid: false, error: `InvalidVersionError: '${metadata.version}' is not valid semantic versioning` };
    }

    // 3. Format
    const allowedFormats = ['ONNX', 'TFLITE', 'GGUF'];
    if (!allowedFormats.includes(metadata.format)) {
      return { valid: false, error: `UnsupportedFormatError: '${metadata.format}' is not supported` };
    }

    // 4. SHA-256
    if (!metadata.sha256 || typeof metadata.sha256 !== 'string' || metadata.sha256.length === 0) {
      return { valid: false, error: 'InvalidChecksumError: sha256 checksum is required' };
    }

    // 5. Size
    if (typeof metadata.sizeBytes !== 'number' || metadata.sizeBytes <= 0 || metadata.sizeBytes > this.MAX_MODEL_SIZE_BYTES) {
      return {
        valid: false,
        error: `InvalidSizeError: size ${metadata.sizeBytes} must be > 0 and <= ${this.MAX_MODEL_SIZE_BYTES} bytes`
      };
    }

    // 6. Input Shape
    if (metadata.inputShape && (!Array.isArray(metadata.inputShape) || metadata.inputShape.some(d => typeof d !== 'number' || d <= 0))) {
      return { valid: false, error: 'InvalidDimensionsError: inputShape must be an array of positive integers' };
    }

    // 7. Output Classes
    if (metadata.outputClasses && (!Array.isArray(metadata.outputClasses) || metadata.outputClasses.some(c => typeof c !== 'string' || c.trim().length === 0))) {
      return { valid: false, error: 'InvalidOutputClassesError: outputClasses must contain non-empty class names' };
    }

    // 8. Quantization
    const allowedQuantizations = ['INT8', 'INT4', 'FP16', 'FP32'];
    if (!allowedQuantizations.includes(metadata.quantization)) {
      return { valid: false, error: `InvalidQuantizationError: '${metadata.quantization}' is not supported` };
    }

    // 9. Task
    const allowedTasks = ['INTENT_CLASSIFICATION', 'SEMANTIC_ANALYSIS', 'EXPLANATION_SYNTHESIS'];
    if (!allowedTasks.includes(metadata.task)) {
      return { valid: false, error: `UnsupportedTaskError: '${metadata.task}' is not a recognized model task` };
    }

    return { valid: true };
  }

  /**
   * Semver comparison helper: returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 === v2.
   */
  public static compareVersions(v1: string, v2: string): number {
    const parse = (v: string) => {
      const core = v.split('-')[0];
      const parts = core.split('.').map(num => parseInt(num, 10) || 0);
      while (parts.length < 3) parts.push(0);
      return parts;
    };

    const [maj1, min1, pat1] = parse(v1);
    const [maj2, min2, pat2] = parse(v2);

    if (maj1 !== maj2) return maj1 > maj2 ? 1 : -1;
    if (min1 !== min2) return min1 > min2 ? 1 : -1;
    if (pat1 !== pat2) return pat1 > pat2 ? 1 : -1;
    return 0;
  }

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

    // 4. Validate metadata integrity
    const metaCheck = this.validateMetadata(expectedMetadata);
    if (!metaCheck.valid) {
      return metaCheck;
    }

    return { valid: true };
  }
}
