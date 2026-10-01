import { describe, it, expect, beforeEach } from 'vitest';
import * as crypto from 'crypto';
import { ModelLoader } from '../../models/model-loader';
import { ModelIntegrityVerifier } from '../../models/model-metadata';
import { DevelopmentMockModelProvider } from '../../models/providers/mock-provider';
import { ModelMetadata, ModelProvider } from '../../types';

describe('ModelLoader & Model Security Verification', () => {
  let loader: ModelLoader;

  beforeEach(() => {
    loader = new ModelLoader();
  });

  it('should register and activate mock provider safely', async () => {
    const mockProvider = new DevelopmentMockModelProvider();
    loader.registerProvider(mockProvider);

    expect(loader.isLoaded(mockProvider.id)).toBe(false);

    const activation = await loader.activateProvider(mockProvider.id);
    expect(activation.success).toBe(true);
    expect(loader.isLoaded(mockProvider.id)).toBe(true);
    expect(loader.getLoadedModelCount()).toBe(1);

    await loader.unloadProvider(mockProvider.id);
    expect(loader.isLoaded(mockProvider.id)).toBe(false);
  });

  it('should verify valid model buffer with exact SHA-256 and size matching', () => {
    const fakeBuffer = Buffer.from('ONNX_MODEL_HEADER_PROTOBUF_DATA_FOR_TESTING');
    const sha256 = crypto.createHash('sha256').update(fakeBuffer).digest('hex');

    const metadata: ModelMetadata = {
      modelId: 'test-onnx-v1',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: fakeBuffer.length,
      inputShape: [1, 128],
      outputClasses: ['A', 'B'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(fakeBuffer, metadata);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should reject empty or null buffer', () => {
    const metadata: ModelMetadata = {
      modelId: 'test-empty',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256: 'somehash',
      sizeBytes: 100,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const emptyResult = ModelIntegrityVerifier.verifyModelBuffer(Buffer.alloc(0), metadata);
    expect(emptyResult.valid).toBe(false);
    expect(emptyResult.error).toContain('EmptyModelBufferError');
  });

  it('should strictly reject model buffer when SHA-256 digest is corrupted or tampered', () => {
    const fakeBuffer = Buffer.from('VALID_ORIGINAL_MODEL_DATA');
    const tamperedBuffer = Buffer.from('TAMPERED_MALICIOUS_MODEL_DATA');
    const originalSha256 = crypto.createHash('sha256').update(fakeBuffer).digest('hex');

    const metadata: ModelMetadata = {
      modelId: 'test-onnx-v1',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256: originalSha256,
      sizeBytes: tamperedBuffer.length,
      inputShape: [1, 128],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(tamperedBuffer, metadata);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('ModelChecksumMismatchError');
  });

  it('should reject model buffer when size differs from expected metadata', () => {
    const fakeBuffer = Buffer.from('DATA_BUFFER');
    const sha256 = crypto.createHash('sha256').update(fakeBuffer).digest('hex');

    const metadata: ModelMetadata = {
      modelId: 'test-size-mismatch',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: fakeBuffer.length + 10,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(fakeBuffer, metadata);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('ModelSizeMismatchError');
  });

  it('should reject models exceeding maximum size allocation limit (50 MB)', () => {
    const hugeBuffer = new Uint8Array(51 * 1024 * 1024); // 51 MB
    const metadata: ModelMetadata = {
      modelId: 'huge-model',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256: 'somehash',
      sizeBytes: hugeBuffer.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(hugeBuffer, metadata);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('ModelSizeExceededError');
  });

  it('should reject truncated ONNX buffers (< 8 bytes)', () => {
    const tinyBuffer = Buffer.from('123');
    const sha256 = crypto.createHash('sha256').update(tinyBuffer).digest('hex');
    const metadata: ModelMetadata = {
      modelId: 'tiny-onnx',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: tinyBuffer.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(tinyBuffer, metadata);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('CorruptedModelError');
  });

  it('should reject corrupted or truncated TFLite buffers', () => {
    const tinyBuffer = Buffer.from('123');
    const sha256Tiny = crypto.createHash('sha256').update(tinyBuffer).digest('hex');
    const metaTiny: ModelMetadata = {
      modelId: 'tiny-tflite',
      version: '1.0.0',
      format: 'TFLITE',
      task: 'INTENT_CLASSIFICATION',
      sha256: sha256Tiny,
      sizeBytes: tinyBuffer.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const resTiny = ModelIntegrityVerifier.verifyModelBuffer(tinyBuffer, metaTiny);
    expect(resTiny.valid).toBe(false);
    expect(resTiny.error).toContain('CorruptedModelError');

    const corruptedTfliteBuffer = Buffer.from('XXXXCORRUPTED_TFLITE_BUFFER');
    const sha256 = crypto.createHash('sha256').update(corruptedTfliteBuffer).digest('hex');

    const metadata: ModelMetadata = {
      modelId: 'test-tflite-v1',
      version: '1.0.0',
      format: 'TFLITE',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: corruptedTfliteBuffer.length,
      inputShape: [1, 64],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const result = ModelIntegrityVerifier.verifyModelBuffer(corruptedTfliteBuffer, metadata);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('InvalidFormatError');
  });

  it('should load model from buffer through cryptographic verification pipeline', async () => {
    const fakeBuffer = Buffer.from('VALID_SECURE_BUFFER_DATA');
    const sha256 = crypto.createHash('sha256').update(fakeBuffer).digest('hex');

    const metadata: ModelMetadata = {
      modelId: 'pipeline-model-v1',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: fakeBuffer.length,
      inputShape: [1, 10],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const loadRes = await loader.loadModelFromBuffer(fakeBuffer, metadata, (meta) => {
      return new DevelopmentMockModelProvider({ simulatedLatencyMs: 0 });
    });

    expect(loadRes.success).toBe(true);
    expect(loadRes.provider).toBeDefined();
    expect(loader.isLoaded(loadRes.provider!.id)).toBe(true);
  });

  it('should handle buffer load verification failure gracefully', async () => {
    const badBuffer = Buffer.from('BAD_BUFFER');
    const metadata: ModelMetadata = {
      modelId: 'bad-meta',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256: 'wrong-hash',
      sizeBytes: badBuffer.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const res = await loader.loadModelFromBuffer(badBuffer, metadata, () => ({} as any));
    expect(res.success).toBe(false);
    expect(res.error).toContain('ModelChecksumMismatchError');
  });

  it('should handle provider initialization failure in loadModelFromBuffer', async () => {
    const buf = Buffer.from('VALID_PAYLOAD_TEST');
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const metadata: ModelMetadata = {
      modelId: 'init-fail-meta',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: buf.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const res = await loader.loadModelFromBuffer(buf, metadata, () => {
      return new DevelopmentMockModelProvider({ failLoad: true });
    });

    expect(res.success).toBe(false);
    expect(res.error).toContain('ModelInitializationFailedError');
  });

  it('should handle exception thrown by providerFactory in loadModelFromBuffer', async () => {
    const buf = Buffer.from('VALID_PAYLOAD_TEST_THROW');
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const metadata: ModelMetadata = {
      modelId: 'throw-meta',
      version: '1.0.0',
      format: 'ONNX',
      task: 'INTENT_CLASSIFICATION',
      sha256,
      sizeBytes: buf.length,
      inputShape: [1],
      outputClasses: ['A'],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const res = await loader.loadModelFromBuffer(buf, metadata, () => {
      throw new Error('FactoryExplosionError');
    });

    expect(res.success).toBe(false);
    expect(res.error).toContain('ModelLoadException');
  });

  it('should return error when attempting to activate unregistered provider', async () => {
    const res = await loader.activateProvider('non-existent-provider-id');
    expect(res.success).toBe(false);
    expect(res.error).toContain('ProviderNotFoundError');
  });

  it('should handle activation failure or exception in activateProvider', async () => {
    const failingProvider: ModelProvider = {
      id: 'failing-activate-provider',
      metadata: {
        modelId: 'fail',
        version: '1.0',
        format: 'ONNX',
        task: 'INTENT_CLASSIFICATION',
        sha256: 'h',
        sizeBytes: 1,
        inputShape: [],
        outputClasses: [],
        quantization: 'INT8',
        isProductionArtifact: false
      },
      load: async () => false,
      unload: async () => {},
      isLoaded: () => false,
      infer: async () => ({} as any)
    };

    loader.registerProvider(failingProvider);
    const failRes = await loader.activateProvider('failing-activate-provider');
    expect(failRes.success).toBe(false);
    expect(failRes.error).toBe('InitializationFailed');

    const throwProvider: ModelProvider = {
      ...failingProvider,
      id: 'throw-activate-provider',
      load: async () => {
        throw new Error('ExplosionOnLoad');
      }
    };
    loader.registerProvider(throwProvider);
    const throwRes = await loader.activateProvider('throw-activate-provider');
    expect(throwRes.success).toBe(false);
    expect(throwRes.error).toContain('ExplosionOnLoad');
  });
});
