import { describe, it, expect } from 'vitest';
import { OnnxModelProvider } from '../../models/providers/onnx-provider';
import { ModelMetadata } from '../../types';

describe('OnnxModelProvider Abstraction', () => {
  const metadata: ModelMetadata = {
    modelId: 'test-onnx-intent-v1',
    version: '1.0.0',
    format: 'ONNX',
    task: 'INTENT_CLASSIFICATION',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sizeBytes: 1024,
    inputShape: [1, 4],
    outputClasses: ['BENIGN', 'SCAM', 'PHISHING'],
    quantization: 'INT8',
    isProductionArtifact: true,
    providerName: 'OnnxModelProvider'
  };

  it('should initialize with correct metadata and provider ID', () => {
    const provider = new OnnxModelProvider(metadata);
    expect(provider.id).toBe('test-onnx-intent-v1');
    expect(provider.isLoaded()).toBe(false);
    expect(provider.metadata.format).toBe('ONNX');
  });

  it('should return false from load when no buffer is provided', async () => {
    const provider = new OnnxModelProvider(metadata);
    const loaded = await provider.load();
    expect(loaded).toBe(false);
    expect(provider.isLoaded()).toBe(false);
  });

  it('should attempt dynamic load with buffer and handle missing runtime safely', async () => {
    const provider = new OnnxModelProvider(metadata, Buffer.from('FAKE_ONNX_BYTES'));
    const loaded = await provider.load();
    // onnxruntime-node is not installed in root, should gracefully return false
    expect(loaded).toBe(false);
    expect(provider.isLoaded()).toBe(false);

    // If loaded is already true, calling load() again should short-circuit to true
    (provider as any).loaded = true;
    const reloaded = await provider.load();
    expect(reloaded).toBe(true);
  });

  it('should return safe FALLBACK result when infer is called while unloaded', async () => {
    const provider = new OnnxModelProvider(metadata);
    const result = await provider.infer({
      requestId: 'req-unloaded-1',
      task: 'INTENT_CLASSIFICATION',
      input: [1, 2, 3, 4]
    });

    expect(result.status).toBe('FALLBACK');
    expect(result.topLabel).toBe('UNLOADED');
    expect(result.confidence).toBe(0.0);
    expect(result.uncertainty).toBe(1.0);
    expect(result.error).toContain('ModelNotLoadedError');
  });

  it('should validate input tensor shape against expected metadata', async () => {
    const provider = new OnnxModelProvider(metadata, Buffer.from('FAKE_ONNX_BYTES'));
    (provider as any).loaded = true;
    (provider as any).session = {};

    const invalidInputResult = await provider.infer({
      requestId: 'req-invalid-shape',
      task: 'INTENT_CLASSIFICATION',
      input: [1, 2] // 2 elements instead of expected 4 (1 * 4)
    });

    expect(invalidInputResult.status).toBe('ERROR');
    expect(invalidInputResult.error).toContain('TensorShapeMismatchError');
  });

  it('should execute inference successfully when session returns output tensors', async () => {
    const provider = new OnnxModelProvider(metadata, Buffer.from('FAKE_ONNX_BYTES'));
    (provider as any).loaded = true;
    (provider as any).session = {
      run: async () => ({
        BENIGN: { data: [0.10] },
        SCAM: { data: [0.20] },
        PHISHING: { data: [0.70] }
      })
    };

    const result = await provider.infer({
      requestId: 'req-success-1',
      task: 'INTENT_CLASSIFICATION',
      input: [0.1, 0.2, 0.3, 0.4]
    });

    expect(result.status).toBe('SUCCESS');
    expect(result.topLabel).toBe('PHISHING');
    expect(result.topScore).toBe(0.70);
    expect(result.confidence).toBe(0.70);
    expect(result.uncertainty).toBe(0.30);
    expect(result.predictions.PHISHING).toBe(0.70);
  });

  it('should catch runtime execution exceptions and return status ERROR', async () => {
    const provider = new OnnxModelProvider(metadata, Buffer.from('FAKE_ONNX_BYTES'));
    (provider as any).loaded = true;
    (provider as any).session = {
      run: async () => {
        throw new Error('OnnxGpuMemoryExhaustion');
      }
    };

    const result = await provider.infer({
      requestId: 'req-err-1',
      task: 'INTENT_CLASSIFICATION',
      input: [0.1, 0.2, 0.3, 0.4]
    });

    expect(result.status).toBe('ERROR');
    expect(result.error).toContain('OnnxInferenceExecutionError');
  });

  it('should cleanly unload and clear session references', async () => {
    const provider = new OnnxModelProvider(metadata, Buffer.from('FAKE_ONNX_BYTES'));
    (provider as any).loaded = true;
    (provider as any).session = { run: async () => ({}) };

    await provider.unload();
    expect(provider.isLoaded()).toBe(false);
    expect((provider as any).session).toBeNull();
  });
});
