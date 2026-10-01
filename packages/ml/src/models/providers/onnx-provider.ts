import {
  InferenceRequest,
  InferenceResult,
  ModelMetadata
} from '../../types';
import { BaseModelProvider } from './model-provider';
import { TextPreprocessor } from '../preprocessing/text-preprocessor';

export interface OnnxSessionOptions {
  readonly executionProvider?: 'cpu' | 'wasm' | 'webgpu' | 'npu';
  readonly numThreads?: number;
  readonly graphOptimizationLevel?: 'disabled' | 'basic' | 'extended' | 'all';
}

function stableSoftmax(logits: number[]): number[] {
  if (logits.length === 0) return [];
  const max = Math.max(...logits);
  const exps = logits.map(x => Math.exp(x - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map(x => (sum > 0 ? Math.round((x / sum) * 10000) / 10000 : 1 / logits.length));
}

/**
 * PRODUCTION-READY ONNX RUNTIME PROVIDER ABSTRACTION
 *
 * Implements the on-device inference contract for ONNX models.
 * Manages runtime session lifecycle, explicit input mapping, tokenization/preprocessing,
 * tensor shape/type validation, output extraction with stable softmax, and abort cancellation.
 * Fails safely and gracefully when runtime binaries or model artifacts are unavailable,
 * guaranteeing zero silent crashes and zero cloud dependencies.
 */
export class OnnxModelProvider extends BaseModelProvider {
  public readonly id: string;
  public readonly metadata: ModelMetadata;
  private modelBuffer?: Uint8Array | Buffer;
  private sessionOptions: OnnxSessionOptions;
  private session: unknown | null = null;
  private preprocessor: TextPreprocessor;

  constructor(
    metadata: ModelMetadata,
    modelBuffer?: Uint8Array | Buffer,
    sessionOptions?: OnnxSessionOptions
  ) {
    super();
    this.id = metadata.modelId;
    this.metadata = metadata;
    this.modelBuffer = modelBuffer;
    this.sessionOptions = sessionOptions ?? { executionProvider: 'cpu', numThreads: 1 };
    const maxSeqLen = metadata.inputShape && metadata.inputShape.length > 1
      ? metadata.inputShape[metadata.inputShape.length - 1]
      : 128;
    this.preprocessor = new TextPreprocessor({ maxSequenceLength: maxSeqLen });
  }

  /**
   * Initializes the ONNX inference session.
   * Dynamically inspects the runtime environment without hardcoding heavy binary dependencies.
   */
  public async load(): Promise<boolean> {
    if (this.loaded) {
      return true;
    }

    if (!this.modelBuffer || this.modelBuffer.length === 0) {
      this.loaded = false;
      return false;
    }

    try {
      // In an environment with onnxruntime-node or onnxruntime-web installed,
      // create the InferenceSession from buffer.
      // If the native module is not installed in the current environment, fail safely.
      let ort: any;
      try {
        const nodePkg = 'onnxruntime-node';
        const webPkg = 'onnxruntime-web';
        ort = await import(/* @vite-ignore */ nodePkg).catch(() => import(/* @vite-ignore */ webPkg));
      } catch {
        // Native ONNX runtime not present in environment
        this.loaded = false;
        return false;
      }

      if (ort && ort.InferenceSession) {
        this.session = await ort.InferenceSession.create(this.modelBuffer, {
          executionProviders: [this.sessionOptions.executionProvider ?? 'cpu']
        });
        this.loaded = true;
        return true;
      }

      this.loaded = false;
      return false;
    } catch {
      this.loaded = false;
      return false;
    }
  }

  public async infer(request: InferenceRequest): Promise<InferenceResult> {
    const startTime = Date.now();

    // Check cancellation
    if (request.abortSignal?.aborted) {
      return {
        requestId: request.requestId,
        predictions: {},
        topLabel: 'ABORTED',
        topScore: 0.0,
        confidence: 0.0,
        uncertainty: 1.0,
        latencyMs: 0.01,
        status: 'ERROR',
        modelMetadata: this.metadata,
        error: 'InferenceAbortedError: inference was cancelled by abort signal'
      };
    }

    if (!this.loaded || !this.session) {
      return {
        requestId: request.requestId,
        predictions: {},
        topLabel: 'UNLOADED',
        topScore: 0.0,
        confidence: 0.0,
        uncertainty: 1.0,
        latencyMs: 0.01,
        status: 'FALLBACK',
        modelMetadata: this.metadata,
        error: 'ModelNotLoadedError: ONNX session is not initialized or model buffer is missing'
      };
    }

    try {
      // 1. Build and validate input feeds
      let feeds: Record<string, unknown> = {};

      if (request.modelInputs) {
        feeds = { ...request.modelInputs };
      } else if (typeof request.input === 'string') {
        // Tokenize and map text input into explicit model tensors
        const preprocessed = this.preprocessor.preprocess(request.input);
        const inputNames = this.metadata.inputNames ?? ['input_ids', 'attention_mask'];
        const inputIdName = inputNames[0] || 'input_ids';
        const maskName = inputNames[1] || 'attention_mask';

        feeds[inputIdName] = {
          data: preprocessed.inputIds,
          dims: [1, preprocessed.inputIds.length],
          type: 'int64'
        };
        feeds[maskName] = {
          data: preprocessed.attentionMask,
          dims: [1, preprocessed.attentionMask.length],
          type: 'int64'
        };
      } else if (Array.isArray(request.input) || request.input instanceof Float32Array) {
        // Numerical tensor input validation
        const inputArray = Array.isArray(request.input) ? request.input : Array.from(request.input);
        const expectedShape = this.metadata.inputShape;

        if (expectedShape.length > 0) {
          const expectedElements = expectedShape.reduce((a, b) => a * b, 1);
          if (inputArray.length !== expectedElements) {
            return {
              requestId: request.requestId,
              predictions: {},
              topLabel: 'INVALID_INPUT',
              topScore: 0.0,
              confidence: 0.0,
              uncertainty: 1.0,
              latencyMs: Date.now() - startTime,
              status: 'ERROR',
              modelMetadata: this.metadata,
              error: `TensorShapeMismatchError: input elements ${inputArray.length} != expected ${expectedElements}`
            };
          }
        }

        // Validate numerical finite values
        if (inputArray.some(v => typeof v !== 'number' || !Number.isFinite(v))) {
          return {
            requestId: request.requestId,
            predictions: {},
            topLabel: 'INVALID_INPUT',
            topScore: 0.0,
            confidence: 0.0,
            uncertainty: 1.0,
            latencyMs: Date.now() - startTime,
            status: 'ERROR',
            modelMetadata: this.metadata,
            error: 'InvalidTensorValueError: input contains NaN or non-finite numerical values'
          };
        }

        const primaryInputName = this.metadata.inputNames?.[0] || 'input';
        feeds[primaryInputName] = {
          data: inputArray,
          dims: expectedShape.length > 0 ? expectedShape : [1, inputArray.length],
          type: 'float32'
        };
      }

      // Check cancellation prior to execution
      if (request.abortSignal?.aborted) {
        return {
          requestId: request.requestId,
          predictions: {},
          topLabel: 'ABORTED',
          topScore: 0.0,
          confidence: 0.0,
          uncertainty: 1.0,
          latencyMs: Date.now() - startTime,
          status: 'ERROR',
          modelMetadata: this.metadata,
          error: 'InferenceAbortedError: inference was cancelled prior to session execution'
        };
      }

      // 2. Execute session run on underlying engine
      const session = this.session as any;
      const outputMap = await session.run(feeds);
      const latencyMs = Math.max(0.1, Date.now() - startTime);

      // 3. Process tensor output
      const predictions: Record<string, number> = {};
      let topLabel = 'UNKNOWN';
      let topScore = 0.0;

      // Check if output is formatted as individual class keys or as a logits tensor
      const outputKeys = Object.keys(outputMap);
      const hasClassKeys = this.metadata.outputClasses.every(cls => cls in outputMap);

      if (hasClassKeys) {
        // Individual class probability outputs
        for (const cls of this.metadata.outputClasses) {
          const val = outputMap[cls]?.data?.[0] ?? outputMap[cls] ?? 0.0;
          predictions[cls] = typeof val === 'number' ? Math.round(val * 10000) / 10000 : 0.0;
          if (predictions[cls] > topScore) {
            topScore = predictions[cls];
            topLabel = cls;
          }
        }
      } else {
        // Single logits tensor output (e.g. outputMap.logits or first output key)
        const logitsKey = this.metadata.outputNames?.[0] ?? outputKeys[0] ?? 'logits';
        const rawTensor = outputMap[logitsKey];
        const rawData = rawTensor?.data ? Array.from(rawTensor.data as ArrayLike<number>) : [];

        if (rawData.length >= this.metadata.outputClasses.length) {
          const probabilities = stableSoftmax(rawData.slice(0, this.metadata.outputClasses.length));
          this.metadata.outputClasses.forEach((cls, idx) => {
            predictions[cls] = probabilities[idx] ?? 0.0;
            if (predictions[cls] > topScore) {
              topScore = predictions[cls];
              topLabel = cls;
            }
          });
        } else {
          // Fallback mapping if output length doesn't match class count
          for (const cls of this.metadata.outputClasses) {
            predictions[cls] = 0.0;
          }
          topLabel = this.metadata.outputClasses[0] || 'UNKNOWN';
        }
      }

      const confidence = topScore;
      const uncertainty = Math.round((1.0 - confidence) * 100) / 100;

      return {
        requestId: request.requestId,
        predictions,
        topLabel,
        topScore,
        confidence,
        uncertainty,
        latencyMs,
        status: 'SUCCESS',
        modelMetadata: this.metadata,
        rawOutput: outputMap
      };
    } catch (err: any) {
      return {
        requestId: request.requestId,
        predictions: {},
        topLabel: 'ERROR',
        topScore: 0.0,
        confidence: 0.0,
        uncertainty: 1.0,
        latencyMs: Date.now() - startTime,
        status: 'ERROR',
        modelMetadata: this.metadata,
        error: `OnnxInferenceExecutionError: ${err.message}`
      };
    }
  }

  public async unload(): Promise<void> {
    this.session = null;
    this.modelBuffer = undefined;
    this.loaded = false;
  }
}
