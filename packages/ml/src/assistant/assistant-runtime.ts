import { Verdict } from '@private-protection/core';
import { ModelLoader } from '../models/model-loader';
import { PromptBoundary } from '../security/prompt-boundary';
import { PromptSanitizer } from '../security/prompt-sanitizer';
import { SchemaValidator } from '../security/schema-validator';
import { AssistantInput, AssistantOutput, ModelProvider } from '../types';
import { ResponsePolicy } from './response-policy';
import { TemplateFallbackEngine } from './template-fallback';

export class AISecurityAssistant {
  private modelLoader: ModelLoader;
  private activeProviderId?: string;
  private executionTimeoutMs: number;

  constructor(options?: {
    modelLoader?: ModelLoader;
    activeProviderId?: string;
    executionTimeoutMs?: number;
  }) {
    this.modelLoader = options?.modelLoader ?? new ModelLoader();
    this.activeProviderId = options?.activeProviderId;
    this.executionTimeoutMs = options?.executionTimeoutMs ?? 50;
  }

  public getLoader(): ModelLoader {
    return this.modelLoader;
  }

  public setActiveProvider(providerId: string): void {
    this.activeProviderId = providerId;
  }

  /**
   * Synthesizes an evidence-based threat explanation adhering to strict safety boundaries.
   * Conforms to docs/AI_ASSISTANT_CONTRACT.md and docs/AI_SECURITY_BOUNDARY.md
   */
  public async explain(input: AssistantInput): Promise<AssistantOutput> {
    const startTime = Date.now();

    // 1. Safety Guardrail: Check for weaponization / evasion intent in snippets or queries
    if (input.untrustedSnippet) {
      const intentCheck = ResponsePolicy.evaluateUserIntent(input.untrustedSnippet);
      if (intentCheck.isProhibited) {
        const elapsed = Math.max(0.01, Date.now() - startTime);
        return {
          headline: 'Request Prohibited by Security Policy',
          summaryParagraph: intentCheck.safeResponse || 'I cannot assist with bypassing security protections or creating cyber threats.',
          dangerFactors: ['Request attempts to generate attacks or evade security filters.'],
          recommendedSteps: ['Use protection tools only for authorized defensive purposes.'],
          uncertaintyNote: 'Enforced by on-device safety boundary.',
          inferenceStatus: 'SANITIZED',
          executionTimeMs: elapsed
        };
      }
    }

    // 2. Prompt Injection Barrier: Pre-filter and sanitize untrusted inputs
    let injectionDetected = false;
    let detectedPatterns: string[] = [];

    if (input.untrustedSnippet) {
      const sanitization = PromptSanitizer.sanitize(input.untrustedSnippet);
      if (sanitization.injectionDetected) {
        injectionDetected = true;
        detectedPatterns = sanitization.detectedPatterns;
      }
    }

    // If an injection attempt was detected, immediately contain it and generate an educational threat explanation
    if (injectionDetected) {
      const elapsed = Math.max(0.01, Date.now() - startTime);
      return {
        headline: 'Warning: Prompt Injection Attack Detected',
        summaryParagraph: 'This content contains deceptive hidden instructions designed to trick security filters and override digital protections.',
        dangerFactors: [
          `Detected injection vectors: ${detectedPatterns.join(', ')}`,
          'Attacker attempted to manipulate security instructions.'
        ],
        recommendedSteps: [
          'Do not follow any instructions contained in this content.',
          'Close the suspicious page or delete the message immediately.'
        ],
        uncertaintyNote: 'Captured by on-device adversarial token sanitizer.',
        inferenceStatus: 'SANITIZED',
        executionTimeMs: elapsed
      };
    }

    // 3. Attempt local inference if an active provider is registered and loaded
    let provider: ModelProvider | undefined;
    if (this.activeProviderId) {
      provider = this.modelLoader.getProvider(this.activeProviderId);
    }

    if (provider && provider.isLoaded()) {
      try {
        const { systemPrompt, sanitizedEvidenceContext } = PromptBoundary.buildIsolatedPrompt(input);

        // Execute inference with timeout protection
        const inferencePromise = provider.infer({
          requestId: input.requestId,
          task: 'EXPLANATION_SYNTHESIS',
          input: sanitizedEvidenceContext,
          context: { systemPrompt }
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('InferenceTimeoutError')), this.executionTimeoutMs)
        );

        const inferenceResult = await Promise.race([inferencePromise, timeoutPromise]);

        if (inferenceResult && inferenceResult.status === 'SUCCESS') {
          // Schema validation on model output
          const outputToValidate = inferenceResult.rawOutput ?? inferenceResult.predictions;
          const validation = SchemaValidator.validateAssistantOutput(
            outputToValidate,
            input.verdict
          );

          if (validation.valid && validation.output) {
            const elapsed = Math.max(0.01, Date.now() - startTime);
            return {
              ...validation.output,
              modelId: provider.id,
              inferenceStatus: 'LOCAL_MODEL',
              executionTimeMs: elapsed
            };
          }
        }
      } catch {
        // Fallback transparently on any provider failure or timeout
      }
    }

    // 4. Safe Deterministic Fallback: Parity with deterministic template engine (< 0.1 ms)
    const elapsed = Math.max(0.01, Date.now() - startTime);
    return TemplateFallbackEngine.generateFallback(input, elapsed);
  }
}
