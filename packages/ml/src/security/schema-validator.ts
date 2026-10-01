import { Verdict } from '@private-protection/core';
import { AssistantOutput } from '../types';

export class SchemaValidator {
  /**
   * Validates raw JSON object against AssistantOutput contract schema.
   * Also verifies that no injection override or safety downgrade has compromised the output.
   */
  public static validateAssistantOutput(
    rawObj: any,
    expectedVerdict: Verdict
  ): { valid: boolean; output?: AssistantOutput; error?: string } {
    if (!rawObj || typeof rawObj !== 'object') {
      return { valid: false, error: 'OutputValidationError: Output is not a valid JSON object' };
    }

    const {
      headline,
      summaryParagraph,
      dangerFactors,
      recommendedSteps,
      uncertaintyNote
    } = rawObj;

    // 1. Headline validation
    if (typeof headline !== 'string' || headline.trim().length === 0 || headline.length > 60) {
      return { valid: false, error: 'OutputValidationError: headline must be a non-empty string <= 60 characters' };
    }

    // 2. Summary paragraph validation
    if (typeof summaryParagraph !== 'string' || summaryParagraph.trim().length === 0 || summaryParagraph.length > 300) {
      return { valid: false, error: 'OutputValidationError: summaryParagraph must be a string <= 300 characters' };
    }

    // 3. Danger factors validation (1 to 4 items, max 100 chars each)
    if (!Array.isArray(dangerFactors) || dangerFactors.length === 0 || dangerFactors.length > 4) {
      return { valid: false, error: 'OutputValidationError: dangerFactors must be an array of 1 to 4 strings' };
    }
    for (const factor of dangerFactors) {
      if (typeof factor !== 'string' || factor.length > 100) {
        return { valid: false, error: 'OutputValidationError: danger factor item exceeds 100 characters' };
      }
    }

    // 4. Recommended steps validation (1 to 3 items, max 120 chars each)
    if (!Array.isArray(recommendedSteps) || recommendedSteps.length === 0 || recommendedSteps.length > 3) {
      return { valid: false, error: 'OutputValidationError: recommendedSteps must be an array of 1 to 3 strings' };
    }
    for (const step of recommendedSteps) {
      if (typeof step !== 'string' || step.length > 120) {
        return { valid: false, error: 'OutputValidationError: recommended step item exceeds 120 characters' };
      }
    }

    // 5. Uncertainty note validation
    if (typeof uncertaintyNote !== 'string' || uncertaintyNote.length > 150) {
      return { valid: false, error: 'OutputValidationError: uncertaintyNote must be a string <= 150 characters' };
    }

    // 6. Authority Isolation & Safety Invariant Check:
    // If verdict was CAUTION, SUSPICIOUS, or DANGEROUS, headline or summary MUST NOT declare the target safe!
    const isThreatVerdict = (
      expectedVerdict === Verdict.CAUTION ||
      expectedVerdict === Verdict.SUSPICIOUS ||
      expectedVerdict === Verdict.DANGEROUS
    );

    if (isThreatVerdict) {
      const combinedLower = `${headline} ${summaryParagraph}`.toLowerCase();
      const forbiddenPhrases = [
        'this is safe',
        'is completely safe',
        'no threat detected',
        'false alarm, you can proceed',
        'safe to enter your password',
        'ignore the warning',
        'verified legitimate'
      ];

      for (const phrase of forbiddenPhrases) {
        if (combinedLower.includes(phrase)) {
          return {
            valid: false,
            error: `AuthorityViolationError: Output attempts to declare threat target as safe ('${phrase}')`
          };
        }
      }
    }

    const validatedOutput: AssistantOutput = {
      headline,
      summaryParagraph,
      dangerFactors,
      recommendedSteps,
      uncertaintyNote,
      inferenceStatus: 'LOCAL_MODEL',
      executionTimeMs: 0
    };

    return { valid: true, output: validatedOutput };
  }
}
