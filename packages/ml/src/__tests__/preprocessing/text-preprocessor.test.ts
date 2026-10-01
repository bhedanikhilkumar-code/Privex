import { describe, it, expect } from 'vitest';
import { TextPreprocessor } from '../../models/preprocessing/text-preprocessor';

describe('TextPreprocessor Tokenization Boundary', () => {
  const preprocessor = new TextPreprocessor({ maxSequenceLength: 16 });

  it('should initialize with default special token constants', () => {
    expect(TextPreprocessor.PAD_TOKEN_ID).toBe(0);
    expect(TextPreprocessor.UNK_TOKEN_ID).toBe(1);
    expect(TextPreprocessor.CLS_TOKEN_ID).toBe(2);
    expect(TextPreprocessor.SEP_TOKEN_ID).toBe(3);
  });

  it('should tokenize simple sentence and generate fixed length vectors with CLS and SEP', () => {
    const res = preprocessor.preprocess('verify your password immediately');

    expect(res.inputIds.length).toBe(16);
    expect(res.attentionMask.length).toBe(16);

    // First token must be [CLS] (2)
    expect(res.inputIds[0]).toBe(TextPreprocessor.CLS_TOKEN_ID);

    // Tokens should be followed by [SEP] (3)
    const sepIdx = res.inputIds.indexOf(TextPreprocessor.SEP_TOKEN_ID);
    expect(sepIdx).toBeGreaterThan(0);

    // Padding after [SEP] must be 0
    for (let i = sepIdx + 1; i < 16; i++) {
      expect(res.inputIds[i]).toBe(TextPreprocessor.PAD_TOKEN_ID);
      expect(res.attentionMask[i]).toBe(0);
    }

    // Attention mask for active tokens must be 1
    for (let i = 0; i <= sepIdx; i++) {
      expect(res.attentionMask[i]).toBe(1);
    }
  });

  it('should handle punctuation and case normalization', () => {
    const resUpper = preprocessor.preprocess('URGENT: PASSWORD RESET!');
    const resLower = preprocessor.preprocess('urgent: password reset!');

    expect(resUpper.inputIds).toEqual(resLower.inputIds);
  });

  it('should clamp input to maxSequenceLength - 2 to preserve CLS and SEP tokens', () => {
    const longText = 'one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen';
    const res = preprocessor.preprocess(longText);

    expect(res.inputIds.length).toBe(16);
    expect(res.inputIds[0]).toBe(TextPreprocessor.CLS_TOKEN_ID);
    expect(res.inputIds[15]).toBe(TextPreprocessor.SEP_TOKEN_ID);
    expect(res.attentionMask.every(m => m === 1)).toBe(true);
  });

  it('should handle empty or whitespace-only strings gracefully', () => {
    const emptyRes = preprocessor.preprocess('');
    expect(emptyRes.inputIds.length).toBe(16);
    expect(emptyRes.inputIds.every(id => id === TextPreprocessor.PAD_TOKEN_ID)).toBe(true);
    expect(emptyRes.attentionMask.every(m => m === 0)).toBe(true);

    const spaceRes = preprocessor.preprocess('   \n\t  ');
    expect(spaceRes.inputIds.every(id => id === TextPreprocessor.PAD_TOKEN_ID)).toBe(true);
  });

  it('should handle non-string or null inputs safely', () => {
    const nullRes = preprocessor.preprocess(null as any);
    expect(nullRes.inputIds.length).toBe(16);
    expect(nullRes.attentionMask.every(m => m === 0)).toBe(true);
  });
});
