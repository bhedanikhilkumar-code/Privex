export interface PreprocessedInput {
  readonly inputIds: number[];
  readonly attentionMask: number[];
  readonly sequenceLength: number;
}

export interface PreprocessorOptions {
  readonly maxSequenceLength?: number;
  readonly lowerCase?: boolean;
}

/**
 * EXPLICIT TEXT PREPROCESSING & TOKENIZATION BOUNDARY
 *
 * Translates raw, untrusted text strings into fixed-length numerical tensor representations
 * (input IDs and attention masks) suitable for on-device ONNX / TFLite transformer inference.
 * Operates purely in volatile memory with zero cloud or filesystem dependencies.
 */
export class TextPreprocessor {
  public static readonly PAD_TOKEN_ID = 0;
  public static readonly UNK_TOKEN_ID = 1;
  public static readonly CLS_TOKEN_ID = 2;
  public static readonly SEP_TOKEN_ID = 3;

  private maxSequenceLength: number;
  private lowerCase: boolean;
  private vocabulary: Map<string, number>;

  constructor(options?: PreprocessorOptions) {
    this.maxSequenceLength = options?.maxSequenceLength ?? 128;
    this.lowerCase = options?.lowerCase ?? true;
    this.vocabulary = this.buildDeterministicVocabulary();
  }

  /**
   * Transforms raw text into padded inputIds and attentionMask vectors.
   */
  public preprocess(text: string): PreprocessedInput {
    if (!text || typeof text !== 'string') {
      return this.buildPaddedVectors([]);
    }

    const normalized = this.lowerCase ? text.toLowerCase().trim() : text.trim();
    if (normalized.length === 0) {
      return this.buildPaddedVectors([]);
    }

    // Whitespace and punctuation tokenization
    const tokens = normalized
      .replace(/([.,/#!$%^&*;:{}=\-_`~()?"'<>@])/g, ' $1 ')
      .split(/\s+/)
      .filter(t => t.length > 0);

    const tokenIds: number[] = [TextPreprocessor.CLS_TOKEN_ID];

    // Max tokens accounting for [CLS] and [SEP]
    const contentBudget = this.maxSequenceLength - 2;
    const clampedTokens = tokens.slice(0, Math.max(0, contentBudget));

    for (const token of clampedTokens) {
      const id = this.vocabulary.get(token) ?? this.hashTokenToVocab(token);
      tokenIds.push(id);
    }

    tokenIds.push(TextPreprocessor.SEP_TOKEN_ID);

    return this.buildPaddedVectors(tokenIds);
  }

  private buildPaddedVectors(tokenIds: number[]): PreprocessedInput {
    const inputIds = new Array<number>(this.maxSequenceLength).fill(TextPreprocessor.PAD_TOKEN_ID);
    const attentionMask = new Array<number>(this.maxSequenceLength).fill(0);

    const len = Math.min(tokenIds.length, this.maxSequenceLength);
    for (let i = 0; i < len; i++) {
      inputIds[i] = tokenIds[i];
      attentionMask[i] = 1;
    }

    return {
      inputIds,
      attentionMask,
      sequenceLength: len
    };
  }

  /**
   * Deterministic Murmur-style token hasher for out-of-vocabulary subwords
   * bounded within vocabulary range [100, 30522] (standard BERT vocabulary space).
   */
  private hashTokenToVocab(token: string): number {
    let hash = 0;
    for (let i = 0; i < token.length; i++) {
      hash = (hash << 5) - hash + token.charCodeAt(i);
      hash |= 0;
    }
    return 100 + (Math.abs(hash) % 30000);
  }

  /**
   * Seed vocabulary for canonical security and threat tokens.
   */
  private buildDeterministicVocabulary(): Map<string, number> {
    const vocab = new Map<string, number>();
    vocab.set('[pad]', TextPreprocessor.PAD_TOKEN_ID);
    vocab.set('[unk]', TextPreprocessor.UNK_TOKEN_ID);
    vocab.set('[cls]', TextPreprocessor.CLS_TOKEN_ID);
    vocab.set('[sep]', TextPreprocessor.SEP_TOKEN_ID);

    const commonTerms = [
      'the', 'of', 'and', 'to', 'a', 'in', 'is', 'you', 'that', 'it', 'he', 'was', 'for', 'on', 'are', 'as', 'with', 'his', 'they',
      'password', 'login', 'account', 'verify', 'update', 'security', 'suspended', 'urgent', 'immediately', 'click', 'link',
      'bank', 'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'invoice', 'payment', 'bitcoin', 'crypto', 'wallet',
      'ransom', 'encrypted', 'files', 'destroy', 'task', 'rating', 'apps', 'deposit', 'commission', 'daily', 'salary', 'usps', 'fedex',
      'package', 'detained', 'redelivery', 'fee', 'customs', 'prince', 'inheritance', 'beneficiary', 'million', 'dollars', 'lottery'
    ];

    let nextId = 4;
    for (const term of commonTerms) {
      vocab.set(term, nextId++);
    }

    return vocab;
  }
}
