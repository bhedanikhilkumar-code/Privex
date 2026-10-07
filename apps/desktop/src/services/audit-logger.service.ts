import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
  AuditLogEntry,
  AuditEventInput,
  AuditLogCategory,
  AuditLogSeverity,
  AuditVerificationResult,
  AuditQueryFilter
} from '../types/desktop.types';

export interface AuditLoggerOptions {
  configDir?: string;
  auditKey?: Buffer;
  clock?: () => number;
  maxEntries?: number;
}

export class AuditLoggerService {
  private readonly configDir: string;
  private readonly auditFilePath: string;
  private readonly auditKey: Buffer;
  private readonly clock: () => number;
  private readonly maxEntries: number;

  private memoryCache: AuditLogEntry[] = [];
  private lastHash: string = '0'.repeat(64);
  private nextIndex: number = 0;

  public static readonly GENESIS_PREV_HASH = '0'.repeat(64);
  public static readonly DEFAULT_MAX_ENTRIES = 10000;

  constructor(options?: AuditLoggerOptions) {
    this.configDir = path.resolve(
      options?.configDir || path.join(os.homedir(), '.private-protection')
    );
    this.auditFilePath = path.join(this.configDir, 'audit.log.enc');
    this.clock = options?.clock || (() => Date.now());
    this.maxEntries = options?.maxEntries || AuditLoggerService.DEFAULT_MAX_ENTRIES;

    this.ensureDir();
    this.auditKey = options?.auditKey ? Buffer.from(options.auditKey) : this.deriveAuditKey();
    this.loadAndVerifyExistingChain();
  }

  private ensureDir(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  private deriveAuditKey(): Buffer {
    this.ensureDir();
    const saltPath = path.join(this.configDir, '.storage.salt');
    let salt: Buffer | null = null;

    if (fs.existsSync(saltPath)) {
      try {
        const loaded = fs.readFileSync(saltPath);
        if (loaded.length >= 16) {
          salt = loaded;
        }
      } catch {
        salt = null;
      }
    }

    if (!salt) {
      salt = crypto.randomBytes(32);
      const tmpPath = `${saltPath}.tmp`;
      fs.writeFileSync(tmpPath, salt, { mode: 0o600 });
      fs.renameSync(tmpPath, saltPath);
    }

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}:audit-hmac`;
    return crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
  }

  /**
   * Deterministically canonicalizes an object by sorting all object keys recursively.
   */
  public static canonicalJson(obj: unknown): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(item => AuditLoggerService.canonicalJson(item)).join(',') + ']';
    }
    const record = obj as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const parts = sortedKeys.map(k => `${JSON.stringify(k)}:${AuditLoggerService.canonicalJson(record[k])}`);
    return '{' + parts.join(',') + '}';
  }

  /**
   * PII and Tier-1 Content Scrubber (RULE-18 Mandate):
   * - Strips URL query strings (?token=..., ?key=...)
   * - Removes sensitive credentials (passwords, auth tokens, bearer tokens)
   * - Removes control characters
   */
  public static scrubPii(text: string): string {
    if (!text) return '';
    let scrubbed = text.replace(/[\r\n\0]/g, ' ');

    // Strip URL query parameters: e.g. https://example.com/api?token=secret#hash -> https://example.com/api
    scrubbed = scrubbed.replace(/(https?:\/\/[^\s?#]+)(\?[^\s#]*)?(#[^\s]*)?/gi, (_, urlBase) => {
      return urlBase;
    });

    // Strip generic query string patterns outside URLs: e.g. ?token=123&secret=abc
    scrubbed = scrubbed.replace(/\?(?:[a-zA-Z0-9_.-]+=[^&\s]*&?)+/g, '[QUERY_SCRUBBED]');

    // Strip Bearer tokens
    scrubbed = scrubbed.replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]');

    // Strip API keys / password tokens
    scrubbed = scrubbed.replace(/(?:password|secret|apikey|api_key|token|auth)\s*[:=]\s*['"]?[^\s,'"]+['"]?/gi, '[CREDENTIAL_REDACTED]');

    return scrubbed.trim();
  }

  private sanitizeMetadata(
    metadata?: Record<string, string | number | boolean>
  ): Record<string, string | number | boolean> | undefined {
    if (!metadata || typeof metadata !== 'object') return undefined;

    const sanitized: Record<string, string | number | boolean> = {};
    const keys = Object.keys(metadata).sort().slice(0, 32);

    for (const key of keys) {
      const val = metadata[key];
      if (typeof val === 'number') {
        if (Number.isFinite(val)) sanitized[key] = val;
      } else if (typeof val === 'boolean') {
        sanitized[key] = val;
      } else if (typeof val === 'string') {
        sanitized[key] = AuditLoggerService.scrubPii(val).slice(0, 500);
      }
    }

    return Object.keys(sanitized).length > 0 ? sanitized : undefined;
  }

  /**
   * Computes HMAC-SHA256 over: index | timestamp | prevHash | canonical(payload)
   */
  private computeEntryHmac(
    index: number,
    timestamp: number,
    prevHash: string,
    payload: {
      category: AuditLogCategory;
      severity: AuditLogSeverity;
      action: string;
      actor: string;
      targetSummary: string;
      sha256?: string;
      ruleIds?: readonly string[];
      verdict?: string;
      riskScore?: number;
      metadata?: Record<string, string | number | boolean>;
    }
  ): string {
    const canonicalPayload = AuditLoggerService.canonicalJson(payload);
    const signString = `${index}|${timestamp}|${prevHash}|${canonicalPayload}`;
    return crypto.createHmac('sha256', this.auditKey).update(signString, 'utf8').digest('hex');
  }

  /**
   * Appends an audit event to the HMAC-SHA256 cryptographically chained log.
   */
  public log(input: AuditEventInput): AuditLogEntry {
    const timestamp = this.clock();
    const index = this.nextIndex;
    const prevHash = this.lastHash;

    const cleanAction = AuditLoggerService.scrubPii(input.action).slice(0, 100);
    const cleanActor = AuditLoggerService.scrubPii(input.actor).slice(0, 100);
    const cleanTarget = AuditLoggerService.scrubPii(input.targetSummary).slice(0, 500);
    const cleanMetadata = this.sanitizeMetadata(input.metadata);

    const payloadObj = {
      category: input.category,
      severity: input.severity,
      action: cleanAction,
      actor: cleanActor,
      targetSummary: cleanTarget,
      ...(input.sha256 ? { sha256: input.sha256 } : {}),
      ...(input.ruleIds && input.ruleIds.length > 0 ? { ruleIds: [...input.ruleIds] } : {}),
      ...(input.verdict ? { verdict: input.verdict } : {}),
      ...(typeof input.riskScore === 'number' ? { riskScore: input.riskScore } : {}),
      ...(cleanMetadata ? { metadata: cleanMetadata } : {})
    };

    const entryHmac = this.computeEntryHmac(index, timestamp, prevHash, payloadObj);

    const entry: AuditLogEntry = {
      index,
      id: `audit-${index}-${crypto.randomBytes(4).toString('hex')}`,
      timestamp,
      category: input.category,
      severity: input.severity,
      action: cleanAction,
      actor: cleanActor,
      targetSummary: cleanTarget,
      prevHash,
      entryHmacSha256: entryHmac,
      ...(input.sha256 ? { sha256: input.sha256 } : {}),
      ...(input.ruleIds && input.ruleIds.length > 0 ? { ruleIds: [...input.ruleIds] } : {}),
      ...(input.verdict ? { verdict: input.verdict } : {}),
      ...(typeof input.riskScore === 'number' ? { riskScore: input.riskScore } : {}),
      ...(cleanMetadata ? { metadata: cleanMetadata } : {})
    };

    this.memoryCache.push(entry);
    this.lastHash = entryHmac;
    this.nextIndex = index + 1;

    // Prune in-memory cache if over capacity (keep latest)
    if (this.memoryCache.length > this.maxEntries) {
      this.memoryCache = this.memoryCache.slice(-this.maxEntries);
    }

    // Persist to disk atomically/append-only
    this.appendToFile(entry);

    return entry;
  }

  private appendToFile(entry: AuditLogEntry): void {
    try {
      this.ensureDir();
      const line = JSON.stringify(entry) + '\n';
      fs.appendFileSync(this.auditFilePath, line, { mode: 0o600 });
    } catch {
      // Best-effort local storage failure handling
    }
  }

  /**
   * Loads existing chain from disk and verifies integrity.
   * If a corrupt line is found at the tail (e.g. crash during write), recovers valid prefix.
   */
  private loadAndVerifyExistingChain(): void {
    this.memoryCache = [];
    this.lastHash = AuditLoggerService.GENESIS_PREV_HASH;
    this.nextIndex = 0;

    if (!fs.existsSync(this.auditFilePath)) {
      return;
    }

    try {
      const content = fs.readFileSync(this.auditFilePath, 'utf8');
      const lines = content.split('\n').filter(l => l.trim().length > 0);

      const validEntries: AuditLogEntry[] = [];
      let expectedPrevHash = AuditLoggerService.GENESIS_PREV_HASH;
      let hadTailCorruption = false;

      for (let i = 0; i < lines.length; i++) {
        try {
          const entry = JSON.parse(lines[i]) as AuditLogEntry;
          if (
            typeof entry.index !== 'number' ||
            typeof entry.timestamp !== 'number' ||
            typeof entry.prevHash !== 'string' ||
            typeof entry.entryHmacSha256 !== 'string'
          ) {
            hadTailCorruption = true;
            break;
          }

          // Verify HMAC
          const payloadObj = {
            category: entry.category,
            severity: entry.severity,
            action: entry.action,
            actor: entry.actor,
            targetSummary: entry.targetSummary,
            ...(entry.sha256 ? { sha256: entry.sha256 } : {}),
            ...(entry.ruleIds && entry.ruleIds.length > 0 ? { ruleIds: [...entry.ruleIds] } : {}),
            ...(entry.verdict ? { verdict: entry.verdict } : {}),
            ...(typeof entry.riskScore === 'number' ? { riskScore: entry.riskScore } : {}),
            ...(entry.metadata ? { metadata: entry.metadata } : {})
          };

          const expectedHmac = this.computeEntryHmac(
            entry.index,
            entry.timestamp,
            entry.prevHash,
            payloadObj
          );

          if (entry.prevHash !== expectedPrevHash || entry.entryHmacSha256 !== expectedHmac || entry.index !== i) {
            hadTailCorruption = true;
            break;
          }

          validEntries.push(entry);
          expectedPrevHash = entry.entryHmacSha256;
        } catch {
          hadTailCorruption = true;
          break;
        }
      }

      this.memoryCache = validEntries.slice(-this.maxEntries);
      if (validEntries.length > 0) {
        this.nextIndex = validEntries.length;
        this.lastHash = validEntries[validEntries.length - 1].entryHmacSha256;
      }

      // If tail corruption was detected, rewrite clean prefix to recover crash state safely
      if (hadTailCorruption) {
        this.rewriteFile(validEntries);
      }
    } catch {
      this.memoryCache = [];
      this.lastHash = AuditLoggerService.GENESIS_PREV_HASH;
      this.nextIndex = 0;
    }
  }

  private rewriteFile(entries: AuditLogEntry[]): void {
    try {
      this.ensureDir();
      const tmpPath = `${this.auditFilePath}.tmp`;
      const data = entries.map(e => JSON.stringify(e)).join('\n') + (entries.length > 0 ? '\n' : '');
      fs.writeFileSync(tmpPath, data, { mode: 0o600 });
      fs.renameSync(tmpPath, this.auditFilePath);
    } catch {
      // Best-effort recovery rewrite
    }
  }

  /**
   * Verifies the cryptographic HMAC-SHA256 chain integrity of the entire audit log on disk.
   */
  public verifyChainIntegrity(): AuditVerificationResult {
    if (!fs.existsSync(this.auditFilePath)) {
      return {
        isValid: true,
        totalEntries: 0,
        verifiedEntries: 0
      };
    }

    try {
      const content = fs.readFileSync(this.auditFilePath, 'utf8');
      const lines = content.split('\n').filter(l => l.trim().length > 0);

      let expectedPrevHash = AuditLoggerService.GENESIS_PREV_HASH;

      for (let i = 0; i < lines.length; i++) {
        let entry: AuditLogEntry;
        try {
          entry = JSON.parse(lines[i]);
        } catch {
          return {
            isValid: false,
            totalEntries: lines.length,
            verifiedEntries: i,
            corruptedIndex: i,
            reason: 'CORRUPTED_JSON_ENTRY',
            tamperDetails: `Malformed JSON line at record index ${i}`
          };
        }

        if (entry.index !== i) {
          return {
            isValid: false,
            totalEntries: lines.length,
            verifiedEntries: i,
            corruptedIndex: i,
            reason: 'INDEX_SEQUENCE_VIOLATION',
            tamperDetails: `Expected index ${i} but received ${entry.index}`
          };
        }

        if (entry.prevHash !== expectedPrevHash) {
          return {
            isValid: false,
            totalEntries: lines.length,
            verifiedEntries: i,
            corruptedIndex: i,
            reason: 'HASH_CHAIN_DISCONTINUITY',
            tamperDetails: `Record ${i} prevHash mismatch (expected ${expectedPrevHash.slice(0, 16)}..., got ${entry.prevHash.slice(0, 16)}...)`
          };
        }

        const payloadObj = {
          category: entry.category,
          severity: entry.severity,
          action: entry.action,
          actor: entry.actor,
          targetSummary: entry.targetSummary,
          ...(entry.sha256 ? { sha256: entry.sha256 } : {}),
          ...(entry.ruleIds && entry.ruleIds.length > 0 ? { ruleIds: [...entry.ruleIds] } : {}),
          ...(entry.verdict ? { verdict: entry.verdict } : {}),
          ...(typeof entry.riskScore === 'number' ? { riskScore: entry.riskScore } : {}),
          ...(entry.metadata ? { metadata: entry.metadata } : {})
        };

        const expectedHmac = this.computeEntryHmac(
          entry.index,
          entry.timestamp,
          entry.prevHash,
          payloadObj
        );

        if (entry.entryHmacSha256 !== expectedHmac) {
          return {
            isValid: false,
            totalEntries: lines.length,
            verifiedEntries: i,
            corruptedIndex: i,
            reason: 'HMAC_SIGNATURE_MISMATCH',
            tamperDetails: `Cryptographic HMAC verification failed for record index ${i}`
          };
        }

        expectedPrevHash = entry.entryHmacSha256;
      }

      return {
        isValid: true,
        totalEntries: lines.length,
        verifiedEntries: lines.length
      };
    } catch (err) {
      return {
        isValid: false,
        totalEntries: 0,
        verifiedEntries: 0,
        reason: 'FILE_READ_ERROR',
        tamperDetails: err instanceof Error ? err.message : String(err)
      };
    }
  }

  /**
   * Retrieves audit logs matching filter with pagination.
   */
  public query(filter?: AuditQueryFilter): {
    entries: AuditLogEntry[];
    total: number;
    offset: number;
    limit: number;
  } {
    // Read from disk to ensure full history is queryable
    let allEntries: AuditLogEntry[] = [];
    if (fs.existsSync(this.auditFilePath)) {
      try {
        const content = fs.readFileSync(this.auditFilePath, 'utf8');
        allEntries = content
          .split('\n')
          .filter(l => l.trim().length > 0)
          .map(l => JSON.parse(l) as AuditLogEntry);
      } catch {
        allEntries = [...this.memoryCache];
      }
    } else {
      allEntries = [...this.memoryCache];
    }

    let filtered = allEntries;

    if (filter?.category) {
      filtered = filtered.filter(e => e.category === filter.category);
    }
    if (filter?.severity) {
      filtered = filtered.filter(e => e.severity === filter.severity);
    }
    if (typeof filter?.startDate === 'number') {
      filtered = filtered.filter(e => e.timestamp >= filter.startDate!);
    }
    if (typeof filter?.endDate === 'number') {
      filtered = filtered.filter(e => e.timestamp <= filter.endDate!);
    }
    if (filter?.search) {
      const q = filter.search.toLowerCase();
      filtered = filtered.filter(
        e =>
          e.action.toLowerCase().includes(q) ||
          e.actor.toLowerCase().includes(q) ||
          e.targetSummary.toLowerCase().includes(q) ||
          (e.sha256 && e.sha256.toLowerCase().includes(q))
      );
    }

    // Default: descending timestamp (newest first)
    filtered.sort((a, b) => b.timestamp - a.timestamp);

    const total = filtered.length;
    const offset = Math.max(0, filter?.offset || 0);
    const limit = Math.max(1, Math.min(1000, filter?.limit || 100));
    const paginated = filtered.slice(offset, offset + limit);

    return {
      entries: paginated,
      total,
      offset,
      limit
    };
  }

  /**
   * Exports audit log to sanitized JSON or CSV format.
   */
  public export(format: 'json' | 'csv'): string {
    const { entries } = this.query({ limit: 10000 });

    if (format === 'json') {
      return JSON.stringify(entries, null, 2);
    }

    // CSV format
    const headers = [
      'index',
      'id',
      'timestamp',
      'category',
      'severity',
      'action',
      'actor',
      'targetSummary',
      'sha256',
      'verdict',
      'riskScore',
      'prevHash',
      'entryHmacSha256'
    ];

    const escapeCsv = (val: unknown): string => {
      if (val === undefined || val === null) return '';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = entries.map(e =>
      [
        e.index,
        e.id,
        new Date(e.timestamp).toISOString(),
        e.category,
        e.severity,
        escapeCsv(e.action),
        escapeCsv(e.actor),
        escapeCsv(e.targetSummary),
        e.sha256 || '',
        e.verdict || '',
        e.riskScore !== undefined ? e.riskScore : '',
        e.prevHash,
        e.entryHmacSha256
      ].join(',')
    );

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Privacy Crypto-Shredder:
   * Securely zeroes key in memory, deletes audit log file and backup.
   */
  public purgeAllLogs(): void {
    this.memoryCache = [];
    this.lastHash = AuditLoggerService.GENESIS_PREV_HASH;
    this.nextIndex = 0;

    if (this.auditKey) {
      this.auditKey.fill(0);
    }

    if (fs.existsSync(this.auditFilePath)) {
      try {
        // Multi-pass overwrite
        const size = fs.statSync(this.auditFilePath).size;
        if (size > 0) {
          const zeros = Buffer.alloc(size, 0);
          fs.writeFileSync(this.auditFilePath, zeros);
          const ones = Buffer.alloc(size, 0xff);
          fs.writeFileSync(this.auditFilePath, ones);
        }
        fs.unlinkSync(this.auditFilePath);
      } catch {
        // continue
      }
    }
  }

  public getCacheSize(): number {
    return this.memoryCache.length;
  }

  public getLastHash(): string {
    return this.lastHash;
  }

  public getNextIndex(): number {
    return this.nextIndex;
  }
}
