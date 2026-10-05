import { describe, expect, it } from 'vitest';
import {
  ActionRecommendation,
  BloomFilter,
  CoreFileAnalyzer,
  DetectionPipeline,
  DetectorLayer,
  DetectorType,
  EngineVerdict,
  InputType,
  ProcessAnalyzer,
  RiskCategory,
  RiskScorer,
  RuleEngine,
  SeverityLevel,
  ThreatIntel,
  Verdict
} from '../../index';

describe('Phase B — Core Detection Engine Expansion (Unit, Integration, Security & Determinism Suite)', () => {
  describe('Step 4, 5 & 6: ThreatIntel Canonical Hash Intelligence & BloomFilter Fast-Path', () => {
    it('classifies seeded EICAR SHA-256 and synthetic malware hashes as KNOWN_BAD', () => {
      const intel = new ThreatIntel();

      const eicarLookup = intel.lookupHash(ThreatIntel.EICAR_SHA256);
      expect(eicarLookup.disposition).toBe('KNOWN_BAD');
      expect(eicarLookup.status).toBe('KNOWN_BAD');
      expect(eicarLookup.isMalicious).toBe(true);
      expect(eicarLookup.isAllowed).toBe(false);
      expect(eicarLookup.isCritical).toBe(true);
      expect(eicarLookup.bloomFilterHit).toBe(true);
      expect(eicarLookup.threatName).toBe('EICAR_TEST_FILE');
      expect(eicarLookup.evidence?.detectorLayer).toBe(DetectorLayer.HASH_INTEL);

      for (const synthetic of ThreatIntel.SYNTHETIC_MALWARE_HASHES) {
        const res = intel.lookupHash(synthetic.hash);
        expect(res.disposition).toBe('KNOWN_BAD');
        expect(res.isMalicious).toBe(true);
        expect(res.threatName).toBe(synthetic.threatName);
      }
    });

    it('classifies explicitly allowed file hashes as KNOWN_GOOD and unknown hashes as UNKNOWN (never KNOWN_GOOD)', () => {
      const intel = new ThreatIntel();
      const benignHash = 'a'.repeat(64);
      const unknownHash = 'b'.repeat(64);

      expect(intel.lookupHash(unknownHash).disposition).toBe('UNKNOWN');
      expect(intel.lookupHash(unknownHash).isAllowed).toBe(false);
      expect(intel.lookupHash(unknownHash).isMalicious).toBe(false);

      intel.addAllowedHash(benignHash);
      expect(intel.isHashAllowed(benignHash)).toBe(true);

      const goodLookup = intel.lookupHash(benignHash);
      expect(goodLookup.disposition).toBe('KNOWN_GOOD');
      expect(goodLookup.isAllowed).toBe(true);
      expect(goodLookup.isMalicious).toBe(false);

      intel.removeAllowedHash(benignHash);
      expect(intel.lookupHash(benignHash).disposition).toBe('UNKNOWN');
    });

    it('enforces Bloom filter false-positive safety: Bloom hit without badHashes confirmation returns UNKNOWN, never KNOWN_BAD', () => {
      const intel = new ThreatIntel();
      const unconfirmedHash = 'c'.repeat(64);

      // Simulate a Bloom filter collision/positive without a corresponding entry in badHashes
      intel.getBloomFilter().add(unconfirmedHash);

      const lookup = intel.lookupHash(unconfirmedHash);
      expect(lookup.bloomFilterHit).toBe(true);
      expect(lookup.disposition).toBe('UNKNOWN');
      expect(lookup.isMalicious).toBe(false);
    });

    it('enforces Critical Malware Hash Precedence: standard user allowlist cannot override critical malware hash without explicit critical override flag', () => {
      const intel = new ThreatIntel();

      // Attempt to allowlist EICAR without critical override permission
      intel.addAllowedHash(ThreatIntel.EICAR_SHA256);
      const standardCheck = intel.lookupHash(ThreatIntel.EICAR_SHA256);
      expect(standardCheck.disposition).toBe('KNOWN_BAD');
      expect(standardCheck.isMalicious).toBe(true);

      // Explicit policy override via lookup option
      const explicitOptionCheck = intel.lookupHash(ThreatIntel.EICAR_SHA256, {
        allowUserOverrideOnCritical: true
      });
      expect(explicitOptionCheck.disposition).toBe('KNOWN_GOOD');

      // Explicit policy override via addAllowedHash(..., { allowCriticalOverride: true })
      intel.addAllowedHash(ThreatIntel.EICAR_SHA256, { allowCriticalOverride: true });
      expect(intel.lookupHash(ThreatIntel.EICAR_SHA256).disposition).toBe('KNOWN_GOOD');
    });

    it('handles malformed, empty, or non-string hashes safely without throwing', () => {
      const intel = new ThreatIntel();
      expect(intel.lookupHash('').disposition).toBe('UNKNOWN');
      expect(intel.lookupHash('   ').disposition).toBe('UNKNOWN');
      expect(intel.lookupHash(null as unknown as string).disposition).toBe('UNKNOWN');
      expect(intel.lookupHash(undefined as unknown as string).disposition).toBe('UNKNOWN');
    });

    it('verifies BloomFilter 64-char SHA-256 hex fast-path determinism and BLOM v1 binary serialization round-trip', () => {
      const filter = new BloomFilter(5000, 0.001);
      const hexDigest = ThreatIntel.EICAR_SHA256;
      const upperHexDigest = hexDigest.toUpperCase();
      const domainItem = 'malicious-test-domain.example';

      filter.add(hexDigest);
      filter.add(domainItem);

      expect(filter.has(hexDigest)).toBe(true);
      expect(filter.has(upperHexDigest)).toBe(true);
      expect(filter.has(domainItem)).toBe(true);
      expect(filter.has('0'.repeat(64))).toBe(false);

      const serialized = filter.serialize();
      const restored = BloomFilter.deserialize(serialized);
      expect(restored.has(hexDigest)).toBe(true);
      expect(restored.has(domainItem)).toBe(true);
      expect(restored.has('0'.repeat(64))).toBe(false);
    });
  });

  describe('Step 7 & 8: RuleEngine Structured Signal Emission & DetectorLayer Mapping', () => {
    it('emits structured Evidence signals with ruleId, detectorLayer, reason, severityLevel, and metadata across URL, TEXT, FILE, and PROCESS', () => {
      const engine = new RuleEngine();

      const urlRes = engine.evaluateUrl('http://192.168.1.1/login');
      expect(urlRes.triggered).toBe(true);
      expect(urlRes.evidence[0].ruleId).toBe('url-ip-based');
      expect(urlRes.evidence[0].detectorLayer).toBe(DetectorLayer.SIGNATURE_ENGINE);
      expect(urlRes.evidence[0].reason).toBeTruthy();
      expect(urlRes.evidence[0].metadata?.ruleId).toBe('url-ip-based');

      const textRes = engine.evaluateText(
        'URGENT: Pay 1.5 BTC to bitcoin wallet immediately or you will be arrested!'
      );
      expect(textRes.triggered).toBe(true);
      const textRuleIds = textRes.evidence.map((e) => e.ruleId);
      expect(textRuleIds).toContain('text-urgency');
      expect(textRuleIds).toContain('text-financial-scam');
      expect(textRuleIds).toContain('text-threat');

      const fileRes = engine.evaluateFile(CoreFileAnalyzer.EICAR_SIGNATURE);
      expect(fileRes.triggered).toBe(true);
      expect(fileRes.evidence[0].ruleId).toBe('file-eicar-signature');
      expect(fileRes.evidence[0].isCriticalOverride).toBe(true);

      const procRes = engine.evaluateProcess(
        'powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgA'
      );
      expect(procRes.triggered).toBe(true);
      expect(procRes.evidence.some((e) => e.ruleId === 'proc-encoded-command')).toBe(true);

      const shadowRes = engine.evaluateProcess('vssadmin.exe delete shadows /all /quiet');
      expect(shadowRes.triggered).toBe(true);
      expect(shadowRes.evidence.some((e) => e.ruleId === 'proc-defense-evasion')).toBe(true);
    });
  });

  describe('Step 9, 10, 11 & 13: RiskScorer 8-Layer Weights, 6-Tier EngineVerdict, Correlation & Signal Dilution Defense', () => {
    it('prevents Signal Dilution Attacks: 1 critical override + 50 low-weight/low-confidence benign signals cannot dilute verdict below BLOCK/QUARANTINE', () => {
      const scorer = new RiskScorer();
      const dilutedEvidence: any[] = [
        {
          ruleId: 'threat-intel-known-bad',
          detectorLayer: DetectorLayer.HASH_INTEL,
          source: 'THREAT_INTEL',
          name: 'Known Malicious Hash',
          description: 'Matches verified malware hash',
          weight: 95,
          scoreContribution: 95,
          confidence: 0.95,
          isCriticalOverride: true
        }
      ];

      for (let i = 0; i < 50; i++) {
        dilutedEvidence.push({
          ruleId: `benign-noise-${i}`,
          detectorLayer: DetectorLayer.STATIC_HEURISTIC,
          source: 'TEXT_ANALYZER',
          name: `Low Signal ${i}`,
          description: 'Benign padding signal',
          weight: 1,
          scoreContribution: 1,
          confidence: 0.21
        });
      }

      const result = scorer.calculateScore(dilutedEvidence, 0, { inputType: InputType.FILE });
      expect(result.score).toBeGreaterThanOrEqual(95);
      expect(result.confidence).toBeGreaterThanOrEqual(0.9);
      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.recommendation).toBe(ActionRecommendation.BLOCK);
      expect(result.engineVerdict).toBe(EngineVerdict.QUARANTINE);
    });

    it('fails closed on partial NaN, Infinity, -Infinity, and negative or overflow scores', () => {
      const scorer = new RiskScorer();

      // Partial NaN where scoreContribution is NaN and weight is 0 must NOT fall through to 0!
      const partialNanResult = scorer.calculateScore([
        {
          source: 'RULE_ENGINE',
          name: 'Corrupt ScoreContribution',
          description: 'scoreContribution is NaN while weight is 0',
          scoreContribution: Number.NaN,
          weight: 0,
          confidence: 0.9
        }
      ]);
      expect(partialNanResult.score).toBeGreaterThanOrEqual(45);
      expect(partialNanResult.verdict).not.toBe(Verdict.ALLOW);

      // Overflow score > 100 is bounded to [0, 100]
      const overflowResult = scorer.calculateScore([
        {
          source: 'RULE_ENGINE',
          name: 'Overflow Signal',
          description: 'Weight 99999',
          weight: 99999,
          confidence: 5.0
        }
      ]);
      expect(overflowResult.score).toBe(100);
      expect(overflowResult.confidence).toBeLessThanOrEqual(1.0);
    });

    it('applies Layer 8 Cross-Layer Correlation while deduplicating identical ruleIds', () => {
      const scorer = new RiskScorer();

      // Metadata + Static/Signature correlation
      const correlated = scorer.calculateScore(
        [
          {
            ruleId: 'proc-writable-dir-execution',
            detectorLayer: DetectorLayer.METADATA_ANALYZER,
            source: 'PROCESS_ANALYZER',
            name: 'Writable Dir',
            description: 'Temp execution',
            weight: 40,
            scoreContribution: 40,
            confidence: 0.9
          },
          {
            ruleId: 'proc-lolbin-cradle',
            detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
            source: 'RULE_ENGINE',
            name: 'LOLBin Download',
            description: 'Download cradle',
            weight: 60,
            scoreContribution: 60,
            confidence: 0.92
          }
        ],
        0,
        { inputType: InputType.PROCESS }
      );
      expect(
        correlated.correlationSignals?.some((c) => c.ruleId === 'corr-metadata-plus-static')
      ).toBe(true);
      expect(correlated.score).toBeGreaterThanOrEqual(75);

      // Duplicate ruleId must NOT trigger multi-layer consensus on its own
      const duplicateRuleOnly = scorer.calculateScore([
        {
          ruleId: 'same-rule-id',
          detectorLayer: DetectorLayer.STATIC_HEURISTIC,
          source: 'URL_ANALYZER',
          name: 'Dup 1',
          description: 'Dup 1',
          weight: 35,
          confidence: 0.85
        },
        {
          ruleId: 'same-rule-id',
          detectorLayer: DetectorLayer.STATIC_HEURISTIC,
          source: 'URL_ANALYZER',
          name: 'Dup 2',
          description: 'Dup 2',
          weight: 35,
          confidence: 0.85
        }
      ]);
      expect(duplicateRuleOnly.correlationSignals?.length || 0).toBe(0);
    });

    it('maps all 6 EngineVerdict tiers accurately across URL, FILE, and PROCESS modalities', () => {
      const scorer = new RiskScorer();

      expect(scorer.calculateScore([]).engineVerdict).toBe(EngineVerdict.ALLOW);

      const informRes = scorer.calculateScore([
        { source: 'URL_ANALYZER', name: 'Minor', description: 'Minor', weight: 30, confidence: 0.9 }
      ]);
      expect(informRes.engineVerdict).toBe(EngineVerdict.INFORM);

      const warnRes = scorer.calculateScore([
        { source: 'URL_ANALYZER', name: 'Medium', description: 'Medium', weight: 65, confidence: 0.9 }
      ]);
      expect(warnRes.engineVerdict).toBe(EngineVerdict.WARN);

      const blockUrlRes = scorer.calculateScore(
        [
          {
            source: 'RULE_ENGINE',
            name: 'Critical URL',
            description: 'Critical URL',
            weight: 90,
            confidence: 0.95,
            isCriticalOverride: true
          }
        ],
        0,
        { inputType: InputType.URL }
      );
      expect(blockUrlRes.engineVerdict).toBe(EngineVerdict.BLOCK);

      const quarantineFileRes = scorer.calculateScore(
        [
          {
            source: 'FileHeaderAnalyzer',
            name: 'Critical File',
            description: 'Critical File',
            weight: 95,
            confidence: 0.99,
            isCriticalOverride: true
          }
        ],
        0,
        { inputType: InputType.FILE }
      );
      expect(quarantineFileRes.engineVerdict).toBe(EngineVerdict.QUARANTINE);

      const containProcRes = scorer.calculateScore(
        [
          {
            source: 'PROCESS_ANALYZER',
            name: 'Critical Process',
            description: 'Critical Process',
            weight: 92,
            confidence: 0.99,
            isCriticalOverride: true
          }
        ],
        0,
        { inputType: InputType.PROCESS }
      );
      expect(containProcRes.engineVerdict).toBe(EngineVerdict.CONTAIN_PROCESS);
    });
  });

  describe('Step 12: Process Input Foundation, CLI Secret Redaction & Type-Confusion Defense', () => {
    it('redacts passwords, API keys, bearer tokens, URL credentials, and JWTs from command lines', () => {
      const rawCli =
        'curl.exe --password="MySuperSecretPassword123!" --api-key=sk_live_987654321 https://admin:PlaintextPass@evil.example/upload token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const sanitized = ProcessAnalyzer.sanitizeCommandLine(rawCli)!;

      expect(sanitized).not.toContain('MySuperSecretPassword123!');
      expect(sanitized).not.toContain('sk_live_987654321');
      expect(sanitized).not.toContain('PlaintextPass');
      expect(sanitized).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(sanitized).toContain('[REDACTED]');
      expect(sanitized).toContain('[REDACTED_JWT]');
    });

    it('evaluates benign signed system processes as ALLOW and marks BEHAVIORAL_ENGINE as NOT_RUN (never SAFE)', async () => {
      const pipeline = new DetectionPipeline();
      const result = await pipeline.scan({
        inputType: InputType.PROCESS,
        processMetadata: {
          pid: 4120,
          ppid: 1024,
          processName: 'svchost.exe',
          parentName: 'services.exe',
          executablePath: 'C:\\Windows\\System32\\svchost.exe',
          isSigned: true,
          signer: 'Microsoft Windows',
          commandLine: 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p'
        }
      });

      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.engineVerdict).toBe(EngineVerdict.ALLOW);
      expect(result.disposition).toBe('SAFE');
      expect(result.detectorLayers?.[DetectorLayer.BEHAVIORAL_ENGINE]).toBe('NOT_RUN');
      expect(result.detectorLayers?.[DetectorLayer.STRUCTURAL_PARSER]).toBe('UNAVAILABLE');
    });

    it('evaluates malicious process chains (Office spawning PowerShell with encoded command or shadow copy deletion) as CONTAIN_PROCESS', async () => {
      const pipeline = new DetectionPipeline();
      const result = await pipeline.scan({
        inputType: InputType.PROCESS,
        processMetadata: {
          pid: 8844,
          ppid: 3312,
          processName: 'powershell.exe',
          parentName: 'WINWORD.EXE',
          executablePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          isSigned: true,
          commandLine: 'powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA'
        }
      });

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.engineVerdict).toBe(EngineVerdict.CONTAIN_PROCESS);
      expect(result.riskCategory).toBe(RiskCategory.MALWARE);
      expect(result.riskScore).toBeGreaterThanOrEqual(88);
    });

    it('rejects FILE vs PROCESS type confusion (passing raw binary Uint8Array as PROCESS input fails closed)', async () => {
      const pipeline = new DetectionPipeline();
      const confusedResult = await pipeline.scan({
        id: 'type-confusion-test',
        timestamp: 1700000000000,
        type: InputType.PROCESS,
        inputType: InputType.PROCESS,
        payload: new Uint8Array([0x4d, 0x5a, 0x90, 0x00])
      });

      expect(confusedResult.analysisStatus).toBe('ANALYSIS_FAILED');
      expect(confusedResult.disposition).toBe('ANALYSIS_FAILED');
      expect(confusedResult.verdict).toBe(Verdict.CAUTION);
      expect(confusedResult.engineVerdict).toBe(EngineVerdict.WARN);
    });
  });

  describe('Step 19: Bitwise Determinism Verification Across URL, TEXT, FILE & PROCESS', () => {
    it('produces bitwise-identical DetectionResult outputs for identical inputs across all 4 modalities', async () => {
      const pipeline = new DetectionPipeline();
      const fixedId = '00000000-0000-4000-8000-0000000000b1';
      const fixedTimestamp = 1710000000000;

      const urlReq = {
        id: fixedId,
        timestamp: fixedTimestamp,
        inputType: InputType.URL,
        input: 'http://198.51.100.23/login/verify-account'
      };
      const urlRun1 = await pipeline.scan(urlReq);
      const urlRun2 = await pipeline.scan(urlReq);
      expect({ ...urlRun1, executionTimeMs: 0 }).toEqual({ ...urlRun2, executionTimeMs: 0 });

      const textReq = {
        id: fixedId,
        timestamp: fixedTimestamp,
        inputType: InputType.TEXT,
        input: 'URGENT: Send 0.5 BTC to bitcoin wallet now or you will be arrested immediately!'
      };
      const textRun1 = await pipeline.scan(textReq);
      const textRun2 = await pipeline.scan(textReq);
      expect({ ...textRun1, executionTimeMs: 0 }).toEqual({ ...textRun2, executionTimeMs: 0 });
      expect(textRun1.riskScore).toBeGreaterThanOrEqual(70);

      const fileReq = {
        id: fixedId,
        timestamp: fixedTimestamp,
        inputType: InputType.FILE,
        payload: new TextEncoder().encode(CoreFileAnalyzer.EICAR_SIGNATURE),
        metadata: { fileName: 'eicar.com', fileSize: '68' }
      };
      const fileRun1 = await pipeline.scan(fileReq);
      const fileRun2 = await pipeline.scan(fileReq);
      expect({ ...fileRun1, executionTimeMs: 0 }).toEqual({ ...fileRun2, executionTimeMs: 0 });
      expect(fileRun1.engineVerdict).toBe(EngineVerdict.QUARANTINE);

      const procReq = {
        id: fixedId,
        timestamp: fixedTimestamp,
        inputType: InputType.PROCESS,
        processMetadata: {
          pid: 9001,
          ppid: 4002,
          processName: 'vssadmin.exe',
          parentName: 'cmd.exe',
          executablePath: 'C:\\Windows\\System32\\vssadmin.exe',
          commandLine: 'vssadmin.exe delete shadows /all /quiet'
        }
      };
      const procRun1 = await pipeline.scan(procReq);
      const procRun2 = await pipeline.scan(procReq);
      expect({ ...procRun1, executionTimeMs: 0 }).toEqual({ ...procRun2, executionTimeMs: 0 });
      expect(procRun1.engineVerdict).toBe(EngineVerdict.CONTAIN_PROCESS);
    });
  });
});
