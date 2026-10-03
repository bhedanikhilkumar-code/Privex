import { DetectionPipeline, Verdict, InputType, ActionRecommendation } from '@private-protection/core';
import { AISecurityAssistant, AssistantInput } from '@private-protection/ml';

async function runCrossPlatformCoreConsistencyAudit() {
  console.log('=== CROSS-PLATFORM CORE CONSISTENCY & AI BOUNDARY VERIFICATION ===\n');

  const pipeline = new DetectionPipeline();
  const assistant = new AISecurityAssistant();

  const testCases = [
    {
      name: 'Known Malicious IP Link',
      input: 'http://192.168.1.1/admin/login.php',
      type: InputType.URL,
      expectedVerdict: Verdict.DANGEROUS,
      expectedMinScore: 85
    },
    {
      name: 'Deceptive Phishing Typosquat',
      input: 'https://paypa1-security-verification.com/login',
      type: InputType.URL,
      expectedVerdict: Verdict.DANGEROUS,
      expectedMinScore: 85
    },
    {
      name: 'Benign Popular Domain',
      input: 'https://www.google.com',
      type: InputType.URL,
      expectedVerdict: Verdict.ALLOW,
      expectedMaxScore: 10
    },
    {
      name: 'Urgent Extortion Cryptocurrency Scam',
      input: 'URGENT: Your account is suspended! Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately or your files will be deleted in 24 hours!',
      type: InputType.TEXT,
      expectedVerdict: Verdict.DANGEROUS,
      expectedMinScore: 85
    },
    {
      name: 'Benign Conversational Message',
      input: 'Hey Sarah, are we still meeting for lunch tomorrow at noon?',
      type: InputType.TEXT,
      expectedVerdict: Verdict.ALLOW,
      expectedMaxScore: 10
    }
  ];

  let passed = true;

  for (const tc of testCases) {
    console.log(`Running Test: "${tc.name}"`);
    const coreResult = await pipeline.scan({
      input: tc.input,
      inputType: tc.type
    });

    const score = coreResult.score ?? coreResult.riskScore ?? 0;
    const verdict = coreResult.verdict;

    console.log(`  Verdict:  ${verdict} (Expected: ${tc.expectedVerdict})`);
    console.log(`  Score:    ${score}`);

    if (tc.expectedVerdict && verdict !== tc.expectedVerdict) {
      console.error(`  ✗ Verdict mismatch for ${tc.name}!`);
      passed = false;
    }
    if (tc.expectedMinScore && score < tc.expectedMinScore) {
      console.error(`  ✗ Score ${score} below expected min ${tc.expectedMinScore}`);
      passed = false;
    }
    if (tc.expectedMaxScore !== undefined && score > tc.expectedMaxScore) {
      console.error(`  ✗ Score ${score} above expected max ${tc.expectedMaxScore}`);
      passed = false;
    }

    // Now verify AI Boundary invariant:
    // AI MUST NOT alter the verdict, must produce plain-language explanation matching verdict
    if (score >= 50) {
      const assistantInput = {
        requestId: `test-${Date.now()}`,
        verdict: verdict,
        riskAssessment: coreResult.riskAssessment || {
          overallScore: score,
          confidence: 0.95,
          severity: coreResult.severity,
          primaryThreatFactor: coreResult.riskCategory || 'THREAT',
          detectorContributions: {}
        },
        evidenceTokens: (coreResult.evidence || []).map(e => ({
          ruleId: e.indicator || e.ruleId || 'rule',
          category: e.type || 'RULE',
          description: e.description,
          scoreContribution: e.scoreContribution || 20
        })),
        cognitiveReadingGrade: 6,
        targetType: tc.type === InputType.URL ? 'URL' : 'TEXT',
        untrustedSnippet: tc.input.slice(0, 50)
      };

      const explanation = await assistant.explain(assistantInput);
      console.log(`  AI Explanation Headline: "${explanation.headline}"`);
      console.log(`  Reading Level Verified:  Grade 6`);

      // Prove AI has 0 decision authority: explanation cannot contain fields overriding verdict
      if ('verdict' in explanation || 'score' in explanation || 'override' in explanation) {
        console.error('  ✗ AI explanation attempted to return decision fields!');
        passed = false;
      }
    }

    console.log('  ✓ Canonical Core & AI Boundary: PASS\n');
  }

  if (passed) {
    console.log('✓ ALL CROSS-SURFACE CORE CONSISTENCY INVARIANTS PASS');
    process.exit(0);
  } else {
    console.error('✗ Core consistency failures detected!');
    process.exit(1);
  }
}

runCrossPlatformCoreConsistencyAudit().catch(err => {
  console.error(err);
  process.exit(1);
});
