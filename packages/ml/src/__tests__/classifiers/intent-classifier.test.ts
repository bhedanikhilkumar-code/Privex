import { describe, it, expect, beforeEach } from 'vitest';
import { ScamIntentClassifier } from '../../classifiers/intent-classifier';
import { UrlSemanticClassifier } from '../../classifiers/semantic-classifier';
import { ModelLoader } from '../../models/model-loader';
import { DevelopmentMockModelProvider } from '../../models/providers/mock-provider';
import { ScamIntent } from '../../types';

describe('Classifiers (Intent & Semantic)', () => {
  let loader: ModelLoader;
  let mockProvider: DevelopmentMockModelProvider;
  let classifier: ScamIntentClassifier;
  let urlClassifier: UrlSemanticClassifier;

  beforeEach(() => {
    loader = new ModelLoader();
    mockProvider = new DevelopmentMockModelProvider();
    loader.registerProvider(mockProvider);
    classifier = new ScamIntentClassifier({
      modelLoader: loader,
      providerId: mockProvider.id
    });
    urlClassifier = new UrlSemanticClassifier();
  });

  describe('ScamIntentClassifier Fallback & Heuristic Path', () => {
    it('should classify task and employment scam messages', async () => {
      const res = await classifier.classify(
        'Work from home task! Earn $500 daily rating apps on Telegram. Deposit $50 to unlock commission.'
      );
      expect(res.intent).toBe(ScamIntent.EMPLOYMENT_TASK_SCAM);
      expect(res.confidence).toBeGreaterThan(0.6);
      expect(res.evidenceToken.scoreContribution).toBeGreaterThan(50);
      expect(res.isModelBacked).toBe(false); // Unloaded provider
    });

    it('should classify tech support auto-renewal invoice fraud', async () => {
      const res = await classifier.classify(
        'Invoice #49281: Your Geek Squad subscription renewed for $499. Call support immediately to refund.'
      );
      expect(res.intent).toBe(ScamIntent.TECH_SUPPORT_INVOICE);
      expect(res.confidence).toBeGreaterThan(0.6);
      expect(res.evidenceToken.scoreContribution).toBeGreaterThan(50);
    });

    it('should classify postal and delivery fee scams', async () => {
      const res = await classifier.classify(
        'USPS: Your package is detained due to incomplete address. Pay $1.99 redelivery fee to update address.'
      );
      expect(res.intent).toBe(ScamIntent.POSTAL_DELIVERY_FRAUD);
      expect(res.evidenceToken.scoreContribution).toBeGreaterThan(50);
    });

    it('should classify ransomware and extortion pressure', async () => {
      const res = await classifier.classify(
        'All your files are encrypted with military-grade cipher. Pay $1000 Bitcoin to decrypt or destroy data.'
      );
      expect(res.intent).toBe(ScamIntent.URGENCY_EXTORTION);
      expect(res.confidence).toBeGreaterThanOrEqual(0.85);
      expect(res.evidenceToken.scoreContribution).toBeGreaterThanOrEqual(80);
    });

    it('should return benign intent for everyday communications', async () => {
      const res = await classifier.classify(
        'Hi Sarah, see you tomorrow at lunch around 12:30 PM.'
      );
      expect(res.intent).toBe(ScamIntent.BENIGN_COMMUNICATION);
      expect(res.evidenceToken.scoreContribution).toBe(0);
    });
  });

  describe('ScamIntentClassifier Model Backed Execution', () => {
    it('should invoke model provider when provider is active and loaded', async () => {
      await loader.activateProvider(mockProvider.id);

      const res = await classifier.classify('Suspicious ambiguous message requiring model evaluation');
      expect(res.isModelBacked).toBe(true);
      expect(res.latencyMs).toBeGreaterThan(0);
      expect(res.uncertainty).toBeGreaterThan(0);
    });
  });

  describe('UrlSemanticClassifier', () => {
    it('should identify semantic brand deception combined with phishing paths', () => {
      const res = urlClassifier.analyzeUrlSemantics('http://paypal-security-update.info/login/verify');
      expect(res.isDeceptive).toBe(true);
      expect(res.evidenceToken).toBeDefined();
      expect(res.evidenceToken?.scoreContribution).toBe(75);
    });

    it('should identify brand tokens on suspicious TLDs', () => {
      const res = urlClassifier.analyzeUrlSemantics('http://apple-support.buzz/portal');
      expect(res.isDeceptive).toBe(true);
      expect(res.evidenceToken?.scoreContribution).toBe(70);
    });

    it('should not flag legitimate top brand domains', () => {
      const res = urlClassifier.analyzeUrlSemantics('https://www.paypal.com/signin');
      expect(res.isDeceptive).toBe(false);
      expect(res.evidenceToken).toBeUndefined();
    });
  });
});
