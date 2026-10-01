import { Verdict } from '@private-protection/core';
import { AssistantInput, AssistantOutput } from '../types';

export class TemplateFallbackEngine {
  /**
   * Generates a deterministic, jargon-free security explanation conforming to Grade 6 reading levels.
   * Executed instantaneously (< 0.1 ms) when the AI model is uninitialized, timed out, or compromised.
   */
  public static generateFallback(input: AssistantInput, executionTimeMs: number = 0.05): AssistantOutput {
    const verdict = input.verdict;
    const primaryFactor = (input.riskAssessment.primaryThreatFactor || 'suspicious-activity').toLowerCase();
    const isOffline = true; // Safe offline assumption

    let headline = 'Security Notice';
    let summaryParagraph = 'We checked this content for digital safety threats.';
    let dangerFactors: string[] = ['Unusual patterns detected during inspection.'];
    let recommendedSteps: string[] = ['Check the source carefully before proceeding.'];
    let uncertaintyNote = 'Verified locally using on-device security rules.';

    if (verdict === Verdict.ALLOW) {
      headline = 'Verified Safe to Proceed';
      summaryParagraph = 'No known security threats or deceptive tricks were found in this content.';
      dangerFactors = ['Content matches known safe standards.'];
      recommendedSteps = ['You can safely proceed with this activity.'];
      uncertaintyNote = 'Verified locally on your device.';
    } else if (verdict === Verdict.INFORM) {
      headline = 'Low Risk: Verify Sender';
      summaryParagraph = 'This content contains minor flags that sometimes appear in suspicious messages.';
      dangerFactors = [
        'Unusual wording or unfamiliar web address format.',
        'Request for your attention or contact.'
      ];
      recommendedSteps = [
        'Confirm who sent this before replying or clicking.',
        'Do not share personal account details.'
      ];
      uncertaintyNote = 'Low risk detected by local threat filters.';
    } else if (primaryFactor.includes('ransom') || primaryFactor.includes('extortion') || primaryFactor.includes('threat')) {
      headline = 'High Risk: Extortion Scam Detected';
      summaryParagraph = 'This message uses fake threats and urgency to pressure you into paying money. Criminals use fear tactics to steal your savings.';
      dangerFactors = [
        'Demands immediate payment via untraceable methods.',
        'Threatens legal action, device locking, or embarrassment.'
      ];
      recommendedSteps = [
        'Do not send any money, cryptocurrency, or gift cards.',
        'Block and delete the sender immediately.',
        'Do not reply or click any links.'
      ];
      uncertaintyNote = 'Identified by local extortion pattern matching.';
    } else if (primaryFactor.includes('job') || primaryFactor.includes('task') || primaryFactor.includes('employment')) {
      headline = 'Warning: Fake Job / Task Scam';
      summaryParagraph = 'This message promises unrealistic daily pay for simple online tasks. Scammers use this trick to steal deposits and personal information.';
      dangerFactors = [
        'Offers high daily pay for rating apps or simple tasks.',
        'Requires sending money or joining private chat groups.'
      ];
      recommendedSteps = [
        'Do not transfer money or share your bank account.',
        'Ignore and block the contact.',
        'Never pay money to get paid for a job.'
      ];
      uncertaintyNote = 'Identified by local task scam pattern rules.';
    } else if (primaryFactor.includes('brand') || primaryFactor.includes('phish') || primaryFactor.includes('typo')) {
      headline = 'Warning: Deceptive Fake Website';
      summaryParagraph = 'This website is pretending to be a real company to steal your login password. The web address is misleading.';
      dangerFactors = [
        'Website address looks similar to a trusted brand.',
        'Designed to steal your password or card number.'
      ];
      recommendedSteps = [
        'Do not enter your password or credit card.',
        'Close this tab or window right now.',
        'Type the company address yourself in a new tab.'
      ];
      uncertaintyNote = 'Blocked by local brand spoofing detection.';
    } else if (verdict === Verdict.DANGEROUS) {
      headline = 'Dangerous Threat Blocked';
      summaryParagraph = 'This content poses an immediate danger to your privacy and security. Our on-device security blocked access to protect you.';
      dangerFactors = [
        'Matches known malicious cyber-threat patterns.',
        'Could attempt to install malware or compromise accounts.'
      ];
      recommendedSteps = [
        'Do not open, download, or interact with this content.',
        'Delete this message or navigate away immediately.'
      ];
      uncertaintyNote = 'Hard security block enforced by local core engine.';
    } else {
      // CAUTION / SUSPICIOUS generic
      headline = 'Caution: Suspicious Content Detected';
      summaryParagraph = 'We noticed multiple warning signs in this content that are common in cyber scams and fake alerts.';
      dangerFactors = [
        'Urgent language asking for immediate action.',
        'Unverified links or unexpected requests.'
      ];
      recommendedSteps = [
        'Do not click links or call numbers provided.',
        'Verify the request through official channels directly.'
      ];
      uncertaintyNote = 'Analyzed locally on-device without cloud telemetry.';
    }

    return {
      headline,
      summaryParagraph,
      dangerFactors,
      recommendedSteps,
      uncertaintyNote,
      inferenceStatus: 'DETERMINISTIC_FALLBACK',
      executionTimeMs
    };
  }
}
