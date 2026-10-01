import { Verdict, SeverityLevel } from '@private-protection/core';

export interface VerdictVisuals {
  readonly label: string;
  readonly badgeBg: string;
  readonly badgeText: string;
  readonly borderColor: string;
  readonly iconName: string;
}

export function getVerdictVisuals(verdict: Verdict): VerdictVisuals {
  switch (verdict) {
    case Verdict.DANGEROUS:
      return {
        label: 'DANGEROUS THREAT',
        badgeBg: '#450a0a',
        badgeText: '#fca5a5',
        borderColor: '#ef4444',
        iconName: 'CRITICAL_ALERT'
      };
    case Verdict.SUSPICIOUS:
      return {
        label: 'SUSPICIOUS',
        badgeBg: '#431407',
        badgeText: '#fdba74',
        borderColor: '#f97316',
        iconName: 'WARNING'
      };
    case Verdict.CAUTION:
      return {
        label: 'CAUTION ADVISED',
        badgeBg: '#451a03',
        badgeText: '#fde047',
        borderColor: '#f59e0b',
        iconName: 'CAUTION'
      };
    case Verdict.INFORM:
      return {
        label: 'INFORMATIONAL',
        badgeBg: '#172554',
        badgeText: '#93c5fd',
        borderColor: '#3b82f6',
        iconName: 'INFO'
      };
    case Verdict.ALLOW:
    default:
      return {
        label: 'SAFE',
        badgeBg: '#022c22',
        badgeText: '#6ee7b7',
        borderColor: '#10b981',
        iconName: 'SHIELD_CHECK'
      };
  }
}

export function formatSeverity(severity: SeverityLevel): string {
  switch (severity) {
    case SeverityLevel.CRITICAL:
      return 'Critical';
    case SeverityLevel.HIGH:
      return 'High';
    case SeverityLevel.MEDIUM:
      return 'Medium';
    case SeverityLevel.LOW:
      return 'Low';
    case SeverityLevel.NONE:
    default:
      return 'None';
  }
}

export function sanitizeDisplayString(str: string): string {
  if (!str) return '';
  return str.replace(/[<>&"']/g, (char) => {
    switch (char) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default: return char;
    }
  });
}

export function escapeHtml(str: string): string {
  return sanitizeDisplayString(str);
}

export function formatRiskScore(score: number): { label: string; color: string } {
  if (score >= 85) return { label: 'Critical Risk', color: '#ef4444' };
  if (score >= 70) return { label: 'High Risk', color: '#f97316' };
  if (score >= 50) return { label: 'Moderate Risk', color: '#eab308' };
  if (score >= 20) return { label: 'Low Risk', color: '#3b82f6' };
  return { label: 'Zero Risk (Safe)', color: '#10b981' };
}

export function formatVerdict(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.DANGEROUS: return 'Dangerous Threat';
    case Verdict.SUSPICIOUS: return 'Suspicious Caution';
    case Verdict.CAUTION: return 'Caution Advised';
    case Verdict.INFORM: return 'Informational';
    case Verdict.ALLOW:
    default:
      return 'Safe / Allowed';
  }
}

export function truncateText(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) return text || '';
  return text.slice(0, maxLength - 3) + '...';
}
