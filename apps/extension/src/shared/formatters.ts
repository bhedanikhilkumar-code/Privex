import { Verdict, SeverityLevel } from '@private-protection/core';

export function escapeHtml(str: string): string {
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

export function formatRiskScore(score: number): { label: string; color: string } {
  if (score >= 85) return { label: 'Critical Risk', color: '#ef4444' };
  if (score >= 70) return { label: 'High Risk', color: '#f97316' };
  if (score >= 50) return { label: 'Moderate Risk', color: '#eab308' };
  if (score >= 20) return { label: 'Low Risk', color: '#3b82f6' };
  return { label: 'Safe', color: '#10b981' };
}

export function formatVerdict(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.DANGEROUS: return 'DANGEROUS THREAT';
    case Verdict.SUSPICIOUS: return 'SUSPICIOUS (CAUTION)';
    case Verdict.CAUTION: return 'CAUTION ADVISED';
    case Verdict.INFORM: return 'INFORMATIONAL';
    case Verdict.ALLOW:
    default:
      return 'SAFE / ALLOWED';
  }
}

export function formatSeverity(severity: SeverityLevel): string {
  switch (severity) {
    case SeverityLevel.CRITICAL: return 'Critical';
    case SeverityLevel.HIGH: return 'High';
    case SeverityLevel.MEDIUM: return 'Medium';
    case SeverityLevel.LOW: return 'Low';
    case SeverityLevel.NONE:
    default:
      return 'None';
  }
}

export function extractDomain(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return rawUrl;
  }
}

export function isRestrictedUrl(url: string): boolean {
  if (!url) return true;
  const lower = url.toLowerCase().trim();
  return (
    lower.startsWith('chrome://') ||
    lower.startsWith('chrome-extension://') ||
    lower.startsWith('edge://') ||
    lower.startsWith('about:') ||
    lower.startsWith('view-source:') ||
    lower.startsWith('devtools://') ||
    lower.startsWith('data:') ||
    lower.startsWith('blob:')
  );
}
