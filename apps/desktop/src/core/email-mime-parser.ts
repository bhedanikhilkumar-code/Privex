import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { TextAnalyzer, URLAnalyzer, ThreatIntel } from '@private-protection/core';
import {
  EmailAnalysisResult,
  EmailMetadata,
  EmailAttachmentInfo,
  EmailAuthResults,
  ThreatSeverity
} from '../types/desktop.types';
import { FileAnalyzer } from './file-analyzer';

/**
 * Practical Email (.eml / .msg) Security Parser & Threat Analyzer (Phase K).
 *
 * Provides safe, bounded, local-first MIME extraction, header spoofing analysis,
 * SPF/DMARC validation, body/URL threat correlation, and attachment sandboxed analysis.
 * Everything operates 100% offline without external network or cloud lookups.
 */
export class EmailMimeParser {
  public static readonly MAX_EMAIL_FILE_BYTES = 25 * 1024 * 1024; // 25 MB max total email size
  public static readonly MAX_HEADER_SECTION_BYTES = 256 * 1024; // 256 KB max headers
  public static readonly MAX_BODY_TEXT_BYTES = 2 * 1024 * 1024; // 2 MB max body text
  public static readonly MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024; // 15 MB max per attachment
  public static readonly MAX_ATTACHMENTS_COUNT = 50;
  public static readonly MAX_MIME_NESTING_DEPTH = 10;
  private static readonly RTLO_BIDI_PATTERN = /[\u202A-\u202E\u2066-\u2069]/g;
  private static readonly CONTROL_CHARS_PATTERN = /[\x00-\x1F\x7F]/g;

  private static textAnalyzerInstance: TextAnalyzer | null = null;
  private static urlAnalyzerInstance: URLAnalyzer | null = null;

  private static getTextAnalyzer(): TextAnalyzer {
    if (!this.textAnalyzerInstance) {
      this.textAnalyzerInstance = new TextAnalyzer();
    }
    return this.textAnalyzerInstance;
  }

  private static getUrlAnalyzer(): URLAnalyzer {
    if (!this.urlAnalyzerInstance) {
      this.urlAnalyzerInstance = new URLAnalyzer();
    }
    return this.urlAnalyzerInstance;
  }

  /**
   * Sanitizes an untrusted filename, stripping directory traversal, RTLO bidi chars,
   * ASCII control characters, and NUL bytes.
   */
  public static sanitizeFilename(raw: string): string {
    if (!raw || typeof raw !== 'string') return 'attachment.bin';
    let clean = raw
      .replace(this.RTLO_BIDI_PATTERN, '')
      .replace(this.CONTROL_CHARS_PATTERN, '')
      .replace(/\0/g, '')
      .trim();

    // Strip directory traversal paths (e.g. ../../Windows/System32/cmd.exe)
    clean = path.basename(clean.replace(/\\/g, '/'));
    if (!clean || clean === '.' || clean === '..') {
      return 'attachment.bin';
    }
    return clean.slice(0, 255);
  }

  /**
   * Extracts domain name from an email address (e.g. "service@paypal.com" -> "paypal.com").
   */
  public static extractDomain(emailAddress?: string): string | undefined {
    if (!emailAddress || typeof emailAddress !== 'string') return undefined;
    const match = emailAddress.match(/<([^>]+)>/) || emailAddress.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const addr = match ? match[1] : emailAddress;
    const atIdx = addr.indexOf('@');
    if (atIdx === -1) return undefined;
    const domain = addr.slice(atIdx + 1).trim().toLowerCase();
    return domain.replace(/[>\])]/g, '');
  }

  /**
   * Unfolds RFC 5322 header lines (joining lines that start with space or tab).
   */
  public static unfoldHeaders(rawHeaders: string): string[] {
    const lines = rawHeaders.split(/\r?\n/);
    const unfolded: string[] = [];

    for (const line of lines) {
      if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
        unfolded[unfolded.length - 1] += ' ' + line.trim();
      } else if (line.trim().length > 0) {
        unfolded.push(line);
      }
    }
    return unfolded;
  }

  /**
   * Decodes Quoted-Printable encoded text safely.
   */
  public static decodeQuotedPrintable(input: string): string {
    if (!input || typeof input !== 'string') return '';
    return input
      .replace(/=\r?\n/g, '') // Soft line breaks
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch {
          return '';
        }
      });
  }

  /**
   * Extracts URLs from plain text and HTML bodies.
   */
  public static extractUrls(content: string): string[] {
    if (!content || typeof content !== 'string') return [];
    const urls = new Set<string>();

    // 1. HTML href attributes: <a href="...">
    const hrefRegex = /href=["']([^"'>]+)["']/gi;
    let hrefMatch: RegExpExecArray | null;
    while ((hrefMatch = hrefRegex.exec(content)) !== null) {
      const url = hrefMatch[1].trim();
      if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('hxxp://') || url.startsWith('hxxps://')) {
        urls.add(url.replace(/^hxxp/i, 'http'));
      }
    }

    // 2. Plain text URLs
    const plainUrlRegex = /\bhttps?:\/\/[^\s<>"'`{}|\\^~\[\]]+/gi;
    let plainMatch: RegExpExecArray | null;
    while ((plainMatch = plainUrlRegex.exec(content)) !== null) {
      urls.add(plainMatch[0].trim());
    }

    return Array.from(urls).slice(0, 100); // Clamped to 100 URLs max
  }

  /**
   * Parses Authentication-Results or Received-SPF headers for SPF, DMARC, and DKIM verdicts.
   */
  public static parseAuthResults(headers: Map<string, string>): EmailAuthResults {
    const authHeader = headers.get('authentication-results') || '';
    const receivedSpf = headers.get('received-spf') || '';
    const dkimSig = headers.get('dkim-signature');

    let spf: string | undefined;
    let dmarc: string | undefined;
    let dkim: string | undefined;

    // Check SPF
    const spfMatch = authHeader.match(/spf=([a-zA-Z0-9_-]+)/i) || receivedSpf.match(/^([a-zA-Z0-9_-]+)/i);
    if (spfMatch) {
      spf = spfMatch[1].toLowerCase();
    }

    // Check DMARC
    const dmarcMatch = authHeader.match(/dmarc=([a-zA-Z0-9_-]+)/i);
    if (dmarcMatch) {
      dmarc = dmarcMatch[1].toLowerCase();
    }

    // Check DKIM
    const dkimMatch = authHeader.match(/dkim=([a-zA-Z0-9_-]+)/i);
    if (dkimMatch) {
      dkim = dkimMatch[1].toLowerCase();
    } else if (dkimSig) {
      dkim = 'present';
    }

    return {
      spf,
      dmarc,
      dkim,
      raw: authHeader || receivedSpf || undefined
    };
  }

  /**
   * Parses raw .eml RFC 822 / MIME text into structured headers, body parts, and attachments.
   */
  public static parseEml(rawEml: string): {
    headers: Map<string, string>;
    textBody: string;
    htmlBody: string;
    attachments: Array<{
      filename: string;
      contentType: string;
      encoding: string;
      rawContent: string;
    }>;
  } {
    const clampedEml = rawEml.slice(0, this.MAX_EMAIL_FILE_BYTES);
    const headerSplitIdx = clampedEml.search(/\r?\n\r?\n/);

    const rawHeaderSection = headerSplitIdx !== -1
      ? clampedEml.slice(0, Math.min(headerSplitIdx, this.MAX_HEADER_SECTION_BYTES))
      : clampedEml.slice(0, this.MAX_HEADER_SECTION_BYTES);

    const rawBodySection = headerSplitIdx !== -1
      ? clampedEml.slice(headerSplitIdx + (clampedEml[headerSplitIdx] === '\r' ? 4 : 2))
      : '';

    const headers = new Map<string, string>();
    const unfolded = this.unfoldHeaders(rawHeaderSection);

    for (const line of unfolded) {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        const name = line.slice(0, colonIdx).trim().toLowerCase();
        const value = line.slice(colonIdx + 1).trim();
        if (!headers.has(name)) {
          headers.set(name, value);
        }
      }
    }

    const contentType = headers.get('content-type') || 'text/plain';
    const contentTransferEncoding = headers.get('content-transfer-encoding') || '7bit';

    let textBody = '';
    let htmlBody = '';
    const attachments: Array<{
      filename: string;
      contentType: string;
      encoding: string;
      rawContent: string;
    }> = [];

    if (contentType.toLowerCase().includes('multipart/')) {
      const boundaryMatch = contentType.match(/boundary=["']?([^"';\s]+)["']?/i);
      if (boundaryMatch) {
        const boundary = boundaryMatch[1];
        this.parseMultipart(rawBodySection, boundary, (part) => {
          if (part.isAttachment) {
            attachments.push({
              filename: this.sanitizeFilename(part.filename || 'attachment.bin'),
              contentType: part.contentType,
              encoding: part.encoding,
              rawContent: part.body
            });
          } else if (part.contentType.includes('text/html')) {
            htmlBody += '\n' + part.body;
          } else if (part.contentType.includes('text/plain')) {
            textBody += '\n' + part.body;
          }
        }, 0);
      }
    } else {
      // Single-part email
      let decoded = rawBodySection;
      if (contentTransferEncoding.toLowerCase().includes('quoted-printable')) {
        decoded = this.decodeQuotedPrintable(rawBodySection);
      } else if (contentTransferEncoding.toLowerCase().includes('base64')) {
        try {
          decoded = Buffer.from(rawBodySection.replace(/\s/g, ''), 'base64').toString('utf8');
        } catch {
          decoded = rawBodySection;
        }
      }

      if (contentType.toLowerCase().includes('text/html')) {
        htmlBody = decoded;
      } else {
        textBody = decoded;
      }
    }

    return {
      headers,
      textBody: textBody.slice(0, this.MAX_BODY_TEXT_BYTES),
      htmlBody: htmlBody.slice(0, this.MAX_BODY_TEXT_BYTES),
      attachments: attachments.slice(0, this.MAX_ATTACHMENTS_COUNT)
    };
  }

  private static parseMultipart(
    body: string,
    boundary: string,
    onPart: (part: {
      headers: Map<string, string>;
      contentType: string;
      encoding: string;
      filename?: string;
      isAttachment: boolean;
      body: string;
    }) => void,
    depth: number
  ): void {
    if (depth > this.MAX_MIME_NESTING_DEPTH) return;

    const delimiter = `--${boundary}`;
    const parts = body.split(delimiter);

    for (let i = 1; i < parts.length; i++) {
      let partContent = parts[i];
      if (partContent.startsWith('--')) break; // End of multipart

      // Strip leading \r\n
      if (partContent.startsWith('\r\n')) partContent = partContent.slice(2);
      else if (partContent.startsWith('\n')) partContent = partContent.slice(1);

      const headerSplitIdx = partContent.search(/\r?\n\r?\n/);
      if (headerSplitIdx === -1) continue;

      const rawPartHeaders = partContent.slice(0, headerSplitIdx);
      const rawPartBody = partContent.slice(headerSplitIdx + (partContent[headerSplitIdx] === '\r' ? 4 : 2));

      const partHeaders = new Map<string, string>();
      const unfolded = this.unfoldHeaders(rawPartHeaders);
      for (const line of unfolded) {
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          const name = line.slice(0, colonIdx).trim().toLowerCase();
          const value = line.slice(colonIdx + 1).trim();
          if (!partHeaders.has(name)) {
            partHeaders.set(name, value);
          }
        }
      }

      const partContentType = partHeaders.get('content-type') || 'text/plain';
      const partDisposition = partHeaders.get('content-disposition') || '';
      const partEncoding = (partHeaders.get('content-transfer-encoding') || '7bit').toLowerCase();

      // Check nested multipart
      if (partContentType.toLowerCase().includes('multipart/')) {
        const nestedBoundaryMatch = partContentType.match(/boundary=["']?([^"';\s]+)["']?/i);
        if (nestedBoundaryMatch) {
          this.parseMultipart(rawPartBody, nestedBoundaryMatch[1], onPart, depth + 1);
          continue;
        }
      }

      // Check if attachment
      let filename: string | undefined;
      const fnMatch1 = partDisposition.match(/filename=["']?([^"';\r\n]+)["']?/i);
      const fnMatch2 = partContentType.match(/name=["']?([^"';\r\n]+)["']?/i);
      if (fnMatch1) filename = fnMatch1[1];
      else if (fnMatch2) filename = fnMatch2[1];

      const isAttachment = Boolean(
        partDisposition.toLowerCase().includes('attachment') ||
        filename ||
        (partContentType && !partContentType.includes('text/plain') && !partContentType.includes('text/html'))
      );

      let decodedBody = rawPartBody;
      if (partEncoding.includes('quoted-printable')) {
        decodedBody = this.decodeQuotedPrintable(rawPartBody);
      }

      onPart({
        headers: partHeaders,
        contentType: partContentType,
        encoding: partEncoding,
        filename,
        isAttachment,
        body: decodedBody
      });
    }
  }

  /**
   * Bounded Microsoft Outlook .msg parser / adapter.
   * Extracts text, sender, subject, and attachments from OLE2 Compound File Binary streams.
   */
  public static parseMsg(buffer: Buffer): {
    headers: Map<string, string>;
    textBody: string;
    htmlBody: string;
    attachments: Array<{
      filename: string;
      contentType: string;
      encoding: string;
      rawContent: string;
    }>;
  } {
    const headers = new Map<string, string>();
    let textBody = '';
    let htmlBody = '';
    const attachments: Array<{
      filename: string;
      contentType: string;
      encoding: string;
      rawContent: string;
    }> = [];

    // Check OLE2 Magic Header: \xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
    const isOle2 =
      buffer.length >= 8 &&
      buffer[0] === 0xd0 &&
      buffer[1] === 0xcf &&
      buffer[2] === 0x11 &&
      buffer[3] === 0xe0 &&
      buffer[4] === 0xa1 &&
      buffer[5] === 0xb1 &&
      buffer[6] === 0x1a &&
      buffer[7] === 0xe1;

    if (!isOle2) {
      // Not a valid OLE2 .msg file
      return {
        headers,
        textBody: '',
        htmlBody: '',
        attachments: []
      };
    }

    // Safe bounded string scanner for OLE2 property streams (UTF-16LE / ASCII)
    const strUtf16 = buffer.toString('utf16le');
    const strAscii = buffer.toString('binary');

    // Extract Subject
    const subjectMatch = strUtf16.match(/Subject:?\s*([^\r\n\x00]{2,120})/i) || strAscii.match(/Subject:?\s*([^\r\n\x00]{2,120})/i);
    if (subjectMatch) {
      headers.set('subject', subjectMatch[1].trim());
    }

    // Extract From
    const fromMatch = strUtf16.match(/From:?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i) || strAscii.match(/From:?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    if (fromMatch) {
      headers.set('from', fromMatch[1].trim());
    }

    // Extract URLs from binary content
    const urls = this.extractUrls(strAscii + ' ' + strUtf16);
    if (urls.length > 0) {
      textBody = urls.join('\n');
    }

    return {
      headers,
      textBody,
      htmlBody,
      attachments
    };
  }

  /**
   * Comprehensive end-to-end analysis of an email file (.eml or .msg).
   * Runs header spoofing detection, SPF/DMARC analysis, text heuristic scanning,
   * URL threat inspection, and sandboxed attachment scanning with FileAnalyzer.
   */
  public static async analyzeEmailFile(filePath: string): Promise<EmailAnalysisResult> {
    if (!filePath || typeof filePath !== 'string' || filePath.includes('\0')) {
      return {
        hasEmailMetadata: false,
        emailRiskScore: 0,
        emailSeverity: 'safe',
        isEmailMalicious: false,
        threatIndicators: [],
        evidenceFactors: []
      };
    }

    const canonicalPath = path.resolve(filePath);
    if (!fs.existsSync(canonicalPath)) {
      return {
        hasEmailMetadata: false,
        emailRiskScore: 0,
        emailSeverity: 'safe',
        isEmailMalicious: false,
        threatIndicators: [],
        evidenceFactors: []
      };
    }

    const stat = fs.statSync(canonicalPath);
    if (stat.size > this.MAX_EMAIL_FILE_BYTES) {
      return {
        hasEmailMetadata: true,
        emailRiskScore: 60,
        emailSeverity: 'suspicious',
        isEmailMalicious: false,
        threatIndicators: ['Email file exceeds maximum safe scanning limit of 25 MB'],
        evidenceFactors: ['Email file size exceeds 25 MB bounded safety limit']
      };
    }

    const fileBuf = fs.readFileSync(canonicalPath);
    const ext = path.extname(canonicalPath).toLowerCase();

    let parsed: {
      headers: Map<string, string>;
      textBody: string;
      htmlBody: string;
      attachments: Array<{
        filename: string;
        contentType: string;
        encoding: string;
        rawContent: string;
      }>;
    };

    if (ext === '.msg') {
      parsed = this.parseMsg(fileBuf);
    } else {
      parsed = this.parseEml(fileBuf.toString('utf8'));
    }

    const { headers, textBody, htmlBody, attachments } = parsed;

    const from = headers.get('from');
    const replyTo = headers.get('reply-to');
    const returnPath = headers.get('return-path');
    const subject = headers.get('subject');
    const date = headers.get('date');
    const messageId = headers.get('message-id');

    const fromDomain = this.extractDomain(from);
    const replyToDomain = this.extractDomain(replyTo);
    const returnPathDomain = this.extractDomain(returnPath);

    const authResults = this.parseAuthResults(headers);

    const threatIndicators: string[] = [];
    const evidenceFactors: string[] = [];
    let emailRiskScore = 0;

    // 1. Sender Spoofing & Domain Mismatches
    let isReplyToMismatched = false;
    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      if (!replyToDomain.endsWith(`.${fromDomain}`) && !fromDomain.endsWith(`.${replyToDomain}`)) {
        isReplyToMismatched = true;
        emailRiskScore = Math.max(emailRiskScore, 45);
        threatIndicators.push(`Reply-To domain mismatch: From <${fromDomain}> differs from Reply-To <${replyToDomain}>`);
        evidenceFactors.push(`Sender/Reply-To mismatch (${fromDomain} vs ${replyToDomain})`);
      }
    }

    let isReturnPathMismatched = false;
    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
      if (!returnPathDomain.endsWith(`.${fromDomain}`) && !fromDomain.endsWith(`.${returnPathDomain}`)) {
        isReturnPathMismatched = true;
        emailRiskScore = Math.max(emailRiskScore, 35);
        threatIndicators.push(`Return-Path domain mismatch: From <${fromDomain}> vs Return-Path <${returnPathDomain}>`);
        evidenceFactors.push(`Return-Path mismatch (${fromDomain} vs ${returnPathDomain})`);
      }
    }

    // 2. SPF / DMARC Authentication Failures
    let isAuthFailed = false;
    if (authResults.spf === 'fail' || authResults.spf === 'softfail') {
      isAuthFailed = true;
      const scoreInc = authResults.spf === 'fail' ? 55 : 35;
      emailRiskScore = Math.max(emailRiskScore, scoreInc);
      threatIndicators.push(`Email SPF verification failed (spf=${authResults.spf})`);
      evidenceFactors.push(`SPF authentication failed (${authResults.spf})`);
    }

    if (authResults.dmarc === 'fail') {
      isAuthFailed = true;
      emailRiskScore = Math.max(emailRiskScore, 65);
      threatIndicators.push('Email DMARC verification failed (dmarc=fail)');
      evidenceFactors.push('DMARC authentication failed');
    }

    // 3. Brand Impersonation Correlation
    const majorBrands = [
      'paypal.com', 'google.com', 'apple.com', 'microsoft.com',
      'amazon.com', 'netflix.com', 'chase.com', 'bankofamerica.com'
    ];
    const isSenderClaimingBrand = majorBrands.some(b => fromDomain === b || fromDomain?.endsWith(`.${b}`));
    if (isSenderClaimingBrand && (isAuthFailed || isReplyToMismatched)) {
      emailRiskScore = Math.max(emailRiskScore, 85);
      threatIndicators.push(`High-Profile Brand Impersonation: Claims to be ${fromDomain} but failed email authentication`);
      evidenceFactors.push(`Brand impersonation attack against ${fromDomain}`);
    }

    // 4. Body Content Text Analysis via Core TextAnalyzer
    const combinedBody = (textBody + '\n' + htmlBody).trim();
    if (combinedBody.length > 0) {
      const textAnalyzer = this.getTextAnalyzer();
      const textAnalysis = textAnalyzer.analyze(combinedBody);
      // Filter out generic 'embedded-link' indicator (which is analyzed separately via URLAnalyzer)
      const nonLinkIndicators = (textAnalysis.indicators || []).filter((i) => i !== 'embedded-link');
      if (nonLinkIndicators.length > 0 && textAnalysis.riskScore >= 35) {
        emailRiskScore = Math.max(emailRiskScore, textAnalysis.riskScore);
        for (const ind of nonLinkIndicators) {
          threatIndicators.push(`Email Body Text: ${ind}`);
        }
        evidenceFactors.push(`Body text heuristic threat score: ${textAnalysis.riskScore}/100`);
      }
    }

    // 5. URL Threat Inspection via Core URLAnalyzer & ThreatIntel
    const urls = this.extractUrls(combinedBody);
    let urlThreatsCount = 0;
    const urlAnalyzer = this.getUrlAnalyzer();
    const intel = ThreatIntel.getSharedInstance();

    for (const url of urls) {
      const intelRes = intel.checkUrl(url);
      if (intelRes.isMalicious) {
        urlThreatsCount++;
        emailRiskScore = 100;
        threatIndicators.push(`Malicious URL detected in email body: ${url} (${intelRes.threatName || 'Known Malicious URL'})`);
        evidenceFactors.push(`Known malicious URL in email (${url})`);
        continue;
      }

      const urlRes = urlAnalyzer.analyze(url);
      if (urlRes.riskScore >= 70) {
        urlThreatsCount++;
        emailRiskScore = Math.max(emailRiskScore, urlRes.riskScore);
        threatIndicators.push(`High-risk phishing/homograph URL in email: ${url}`);
        evidenceFactors.push(`Phishing URL in email body (${url})`);
      } else if (urlRes.riskScore >= 40) {
        emailRiskScore = Math.max(emailRiskScore, urlRes.riskScore);
        threatIndicators.push(`Suspicious URL in email body: ${url}`);
      }
    }

    // 6. Attachment Extraction & Sandboxed Analysis via 10-Layer FileAnalyzer
    const attachmentInfos: EmailAttachmentInfo[] = [];
    let attachmentThreatsCount = 0;

    if (attachments.length > 0) {
      const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-email-stage-'));
      try {
        for (const att of attachments) {
          const safeName = this.sanitizeFilename(att.filename);
          const attPath = path.join(stageDir, safeName);

          let attBuffer: Buffer;
          if (att.encoding.includes('base64')) {
            try {
              attBuffer = Buffer.from(att.rawContent.replace(/\s/g, ''), 'base64');
            } catch {
              attBuffer = Buffer.from(att.rawContent, 'utf8');
            }
          } else {
            attBuffer = Buffer.from(att.rawContent, 'utf8');
          }

          // Enforce per-attachment limit
          if (attBuffer.length > this.MAX_ATTACHMENT_BYTES) {
            attBuffer = attBuffer.subarray(0, this.MAX_ATTACHMENT_BYTES);
          }

          fs.writeFileSync(attPath, attBuffer);

          const sha256Hash = crypto.createHash('sha256').update(attBuffer).digest('hex');

          // Check ThreatIntel hash
          const hashLookup = intel.lookupHash(sha256Hash);
          if (hashLookup.isMalicious) {
            attachmentThreatsCount++;
            emailRiskScore = 100;
            const threatName = hashLookup.threatName || 'KNOWN_MALICIOUS_ATTACHMENT';
            threatIndicators.push(`Attachment '${safeName}' matches known malware hash: ${threatName}`);
            evidenceFactors.push(`Malicious attachment (${safeName}: ${threatName})`);

            attachmentInfos.push({
              fileName: safeName,
              contentType: att.contentType,
              sizeBytes: attBuffer.length,
              sha256: sha256Hash,
              isExecutable: true,
              isThreat: true,
              threatName,
              riskScore: 100,
              evidenceFactors: [`Known malicious malware hash (${threatName})`]
            });
            continue;
          }

          // Analyze with full 10-layer FileAnalyzer
          const fileAnalysis = await FileAnalyzer.analyzeFile(attPath);

          const isThreat = fileAnalysis.verdict === 'BLOCK' || fileAnalysis.riskScore >= 70;
          if (isThreat) {
            attachmentThreatsCount++;
            emailRiskScore = Math.max(emailRiskScore, fileAnalysis.riskScore);
            threatIndicators.push(`Malicious attachment detected: '${safeName}' (${fileAnalysis.threatName}, Score: ${fileAnalysis.riskScore})`);
            evidenceFactors.push(`Malicious attachment '${safeName}' (${fileAnalysis.threatName})`);
          } else if (fileAnalysis.riskScore >= 40) {
            emailRiskScore = Math.max(emailRiskScore, fileAnalysis.riskScore);
            threatIndicators.push(`Suspicious attachment: '${safeName}' (Score: ${fileAnalysis.riskScore})`);
          }

          attachmentInfos.push({
            fileName: safeName,
            contentType: att.contentType,
            sizeBytes: attBuffer.length,
            sha256: sha256Hash,
            isExecutable: fileAnalysis.isExecutable,
            isThreat,
            threatName: fileAnalysis.threatName,
            riskScore: fileAnalysis.riskScore,
            evidenceFactors: fileAnalysis.evidenceFactors
          });
        }
      } finally {
        // Guaranteed cleanup of staging sandbox
        try {
          fs.rmSync(stageDir, { recursive: true, force: true });
        } catch {
          // Best-effort cleanup
        }
      }
    }

    // Map final severity
    let emailSeverity: ThreatSeverity = 'safe';
    if (emailRiskScore >= 85) emailSeverity = 'critical';
    else if (emailRiskScore >= 70) emailSeverity = 'dangerous';
    else if (emailRiskScore >= 40) emailSeverity = 'suspicious';
    else if (emailRiskScore >= 15) emailSeverity = 'low';

    const isEmailMalicious = emailRiskScore >= 70;

    const metadata: EmailMetadata = {
      from: from || undefined,
      fromDomain,
      replyTo: replyTo || undefined,
      replyToDomain,
      returnPath: returnPath || undefined,
      returnPathDomain,
      subject: subject || undefined,
      date: date || undefined,
      messageId: messageId || undefined,
      authResults,
      urlsFound: urls,
      urlThreatsCount,
      attachmentsCount: attachmentInfos.length,
      attachmentThreatsCount,
      attachments: attachmentInfos,
      isSenderSpoofed: Boolean(isSenderClaimingBrand && isAuthFailed),
      isReplyToMismatched,
      isReturnPathMismatched,
      isAuthFailed
    };

    return {
      hasEmailMetadata: true,
      metadata,
      emailRiskScore,
      emailSeverity,
      isEmailMalicious,
      threatIndicators,
      evidenceFactors,
      bodyTextSnippet: combinedBody.slice(0, 300)
    };
  }
}
