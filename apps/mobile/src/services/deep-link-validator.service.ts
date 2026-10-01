import { DeepLinkPayload } from '../types/mobile.types';

export class DeepLinkValidatorService {
  /**
   * Validates inbound deep link URLs (privateprotection://scan?url=...)
   * Rejects unauthorized commands, oversized payloads, and state manipulation attempts.
   */
  public static parseAndValidate(uri: string): DeepLinkPayload {
    if (!uri || typeof uri !== 'string') {
      return { valid: false, error: 'Empty or invalid URI' };
    }

    if (uri.length > 4096) {
      return { valid: false, error: 'Oversized URI exceeds 4KB security threshold' };
    }

    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      return { valid: false, error: 'Malformed URI structure' };
    }

    // 1. Enforce strict scheme validation
    if (parsed.protocol !== 'privateprotection:') {
      return { valid: false, error: `Unauthorized scheme: ${parsed.protocol}` };
    }

    const host = parsed.hostname || parsed.pathname.replace(/^\/\//, '');

    // 2. Reject any command execution or administrative verbs
    const forbiddenVerbs = ['disable', 'toggle', 'allow', 'bypass', 'shred', 'config', 'exec', 'system'];
    if (forbiddenVerbs.some((v) => host.toLowerCase().includes(v))) {
      return { valid: false, error: 'Unauthorized administrative command via deep link rejected' };
    }

    // 3. Supported Action: Scan URL
    if (host === 'scan' || host === 'url') {
      const urlParam = parsed.searchParams.get('url');
      if (!urlParam) {
        return { valid: false, error: 'Missing "url" parameter in scan deep link' };
      }
      if (urlParam.length > 2048) {
        return { valid: false, error: 'Target URL parameter exceeds 2KB limit' };
      }
      return {
        valid: true,
        action: 'SCAN_URL',
        target: decodeURIComponent(urlParam)
      };
    }

    // 4. Supported Action: Scan Text
    if (host === 'scan-text' || host === 'text') {
      const textParam = parsed.searchParams.get('text');
      if (!textParam) {
        return { valid: false, error: 'Missing "text" parameter in scan-text deep link' };
      }
      if (textParam.length > 10000) {
        return { valid: false, error: 'Target text parameter exceeds 10KB limit' };
      }
      return {
        valid: true,
        action: 'SCAN_TEXT',
        target: decodeURIComponent(textParam)
      };
    }

    return { valid: false, error: `Unrecognized deep link action: ${host}` };
  }
}
