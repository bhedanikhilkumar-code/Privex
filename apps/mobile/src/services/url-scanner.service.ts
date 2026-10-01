import { MobileSecurityAdapter } from '../adapters/mobile-security-adapter';
import { MobileScanResult } from '../types/mobile.types';

export class UrlScannerService {
  constructor(private adapter: MobileSecurityAdapter) {}

  public async scanUrl(
    rawUrl: string,
    readingGrade: 6 | 8 = 6,
    allowlist: string[] = []
  ): Promise<MobileScanResult> {
    if (!rawUrl || rawUrl.trim().length === 0) {
      throw new Error('URL_REQUIRED: Please enter or paste a URL to scan.');
    }

    let urlToScan = rawUrl.trim();
    if (!urlToScan.startsWith('http://') && !urlToScan.startsWith('https://')) {
      urlToScan = `https://${urlToScan}`;
    }

    return await this.adapter.scanUrl(urlToScan, readingGrade, allowlist);
  }
}
