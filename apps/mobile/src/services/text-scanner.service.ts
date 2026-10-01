import { MobileSecurityAdapter } from '../adapters/mobile-security-adapter';
import { MobileScanResult } from '../types/mobile.types';

export class TextScannerService {
  constructor(private adapter: MobileSecurityAdapter) {}

  public async scanText(
    text: string,
    readingGrade: 6 | 8 = 6
  ): Promise<MobileScanResult> {
    if (!text || text.trim().length === 0) {
      throw new Error('TEXT_REQUIRED: Please enter or paste message text to scan.');
    }

    return await this.adapter.scanText(text.trim(), readingGrade);
  }
}
