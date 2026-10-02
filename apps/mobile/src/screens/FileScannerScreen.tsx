import React, { useState } from 'react';
import { FileScannerService } from '../services/file-scanner.service';
import { FileInspectionResult } from '../types/mobile.types';
import { SecurityBadge } from '../components/SecurityBadge';
import { EvidenceCard } from '../components/EvidenceCard';

interface FileScannerScreenProps {
  scannerService: FileScannerService;
  onNavigateHome: () => void;
}

export const FileScannerScreen: React.FC<FileScannerScreenProps> = ({ scannerService, onNavigateHome }) => {
  const [result, setResult] = useState<FileInspectionResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size === 0) {
      setErrorMessage('Selected file is empty (0 bytes).');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      // Read first 8,192 bytes for header analysis and entropy calculation
      const sliceSize = Math.min(8192, file.size);
      const sliceBlob = file.slice(0, sliceSize);
      const arrayBuffer = await sliceBlob.arrayBuffer();
      const headerBytes = Array.from(new Uint8Array(arrayBuffer));

      const inspection = scannerService.inspectFile({
        name: file.name,
        sizeBytes: file.size,
        mimeType: file.type || 'application/octet-stream',
        headerBytes
      });
      setResult(inspection);
    } catch (err: any) {
      setErrorMessage(`Failed to inspect file: ${err?.message || 'Read error'}`);
    } finally {
      setIsLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const simulateFileScan = (fileName: string, mime: string, header: number[]) => {
    setErrorMessage(null);
    const inspection = scannerService.inspectFile({
      name: fileName,
      sizeBytes: header.length * 1024,
      mimeType: mime,
      headerBytes: header
    });
    setResult(inspection);
  };

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#34d399' }}>
          On-Device File Inspection
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Analyzes header magic bytes and entropy in volatile memory. No files are uploaded or executed.
        </p>
      </div>

      <div style={{ backgroundColor: '#1e293b', border: '1px dashed #334155', borderRadius: '16px', padding: '1.5rem', textAlign: 'center' }}>
        <span style={{ fontSize: '2.5rem', display: 'block', marginBottom: '0.5rem' }}>📄</span>
        <strong style={{ fontSize: '1rem', display: 'block', marginBottom: '0.25rem' }}>
          Select File to Inspect
        </strong>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', display: 'block', marginBottom: '1rem' }}>
          Single-file scoped analysis via Android Storage Access Framework
        </span>

        {/* Hidden SAF Native File Input */}
        <input
          ref={fileInputRef}
          type="file"
          data-testid="saf-file-input"
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />

        {/* Primary Real File Chooser Button */}
        <button
          type="button"
          data-testid="choose-file-btn"
          onClick={() => fileInputRef.current?.click()}
          disabled={isLoading}
          style={{
            width: '100%',
            padding: '0.85rem',
            backgroundColor: '#3b82f6',
            border: 'none',
            borderRadius: '10px',
            color: '#ffffff',
            fontWeight: 700,
            fontSize: '0.95rem',
            cursor: isLoading ? 'not-allowed' : 'pointer',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem'
          }}
        >
          <span>📁</span>
          <span>{isLoading ? 'Reading File Bytes...' : 'Choose File from Storage (SAF)'}</span>
        </button>

        {errorMessage && (
          <div
            data-testid="file-error-banner"
            style={{
              padding: '0.6rem',
              backgroundColor: '#451a1a',
              border: '1px solid #ef4444',
              borderRadius: '8px',
              color: '#fca5a5',
              fontSize: '0.8rem',
              marginBottom: '1rem'
            }}
          >
            {errorMessage}
          </div>
        )}

        <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem', marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Or Run Quick Verification Samples
          </span>
        </div>

        {/* Test sample files */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', textAlign: 'left' }}>
          <button
            type="button"
            onClick={() => simulateFileScan('invoice_document.pdf.exe', 'application/x-msdownload', [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])}
            style={{
              padding: '0.75rem',
              backgroundColor: '#0f172a',
              border: '1px solid #ef4444',
              borderRadius: '8px',
              color: '#fca5a5',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            🛑 Test Deceptive Executable: "invoice_document.pdf.exe" (MZ bytes)
          </button>

          <button
            type="button"
            onClick={() => simulateFileScan('classes.dex', 'application/vnd.android.dex', [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00])}
            style={{
              padding: '0.75rem',
              backgroundColor: '#0f172a',
              border: '1px solid #f59e0b',
              borderRadius: '8px',
              color: '#fcd34d',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            ⚡ Test Android Bytecode: "classes.dex" (dex\n bytes)
          </button>

          <button
            type="button"
            onClick={() => simulateFileScan('report.pdf', 'application/pdf', [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35])}
            style={{
              padding: '0.75rem',
              backgroundColor: '#0f172a',
              border: '1px solid #10b981',
              borderRadius: '8px',
              color: '#6ee7b7',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            ✓ Test Normal Document: "report.pdf" (%PDF bytes)
          </button>
        </div>
      </div>

      {result && (
        <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem' }}>{result.fileName}</h3>
              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Type: {result.detectedMimeType}</span>
            </div>
            <SecurityBadge verdict={result.verdict} score={result.score} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.8rem' }}>
            <div style={{ backgroundColor: '#0f172a', padding: '0.5rem', borderRadius: '6px' }}>
              <span style={{ color: '#94a3b8' }}>Executable Header: </span>
              <strong>{result.isExecutable ? 'YES' : 'NO'}</strong>
            </div>
            <div style={{ backgroundColor: '#0f172a', padding: '0.5rem', borderRadius: '6px' }}>
              <span style={{ color: '#94a3b8' }}>Shannon Entropy: </span>
              <strong>{result.shannonEntropy}/8.0</strong>
            </div>
          </div>

          <EvidenceCard evidence={result.evidence} />

          <div style={{ backgroundColor: '#0f172a', borderRadius: '8px', padding: '0.75rem', fontSize: '0.85rem' }}>
            <span style={{ color: '#38bdf8', fontWeight: 600 }}>Recommendation: </span>
            {result.recommendation.suggestedAction}
          </div>

          <button
            type="button"
            onClick={() => setResult(null)}
            style={{
              padding: '0.75rem',
              backgroundColor: '#334155',
              border: 'none',
              borderRadius: '8px',
              color: '#f8fafc',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Inspect Another File
          </button>

          <button
            type="button"
            onClick={onNavigateHome}
            style={{
              padding: '0.65rem',
              backgroundColor: '#1e293b',
              border: 'none',
              borderRadius: '8px',
              color: '#94a3b8',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Return to Dashboard
          </button>
        </div>
      )}
    </div>
  );
};
