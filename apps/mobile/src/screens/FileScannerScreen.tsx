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

  const simulateFileScan = (fileName: string, mime: string, header: number[]) => {
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
