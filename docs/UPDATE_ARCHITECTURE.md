# Secure Update Architecture: PRIVEX

## 1. Overview & Security Mandate

The update distribution mechanism is the most critical supply-chain vector in any cybersecurity product. A compromised update pipeline can distribute poisoned rules or weaponized models to millions of endpoints.

PRIVEX enforces an **Air-Gapped Cryptographic Update Pipeline**:
1. **Authenticated**: All update payloads must be digitally signed offline using Ed25519 hardware keys.
2. **Integrity-Checked**: Full SHA-256 Merkle root verification before any byte touches persistent storage.
3. **Monotonically Versioned**: Strictly increasing sequence integers prevent downgrade attacks.
4. **Rollback-Capable**: Atomic symlink swaps preserve known-good versions for instant recovery.
5. **Zero-Knowledge**: Client update checks transmit zero device identifiers, IP metadata, or browsing history.

---

## 2. Update Modality Specifications

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           OFFLINE AIR-GAPPED BUILD SYSTEM                       │
│  • Compiles threat blocklists into Bloom filters                                │
│  • Quantizes ML model weights (INT8 / INT4)                                      │
│  • Generates binary differential patch (bsdiff) against prior version           │
│  • Signs manifest with Ed25519 Hardware Security Module (YubiKey / HSM)         │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ (Push signed manifest + patch)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    GLOBAL CDN EDGE DISTRIBUTION NETWORK (STATELESS)             │
│  • Serves `/v1/updates/manifest.json`                                           │
│  • Serves `/v1/updates/patches/{version_from}_to_{version_to}.patch`            │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ (Anonymous Inbound Poll via HTTPS)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             CLIENT ENDPOINT UPDATER                             │
│                                                                                 │
│   Step 1: Check Inbound Version > Current Monotonic Version (Reject Downgrades) │
│   Step 2: Verify Ed25519 Signature against Hardcoded Root Public Key            │
│   Step 3: Download Binary Patch to Isolated Temporary Sandbox                  │
│   Step 4: Verify SHA-256 Checksum of Downloaded Patch                           │
│   Step 5: Apply bsdiff Delta Patch to Local Base Image                          │
│   Step 6: Verify SHA-256 Merkle Root of Reconstructed Target Image              │
│   Step 7: Atomic Swap (`rename`) into Active Production Path                   │
│   Step 8: If Engine Fails Initialization, Revert Atomically to Previous Image   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Four Core Update Vectors

### 3.1 Detection Rules Update
- **Frequency**: Daily or hourly upon critical zero-day campaign discovery.
- **Payload Format**: Compressed JSON or Protocol Buffer byte stream containing new regexes and indicator weights.
- **Size Budget**: $<100\text{KB}$ delta.
- **Verification**: Ed25519 digital signature verified against immutable client public key.

### 3.2 Threat Intelligence Bloom Filter Update
- **Frequency**: Daily compilation from authoritative feeds (PhishTank, OpenPhish, URLhaus).
- **Payload Format**: Binary differential patch (`bsdiff`) applied against the base Bloom filter image.
- **Size Budget**: $<500\text{KB}$ delta patch (full image $<5\text{MB}$).
- **Verification**: SHA-256 hash tree validation over Bloom filter bit vectors.

### 3.3 AI/ML Model Weights Update
- **Frequency**: Monthly or bi-monthly model retraining.
- **Payload Format**: Quantized ONNX / TFLite / GGUF binary chunks with embedded layer checksums.
- **Size Budget**: 10MB to 50MB for lightweight intent models; full SLM weights updated via background Wi-Fi scheduler.
- **Verification**: Ed25519 signature + internal ONNX graph tensor checksums.

### 3.4 Application Software Update
- **Frequency**: Bi-weekly or monthly feature / security releases.
- **Distribution Channel**:
  - **Mobile**: Official app stores (Google Play Store, Apple App Store).
  - **Browser Extension**: Official extension webstores (Chrome Web Store, Mozilla Add-ons, Edge Store).
  - **Desktop**: Native Tauri update framework (`tauri-plugin-updater`) with signed MSI/DMG installers.
  - **Web Dashboard**: Immediate server deployment with PWA service worker cache invalidation.

---

## 4. Cryptographic Manifest Schema

All updates are governed by a canonical, signed JSON manifest file:

```json
{
  "manifestVersion": 1,
  "component": "threat-intel-bloom-filter",
  "fromVersion": 2026100101,
  "toVersion": 2026100201,
  "minimumAppVersion": "1.0.0",
  "timestamp": "2026-10-02T00:00:00Z",
  "patch": {
    "url": "https://cdn.privateprotection.io/patches/bloom_2026100101_to_2026100201.patch",
    "sizeBytes": 348192,
    "sha256": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
  },
  "targetImage": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sizeBytes": 4194304
  },
  "signature": {
    "algorithm": "Ed25519",
    "keyId": "prod-root-signer-2026-01",
    "signatureValue": "MC4CAQACBQDY...[Base64 Signature]..."
  }
}
```

---

## 5. Rollback & Anti-Downgrade Safeguards

1. **Monotonic Version Counter Enforcement**: The client maintains the highest applied `toVersion` integer in secure OS storage. Any manifest presenting a `toVersion` $\le$ `currentVersion` is immediately dropped to prevent replay/downgrade attacks.
2. **Atomic Symlink / File Rename**: Updates are unpacked and reconstructed in a staging directory (`cache/staging`). The file swap occurs via atomic filesystem operations (`rename()` / atomic file move).
3. **Automated Smoke Test Verification**: Prior to finalizing an update swap, the client initializes an isolated test engine against the new file and executes an internal 5-sample smoke test. If the test panics or crashes, the staged file is discarded, and the existing operational engine remains active.
4. **Permanent Known-Good Seed Fallback**: The client binary permanently bundles an immutable factory seed database. If local storage is corrupted, the client reverts to the factory seed without crashing.
