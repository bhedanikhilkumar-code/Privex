# Phase D Audit Remediation Plan (PPVAULT2 Hardening)

**Document:** `docs/PHASE_D_REMEDIATION.md`  
**Phase:** D — Quarantine Hardening (PPVAULT2)  
**Audit Date:** 2026-10-06  
**Status:** REMEDIATION IN PROGRESS  

---

## 1. Executive Summary

During the Phase D Final Independent Audit, 10 independent subagents (D-A through D-J) reviewed the implementation. While cryptographic primitives (AES-256-GCM, per-chunk CSPRNG IVs, 41-byte AAD binding, DPAPI key sealing) and empirical streaming performance (bounded <4.5 MB heap delta on 100 MB files) passed inspection, subagents D-A, D-I, and D-H identified 4 concrete defects in memory bounds against crafted headers, concurrency serialization, crash recovery atomicity, and startup temporary file cleanup.

In accordance with constitutional governance, Phase D is determined to be **NO-GO** until all 4 blockers are remediated and verified with regression tests.

---

## 2. Inventory of Blockers

### SEC-D-01: Untrusted `ciphertextLen` Buffer Allocation in `decryptStream`
- **Severity:** HIGH
- **Component:** Quarantine Engine (`QuarantineService`)
- **File:** `apps/desktop/src/services/quarantine.service.ts`
- **Function/Class:** `QuarantineService.decryptStream` (line 584) & `decryptBytes` (line 764)
- **Root Cause:** `Buffer.allocUnsafe(ciphertextLen)` is called immediately upon reading the 32-bit unsigned length field from the on-disk frame header, prior to verifying whether `ciphertextLen` exceeds the maximum chunk size or the remaining bytes in the container file.
- **Security Impact:** A malicious or corrupted container crafted with `ciphertextLen = 0x7FFFFFFF` (2 GB) forces the V8 engine to allocate a huge buffer, causing out-of-memory crashes before the subsequent truncation or authentication tag validation occurs.
- **Reproduction:** Call `decryptStream` on a container with frame `ciphertextLen` set to `0x7FFFFFFF`.
- **Required Fix:** Enforce strict pre-allocation bounds checking:
  ```typescript
  if (ciphertextLen > QuarantineService.CHUNK_SIZE + 64 || currentOffset + ciphertextLen > sourceStat.size) {
    throw new Error('CORRUPTED_VAULT: Quarantined container chunk length exceeds maximum bounds.');
  }
  ```
- **Regression Test:** Add test in `quarantine-streaming.test.ts` verifying that huge declared `ciphertextLen` is rejected immediately without allocating excessive memory.

---

### SEC-D-02: Concurrency Serialization & Dynamic Manifest Staging
- **Severity:** HIGH
- **Component:** Quarantine Manager (`QuarantineService`)
- **File:** `apps/desktop/src/services/quarantine.service.ts`
- **Function/Class:** `QuarantineService.isolateFile`, `restoreItem`, `permanentDelete`, and `saveManifest`
- **Root Cause:** 
  1. `QuarantineService` lacks an in-memory asynchronous operation queue or mutex per item, allowing concurrent invocations (e.g. rapid double-clicking "Restore" or "Delete" in UI) to race on the same file blob and manifest entries.
  2. `saveManifest()` stages output to a static path `${this.manifestPath}.tmp`. Concurrent calls collide on the same temporary file, risking torn writes.
- **Security Impact:** Concurrent restores trigger unhandled `ENOENT` errors when attempting to unlink already-removed blobs; concurrent manifest saves risk corrupted staging files.
- **Reproduction:** Execute `Promise.all([service.restoreItem(id), service.restoreItem(id)])` or concurrent `isolateFile` calls.
- **Required Fix:**
  1. Implement an async mutex queue (`operationQueue`) to serialize manifest write operations.
  2. Maintain an `activeOperations: Set<string>` to reject or await concurrent operations targeting the same `quarantineId`.
  3. Use PID-, timestamp-, and random-nonce unique staging paths in `saveManifest()`: `${this.manifestPath}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`.
- **Regression Test:** Add concurrency race tests in `quarantine-streaming.test.ts` demonstrating safe serialization of concurrent restore and delete operations.

---

### SEC-D-03: Boot-Time Temporary Staging File Sweep
- **Severity:** MEDIUM
- **Component:** Vault Confinement & Cleanup (`QuarantineService`)
- **File:** `apps/desktop/src/services/quarantine.service.ts`
- **Function/Class:** `QuarantineService.initVault` / `sweepStaleTempFiles`
- **Root Cause:** No cleanup logic runs during service initialization to sweep abandoned temporary files (`*.blob.tmp`, `manifest.json.enc.tmp*`) left behind by process termination or system power loss.
- **Security Impact:** Aborted quarantine or restore operations leave stale unlinked temporary files in `vaultDir`.
- **Reproduction:** Write a dummy `.blob.tmp` into `vaultDir` and instantiate `QuarantineService`. The file remains indefinitely.
- **Required Fix:** In `initVault()`, scan `this.vaultDir` for files matching `*.tmp` or `*.blob.tmp*` and unlink them if older than 30 seconds.
- **Regression Test:** Add test in `quarantine.service.test.ts` verifying that stale temporary files are cleaned up on startup.

---

### SEC-D-04: Crash Recovery Window Between Source Unlink and Manifest Commit
- **Severity:** MEDIUM
- **Component:** State Transition Atomicity (`QuarantineService`)
- **File:** `apps/desktop/src/services/quarantine.service.ts`
- **Function/Class:** `QuarantineService.isolateFile` (lines 946–983) and `initVault`
- **Root Cause:** Source file is unlinked before `this.manifest.set(quarantineId, item)` and `this.saveManifest()`. If a crash occurs between unlinking and manifest commit, an unindexed `.blob` is left in the vault with no manifest record.
- **Security Impact:** An interrupted quarantine leaves an unreferenced blob that the user cannot view or restore via `listQuarantine()`.
- **Reproduction:** Simulate crash right after `fs.promises.unlink(canonicalSource)`. The file is in `vaultDir` but missing from `manifest`.
- **Required Fix:**
  1. Commit the manifest entry with `status: 'STAGED'` or record it in `this.manifest` before unlinking `canonicalSource`. If `unlink` fails, roll back manifest and remove blob.
  2. Implement an orphaned blob reconciler in `initVault()`: scan `vaultDir` for `.blob` files. If any `.blob` has no corresponding entry in `manifest.json.enc`, synthesize a recovered manifest record (`threatName: 'RECOVERED_ORPHANED_BLOB'`) so the file can be inspected or restored.
- **Regression Test:** Add test simulating an unreferenced `.blob` file on startup and verifying automatic recovery into the manifest.

---

## 3. Remediation Execution Plan

1. **Apply Code Fixes:**
   - Update `apps/desktop/src/services/quarantine.service.ts` with:
     - Strict pre-allocation `ciphertextLen` bounds check in `decryptStream` and `decryptBytes`.
     - In-memory `operationQueue` and `activeOperations` set.
     - Unique temporary paths for `saveManifest()`.
     - Boot-time `sweepStaleTempFiles()`.
     - Boot-time `reconcileOrphanedBlobs()`.
     - Manifest staging before source unlink with atomic rollback.
2. **Add Targeted Regression Tests:**
   - In `apps/desktop/src/__tests__/services/quarantine-streaming.test.ts`:
     - Test huge declared `ciphertextLen` rejection.
     - Test concurrent double-restore and double-delete serialization.
     - Test orphaned `.blob` startup recovery.
     - Test boot-time temporary file sweep.
3. **Run Regression Suites & Performance Benchmarks:**
   - Verify all quarantine tests pass.
   - Run full monorepo regression suite (`npm test`).
4. **Git Protocol:** Commit remediation with an informative commit message and push to `origin/main`.
