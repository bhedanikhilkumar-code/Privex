# Private Protection v0.1.1

## Release status
Official public release.

## Verification
- Full test suite: PASS (185 test files, 1,250 passed, 0 failed, exit code 0)
- Typecheck: PASS (6/6 workspaces, 0 errors, exit code 0)
- Production build: PASS (core, ml, desktop, extension, mobile, web, exit code 0)
- Windows EXE smoke test: PASS (PrivateProtection.exe --headless-verify, exit code 0)
- Security audit: GO (0 critical/high/medium findings, zero-knowledge, canonical authority intact)
- Privacy/offline audit: PASS (100% on-device local execution, zero Tier-1 transmission, air-gapped parity)
- SHA-256 verification: PASS (100% matching SHA256SUMS.txt)

## Artifacts
| Filename | Platform | SHA-256 |
|---|---|---|
| `PrivateProtection-0.1.1-win-x64.exe` | Windows 10/11 x64 (Portable) | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` |
| `PrivateProtection-Setup-0.1.1.exe` | Windows 10/11 x64 (Installer) | `9ca273b992bedaabc42d3161dbf3ac1c24aad518b84faf8e99e005c5a54d8d84` |
| `private-protection-web-0.1.1.zip` | Web PWA Client Bundle | `0a4d73bab911bf00b6870f3c722d2ab77e29ac72d1fd2b8e05284d1507e895c7` |
| `private-protection-extension-0.1.1.zip` | Chromium MV3 Browser Extension | `c1c66d041fe3d198c52025f53122d5eefce328e1ad7c61db798c98d2493daadf` |
| `private-protection-mobile-0.1.1.apk` | Android 8.0+ Direct Distribution APK | `8229c2c1188f09c55d3d290a3e3b4a2486a93cf3588f4f51da40faf8cdaed5c8` |
| `private-protection-mobile-0.1.1.aab` | Android Build Archive AAB (Build Artifact) | `0e1117b2dbd0653191935de6578c2f4c73bbbe62651cf428e352195662134a32` |

## Privacy
Private Protection remains 100% privacy-first and offline-capable. All threat detection, AI briefing synthesis, URL tokenization, and quarantine operations execute locally on-device in volatile RAM without transmitting user payloads off-device.

## Distribution
Available for Windows, Web, Browser Extension, and Android direct distribution via verified GitHub release assets. No publication has occurred on the Google Play Store.
