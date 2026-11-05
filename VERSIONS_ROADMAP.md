# VERSIONS_ROADMAP.md — Sideloadly-Cert platform plan

> Written 2026-11-05 by ZCode, at Timur's request.
> **Any agent working on this repo MUST read this before touching builds or releases.**

## Target: three public versions (eventually)

| # | Version | Status | Notes |
|---|---------|--------|-------|
| 1 | **macOS (Intel binary, runs on Silicon via Rosetta 2)** | ✅ **SHIPPED — v1.0.1** | The ONLY possible macOS build today. Works on Intel Macs AND Apple Silicon (M1–M5) through Rosetta 2. |
| 2 | **macOS Apple Silicon (native arm64)** | ⛔ **BLOCKED — waiting on upstream** | Sideloadly itself has NO arm64/universal build (verified: installed v0.72 is x86_64-only; sideloadly.io changelog has zero arm64 mentions — all "Apple Silicon" entries are about sideloading ONTO M-series Macs). We cannot create a Silicon-native version of a closed-source Intel app. |
| 3 | **Windows 10/11** | ⛔ **BLOCKED — needs new engineering** | Official Sideloadly for Windows exists, but our cert-signing feature is a macOS dylib injection (proxy dylib + Python hook + Qt5 symbol binding). A Windows port needs a different injection mechanism designed from scratch. Later project. |

## The "Support Ending for Intel-based Apps" dialog is NOT an error

On Apple Silicon Macs (Timur's is an **M5**), macOS shows this warning dialog when an
Intel app launches. It means Rosetta 2 will be removed in some FUTURE macOS release.
The app **runs perfectly fine today** — v1.0.1 was built, launched, and tested on the M5.
No reinstall is ever needed because of this dialog.

## Hard rules for agents (violating these broke the app once before)

1. **NEVER modify `/Applications/Sideloadly.app`** — it is the pristine source the patcher
   copies FROM. Patches always go into a separate output bundle (`Sideloadly-Cert.app`).
2. **The injected proxy dylib MUST match the host executable's architecture** (currently
   `x86_64`). Do not "fix" this to arm64 on Silicon Macs — the dylib loads into the
   Sideloadly process, which is Intel. Verify after every build:
   `lipo -archs <app>/Contents/MacOS/Sideloadly` vs `lipo -archs <app>/Contents/Frameworks/sideloadly.dylib`
3. **Verify Qt symbol exports before shipping a rebuilt dylib** — see
   `src/sideloadly_dylib_proxy.mm` header comment. Qt 5.15 inline functions
   (`resize(int,int)`, `width()`, `height()`, `isVisible()`) are NOT exported and crash
   at call time under `-undefined dynamic_lookup`.
4. When an official arm64/universal Sideloadly appears: add an `--arch` option to
   `bin/sideloadly-cert-patcher` (it currently hardcodes `-arch x86_64` in
   `build_proxy_dylib()`), rebuild the proxy for the host's arch, re-verify symbols
   against the NEW app's Qt frameworks (they may differ), and ship version 2 of this
   table as the "macOS Silicon" download.

## Current build & release flow (version 1)

```bash
./bin/sideloadly-cert-patcher --source /Applications/Sideloadly.app --output /Applications/Sideloadly-Cert.app
cd /tmp && ditto -c -k --sequesterRsrc --keepParent /Applications/Sideloadly-Cert.app Sideloadly-Cert-macOS.zip
gh release create vX.Y.Z build/Sideloadly-Cert-macOS.zip --title ... --notes ...
```

Website: `sideloadlycert.de` (pi-voice, self-hosted zip at `/download/` — see
`~/.zcode` project memory or `48_Websites/sideloadlycert.de/` for deployment detail).
