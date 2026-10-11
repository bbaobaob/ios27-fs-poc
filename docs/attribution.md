# Attribution — original code vs. standard APIs

## Independently authored for this project

Everything under `Sources/` and `Tests/` was written for this project from first principles:

- `Sources/FSProbeCore/FSOperation.swift` — operation taxonomy and per-operation documentation.
- `Sources/FSProbeCore/ProbeTypes.swift` — result model, evidence model, outcome and cause enums.
- `Sources/FSProbeCore/ErrorClassifier.swift` — errno-to-outcome and errno-to-cause mapping,
  including the `EPERM` (sandbox) vs `EACCES` (POSIX permissions) distinction.
- `Sources/FSProbeCore/POSIXShim.swift`, `POSIXShim+Darwin.swift`, `POSIXShim+Compat.swift` — the
  platform seam and its two implementations.
- `Sources/FSProbeCore/POSIXProbeEngine.swift` — the probe engine, including the synthetic-file
  write protocol (create → verify by read-back → clean up) and bounded reads.
- `Sources/FSProbeCore/CapabilityMatrix.swift` — matrix model and discrepancy analysis.
- `Sources/FSProbeCore/MatrixRunner.swift`, `ReportExporter.swift` — runner and JSON/text export.
- `Sources/FSProbeCore/FSTargets.swift` — target list and rationale.
- `Sources/FSProbeCore/ErrnoAccess.swift` — portable errno accessor.
- `Sources/fsprobe-cli/main.swift` — command-line runner and host identification.
- `Tests/FSProbeCoreTests/*` — 20 unit tests covering classification, engine mechanics, safety
  rules (no overwrite of pre-existing files, cleanup after write probes, bounded reads), matrix
  attribution, and export round-tripping.
- `docs/*`, `README.md`, `.github/workflows/ci.yml`.

## Third-party build tooling used (not an implementation source)

- **xtool** (https://github.com/xtool-org/xtool), version 1.21.0, used by
  `.github/workflows/xtool.yml` to build the iOS app from the SwiftPM package. xtool is a
  build/deploy toolchain — the Linux/Windows analogue of Xcode — and is used here purely as
  build infrastructure, exactly as Xcode is. It contributes no probe logic, no exploit, and no
  PoC implementation: every line of filesystem-probing code in `Sources/FSProbeCore` was
  written for this project. xtool's signing capability (a free-Apple-ID development signing
  flow) is documented but deliberately unused, because it would require Apple ID credentials
  in CI.
- The macOS xtool binary is a GUI app that requires `XTL_CLI=1` to run as a CLI; the workflow
  sets it and invokes xtool through its own `Resources/bin/xtool` wrapper. Without it the
  binary launches its UI and hangs forever on a headless runner.

## Standard APIs and documented platform capabilities relied upon

These are used as documented, public interfaces — not as an implementation source:

- POSIX: `open`, `close`, `read`, `write`, `unlink`, `readlink`, `opendir`, `readdir`, `closedir`,
  `stat`, `lstat`, `strerror`, `errno` (all from Darwin on iOS/macOS).
- Foundation: `FileManager`, `Data`, `JSONEncoder`/`JSONDecoder`, `ProcessInfo`,
  `ISO8601DateFormatter`, `NSHomeDirectory()`.
- Swift standard library and XCTest.
- GitHub Actions: `actions/checkout`, `actions/upload-artifact`, `macos-15` runner image.

## What this project does not use

No third-party exploit, PoC, exploit chain, jailbreak tool, or filesystem helper was cloned,
downloaded, copied, renamed, wrapped, or adapted. No private entitlement is claimed or invented. No
undocumented kernel interface is used. Where public vulnerability advisories or Apple documentation
informed the reasoning (for example, that iOS sandbox denial surfaces as `EPERM`), they informed the
hypotheses only — see `docs/research-plan.md`.

## Platform seam disclosure

`POSIXShim+Compat.swift` binds directly to the same C symbols as the Darwin implementation using
`@_silgen_name`. It exists **only** so the identical probe logic can be compiled and unit-tested on
a non-Darwin verification host. It is compiled out entirely on iOS and macOS (`#if !canImport(Darwin)`),
where `POSIXShim+Darwin.swift` calls the platform libc directly.
