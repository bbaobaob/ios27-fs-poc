# Device validation log

Every PoC must record the following before any conclusion is drawn. A build succeeding is not
runtime proof.

## Required record per PoC

| Field | Value |
| --- | --- |
| Exact iOS version **and build** | |
| Device model | |
| Signing context (development / ad hoc / enterprise / none) | |
| Entitlements present | |
| Test directory | |
| Operation | |
| Expected behaviour | |
| Actual observed behaviour | |
| Exact error output (errno + `strerror()`) | |
| Reproduction count (n of n) | |
| Sanitised logs | |
| Known limitations | |

## Current blocker (as of this commit)

The project environment is a Termux/Android host with `gh` and Swift available, but **no Mac, no
Xcode, and no physical iPhone attached**. Therefore:

- CI results (macOS runner) are recorded separately and labelled as host results.
- No iOS device validation has been performed.
- No claim about iOS 27 filesystem behaviour is made from host results.

### Blocker: no iOS 27 build or runtime exists in this environment

The free macOS runner image (`macos-15`, Xcode 16.4) ships iOS simulator runtimes **18.5 through
26.2** and nothing newer. There is no iOS 27 simulator runtime, and no Xcode release on the runner
that can target iOS 27. Consequences:

- The newest iOS the harness has actually run on is **26.2** (simulator).
- Every iOS result recorded here is explicitly labelled with its runtime.
- **iOS 27 remains completely untested.** No statement in this repository should be read as a
  statement about iOS 27.

Clearing this blocker requires a Mac with an Xcode release that supports iOS 27, plus a physical
iPhone running iOS 27. Neither is available here.

## Runs

### 2026-10-11 — macOS runner host (NOT a device)

- Platform: macOS 15.7.9 (Build 24G830), `VirtualMac2,1`, Xcode 16.4, `macos-15` runner.
- Purpose: compile and unit-test the Darwin code path; run the harness end-to-end on real Darwin.
- Result: 22/22 unit tests passed; CLI produced a matrix (recorded in
  `docs/capability-matrix.md`). Two harness defects were found and fixed as a direct result of this
  run: the self-recursive `read`/`write` shim methods, and a false "asymmetric access" finding on
  directory targets.
- Notable observation: on this host `/var` permits stat/open/readdir but denies create/write/unlink
  with `EACCES` (macOS SIP), not `EPERM`. Host behaviour only; it says nothing about iOS.
- Limitations: this is not iOS. iOS sandbox (`EPERM`) semantics, container layout, and the
  `/var/mobile` tree are untested.

### 2026-10-11 — verification host (NOT a device)

- Platform: Swift 6.4 verification host (Android/Termux), aarch64.
- Purpose: compile and unit-test the identical probe logic; confirm the harness runs end-to-end.
- Result: 22/22 unit tests passed; CLI produced a matrix; `/var/...` paths reported `ENOENT`
  (absent), which is correct for this host.
- Limitations: this is not iOS. Sandbox behaviour, `EPERM` semantics, and container layout on iOS
  are untested.

### iOS 27 physical device

_Pending — to be filled in when a signed build can be installed on the target iPhone._

### 2026-10-11 — iOS Simulator, runtime 26.2 (NOT a physical device)

- Platform recorded by the app: iOS 26.2, build 24G830, simulator runtime 26.2 - 23C54, `arm64`.
- Method: built by the `ios` workflow for `iphonesimulator`, installed with `simctl install`,
  launched with `simctl launch`; the app computed the matrix on launch and wrote `matrix.json` /
  `matrix.txt` into its Documents directory, which was extracted with
  `simctl get_app_container ... data`.
- Result: matrix captured and recorded in `docs/capability-matrix.md`. App container fully
  accessible; `/var/mobile/...` reported `notFound` because those paths do not exist in the
  simulator; `/var` write denied with `EACCES` (macOS host behaviour, not iOS).
- Reproducibility: run twice (iOS 18.5 and iOS 26.2 runtimes) with identical results.
- Limitations: **not iOS 27**, and **not a physical device**. The simulator's filesystem is the
  macOS host's, so it cannot answer any `/var/mobile` question. The `/var` denial seen here is
  macOS SIP, not the iOS sandbox, so it says nothing about whether iOS denies with `EPERM`.

### iOS 27 on a physical iPhone

_Pending — blocked: no iOS 27 runtime or Xcode release is available in this environment._

### 2026-10-11 — unsigned IPA artifact (build only, never executed)

- Produced by the `ios` workflow, job "Build FSProbe for iOS Simulator", step
  "Package unsigned IPA", from the `Release-iphoneos` build (`CODE_SIGNING_ALLOWED=NO`).
- Artifact: `FSProbe-unsigned-ipa` on the run.
- Verified after download:
  - Structure: `FSProbe.app/` at the archive root, containing `FSProbe` (executable),
    `Info.plist`, `PkgInfo` (`APPL????`). This is the correct IPA layout.
  - `Info.plist`: `CFBundleIdentifier = com.bbaobaob.fsprobe`,
    `CFBundleShortVersionString = 1.0`, `MinimumOSVersion = 17.0`, `UIDeviceFamily = 1`,
    `CFBundleSupportedPlatforms = iPhoneOS`.
  - Executable: Mach-O 64-bit arm64, links `/usr/lib/dyld`, contains no
    `/Library/Developer/CoreSimulator` path — a **device** binary, not a simulator slice.
  - Contains the probe engine: the strings `fsprobe-writetest.tmp`, `kern.osversion`,
    `matrix.json`, and the `fsprobe.capability-matrix.v1` schema tag are all present.
- Limitations: **unsigned**. Built with `CODE_SIGNING_ALLOWED=NO`, so there is no
  `_CodeSignature`. It cannot be installed on a stock device as-is. Installing requires a
  signing step with an Apple ID (free personal accounts are sufficient for development
  signing) using Xcode, AltStore, or Sideloadly.
- The IPA has never been executed. Nothing in this entry is a runtime result.

### 2026-10-11 — xtool-built IPA (build only, never executed)

- Produced by the `xtool` workflow: xtool 1.21.0 on a `macos-15` runner, building the
  `App/` SwiftPM package with `xtool dev build --configuration release --ipa`.
- Artifact: `fsprobe-xtool-ipa`, containing `App/xtool/FSProbe.ipa`.
- Verified after download:
  - Structure: `Payload/FSProbe.app/` containing `FSProbe` (executable) and `Info.plist`.
  - `Info.plist`: `CFBundleIdentifier = com.bbaobaob.fsprobe`, `CFBundleExecutable = FSProbe`,
    `CFBundleShortVersionString = 1.0.0`, `MinimumOSVersion = 17.0`,
    `UIDeviceFamily = [1, 2]`, `CFBundleSupportedPlatforms = iPhoneOS`.
  - Executable: Mach-O 64-bit arm64, links `/usr/lib/dyld`, contains no
    `/Library/Developer/CoreSimulator` path — a device binary.
  - Contains the probe engine: `fsprobe-writetest.tmp`, `kern.osversion`, `matrix.json`, and
    the `fsprobe.capability-matrix.v1` schema tag are all present.
- Size: 1.4 MB, versus 325 KB for the xcodebuild-produced IPA. Both are device binaries; the
  difference is build configuration, not platform.
- Limitations: **unsigned** and **never executed**. No runtime result is claimed.
- Note: this IPA was built entirely from the SwiftPM package (`App/`) with no generated
  `.xcodeproj` and no pbxproj involved, which is the point of the xtool path.

### 2026-10-12 — CI-built IPA handover (build only, never executed)

Two IPAs are produced by CI at every push to `main`, from the same source tree, by
two independent build systems. Both were re-verified after download on this date.

| Workflow | Build system | Artifact | Size |
| --- | --- | --- | --- |
| `ios` | `xcodebuild` on `macos-15` (Release, `iphoneos`) | `FSProbe-unsigned-ipa` | 336 KB |
| `xtool` | `xtool dev build` on `macos-15` (Release) | `fsprobe-xtool-ipa` | 1.4 MB |

Verified for both:

- `Payload/FSProbe.app/FSProbe` is a Mach-O 64-bit **arm64 device** binary (links
  `/usr/lib/dyld`, contains no `/Library/Developer/CoreSimulator` path).
- Contains the current experiment code: the `fsprobe.capability-matrix.v2` schema
  tag, the `Boundary established` ascent stop reason, and the
  `fsprobe-writetest.tmp` synthetic filename.
- Bundle identity: `com.bbaobaob.fsprobe`, `MinimumOSVersion = 17.0`,
  `CFBundleSupportedPlatforms = iPhoneOS`.

Both are **unsigned** and **have never been executed**. No runtime result is claimed.

The xtool path builds from the `App/` SwiftPM package with no generated
`.xcodeproj` and no pbxproj involved; the xcodebuild path uses the generated
project. Two independent toolchains agreeing on the artifact is the point of
keeping both.

### Install path (research finding, recorded 2026-10-12)

The only computer available to the operator is an Android phone running Termux.
Research into getting an IPA onto a physical iPhone with no Mac found:

- **Sideloadly** (v0.60.0) signs and installs an unsigned IPA with a **free Apple
  ID**. Hosts: **macOS and Windows only** — there is no Linux or Android build.
  Free-account apps last 7 days; auto-refresh re-signs them.
- **AltStore / AltServer** likewise requires a macOS or Windows host.
- **Feather** (on-device, no computer) installs IPAs but **requires the user to
  supply a `.p12` certificate and a `.mobileprovision` profile**. It does not mint
  a free-account certificate itself. The community route is shared third-party
  certificates (KravaSign, "applep12.com", "Sunshine"), which are frequently
  revoked and which require trusting an unknown third party with signing
  material. **Not recommended.**
- **xtool** can sign and install over USB from Linux/macOS/Windows-WSL with a
  free Apple ID, but needs a computer and a USB-connected device. Its aarch64
  AppImage would not solve the problem: `usbmuxd` does not exist for Android
  userspace, so an iPhone is not reachable from Termux.

**Conclusion: there is no Android-only path.** Installing on the physical iPhone
requires a macOS or Windows computer (Sideloadly), or a Linux/WSL computer with
xtool. This is a platform requirement, not a limitation of the artifact.
