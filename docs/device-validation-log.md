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

**Schema tag.** The exporter currently writes `fsprobe.capability-matrix.v9`. Entries below that
quote an earlier tag (`v1`, `v2`, …) record what that dated artifact actually contained; they are
historical records of a specific build and are not rewritten when the tag advances. The tag to
expect from the current code is the one stated here.

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

### iOS 27 physical device — RECORDED (three runs)

The blocker recorded above was cleared: a signed build was installed on a physical iPhone running
stock iOS 27.0. Every device result in this repository comes from these runs, and from nowhere else.

| Field | Value |
| --- | --- |
| Exact iOS version and build | **iOS 27.0, build 24A437** |
| Device model | iPhone12,5 (iPhone 11 Pro Max) |
| Signing context | development-signed with a free Apple ID, off-device (no Mac) |
| Entitlements present | none beyond the default app sandbox |
| Runs | 2026-10-13T05:06:42Z, 2026-10-13T09:38:53Z, 2026-10-13T12:34:04Z |
| Reproduction | mach-lookup result reproduced across two independent runs |

What these runs established: the filesystem capability matrix, ancestor ascent, boundary
experiments, container write map, `openbyid_np`, `clonefile`, sandbox-profile metadata,
`NSFileCoordinator` as a deputy, mach-service reachability, cross-process introspection, cfprefsd
as a deputy, and the untested operation classes. See `docs/capability-matrix.md` and
`docs/round5-cross-process.md`.

**No simulator result in this repository is evidence about iOS.** The simulator shares the macOS
host filesystem, services, and kernel, and applies a weaker sandbox; `/var/mobile` does not exist
there. Simulator runs exist to compile-validate the app and to calibrate the instrument, and every
one of them is labelled as such at the point of use.

### Runner capability — probed, not assumed (2026-10-13)

A dedicated workflow (`probe-runners.yml`) enumerated what each GitHub-hosted macOS runner image
actually ships. Result:

| Runner | Default Xcode | Newest iOS SDK | iOS 27 simulator runtime |
| --- | --- | --- | --- |
| `macos-15` | 16.4 | 18.5 | none (runtimes stop at 26.2) |
| `macos-26` | 26.6 | **26.5** | **none** |
| `macos-latest` | 26.6 | **26.5** | **none** |

**GitHub-hosted runners cannot build against the iOS 27 SDK and cannot run an iOS 27 simulator.**
This is measured from each image's own `xcodebuild -showsdks` and `xcrun simctl list runtimes`
output, not inferred from a comment. The device is therefore the only iOS 27 environment available
to this project, which makes the physical-device runs above load-bearing rather than optional.

The `ios` workflow builds the device target on `macos-26` with Xcode 26.6 so the code is compiled
against the newest SDK reachable (26.5) rather than 18.5. That is closer to iOS 27 and is the
honest limit of what CI can provide; it is still not iOS 27, and the difference is recorded here
rather than smoothed over.

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
    `matrix.json`, and the `fsprobe.capability-matrix.v1` schema tag are all present (the tag this
    artifact carried; the current exporter emits v9).
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
    the `fsprobe.capability-matrix.v1` schema tag are all present (the tag this artifact carried;
    the current exporter emits v9).
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
  tag (the tag this artifact carried; the current exporter emits v9), the
  `Boundary established` ascent stop reason, and the
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
