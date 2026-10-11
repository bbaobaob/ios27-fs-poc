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
