# ios27-fs-poc

Original research harness for investigating **filesystem access behaviour on stock iOS 27** —
specifically which directory-enumeration, file-read, and file-write capabilities an ordinary,
conventionally signed app has over selected locations under `/var/`.

This repository exists because the project has **no Mac and no local Xcode**. Making the
repository **public** gives access to GitHub-hosted **macOS runners for free**, which supply the
Xcode toolchain (and iOS Simulator) needed to build and exercise the harness. The macOS runner is
a *build and verification* platform; runtime evidence from the physical iPhone is recorded
separately in `docs/device-validation-log.md`.

## Status (honest)

| Phase | State | Evidence |
| --- | --- | --- |
| Environment / tooling | done | `gh` auth, Swift 6.4 verification host, public repo with macOS CI |
| Research plan (hypotheses) | done | `docs/research-plan.md` |
| Core probe harness | authored + unit-tested | `Sources/FSProbeCore`, 22 tests passing on the macOS runner and the verification host |
| macOS (Darwin) build + test | verified by CI (green) | `.github/workflows/ci.yml`, 22/22 tests on `macos-15` |
| iOS app target | builds and runs | `FSProbe.xcodeproj` (generated), `.github/workflows/ios.yml` |
| iOS Simulator run (26.2) | done | matrix captured; app container baseline confirmed |
| **iOS 27 physical device** | **blocked — not performed** | no iOS 27 runtime or Xcode release exists in this environment |

No iOS 27 result exists yet. The simulator runs are labelled with their runtime (18.5 and 26.2)
and are **not** presented as iOS 27 evidence; the simulator's filesystem is the macOS host's, so it
cannot answer any `/var/mobile` question at all.

## What the harness measures

Every probe calls POSIX syscalls directly (`lstat`, `stat`, `opendir`, `readdir`, `open`, `read`,
`write`, `unlink`, `readlink`) so the **exact errno** is observable. Foundation's `FileManager`
collapses distinct failures into one `NSError` domain and hides the errno, which would destroy the
primary evidence.

The distinction that matters:

- `EPERM` — on iOS this is the **seatbelt sandbox** denial signature.
- `EACCES` — POSIX permission bits / ACLs.
- `ENOENT` — the path does not exist. *Not a security observation.*

Conflating these would hide the authorization boundary under investigation.

### Safety rules built into the engine

- Write probes use a dedicated synthetic filename (`fsprobe-writetest.tmp`) **inside** the target
  directory. They never overwrite a pre-existing file, always verify by read-back, and always clean
  up.
- Reads are bounded (4096 bytes) so unrelated private data is never pulled into a report.
- Enumeration records entry **counts**; entry **names** are only recorded for directories this
  harness created.
- Operations are probed independently: a successful read is never treated as proof of enumeration
  capability, and a successful write in the app container is never treated as proof of write access
  elsewhere.

## Layout

```
Sources/FSProbeCore/        Probe engine, result model, error classification, matrix, export
Sources/fsprobe-cli/        Command-line runner used by CI
Tests/FSProbeCoreTests/     Unit tests (20, passing on the verification host)
.github/workflows/ci.yml    macOS runner: build, test, run harness, upload matrix
docs/research-plan.md       Falsifiable hypotheses and control experiments
docs/capability-matrix.md   Matrix format + host results
docs/device-validation-log.md  Device-validation record template + current blocker
docs/attribution.md         What is original vs. standard APIs
```

## Running locally

```sh
swift build -c release
swift test -c release
.build/release/fsprobe-cli --label "my-host" --json matrix.json --text matrix.txt
```

The core library targets iOS 17+ and macOS 14+. The verification host used during development was
Swift 6.4 on Android (Termux); a non-Darwin compatibility seam exists purely so the identical probe
logic can be compiled and unit-tested there. On iOS and macOS that seam is inert and the platform
libc is called directly.

## CI (free macOS runner)

`ci.yml` runs on `macos-15` on every push and pull request. Public repositories get standard
GitHub-hosted runners — including macOS — at no cost, which is why this repository is public.

The workflow builds the package in release mode, runs the unit tests, runs the harness to produce a
matrix, and uploads the matrix plus the platform context (`sw_vers`, `xcodebuild -version`) as an
artifact.

## Originality

All probe logic, result model, error classification, matrix analysis, discrepancy detection, CLI,
tests, and documentation in this repository were written for this project from first principles.
No third-party exploit, PoC, or tool was cloned, copied, renamed, or wrapped. See
`docs/attribution.md` for the precise boundary between original code and standard platform APIs.

## Licence

MIT — see `LICENSE`.
