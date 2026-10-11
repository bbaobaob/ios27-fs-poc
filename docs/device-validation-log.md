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
