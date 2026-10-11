# Filesystem capability matrix

## Format

One row per investigation target, one column per operation. Every cell is recorded **independently**
— a successful read is never inferred to prove enumeration capability, and a successful write in the
app container is never inferred to prove write access elsewhere.

| Column | Syscall | What it exercises |
| --- | --- | --- |
| `lstat` | `lstat()` | metadata without following a final symlink |
| `stat` | `stat()` | metadata, following a final symlink |
| `opendir` | `opendir()` | acquiring a directory handle (search permission) |
| `readdir` | `readdir()` | listing entries (read permission on the directory) |
| `open+read` | `open(O_RDONLY)` + `read()` | reading file contents |
| `open+create` | `open(O_CREAT\|O_EXCL)` | creating a new file in the target directory |
| `open+write` | `open(O_WRONLY\|O_CREAT\|O_TRUNC)` + `write()` | modifying a file in the target directory |
| `unlink` | `unlink()` | removing a file |
| `readlink` | `readlink()` | resolving a symbolic link |

Cell values: `succeeded`, `deniedEPERM`, `deniedEACCES`, `notFound`, `notDirectory`,
`failedOther`.

Write probes operate on the synthetic file `fsprobe-writetest.tmp` **inside** the target directory,
verify by read-back, and remove it. They never overwrite a pre-existing file.

## Host result — macOS runner (NOT iOS)

Platform: macOS 15.7.9 (Build 24G830), `VirtualMac2,1`, Xcode 16.4 toolchain, captured by the
`ci` workflow on the free macOS runner (`macos-15`) on 2026-10-11.
**These are not iOS device results.** They are recorded because they are real Darwin syscall
behaviour from the same engine, and they already surfaced two harness defects.

```
path                                    lstat        stat         opendir      readdir      open+read    open+create  open+write   unlink       readlink
------------------------------------------------------------------------------------------------------------------------------------------------------------------
/Users/runner                           succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/Documents                 succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/Library                   succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/tmp                       notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var                                    succeeded    succeeded    succeeded    succeeded    failedOther  deniedEACCES deniedEACCES deniedEACCES succeeded
/private/var                            succeeded    succeeded    succeeded    succeeded    failedOther  deniedEACCES deniedEACCES deniedEACCES failedOther
/var/mobile                             notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library                     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library/Preferences         notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers                  notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Data/Application notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Shared/AppGroup  notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/tmp                                succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
```

Notes on the macOS result:

- `/var` is a symlink to `/private/var` on macOS, exactly as on iOS. `readlink` on `/var` succeeds
  and on `/private/var` fails — the matrix distinguishes them, which is the behaviour H4 predicts.
- On this host, `/var` allows `lstat`/`stat`/`opendir`/`readdir` but denies create/write/unlink with
  **`EACCES`** (macOS System Integrity Protection), *not* `EPERM`. This is precisely why the engine
  keeps `EPERM` and `EACCES` separate: on iOS the sandbox denies with `EPERM`, and conflating the
  two would hide the boundary. This observation is **macOS host behaviour only** and says nothing
  about iOS.
- `open+read` on a directory reports `failedOther` (`EISDIR`) — expected, recorded, not hidden.
- `/var/mobile/...` does not exist on macOS, so every cell is `notFound`. Absence is never reported
  as denial.

### Harness defects the host run exposed (and their fixes)

1. **Self-recursive `read`/`write`.** The Darwin shim's methods named `read`/`write` shadowed the
   libc functions of the same name, so their bodies called themselves: an infinite loop under `-O`
   (a 25-minute CI hang) and a stack overflow in debug (SIGSEGV). Fixed by renaming to
   `readFD`/`writeFD`. Regression guard:
   `POSIXProbeEngineTests.testWriteProbeVerifiesByReadBackAndCleansUp`, which asserts read-back
   matches written content and cannot pass while `read`/`write` are broken.
2. **False asymmetry finding on directories.** The discrepancy analysis reported "write succeeded
   but read failed" for directory targets, where `open+read` legitimately returns `EISDIR`. Fixed by
   recording `statIsDirectory` and skipping the check for directory targets. Guarded by
   `testDirectoryTargetDoesNotProduceFalseAsymmetry` and
   `testRegularFileAsymmetryIsStillFlagged`.

## Verification-host result — Swift 6.4 on Android/Termux

Platform: Swift 6.4 verification host (aarch64 Android), captured by a local run of the same CLI.
Also **not iOS**. Used to compile and unit-test the identical probe logic off-device: 22/22 tests
passed, and every `/var/...` path correctly reported `ENOENT` because it does not exist there.

## iOS device result

### iOS Simulator result (iOS 26.2 — NOT iOS 27)

Captured by the `ios` workflow on the free macOS runner: the app was built for the simulator,
installed, launched, and the matrix it wrote into its Documents directory was extracted. Platform
recorded by the app itself: **iOS 26.2**, build 24G830 (simulator runtime 26.2 - 23C54), `arm64`.

**Read this section with two caveats, because both limit what it can prove:**

1. **This is not iOS 27.** The runner's Xcode 16.4 image provides iOS simulator runtimes 18.5
   through 26.2 and nothing newer. There is no iOS 27 runtime available in this environment, so
   iOS 27 behaviour is untested here.
2. **The simulator's filesystem is the macOS host's filesystem.** The app container lives under
   `/Users/runner/Library/Developer/CoreSimulator/Devices/<UDID>/data/Containers/Data/Application/<UUID>`,
   not under `/var/mobile/Containers/...`. Consequently `/var/mobile` **does not exist** in the
   simulator, and every `/var/mobile/...` cell is `notFound`. The `/var` and `/var/tmp` rows reflect
   the macOS host filesystem, not iOS.

```
/Users/runner/.../Containers/Data/Application/<UUID>            succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/.../Containers/Data/Application/<UUID>/Documents   succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/.../Containers/Data/Application/<UUID>/Library     succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/Users/runner/.../Containers/Data/Application/<UUID>/tmp         succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/var                                                             succeeded    succeeded    succeeded    succeeded    failedOther  deniedEACCES deniedEACCES deniedEACCES succeeded
/private/var                                                     succeeded    succeeded    succeeded    succeeded    failedOther  deniedEACCES deniedEACCES deniedEACCES failedOther
/var/mobile                                                      notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library                                              notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library/Preferences                                  notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers                                           notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Data/Application                           notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Shared/AppGroup                           notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/tmp                                                         succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
```

What this run **does** establish:

- The harness runs end-to-end on real iOS userspace: it builds, installs, launches, computes the
  matrix, and writes `matrix.json` / `matrix.txt` into the app container with no user interaction.
- The app container behaves as the documented baseline predicts: full access to its own
  `Documents`, `Library`, and `tmp`.
- The result was identical on the iOS 18.5 and iOS 26.2 runtimes, i.e. this baseline is stable
  across the versions available here.
- The app log shows no crash; the only messages are ordinary simulator noise (a missing
  `eligibility.plist` and `libCoreFSCache` cache invalidation).

What it **cannot** establish, and must not be read as establishing:

- Anything about `/var/mobile`, `/var/mobile/Library`, `/var/mobile/Containers/...`, or App Group
  containers — those paths do not exist in the simulator.
- Anything about iOS 27 specifically.
- Whether iOS denies with `EPERM` (seatbelt) as opposed to the `EACCES` seen for `/var` here,
  because the `/var` denial observed in the simulator comes from the macOS host.

The `/var/mobile` investigation therefore requires the physical iPhone. See
`docs/device-validation-log.md`.

---

## Experiment: directory ascent from the app container

An original experiment added after the fixed target list, because the fixed list
cannot express it: the ancestors of the app container are only known at runtime.
Starting from a directory the process legitimately owns, the harness walks
upwards one level at a time and probes each ancestor with **read-only**
operations (`lstat`, `opendir`, `readdir`). It never creates, writes, or deletes
in an ancestor, because ancestors of the app container are not authorized
locations for this process.

The question it answers is the one from the research plan: *why can an ordinary
app read some files but fail to enumerate their parent directories?* Answering it
requires probing the parents themselves.

### Result on iOS 26.2 (Simulator) — recorded 2026-10-11

```
 0 .../Devices/E952A9B0.../data/Containers/Data/Application/E0E9337D...  visible (7 entries)
 1 .../Devices/E952A9B0.../data/Containers/Data/Application               visible (145 entries)
 2 .../Devices/E952A9B0.../data/Containers/Data                           visible (6 entries)
 3 .../Devices/E952A9B0.../data/Containers                                visible (7 entries)
 4 .../Devices/E952A9B0.../data                                           visible (12 entries)
 5 .../Devices/E952A9B0...                                                visible (5 entries)
 6 .../Devices                                                            visible (135 entries)
 7 .../Library/Developer/CoreSimulator                                    visible (5 entries)
```

**Attribution, stated plainly: this is a Simulator result and it is not an iOS
finding.** The iOS Simulator runs apps under a macOS seatbelt profile and shares
the host filesystem; it does not implement the iOS container isolation model. The
fact that depth 1 — the parent that on a device is `/var/mobile/Containers/Data/Application`
— was enumerable with **145 entries** (i.e. 145 sibling app containers) is a
property of the simulator, not of iOS.

On a physical device this is the expected-to-be-denied case, and it is exactly
what the device run must measure. Nothing here should be read as evidence that
iOS permits cross-app container enumeration.

### Control: the same ascent on the macOS host

```
 0 /Users/runner  visible (41 entries)
 1 /Users         visible (5 entries)
 2 /              visible (23 entries)
```

The control confirms the mechanics on a third platform and shows the walk
terminating correctly at the filesystem root.

### Control: the same ascent on the verification host (Android/Termux)

```
 0 <repo>            visible (15 entries)
 1 <home>            visible (24 entries)
 2 .../files         visible (5 entries)
 3 .../usr           visible (6 entries)
 4 /data/data        lstat=succeeded opendir=deniedEACCES readdir=deniedEACCES [EACCES]
 5 /data             lstat=succeeded opendir=deniedEACCES readdir=deniedEACCES [EACCES]
 6 /                 lstat=succeeded opendir=deniedEACCES readdir=deniedEACCES [EACCES]
      stopped: boundary established after 3 consecutive not-fully-visible ancestors
  boundary: first not-fully-visible ancestor is depth 4 (/data/data)
```

This is the shape of result the experiment is designed to produce: a clean
boundary located relative to a known-good start, with the denying errno recorded.
Note that here `lstat` succeeds while `opendir` is refused — precisely the
"can see the name but not the contents" asymmetry the research plan asks about,
and the reason the experiment records each operation independently.

### The device question this leaves open

On a physical iPhone the ascent starts at
`/var/mobile/Containers/Data/Application/<UUID>` and the first four ancestors are
the research targets themselves:

| Depth | Path on device | Expected | Simulator showed |
| --- | --- | --- | --- |
| 1 | `/var/mobile/Containers/Data/Application` | denied | **visible, 145 entries** |
| 2 | `/var/mobile/Containers/Data` | denied | visible |
| 3 | `/var/mobile/Containers` | denied | visible |
| 4 | `/var/mobile` | denied | not probed (walk reached maxDepth) |

The simulator cannot answer any of these. The device run is required.
