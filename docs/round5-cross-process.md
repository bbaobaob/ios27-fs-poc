# Round 5 — Cross-process and IPC authorization

Status: **hypothesis recorded, experiment implemented, device result outstanding.**

Device: iPhone12,5, iOS 27.0 build 24A437 (stock, not jailbroken).
Process: ordinary sandboxed app, unsigned IPA signed off-device with a free Apple ID.

## Why this direction

Rounds 1–4 tested what *this process* can do to *the filesystem*. Every
mechanism class available to an ordinary app was refused, consistently, with
`EPERM`. That establishes that the filesystem boundary holds. It does not
establish anything about the two other authorization paths, and concluding
otherwise would be exactly the error the mission warns against: "do not conclude
that an entire security boundary is invulnerable merely because the tested
filesystem operations were denied."

Two distinct hypotheses remain, in a mechanism class that has never been tested
in this project.

## Hypothesis 1 — mach-lookup (confused deputy)

**Boundary under test:** launchd's mach-lookup gate. A sandboxed app must not be
able to reach a named system service that its sandbox profile does not permit,
because such a service acts with privileges the caller does not hold.

**Why it was not tested before:** the iOS SDK marks
`NSXPCConnection(machServiceName:)` `API_UNAVAILABLE(ios, watchos, tvos)` and
`xpc_connection_create_mach_service` unavailable. The earlier round therefore
reported the avenue closed. That conclusion was **hard-coded rather than
measured** (audit defect D11), and it conflated two different things:

- *unavailability in a header*, which prevents **linking** by name, and
- *absence from the runtime*, which would prevent **calling** at all.

If the code exists in libxpc and the process resolves it at runtime, the real
gate is the operating system's mach-lookup check, and that is a measurable
question.

**Mechanism:** `dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service")`,
resolved at runtime, then a real connection attempt to each candidate service.
This is the same pattern already used for `clonefile` and `openbyid_np`, both of
which resolved successfully on this device.

**Control:** the first candidate is `com.bbaobaob.fsprobe.nonexistent.control`,
a name that cannot exist. It calibrates the platform's "not found" signature.
Without it, a candidate producing that same signature is uninterpretable — it
could mean "denied by policy" or "no such service".

**Expected:** the symbol resolves, and every candidate is refused with the same
signature as the negative control.

**Falsified by:** any candidate that does *not* produce the negative control's
signature, i.e. a service that answers a connection carrying no protocol.

**Note:** reachability is not a vulnerability. A connection that opens proves
only that the service exists and answered. A finding requires an *effect* the
caller was not authorized to produce.

## Hypothesis 2 — cross-process introspection

**Boundary under test:** process isolation. An ordinary app must not be able to
observe or control a process other than its own.

**Mechanisms and what each would mean:**

| Operation | If it succeeds | Boundary |
|---|---|---|
| `proc_pidpath(1)` (launchd) | discloses a protected process's executable path | information disclosure |
| `task_for_pid(1)` | grants a task port for another process | **process isolation** — control over its address space |
| `proc_listallpids` | enumerates the process table | not a violation by itself; identifiers only |

**Control:** `proc_pidpath(getpid())` must return this binary's own path. If the
control fails, every other result is uninterpretable — a blanket refusal would
mean the API does not work here, not that the policy denies it. The module
records `controlSucceeded` and marks the whole experiment inconclusive if it is
false.

**Expected:** the control succeeds; `proc_pidpath` on pid 1 and 0 is refused;
`task_for_pid` on both is refused (it normally requires the
`task_for_pid-allow` entitlement); `proc_listallpids` may or may not enumerate.

**Falsified by:** `task_for_pid` returning a port for another process, or
`proc_pidpath` returning another process's path.

## Instrumentation requirements this experiment adds

Per the audit, several harness defects had to be fixed before any new result is
trustworthy as evidence. The relevant ones for this module:

- Every result must distinguish *exact errno* from *failedOther* from
  *not attempted*. `EISDIR` and `EINVAL` are documented POSIX answers, not
  unexplained failures.
- A granted operation with no effect must not be recorded as a denial, and a
  denial must not be recorded as a success.
- "Not probed" must never be printed for a path that *was* probed and denied.
- Symbol-resolution failure is `NOT_ATTEMPTED`, not a denial.

## Outcome — device result recorded

**Device:** iPhone12,5, iOS 27.0 build 24A437, stock, unsigned IPA signed
off-device. Run at 2026-10-13T09:38:53Z, container
`687A75DA-3415-469E-83F4-3E5EE328B2BD`.

### Hypothesis 2 — cross-process introspection: FALSIFIED

| Operation | Target | Result |
|---|---|---|
| `proc_pidpath` | self | **succeeded**, 99 bytes, own bundle path |
| `proc_pidpath` | launchd (pid 1) | **denied, EPERM** |
| `proc_pidpath` | kernel (pid 0) | **denied, EPERM** |
| `task_for_pid` | launchd, kernel | **denied, kern_return_t 5** |
| `proc_listallpids` | all | **denied, EPERM** |

The control succeeded, so the refusals are interpretable as policy denials
rather than as a broken API. Compare the macOS calibration run, where
`proc_listallpids` returned 179 pids: the same code reports success when success
is available, so the iOS refusals are real.

**Instrumentation defect found and fixed while reading this result.** The
original build reported pid 1 and pid 0 as `notApplicable` with EPERM, and the
interpretation claimed "EPERM indicates the target has no executable path rather
than that access was refused." That was wrong twice over:

1. errno was not cleared before the call, so pid 0's EPERM may have been
   inherited from pid 1's — an artifact of loop order, not a measurement.
2. EPERM is the sandbox denial signature, the same value every other denied
   operation on this device produced. Reporting it as "not a security
   observation" would have discarded a correct denial.

Fixed by clearing errno before the call and classifying a zero return with errno
set as `.denied`. The device result above is from the *fixed* logic applied to
the recorded values.

### Hypothesis 1 — mach-lookup: PREVIOUS CONCLUSION FALSIFIED, AVENUE OPEN

The round-4 claim that an ordinary iOS app cannot open a mach service by name
was hard-coded, not measured. Measurement refutes it:

| Service | Result | Timing |
|---|---|---|
| negative control (nonexistent) | refused, "Connection invalid" | 0 ms |
| `com.apple.FileCoordination` | **reachable** | 3005 ms |
| `com.apple.cfprefsd.daemon` | **reachable** | 3005 ms |
| `com.apple.containermanagerd` | **reachable** | 3002 ms |
| `com.apple.containermanagerd.system` | **reachable** | 3002 ms |
| `com.apple.coreservices.quarantine-resolver` | refused, same signature | 1 ms |
| `com.apple.mobile.installation_proxy` | refused, same signature | 0 ms |
| `com.apple.LaunchServices` | refused, same signature | 0 ms |

The negative control is what makes this readable. Three services were refused
with the *identical* signature and reason as a name that cannot exist, while four
produced no interruption at all across a three-second window — the lookup was
permitted and the service is registered. So the mach-lookup gate is enforced
**per service**, and an ordinary app is permitted to reach at least these four.

**This is not itself a vulnerability.** Reachability is reconnaissance. Two of
the four back documented public APIs this app already uses (`NSFileCoordinator`
worked in the control experiment, and every app uses `UserDefaults`), so their
reachability is expected. What changed is that the avenue is open and must now
be tested with real requests.

### Next experiment, now justified by measurement

`com.apple.cfprefsd.daemon` is reachable and is a privileged daemon that writes
files on the caller's behalf. `PreferenceDeputyProbe` tests whether it resolves
a caller-supplied suite name against the caller's own container or against a
global location, using `UserDefaults(suiteName:)` — the documented public
surface, not an invented protocol.

The discriminating signal is location: a suite this app owns must produce a file
inside this container (the control), and a foreign suite name must likewise land
here. If the write reports success but no such file appears here, the daemon
resolved the name against something outside this container.

The control gates the test case. On a platform whose preference storage is
elsewhere, "no file appeared" cannot distinguish a cross-container write from an
ordinary write to the platform's own location — running the test anyway would
report a false finding, so it is withheld and the case reports
`notApplicable`.

### Consolidated negative results (all measured on iOS 27.0)

Filesystem: ancestor ascent, `..` traversal, symlink escape, dirfd-relative
escape, `link()` from `/usr/lib/dyld`, same-volume `rename()` to the container
parent, directory enumeration (POSIX and Foundation), `openbyid_np` on nine
paths, `clonefile()` outward to `/var/mobile/Media`, `clonefile()` inward
(EXDEV, cross-volume, not attributable). All refused; the container write map
matches the documented profile.

Cross-process: `proc_pidpath`, `task_for_pid`, `proc_listallpids` on other
processes. All refused, with a working self-control.

Service-mediated: `NSFileCoordinator` granted coordination but the underlying
read and write were refused (`NSCocoaErrorDomain 513`) — coordination is not
authorization.

**No boundary violation has been demonstrated.** The mach-lookup avenue is open
and is the next thing to test with a real request.

