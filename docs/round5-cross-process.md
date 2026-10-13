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

## Outcome

**Device result outstanding.** The IPA containing this experiment is built and
verified (correct `Payload/` layout, arm64 device binary, experiment linked).

### Calibration run — macOS simulator, iOS 26.2 (NOT an iOS finding)

The simulator shares the macOS host filesystem, services, and kernel, so nothing
below is evidence about iOS. It is recorded because it calibrates the instrument:

| Observation | Value | What it establishes |
|---|---|---|
| connection factory resolved | 8 of 8 | dlsym reaches the symbol; the experiment is runnable |
| negative control | refused, "Connection invalid", 3 ms | the refusal signature is measurable and distinguishable |
| 4 of 7 candidates | reachable (full timeout) | on macOS these services accept connections |
| 3 of 7 candidates | refused, same signature as the control | indistinguishable from "no such service" |
| `proc_pidpath` self | succeeded, own path | **the control works** |
| `proc_pidpath` launchd (pid 1) | **succeeded, `/sbin/launchd`** | **the detector fires on a real disclosure** |
| `proc_pidpath` kernel (pid 0) | `ESRCH`, not applicable | a non-event is not reported as a denial |
| `task_for_pid` both | denied, `(os/kern) failure` | the isolation boundary holds here |
| `proc_listallpids` | 179 pids visible | identifier visibility is not a violation |

The `proc_pidpath` result on pid 1 is the important one: the experiment reported
a genuine information disclosure rather than a denial. That proves the detector
is not hard-wired to answer "denied", which is what makes an iOS negative result
meaningful. On macOS this is expected behaviour, not a vulnerability — the
distinction is the whole reason the device run is required.

### What the device run must show

On iOS 27.0 the sandbox governs both the filesystem and the mach-lookup gate,
so the expected results are:

- the connection factory resolves (the symbol exists in the runtime),
- the negative control is refused,
- every candidate is refused, and — critically — **with the same signature as
  the negative control**, which distinguishes "denied by policy" from "no such
  service",
- `proc_pidpath` on pid 1 and 0 is refused while the self-control succeeds,
- `task_for_pid` on both is refused.

If any candidate does *not* match the negative control's signature, or
`proc_pidpath` returns another process's path, or `task_for_pid` returns a port,
that is the finding.

