# Round 9 — the XPC reply chain, followed to its end

Device: iPhone12,5, iOS 27.0 build 24A437 (stock). Simulator runtime for this
round: iOS 26.2 (the newest GitHub-hosted runner can provide).

## What this round did

The mach-lookup experiment found four services reachable from an ordinary app.
The mission's confused-deputy question was then followed as far as it could be
followed with an empty request, in three steps, each of which could have ended
the chase and did not:

1. **Do the reachable services answer?** Four replied to an empty message,
   within a millisecond. Reported as the confused-deputy shape.

2. **Is the reply the service, or the transport?** The reply's shape was
   recorded — type and key count, never values. Three services returned a real
   dictionary with two keys. That ruled out transport bookkeeping, so the
   daemons themselves were answering.

3. **What do the keys contain?** Only key NAMES were read, never values, which
   is what makes it safe to ask a privileged daemon. **All three replies were
   empty dictionaries.**

An empty dictionary is the answer that closes the question. It means the
daemon recognised a message with no protocol and had nothing to say to it —
not that it performed work for an unidentified caller. The confused-deputy
hypothesis for these four services is falsified, and the evidence is the empty
dictionary rather than the absence of a reply.

## The host-port chain, followed to its end

`task_get_special_port(TASK_HOST_PORT)` returns a host port on the simulator.
Reported as a violation. Followed up:

- `host_get_special_port` — refused, KERN_INVALID_ARGUMENT (validity)
- `host_processor_set_priv` — refused, invalid port right (policy)
- `host_statistics` — refused, KERN_INVALID_HOST (policy)

The port is obtainable and impotent. That is a macOS artifact — the simulator
shares the macOS kernel, where a host port is easier to obtain than on iOS —
and the module records exactly that distinction, because a policy refusal and
a validity refusal mean different things and only one of them means the port
is real.

## Simulator findings, each with its reason

| Finding | Why it is not an iOS finding |
|---|---|
| `clone-write-outward` permitted | simulator shares the macOS filesystem; `/var/mobile` does not exist there |
| `rename-cross-boundary-*` permitted | same |
| `mach-host-port` / `task_get_special_port-host` | port is impotent; every use refused |
| `getfsstat`, `sysctl-kern-bootargs`, `sysctl-sandbox-sentinel` | macOS kernel state, not iOS sandbox |
| four services replying | replies are empty dictionaries |

Every one of these is recorded as a simulator result at the point of use, and
none is carried into the iOS evidence.

## What is now settled for iOS 27.0

Confirmed refusals on the physical device: the whole filesystem operation set,
ancestor ascent, `..` traversal, symlink escape, dirfd-relative escape,
`link()` from a protected source, `rename()` across the boundary, directory
enumeration by two syscalls, `openbyid_np` on nine paths, `clonefile()` in both
directions, `proc_pidpath` / `task_for_pid` / `proc_listallpids` on other
processes, and `NSFileCoordinator` as a deputy (coordination granted, read and
write refused underneath).

Confirmed falsified with evidence: the claim that an app cannot reach a mach
service by name (four are reachable), and now the confused-deputy hypothesis
for those four (they answer with nothing).

**No boundary violation has been demonstrated on iOS 27.0.**

## What this round cost, and what it taught

Six defects were found and fixed while building this round, and every one of
them would have produced a wrong answer rather than a crash:

- `releasePortArray` walked a vm buffer with `mach_port_deallocate`. SIGSEGV.
- `mach_vm_read`'s data released as a port instead of as a vm buffer.
- The memory probe read address zero, so its control could never pass.
- The probe page was allocated once and released per run, so the second call
  read freed memory.
- A failed control removed the foreign reads from the report entirely.
- Three string literals contained double quotes inside interpolations.

The pattern across all of them: each was a case of assuming what a value was
rather than looking it up. A send right and a vm address are both integers. A
control that cannot pass hides the question. A rename that matches its own
output damages the definition.
