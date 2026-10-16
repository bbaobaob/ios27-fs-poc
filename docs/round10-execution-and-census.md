# Round 10 — the loop resumes: execution, the profile-spawn CVE, and a census

Simulator runtime for this round: iOS 26.5 SDK on macOS runners (the newest
GitHub can provide). Device: iPhone12,5, iOS 27.0 build 24A437 — the only iOS
27 environment, and the only place any of this counts as a finding.

## What this round did

External research (public CVE writeups and sandbox-escape literature,
2019–2026) replaced guessing with four mechanisms this project had never
tested. Each was implemented from scratch; nothing was adapted from
third-party exploit code.

1. **Process execution.** Nineteen modules had tested what an app can reach,
   read, and write. None had tested whether it can RUN something. posix_spawn,
   system, and popen are separate code paths and all went in, with a
   nonexistent-path control whose ENOENT calibrates every refusal.

2. **CVE-2026-20628 (profile-spawn).** `posix_spawnattr_setmacpolicyinfo_np`
   lets a process name a built-in sandbox profile for its child, and the child
   received it INSTEAD OF the parent's. Fixed in 26.3 by blanket denial; iOS
   27.0 is later, so the fix is expected — but expected is not measured, and
   the original researcher could only exploit on macOS. Step one sets the
   attribute and spawns nothing; step two runs only if step one succeeds.

3. **Mach-service census.** Every service experiment so far used eight
   hand-written names. The published method — parse
   `/System/Library/xpc/launchd.plist`, try every name — replaced the guess.

4. **Embedded XPC services.** Helpers shipped INSIDE system frameworks register
   into the loading app's PID domain, invisible to launchd lookup and unnamed
   by the sandbox profile. The class produced a run of 2023 CVEs with one root
   cause (no caller code-signature check). The probe loads the framework, then
   sends an EMPTY message. A reply is explicitly not a finding.

## What broke, and what it taught

- **system() is a trap, not a call.** The first simulator run with the new
  battery died between "mach-ladder" and "execution-and-profile-spawn". The
  crash log named the killer: system() aborts its caller via abort_report_np
  (SIGABRT) instead of returning. The SDK note meant exactly what it said.
  system() is now recorded as a callerAborted trap and never called; its
  binding was deleted so no call site can grow back by accident.

- **The harness can now survive its own death.** Two mechanisms, both built
  for this exact failure: per-phase partial writes (matrix-partial.json/txt
  after every phase — the run that died still yielded 151K of evidence naming
  the death window) and crash-log capture in CI diagnostics. A second
  addition: one progress marker per module through any death window, so the
  next death names a module instead of a group of three.

- **posix_spawn returns its errno; errno stays zero.** The control answered
  return-2 (ENOENT) and was misreported as "otherError" because the code read
  errno instead of the return value. Both spawn call sites and both spawnattr
  sites now use a nonzero return as the errno directly, and the mapping is
  pinned by a test table.

## Simulator results (artifacts, not findings)

The first green run flags simulator "violations" that a macOS process is
expected to produce: posix_spawn of /bin/sh succeeds, popen returns a pipe,
profile names are accepted, embedded helpers answer. The simulator app is a
macOS process; macOS permits these. Simulator results are never iOS findings
— the device run decides each one.

Genuinely new reconnaissance, valid on any platform: 347 XPC service bundles
inside system frameworks (25 examined, several answer an empty message), and
the launchd manifest parses to zero MachServices entries on the simulator
runtime (recorded, not worked around).

## Standing questions for the device

- posix_spawn /bin/sh on iOS 27.0: EPERM, or something else?
- `posix_spawnattr_setmacpolicyinfo_np("no-network")`: accepted or denied?
- Which embedded services answer on a real device, and what do their replies
  contain (shape only)?
- Concrete (non-empty) XPC requests remain unauthorised: they need real
  protocol knowledge, not invention.
