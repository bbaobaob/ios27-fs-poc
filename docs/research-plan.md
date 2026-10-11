# Research plan — falsifiable hypotheses

Phase 2 deliverable. Each hypothesis states the expected result, the control experiment, the
alternative explanations, and the evidence needed to confirm or reject it. A denial is **not**
assumed to be a vulnerability, and success is **not** assumed to be a capability.

Platform context to be recorded before any conclusion is drawn: exact iOS version **and build**,
device model, signing/entitlement context.

---

## H1 — Baseline capability

**Claim.** An ordinary app has full read/write/enumerate access to its own container
(`NSHomeDirectory()`, `Documents`, `Library`, `tmp`) and no access to any path outside it that it
did not receive through a documented grant.

- **Expected:** all operations succeed on container paths; `/var/mobile/...` paths fail.
- **Control:** the container paths themselves. If the baseline fails, the harness is broken and no
  other result is meaningful.
- **Alternatives:** container paths could be affected by data-protection class (file locked while
  device is locked) — distinguish by checking `NSFileProtectionComplete` behaviour and by testing
  while unlocked.
- **Evidence:** per-operation outcomes and errno for each container path.

## H2 — Sandbox denial is `EPERM`, not `EACCES`

**Claim.** On stock iOS, access denied by the seatbelt sandbox surfaces as `EPERM`, whereas POSIX
permission bits surface as `EACCES`.

- **Expected:** `/var/mobile` (mode 0755, owned by `mobile`) yields `EPERM` from the sandbox, not
  `EACCES`.
- **Control:** compare against a path that is absent (`ENOENT`) and against the app container
  (success). Absence must never be reported as denial.
- **Alternatives:** a directory with restrictive POSIX bits would produce `EACCES` and must be
  attributed to permissions, not the sandbox.
- **Evidence:** exact errno name and `strerror()` text for every denied probe.

## H3 — Read without enumeration

**Claim.** If a file inside a directory can be opened and read while the directory cannot be
enumerated, the authorization surface is inconsistent between `open()` and `readdir()`.

- **Expected:** on stock iOS both are denied identically; a divergence would be an implementation
  discrepancy worth investigating.
- **Control:** the app container, where both succeed.
- **Alternatives:** the file may be reachable through a *different* path (e.g. an App Group
  container, a security-scoped bookmark, or a documented shared location) rather than through the
  parent directory. Test both the direct path and the parent.
- **Evidence:** paired `open+read` and `readdir` outcomes on the same target, recorded
  independently.

## H4 — `/var` symlink and path resolution

**Claim.** `/var` is a symbolic link to `/private/var` on iOS, and path resolution through the
symlink does not change the authorization decision.

- **Expected:** `lstat("/var")` and `lstat("/private/var")` both succeed or fail identically;
  `stat`/`lstat` disagreement would indicate the final component is a symlink.
- **Control:** a symlink created inside the app container, where both paths are fully accessible.
- **Alternatives:** a sandbox profile rule may match on the literal path string, making
  `/var/...` and `/private/var/...` behave differently. This is exactly the kind of discrepancy the
  matrix is designed to surface.
- **Evidence:** `lstat` vs `stat` outcome pairs, plus `readlink` results.

## H5 — `/var/tmp` reachability

**Claim.** `/var/tmp` is not writable by an ordinary app.

- **Expected:** `open+create` fails; the write probe uses a synthetic file and cleans up.
- **Control:** the app container `tmp` directory, where creation succeeds.
- **Alternatives:** on a jailbroken or misconfigured device `/var/tmp` may be world-writable — that
  would be a **configuration issue**, not a sandbox escape, and must be labelled as such.
- **Evidence:** create/write/unlink outcomes with exact errno.

## H6 — App Group containers and documented grants

**Claim.** App Group containers are reachable only when the app holds the matching entitlement and
group identifier; the directory permissions alone do not grant access.

- **Expected:** `/var/mobile/Containers/Shared/AppGroup` is not enumerable; an app-group-relative
  path *inside* the app's own group is accessible only with the entitlement.
- **Control:** with and without the entitlement, if an App Group is configured for the test app.
- **Alternatives:** access could come from a *user grant* (document picker, security-scoped
  bookmark) rather than the entitlement. Distinguish by checking whether the grant is required at
  all.
- **Evidence:** entitlement context plus per-operation outcomes for group paths.

## H7 — Discrepancy between `FileManager` and raw POSIX

**Claim.** Foundation's high-level APIs can report a different outcome than the underlying syscall
for the same path (for example when a failure is cached or remapped).

- **Expected:** `FileManager.contentsOfDirectory` and raw `readdir` agree.
- **Control:** run both against the app container.
- **Alternatives:** a difference may be an artefact of Foundation's error mapping rather than a
  security-relevant behaviour. Only a difference that changes the *access decision* is interesting.
- **Evidence:** paired outcomes from both APIs on the same path.

---

## Negative-result discipline

If a hypothesis fails, the negative result is preserved and recorded in
`docs/device-validation-log.md` with the exact errno and reproduction count. A failed hypothesis is
a result, not a defect.

## Explicitly out of scope

- Claiming a sandbox escape without reproducible evidence.
- Inventing private entitlements or undocumented kernel access.
- Using, copying, or wrapping third-party exploit code.
- Recursively collecting unrelated private device data.
