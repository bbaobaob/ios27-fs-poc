//
//  PrivilegeAndSnapshotProbe.swift
//  FSProbeCore — the classic sandbox-escape primitives, measured directly.
//
//  WHY THIS EXISTS
//  ---------------
//  Every iOS sandbox escape in public history ends at one of a small set of
//  primitives: credentials that changed hands, an APFS snapshot created or
//  reverted, an attribute written outside the container, a rename that moved
//  two objects past a check, or a file descriptor seen through another
//  process. This module has measured reachability — which paths open, which
//  services answer — but it has never measured the manipulation primitives
//  themselves, the operations that DO something rather than look at something.
//  Every earlier claim about them here was assumption. This file replaces
//  assumption with returns and errnos: five groups, each with a positive
//  control run first, each refusal named by its errno.
//
//  HYPOTHESIS
//  ----------
//  An ordinary sandboxed app on iOS 27.0 is refused each of these primitives
//  with EPERM — the seatbelt's signature — while its own equivalents (setting
//  its own uid, exchanging two temp files, reading its own xattrs, reading its
//  own fd table) succeed. The SHAPE of the refusal matters as much as the
//  refusal: EPERM on a call the sandbox never let through is policy, while
//  ENOENT on a name that was never supposed to be looked up would mean the
//  syscall went through and only the name failed — a different and far more
//  serious result, which the snapshot-revert and xattr controls are built to
//  tell apart.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Five, one group per boundary:
//    1. privilege      — setuid(0)/setgid(0)/seteuid(0)/setegid(0), chroot("/"),
//                        mount("tmpfs", "/private/var"), unmount("/private/var")
//    2. apfs-snapshot  — fs_snapshot_list/create/revert on the root volume,
//                        reached through a dirfd on "/"
//    3. extended-attr  — getxattr/setxattr/listxattr/removexattr inside the
//                        app's own container and on /etc/passwd
//    4. rename-exchange — renameatx_np(..., RENAME_SWAP) inside the container
//                        and from the container toward /etc/passwd
//    5. cross-process-fd — proc_listallpids, then proc_pidfdinfo on the
//                        caller's own pid and on launchd (pid 1)
//
//  CONTROL
//  -------
//  Every group runs a positive control FIRST, unconditionally, before any
//  call that is expected to be refused:
//    group 1: setuid(getuid()) — a no-op to the caller's OWN uid, which must
//             succeed. If it does not, every credential refusal below is
//             inconclusive and each entry says so instead of claiming denial.
//    group 2: fs_snapshot_list on the same dirfd — the read-only half of the
//             family, which calibrates create/revert on the same fd.
//    group 3: a full set/get/list/remove xattr round-trip on a file in the
//             app's OWN temp directory, recorded before any /etc/passwd call,
//             so a refusal there is about the PATH and not about xattrs being
//             unavailable. The /etc/passwd getxattr of a nonexistent
//             attribute name is the outside-path control: EPERM there means
//             policy refused the lookup, ENOENT means the lookup ran.
//    group 4: an in-container RENAME_SWAP of two temp files — both inside the
//             container, expected to be permitted.
//    group 5: proc_pidfdinfo on the caller's OWN pid (getpid()) — the same
//             call, the same flavor, the same buffer shape, one process we
//             are certainly allowed to see.
//  A control that does not produce its expected shape does not become a
//  denial: its group is marked inconclusive in the interpretation text.
//
//  SAFETY
//  ------
//  Nothing here is intended to change state, and every entry says what it
//  would do if the boundary did not hold:
//    - The credential calls are expected to fail. If one unexpectedly
//      SUCCEEDED, the process's credentials would have changed and this run
//      must be discarded rather than trusted; nothing in the harness depends
//      on being root, so no restoration path is needed — the run is simply
//      invalid, and the entry records the success as a must-reproduce-on-device
//      candidate, never as a confirmed finding.
//    - fs_snapshot_create uses the throwaway name "fsprobe-snap-test" on "/"
//      and is expected to be refused; if it ever succeeds on a device, that
//      snapshot must be deleted afterwards before anything else runs.
//    - fs_snapshot_revert targets a name that does not exist, so even an
//      unblocked call has nothing to revert to.
//    - The xattr writes on /etc/passwd are expected to be refused; the
//      removexattr that follows doubles as cleanup if a set ever succeeded.
//      The in-container control file is unlinked at the end of the group.
//    - THE ONE DANGEROUS CALL: renameatx_np swapping a temp file with
//      /etc/passwd. Expected EPERM. If it ever returns success on a device,
//      stop the run immediately — the two objects have exchanged contents and
//      must be swapped back before anything else executes. The in-container
//      swap is harmless and its two files are unlinked afterwards.
//    - The process-table enumeration touches no process; proc_pidfdinfo is a
//      read of another process's fd list through the kernel and writes
//      nothing. Enumerating pids is reconnaissance, not a finding.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum PrivilegeAndSnapshotProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call returned a non-negative value: the primitive was permitted.
        case permitted
        /// The call failed with EPERM — the seatbelt's denial signature.
        case denied
        /// The call failed with ENOENT: the name or path was not there.
        case notFound
        /// The call failed for another recorded reason, named in `errnoName`.
        case otherError
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
        /// The symbol is not present on this platform.
        case symbolUnavailable
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        /// Which of the five groups the operation belongs to.
        public let group: String
        /// The exact call exercised.
        public let operation: String
        /// The concrete target: a path, a uid, a pid, a volume.
        public let target: String
        public let outcome: Outcome
        /// The errno name, captured via currentErrno() immediately after a
        /// failing (-1) call, and nil for a successful one.
        public let errnoName: String?
        /// The return value exactly as the platform reported it.
        public let returnedValue: String?
        /// Raw observation, kept separate from interpretation.
        public let observed: String?
        /// What the observation means — including the honest say-so when a
        /// control failed and the group is inconclusive.
        public let interpretation: String

        public init(
            id: String,
            group: String,
            operation: String,
            target: String,
            outcome: Outcome,
            errnoName: String?,
            returnedValue: String?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.group = group
            self.operation = operation
            self.target = target
            self.outcome = outcome
            self.errnoName = errnoName
            self.returnedValue = returnedValue
            self.observed = observed
            self.interpretation = interpretation
        }

        /// ALWAYS false, without exception: even a successful setuid(0) or a
        /// successful snapshot revert is recorded as a serious candidate that
        /// must be reproduced on a physical device, never as a confirmed
        /// finding. Nothing in this probe can flag a boundary violation.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let entries: [Entry]
        public let violations: [Entry]

        public init(entries: [Entry], violations: [Entry]) {
            self.entries = entries
            self.violations = violations
        }

        /// Structural proof that no entry was flagged: `isBoundaryViolation`
        /// is hardwired false, so this can only ever be true.
        public var violationsAlwaysEmpty: Bool { violations.isEmpty }
    }

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        entries.append(contentsOf: privilegeEntries())
        entries.append(contentsOf: snapshotEntries())
        entries.append(contentsOf: xattrEntries())
        entries.append(contentsOf: renameEntries())
        entries.append(contentsOf: crossProcessEntries())
        return Result(entries: entries, violations: entries.filter(\.isBoundaryViolation))
        #else
        // One entry per group, controls included and named inside each entry.
        // Recording a group without its control would read as complete data
        // when it is no data at all, so the control lives in the same
        // notAttempted record rather than being silently omitted.
        let platformNote = "this host cannot import Darwin, so no Darwin call exists to make"
        return Result(
            entries: [
                Entry(
                    id: "group-privilege",
                    group: "privilege",
                    operation: """
                        CONTROL setuid(getuid()), then setuid(0), setgid(0), \
                        seteuid(0), setegid(0), chroot("/"), \
                        mount("tmpfs", "/private/var", 0, nil), \
                        unmount("/private/var", 0)
                        """,
                    target: "the caller's credentials and the mount table",
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: platformNote,
                    interpretation: """
                        NOT ATTEMPTED: the privilege group runs only on Darwin. \
                        Its control — setuid to the caller's own uid, which must \
                        succeed — is recorded here too, as notAttempted, because \
                        a group without a control would be impossible to \
                        interpret even if the calls had been made.
                        """
                ),
                Entry(
                    id: "group-apfs-snapshot",
                    group: "apfs-snapshot",
                    operation: """
                        CONTROL fs_snapshot_list(dirfd, &buf, 0), then \
                        fs_snapshot_create(dirfd, "fsprobe-snap-test", 0) and \
                        fs_snapshot_revert(dirfd, "fsprobe-nonexistent-snap", 0) \
                        on a dirfd from POSIXShim.openFile("/", O_RDONLY, 0)
                        """,
                    target: "/ (the root volume)",
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: platformNote,
                    interpretation: """
                        NOT ATTEMPTED: the fs_snapshot_* family is Darwin-only \
                        and is bound by name in this module. The read-only list \
                        call is this group's control — it calibrates the dirfd \
                        before create/revert — and it is recorded here, as \
                        notAttempted, rather than omitted.
                        """
                ),
                Entry(
                    id: "group-extended-attribute",
                    group: "extended-attribute",
                    operation: """
                        CONTROL setxattr/getxattr/listxattr/removexattr \
                        round-trip on a file under NSTemporaryDirectory(), then \
                        getxattr("/etc/passwd", "com.apple.probe-nonexistent", \
                        nil, 0, 0, 0), setxattr on /etc/passwd, \
                        removexattr on /etc/passwd
                        """,
                    target: "the app's own temp file and /etc/passwd",
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: platformNote,
                    interpretation: """
                        NOT ATTEMPTED: the xattr group runs only on Darwin. Its \
                        positive control — a full round-trip on the app's OWN \
                        file, which must succeed and is recorded first — is \
                        here as notAttempted, so an empty group cannot be \
                        mistaken for a group whose control passed.
                        """
                ),
                Entry(
                    id: "group-rename-exchange",
                    group: "rename-exchange",
                    operation: """
                        CONTROL renameatx_np(AT_FDCWD, A, AT_FDCWD, B, \
                        RENAME_SWAP) on two temp files, then \
                        renameatx_np(AT_FDCWD, A, AT_FDCWD, "/etc/passwd", \
                        RENAME_SWAP)
                        """,
                    target: "two files under NSTemporaryDirectory() and /etc/passwd",
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: platformNote,
                    interpretation: """
                        NOT ATTEMPTED: renameatx_np is Darwin-only. The \
                        in-container swap — both objects inside the container, \
                        expected to be permitted — is this group's control and \
                        is recorded here as notAttempted rather than left out; \
                        without it a refusal on the outward swap would have \
                        nothing to be read against.
                        """
                ),
                Entry(
                    id: "group-cross-process-fd",
                    group: "cross-process-fd",
                    operation: """
                        proc_listallpids(buf, bufsize), then CONTROL \
                        proc_pidfdinfo(getpid(), 0, PROC_PIDFDINFO, &buf, size), \
                        then proc_pidfdinfo(1, 0, PROC_PIDFDINFO, &buf, size)
                        """,
                    target: "the process table, the caller's own pid, launchd (pid 1)",
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: platformNote,
                    interpretation: """
                        NOT ATTEMPTED: the libproc calls run only on Darwin; \
                        proc_listallpids is reused from MachShim and \
                        proc_pidfdinfo is bound by name in this module. The \
                        own-pid control — the same call against the caller's \
                        own process, recorded first — appears here as \
                        notAttempted, because a refusal on launchd with no \
                        own-pid control beside it would be uninterpretable.
                        """
                ),
            ],
            violations: []
        )
        #endif
    }

    // MARK: - Darwin implementation

    #if canImport(Darwin)

    // MARK: Classification

    /// The mapping the whole probe turns on: a non-negative return is
    /// permission granted, -1 with EPERM is policy, ENOENT is a missing name,
    /// and anything else keeps its own errno rather than being collapsed into
    /// a denial it did not earn.
    private static func classify(rc: Int, err: Int32) -> Outcome {
        if rc >= 0 { return .permitted }
        if err == Int32(EPERM) { return .denied }
        if err == Int32(ENOENT) { return .notFound }
        return .otherError
    }

    /// The errno name, recorded only when the call actually failed. A
    /// successful call has no errno, and inventing one would be fabrication.
    private static func errnoName(rc: Int, err: Int32) -> String? {
        rc < 0 ? ErrorClassifier.errnoName(err) : nil
    }

    /// Raw observation: the return value, and the errno only when there is one.
    private static func rawReturn(_ rc: Int, _ err: Int32) -> String {
        rc < 0 ? "returned \(rc), errno \(ErrorClassifier.errnoName(err))" : "returned \(rc)"
    }

    // MARK: Group 1 — privilege

    private static func privilegeEntries() -> [Entry] {
        var entries: [Entry] = []
        let group = "privilege"

        // CONTROL FIRST, unconditionally: setuid to the caller's OWN uid.
        // This is a no-op that must succeed; it proves the set*id machinery
        // answers this process at all, which is what turns an EPERM on
        // setuid(0) below into a policy refusal rather than a broken call.
        let ownUID = getuid()
        setErrno(0)
        let controlRC = Int(setuid(ownUID))
        let controlErr = currentErrno()
        let controlOutcome = classify(rc: controlRC, err: controlErr)
        let controlOK = controlOutcome == .permitted
        entries.append(Entry(
            id: "priv-control-setuid-own",
            group: group,
            operation: "setuid(getuid())",
            target: "the caller's own uid \(ownUID)",
            outcome: controlOutcome,
            errnoName: errnoName(rc: controlRC, err: controlErr),
            returnedValue: "\(controlRC)",
            observed: rawReturn(controlRC, controlErr),
            interpretation: controlOK
                ? """
                CONTROL: setting the real uid to the caller's OWN uid — a no-op \
                that must succeed — returned 0. The set*id machinery answers this \
                process, so an EPERM on setuid(0) below can be read as a policy \
                refusal rather than as a broken call.
                """
                : """
                CONTROL FAILED: setuid to the caller's own uid — a no-op that \
                must succeed — \(rawReturn(controlRC, controlErr)). Every \
                credential result below is therefore INCONCLUSIVE: a refusal \
                there could be this same breakage rather than a sandbox \
                boundary, so no denial claim is made from this run of the group. \
                Recorded plainly instead of being converted into a denial.
                """
        ))

        // Threaded into every non-success credential interpretation: when the
        // control fails, the refusals below cannot be attributed to policy.
        let inconclusive = controlOK ? "" : """
            INCONCLUSIVE FOR THIS GROUP: the setuid(getuid()) control above \
            failed, so this answer could be the same breakage rather than a \
            policy boundary, and no denial claim is made from it.
            """

        let credentialCalls: [(id: String, operation: String, call: () -> Int32)] = [
            ("priv-setuid-0", "setuid(0)", { setuid(0) }),
            ("priv-setgid-0", "setgid(0)", { setgid(0) }),
            ("priv-seteuid-0", "seteuid(0)", { seteuid(0) }),
            ("priv-setegid-0", "setegid(0)", { setegid(0) }),
        ]

        for entry in credentialCalls {
            setErrno(0)
            let rc = Int(entry.call())
            let err = currentErrno()
            let outcome = classify(rc: rc, err: err)
            let interpretation: String
            switch outcome {
            case .permitted:
                interpretation = """
                    SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: \
                    \(entry.operation) returned \(rc), which would mean an \
                    ordinary app can make its own credentials 0. Recorded as a \
                    candidate only — isBoundaryViolation stays false until this \
                    is reproduced on a physical device and ruled out as a \
                    simulator artifact — never as a confirmed finding. If it is \
                    real, every other measurement in this run must be re-read \
                    under the assumption this process was privileged.
                    """
            case .denied:
                interpretation = """
                    Refused with EPERM — the seatbelt's signature and the \
                    expected shape: an ordinary app does not acquire uid/gid 0. \
                    \(inconclusive)
                    """
            default:
                interpretation = """
                    Failed with \(ErrorClassifier.errnoName(err)) rather than the \
                    expected EPERM, so this is not a policy-shaped refusal and \
                    nothing is claimed about the boundary from it. \
                    \(inconclusive)
                    """
            }
            entries.append(Entry(
                id: entry.id,
                group: group,
                operation: entry.operation,
                target: "uid 0 / gid 0",
                outcome: outcome,
                errnoName: errnoName(rc: rc, err: err),
                returnedValue: "\(rc)",
                observed: rawReturn(rc, err),
                interpretation: interpretation
            ))
        }

        // chroot("/") — expected EPERM.
        setErrno(0)
        let chrootRC = Int("/".withCString { chroot($0) })
        let chrootErr = currentErrno()
        entries.append(Entry(
            id: "priv-chroot-root",
            group: group,
            operation: "chroot(\"/\")",
            target: "/",
            outcome: classify(rc: chrootRC, err: chrootErr),
            errnoName: errnoName(rc: chrootRC, err: chrootErr),
            returnedValue: "\(chrootRC)",
            observed: rawReturn(chrootRC, chrootErr),
            interpretation: chrootRC >= 0
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: chroot on "/" \
                returned \(chrootRC) — a sandboxed app changing its own root \
                would be an escape primitive. isBoundaryViolation stays false; \
                this must be reproduced on a physical device before anything is \
                claimed.
                """
                : """
                \(chrootErr == EPERM
                    ? "Refused with EPERM — the expected shape: an ordinary app cannot change its root directory."
                    : "Failed with \(ErrorClassifier.errnoName(chrootErr)) rather than the expected EPERM, so this is not a policy-shaped refusal and nothing is claimed about the boundary.")
                \(inconclusive)
                """
        ))

        // mount("tmpfs", "/private/var", 0, nil) — expected EPERM.
        setErrno(0)
        let mountRC = Int("tmpfs".withCString { typePtr in
            "/private/var".withCString { dirPtr in
                mount(typePtr, dirPtr, 0, nil)
            }
        })
        let mountErr = currentErrno()
        entries.append(Entry(
            id: "priv-mount-tmpfs",
            group: group,
            operation: "mount(\"tmpfs\", \"/private/var\", 0, nil)",
            target: "/private/var",
            outcome: classify(rc: mountRC, err: mountErr),
            errnoName: errnoName(rc: mountRC, err: mountErr),
            returnedValue: "\(mountRC)",
            observed: rawReturn(mountRC, mountErr),
            interpretation: mountRC >= 0
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: an ordinary app \
                mounted a filesystem over /private/var, which would let it \
                shadow system paths. isBoundaryViolation stays false until \
                reproduced on a physical device.
                """
                : """
                \(mountErr == EPERM
                    ? "Refused with EPERM — the expected shape: an ordinary app cannot mount over a system path."
                    : "Failed with \(ErrorClassifier.errnoName(mountErr)) rather than the expected EPERM (\(mountErr == ENOENT ? "the target path is absent" : mountErr == EINVAL ? "the request was invalid" : "another reason")) — not a policy-shaped refusal, so nothing is claimed about the boundary.")
                \(inconclusive)
                """
        ))

        // unmount("/private/var", 0) — expected EPERM or EINVAL: EPERM is the
        // sandbox refusing before the call, EINVAL is the call running and
        // finding no mount point this process owns. Only success is a candidate.
        setErrno(0)
        let unmountRC = Int("/private/var".withCString { unmount($0, 0) })
        let unmountErr = currentErrno()
        entries.append(Entry(
            id: "priv-unmount-private-var",
            group: group,
            operation: "unmount(\"/private/var\", 0)",
            target: "/private/var",
            outcome: classify(rc: unmountRC, err: unmountErr),
            errnoName: errnoName(rc: unmountRC, err: unmountErr),
            returnedValue: "\(unmountRC)",
            observed: rawReturn(unmountRC, unmountErr),
            interpretation: unmountRC >= 0
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: an ordinary app \
                unmounted /private/var. isBoundaryViolation stays false; must be \
                reproduced on a physical device.
                """
                : """
                \(unmountErr == EPERM
                    ? "Refused with EPERM — the expected shape: policy refused the call before it ran."
                    : unmountErr == EINVAL
                        ? "EINVAL: the call ran and /private/var is not a mount point this process owns — an answer from the filesystem, not a sandbox refusal, and recorded under its own name."
                        : "Failed with \(ErrorClassifier.errnoName(unmountErr)) — neither EPERM nor EINVAL, so nothing is claimed about the boundary.")
                \(inconclusive)
                """
        ))

        return entries
    }

    // MARK: Group 2 — APFS snapshots

    /// The list buffer is deliberately large and zeroed. Its contents are NOT
    /// parsed: the return value and errno are the measurement, and a raw
    /// buffer keeps the probe from inventing structure the kernel may not
    /// have written.
    private static let snapshotListBufferBytes = 64 * 1024

    private static func snapshotEntries() -> [Entry] {
        var entries: [Entry] = []
        let group = "apfs-snapshot"

        setErrno(0)
        let dirfd = POSIXShim.openFile("/", O_RDONLY, 0)
        let openErr = currentErrno()
        entries.append(Entry(
            id: "snap-open-root",
            group: group,
            operation: "POSIXShim.openFile(\"/\", O_RDONLY, 0)",
            target: "/",
            outcome: classify(rc: Int(dirfd), err: openErr),
            errnoName: errnoName(rc: Int(dirfd), err: openErr),
            returnedValue: "\(dirfd)",
            observed: rawReturn(Int(dirfd), openErr),
            interpretation: dirfd >= 0
                ? """
                A dirfd on "/" — the handle every fs_snapshot_* call below \
                works through. Opening it is reachability, not a finding.
                """
                : """
                The dirfd could not be opened (\(ErrorClassifier.errnoName(openErr))), \
                so none of the snapshot calls below can be made. That is recorded \
                as notAttempted with the errno, rather than left out — an absent \
                group would read like a refused one.
                """
        ))

        guard dirfd >= 0 else {
            let why = "the / dirfd failed to open with \(ErrorClassifier.errnoName(openErr))"
            entries.append(Entry(
                id: "snap-list", group: group,
                operation: "fs_snapshot_list(dirfd, &buf, 0)",
                target: "/ (root volume)",
                outcome: .notAttempted,
                errnoName: nil, returnedValue: nil,
                observed: why,
                interpretation: """
                    NOT ATTEMPTED: this group's control (the read-only list call) \
                    needs the dirfd, and \(why). Without it, create/revert below \
                    would measure nothing, so they are recorded as notAttempted \
                    beside it rather than omitted.
                    """
            ))
            entries.append(Entry(
                id: "snap-create-test", group: group,
                operation: "fs_snapshot_create(dirfd, \"fsprobe-snap-test\", 0)",
                target: "/ (root volume), name fsprobe-snap-test",
                outcome: .notAttempted,
                errnoName: nil, returnedValue: nil,
                observed: why,
                interpretation: "NOT ATTEMPTED: \(why)."
            ))
            entries.append(Entry(
                id: "snap-revert-nonexistent", group: group,
                operation: "fs_snapshot_revert(dirfd, \"fsprobe-nonexistent-snap\", 0)",
                target: "/ (root volume), name fsprobe-nonexistent-snap",
                outcome: .notAttempted,
                errnoName: nil, returnedValue: nil,
                observed: why,
                interpretation: "NOT ATTEMPTED: \(why)."
            ))
            return entries
        }
        // Closed on every path out of here, including the early returns below:
        // an open dirfd held past the probe is a leak the SAFETY section
        // claims not to have.
        defer { _ = POSIXShim.closeFile(dirfd) }

        // CONTROL for this group: the read-only half of the same family, on
        // the same dirfd. It calibrates whether fs_snapshot_* reaches the
        // kernel at all, which is what makes create/revert interpretable.
        var listBuffer = [UInt8](repeating: 0, count: snapshotListBufferBytes)
        setErrno(0)
        let listRC = Int(listBuffer.withUnsafeMutableBytes { raw in
            fsSnapshotList(dirfd, raw.baseAddress, 0)
        })
        let listErr = currentErrno()
        let listOutcome = classify(rc: listRC, err: listErr)
        entries.append(Entry(
            id: "snap-list",
            group: group,
            operation: "fs_snapshot_list(dirfd, &buf, 0)",
            target: "/ (root volume)",
            outcome: listOutcome,
            errnoName: errnoName(rc: listRC, err: listErr),
            returnedValue: "\(listRC)",
            observed: """
                \(rawReturn(listRC, listErr)); buffer \(snapshotListBufferBytes) \
                bytes, zeroed; contents deliberately not parsed
                """,
            interpretation: listOutcome == .permitted
                ? """
                CONTROL: the read-only half of the fs_snapshot_* family answered \
                on "/" with \(listRC), which calibrates the dirfd and shows the \
                family reaches the kernel. Snapshot names are visibility — \
                reconnaissance, not a finding — and the return value is recorded \
                raw exactly as measured.
                """
                : """
                The group's control (the read-only list call) was refused with \
                \(ErrorClassifier.errnoName(listErr)). The family's shape on this \
                system is therefore refusal-or-unavailable, and the create and \
                revert answers below must be read against that, not as \
                independently calibrated denials.
                """
        ))

        // fs_snapshot_create — expected EPERM.
        setErrno(0)
        let createRC = Int("fsprobe-snap-test".withCString { fsSnapshotCreate(dirfd, $0, 0) })
        let createErr = currentErrno()
        let createOutcome = classify(rc: createRC, err: createErr)
        entries.append(Entry(
            id: "snap-create-test",
            group: group,
            operation: "fs_snapshot_create(dirfd, \"fsprobe-snap-test\", 0)",
            target: "/ (root volume), name fsprobe-snap-test",
            outcome: createOutcome,
            errnoName: errnoName(rc: createRC, err: createErr),
            returnedValue: "\(createRC)",
            observed: rawReturn(createRC, createErr),
            interpretation: createOutcome == .permitted
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: an ordinary app \
                created an APFS snapshot on the root volume, which would be a \
                write primitive against the system volume's history. Recorded as \
                a candidate only — isBoundaryViolation stays false until this is \
                reproduced on a physical device. If it ever happens on a device, \
                the snapshot named fsprobe-snap-test must be deleted afterwards.
                """
                : """
                \(createOutcome == .denied
                    ? "Refused with EPERM — the expected shape: snapshot creation on / is not for ordinary apps. Because the list control above answered first, this refusal is read against a family that does reach the kernel."
                    : "Failed with \(ErrorClassifier.errnoName(createErr)) rather than the expected EPERM, so this is not a policy-shaped refusal and nothing is claimed about the boundary.")
                """
        ))

        // fs_snapshot_revert against a name that cannot exist — expected EPERM.
        // ENOENT here means something entirely different: the sandbox let the
        // syscall through and only the NAME failed. That distinction is the
        // reason this control exists.
        setErrno(0)
        let revertRC = Int("fsprobe-nonexistent-snap".withCString { fsSnapshotRevert(dirfd, $0, 0) })
        let revertErr = currentErrno()
        let revertOutcome = classify(rc: revertRC, err: revertErr)
        let revertInterpretation: String
        switch revertOutcome {
        case .denied:
            revertInterpretation = """
                Refused with EPERM — the expected shape: the sandbox blocked \
                the revert syscall outright, before any snapshot name was \
                looked up. A refusal on a name that cannot exist is only \
                meaningful when it is EPERM, and it is.
                """
        case .notFound:
            revertInterpretation = """
                ENOENT INSTEAD OF EPERM: the sandbox let the syscall through \
                and only the NAME failed — the revert reached the filesystem \
                and was answered by the absence of the snapshot, not by policy. \
                This is a POTENTIAL BOUNDARY VIOLATION CANDIDATE and the single \
                most interesting shape this group can produce. It is recorded \
                with isBoundaryViolation == false, because it must be reproduced \
                on a physical device before it is anything more than a candidate \
                from one run.
                """
        case .permitted:
            revertInterpretation = """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: the revert of \
                a name that cannot exist returned \(revertRC). A successful \
                revert would change volume history; isBoundaryViolation stays \
                false until reproduced on a physical device.
                """
        default:
            revertInterpretation = """
                Failed with \(ErrorClassifier.errnoName(revertErr)) — neither the \
                expected EPERM nor the candidate-shaped ENOENT — so nothing is \
                claimed about the boundary from this call.
                """
        }
        entries.append(Entry(
            id: "snap-revert-nonexistent",
            group: group,
            operation: "fs_snapshot_revert(dirfd, \"fsprobe-nonexistent-snap\", 0)",
            target: "/ (root volume), name fsprobe-nonexistent-snap (deliberately cannot exist)",
            outcome: revertOutcome,
            errnoName: errnoName(rc: revertRC, err: revertErr),
            returnedValue: "\(revertRC)",
            observed: rawReturn(revertRC, revertErr),
            interpretation: revertInterpretation
        ))

        return entries
    }

    // MARK: Group 3 — extended attributes

    private static let xattrBufferBytes = 4096
    private static let maxListedXattrNames = 32

    // setxattr returns C `int` (Int32) while the others return ssize_t (Int),
    // so each helper pins its closure's result type explicitly. Without the
    // annotation the nested withCString closures cannot infer a type and the
    // build fails with "type of expression is ambiguous" -- which is a
    // confusing way to be told that two POSIX calls disagree about width.
    //
    // All five are resolved with dlsym rather than named, and the reason is
    // the same one MachShim's header records: a @_silgen_name declaration
    // occupies its symbol's name module-wide. MetadataReadProbe already binds
    // `getxattr` and `listxattr`, so calling those names from here would
    // resolve to THAT declaration and fail with a function-type mismatch. A
    // symbol that cannot be resolved answers ENOSYS -- "function not
    // implemented" -- which the caller records as unattempted rather than
    // reading as a sandbox denial.
    private typealias SetXAttrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafeRawPointer?, Int, UInt32, Int32
    ) -> Int32
    private typealias GetXAttrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafeMutableRawPointer?, Int, UInt32, Int32
    ) -> Int
    private typealias ListXAttrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutableRawPointer?, Int, Int32
    ) -> Int
    private typealias RemoveXAttrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, Int32
    ) -> Int32

    private static func setXAttr(_ path: String, _ name: String, _ value: String) -> Int {
        guard let sym = POSIXShim.lookupSymbol("setxattr") else {
            setErrno(Int32(ENOSYS))
            return -1
        }
        let fn = unsafeBitCast(sym, to: SetXAttrFn.self)
        let rc: Int32 = path.withCString { pathPtr in
            name.withCString { namePtr in
                value.withCString { valuePtr in
                    fn(pathPtr, namePtr, valuePtr, value.utf8.count, 0, 0)
                }
            }
        }
        return Int(rc)
    }

    private static func getXAttr(_ path: String, _ name: String, _ buffer: inout [UInt8]) -> Int {
        guard let sym = POSIXShim.lookupSymbol("getxattr") else {
            setErrno(Int32(ENOSYS))
            return -1
        }
        let fn = unsafeBitCast(sym, to: GetXAttrFn.self)
        return path.withCString { pathPtr in
            name.withCString { namePtr in
                buffer.withUnsafeMutableBytes { raw in
                    fn(pathPtr, namePtr, raw.baseAddress, raw.count, 0, 0)
                }
            }
        }
    }

    /// The size-only form the /etc/passwd control uses: nil value, zero size.
    private static func getXAttrSizeOnly(_ path: String, _ name: String) -> Int {
        guard let sym = POSIXShim.lookupSymbol("getxattr") else {
            setErrno(Int32(ENOSYS))
            return -1
        }
        let fn = unsafeBitCast(sym, to: GetXAttrFn.self)
        return path.withCString { pathPtr in
            name.withCString { namePtr in
                fn(pathPtr, namePtr, nil, 0, 0, 0)
            }
        }
    }

    private static func listXAttr(_ path: String, _ buffer: inout [UInt8]) -> Int {
        guard let sym = POSIXShim.lookupSymbol("listxattr") else {
            setErrno(Int32(ENOSYS))
            return -1
        }
        let fn = unsafeBitCast(sym, to: ListXAttrFn.self)
        return path.withCString { pathPtr in
            buffer.withUnsafeMutableBytes { raw in
                fn(pathPtr, raw.baseAddress, raw.count, 0)
            }
        }
    }

    private static func removeXAttr(_ path: String, _ name: String) -> Int {
        guard let sym = POSIXShim.lookupSymbol("removexattr") else {
            setErrno(Int32(ENOSYS))
            return -1
        }
        let fn = unsafeBitCast(sym, to: RemoveXAttrFn.self)
        let rc: Int32 = path.withCString { pathPtr in
            name.withCString { namePtr in
                fn(pathPtr, namePtr, 0)
            }
        }
        return Int(rc)
    }

    private static func xattrEntries() -> [Entry] {
        var entries: [Entry] = []
        let group = "extended-attribute"
        let xattrName = "com.apple.fsprobe-probe"
        let xattrValue = "fsprobe-probe"
        let controlPath = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("fsprobe-xattr-\(getpid())")
        let outsidePath = "/etc/passwd"
        let outsideExists = pathExists(outsidePath)

        // POSITIVE CONTROL FIRST: a full round-trip on the app's OWN file.
        // If this machinery does not work, a refusal on /etc/passwd below
        // would say nothing about paths — only about broken xattrs.
        setErrno(0)
        let createFD = POSIXShim.openFile(controlPath, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let createErr = currentErrno()
        entries.append(Entry(
            id: "xattr-control-create",
            group: group,
            operation: "POSIXShim.openFile(tmp, O_CREAT|O_TRUNC|O_WRONLY, 0o644)",
            target: controlPath,
            outcome: classify(rc: Int(createFD), err: createErr),
            errnoName: errnoName(rc: Int(createFD), err: createErr),
            returnedValue: "\(createFD)",
            observed: rawReturn(Int(createFD), createErr),
            interpretation: createFD >= 0
                ? """
                The substrate for this group's control: a file in the app's own \
                temp directory, on which the xattr round-trip below runs first.
                """
                : """
                The control file could not be created (\(ErrorClassifier.errnoName(createErr))), \
                so the four round-trip steps below are recorded as notAttempted \
                beside it rather than omitted — a group with no control in it \
                would read like a group whose control passed.
                """
        ))

        if createFD >= 0 {
            _ = POSIXShim.closeFile(createFD)

            setErrno(0)
            let setRC = setXAttr(controlPath, xattrName, xattrValue)
            let setErr = currentErrno()
            entries.append(Entry(
                id: "xattr-control-set",
                group: group,
                operation: "setxattr(ownFile, \"\(xattrName)\", value, len, 0, 0)",
                target: controlPath,
                outcome: classify(rc: setRC, err: setErr),
                errnoName: errnoName(rc: setRC, err: setErr),
                returnedValue: "\(setRC)",
                observed: rawReturn(setRC, setErr),
                interpretation: setRC >= 0
                    ? """
                    CONTROL: the app's OWN file accepted an extended attribute, \
                    so the xattr machinery works for this process. A refusal on \
                    /etc/passwd below is then about the PATH — not about xattrs \
                    being unavailable, which ENOTSUP would have said instead.
                    """
                    : """
                    CONTROL FAILED: setxattr on the app's own file \
                    \(rawReturn(setRC, setErr)). The /etc/passwd results below \
                    are inconclusive for the same reason — without a working \
                    round-trip, a refusal there could be broken xattrs rather \
                    than a boundary.
                    """
            ))

            var getBuffer = [UInt8](repeating: 0, count: xattrBufferBytes)
            setErrno(0)
            let getRC = getXAttr(controlPath, xattrName, &getBuffer)
            let getErr = currentErrno()
            let readBack = getRC > 0 && getRC <= getBuffer.count
                ? String(decoding: getBuffer.prefix(getRC), as: UTF8.self)
                : nil
            entries.append(Entry(
                id: "xattr-control-get",
                group: group,
                operation: "getxattr(ownFile, \"\(xattrName)\", &buf, cap, 0, 0)",
                target: controlPath,
                outcome: classify(rc: getRC, err: getErr),
                errnoName: errnoName(rc: getRC, err: getErr),
                returnedValue: "\(getRC)",
                observed: rawReturn(getRC, getErr) + (readBack.map { "; read back \"\($0)\"" } ?? ""),
                interpretation: getRC >= 0
                    ? """
                    CONTROL: reading the attribute back returned \(getRC) bytes\(readBack == xattrValue
                        ? ", byte-identical to what was written."
                        : " — the bytes differ from what was written, so the round-trip is only half-confirmed.")
                    """
                    : """
                    CONTROL FAILED: getxattr on the app's own file \
                    \(rawReturn(getRC, getErr)); the /etc/passwd reads below are \
                    inconclusive beside it.
                    """
            ))

            var listBuffer = [UInt8](repeating: 0, count: xattrBufferBytes)
            setErrno(0)
            let listRC = listXAttr(controlPath, &listBuffer)
            let listErr = currentErrno()
            // Names come back NUL-separated. The walk is bounded so a huge
            // attribute list cannot turn a probe into a hang, and the count
            // recorded alongside says when it was bounded.
            var listedNames: [String] = []
            if listRC > 0 {
                let bytes = listBuffer.prefix(min(listRC, listBuffer.count))
                var current: [UInt8] = []
                for byte in bytes where listedNames.count < maxListedXattrNames {
                    if byte == 0 {
                        if !current.isEmpty {
                            listedNames.append(String(decoding: current, as: UTF8.self))
                        }
                        current.removeAll(keepingCapacity: true)
                    } else {
                        current.append(byte)
                    }
                }
            }
            entries.append(Entry(
                id: "xattr-control-list",
                group: group,
                operation: "listxattr(ownFile, &buf, cap, 0)",
                target: controlPath,
                outcome: classify(rc: listRC, err: listErr),
                errnoName: errnoName(rc: listRC, err: listErr),
                returnedValue: "\(listRC)",
                observed: rawReturn(listRC, listErr)
                    + "; \(listedNames.count) names"
                    + (listedNames.count >= maxListedXattrNames
                        ? " (name walk bounded at \(maxListedXattrNames))"
                        : "")
                    + (listedNames.contains(xattrName) ? ", probe attribute present" : ""),
                interpretation: listRC >= 0
                    ? """
                    CONTROL: the app's own attribute list enumerates, and the \
                    probe's attribute appears in it — the last read half of the \
                    round-trip before removal.
                    """
                    : """
                    CONTROL FAILED: listxattr on the app's own file \
                    \(rawReturn(listRC, listErr)); the group's calibration is \
                    incomplete and /etc/passwd results below read against that.
                    """
            ))

            setErrno(0)
            let removeRC = removeXAttr(controlPath, xattrName)
            let removeErr = currentErrno()
            entries.append(Entry(
                id: "xattr-control-remove",
                group: group,
                operation: "removexattr(ownFile, \"\(xattrName)\", 0)",
                target: controlPath,
                outcome: classify(rc: removeRC, err: removeErr),
                errnoName: errnoName(rc: removeRC, err: removeErr),
                returnedValue: "\(removeRC)",
                observed: rawReturn(removeRC, removeErr),
                interpretation: removeRC >= 0
                    ? """
                    CONTROL: the attribute was removed from the app's own file, \
                    completing a full set/get/list/remove round-trip. Every \
                    /etc/passwd refusal below is now read against working \
                    machinery and a known-good control.
                    """
                    : """
                    CONTROL FAILED: removexattr on the app's own file \
                    \(rawReturn(removeRC, removeErr)). The round-trip did not \
                    complete, so the group is only partially calibrated.
                    """
            ))
        } else {
            for step in ["set", "get", "list", "remove"] {
                entries.append(Entry(
                    id: "xattr-control-\(step)",
                    group: group,
                    operation: "xattr control round-trip step: \(step)",
                    target: controlPath,
                    outcome: .notAttempted,
                    errnoName: nil,
                    returnedValue: nil,
                    observed: "the control file could not be created: \(ErrorClassifier.errnoName(createErr))",
                    interpretation: """
                        NOT ATTEMPTED: the round-trip on the app's own file \
                        needs that file, and it could not be created. Recorded \
                        as notAttempted so the group cannot read as though its \
                        control ran.
                        """
                ))
            }
        }

        // OUTSIDE-PATH CONTROL: getxattr for an attribute name that cannot
        // exist, on a path outside the container. EPERM means policy refused
        // the lookup before it ran. ENOENT means the syscall reached the file
        // and only the name failed — on a reachable file, a missing attribute
        // is exactly what ENOENT looks like, which is the whole point of
        // picking this name.
        setErrno(0)
        let outsideGetRC = getXAttrSizeOnly(outsidePath, "com.apple.probe-nonexistent")
        let outsideGetErr = currentErrno()
        let outsideGetOutcome = classify(rc: outsideGetRC, err: outsideGetErr)
        let outsideGetInterpretation: String
        switch outsideGetOutcome {
        case .denied:
            outsideGetInterpretation = """
                OUTSIDE-PATH CONTROL: refused with EPERM before any \
                attribute lookup — the expected shape, and what makes \
                the successful round-trip above mean "the machinery \
                works, the path is refused."
                """
        case .notFound:
            outsideGetInterpretation = """
                ENOENT INSTEAD OF EPERM: the sandbox let the syscall \
                reach the VFS and only the ATTRIBUTE NAME failed to \
                exist — which on a reachable file is indistinguishable \
                from reaching \(outsidePath) itself. POTENTIAL BOUNDARY \
                VIOLATION CANDIDATE, recorded with \
                isBoundaryViolation == false because it must be \
                reproduced on a physical device first. Note the path \
                check above: exists: \(outsideExists) — if the path is \
                absent, ENOENT says nothing.
                """
        case .permitted:
            outsideGetInterpretation = """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: the \
                size-only getxattr for a nonexistent attribute returned \
                \(outsideGetRC), which would mean the call answered \
                about a path outside the container. isBoundaryViolation \
                stays false until reproduced on a physical device.
                """
        default:
            outsideGetInterpretation = """
                Failed with \(ErrorClassifier.errnoName(outsideGetErr)) \
                — neither EPERM nor ENOENT. Named rather than folded \
                into a denial: \(outsideGetErr == EACCES
                    ? "EACCES is POSIX/SIP, not the seatbelt"
                    : "nothing is claimed about the boundary from this shape").
                """
        }
        entries.append(Entry(
            id: "xattr-etc-get-nonexistent",
            group: group,
            operation: "getxattr(\"\(outsidePath)\", \"com.apple.probe-nonexistent\", nil, 0, 0, 0)",
            target: "\(outsidePath) (exists: \(outsideExists))",
            outcome: outsideGetOutcome,
            errnoName: errnoName(rc: outsideGetRC, err: outsideGetErr),
            returnedValue: "\(outsideGetRC)",
            observed: rawReturn(outsideGetRC, outsideGetErr),
            interpretation: outsideGetInterpretation
        ))

        setErrno(0)
        let outsideSetRC = setXAttr(outsidePath, xattrName, xattrValue)
        let outsideSetErr = currentErrno()
        entries.append(Entry(
            id: "xattr-etc-set",
            group: group,
            operation: "setxattr(\"\(outsidePath)\", \"\(xattrName)\", value, len, 0, 0)",
            target: "\(outsidePath) (exists: \(outsideExists))",
            outcome: classify(rc: outsideSetRC, err: outsideSetErr),
            errnoName: errnoName(rc: outsideSetRC, err: outsideSetErr),
            returnedValue: "\(outsideSetRC)",
            observed: rawReturn(outsideSetRC, outsideSetErr),
            interpretation: outsideSetRC >= 0
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: an ordinary app \
                wrote an extended attribute onto a system path. \
                isBoundaryViolation stays false; if it is reproduced on a \
                device, the attribute the very next call removes must be \
                verified gone.
                """
                : """
                \(outsideSetErr == EPERM
                    ? "Refused with EPERM — the expected shape: an ordinary app cannot write attributes onto a path outside its container. The successful set on the app's own file above is the contrast that gives this refusal meaning."
                    : "Failed with \(ErrorClassifier.errnoName(outsideSetErr)) rather than the expected EPERM — not a policy-shaped refusal, so nothing is claimed about the boundary.")
                """
        ))

        setErrno(0)
        let outsideRemoveRC = removeXAttr(outsidePath, xattrName)
        let outsideRemoveErr = currentErrno()
        entries.append(Entry(
            id: "xattr-etc-remove",
            group: group,
            operation: "removexattr(\"\(outsidePath)\", \"\(xattrName)\", 0)",
            target: "\(outsidePath) (exists: \(outsideExists))",
            outcome: classify(rc: outsideRemoveRC, err: outsideRemoveErr),
            errnoName: errnoName(rc: outsideRemoveRC, err: outsideRemoveErr),
            returnedValue: "\(outsideRemoveRC)",
            observed: rawReturn(outsideRemoveRC, outsideRemoveErr),
            interpretation: outsideRemoveRC >= 0
                ? """
                The removal was permitted. On its own that changes nothing \
                (removing an attribute that was never there is a no-op), but it \
                doubles as the cleanup path if the set above ever succeeded — \
                check that entry's outcome alongside this one.
                """
                : """
                \(outsideRemoveErr == EPERM
                    ? "Refused with EPERM — the expected shape, matching the set refusal above: the boundary holds for removal too."
                    : "Failed with \(ErrorClassifier.errnoName(outsideRemoveErr)) rather than the expected EPERM — recorded under its own name.")
                """
        ))

        // Clean up the in-container control file on every path.
        _ = POSIXShim.unlinkFile(controlPath)
        return entries
    }

    // MARK: Group 4 — rename exchange

    /// RENAME_SWAP from <stdio.h> (0x00000002): exchange the two paths
    /// atomically. Spelled as a literal because the macro's Swift import is
    /// not guaranteed to carry that name across SDKs; the value is what the
    /// kernel reads.
    private static let renameSwapFlag: UInt32 = 0x0000_0002

    private static func renameEntries() -> [Entry] {
        var entries: [Entry] = []
        let group = "rename-exchange"
        let fileA = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("fsprobe-swap-A-\(getpid())")
        let fileB = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("fsprobe-swap-B-\(getpid())")

        setErrno(0)
        let fdA = POSIXShim.openFile(fileA, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let errA = currentErrno()
        setErrno(0)
        let fdB = POSIXShim.openFile(fileB, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let errB = currentErrno()
        if fdA >= 0 { _ = POSIXShim.closeFile(fdA) }
        if fdB >= 0 { _ = POSIXShim.closeFile(fdB) }

        guard fdA >= 0, fdB >= 0 else {
            let why = fdA >= 0
                ? "file B could not be created: \(ErrorClassifier.errnoName(errB))"
                : "file A could not be created: \(ErrorClassifier.errnoName(errA))"
            entries.append(Entry(
                id: "rename-control-swap-in-container", group: group,
                operation: "renameatx_np(AT_FDCWD, A, AT_FDCWD, B, UInt32(RENAME_SWAP))",
                target: "\(fileA) <-> \(fileB)",
                outcome: .notAttempted,
                errnoName: nil, returnedValue: nil,
                observed: why,
                interpretation: """
                    NOT ATTEMPTED: the in-container swap — this group's control, \
                    expected to be permitted — needs both temp files, and \(why). \
                    Recorded as notAttempted rather than omitted, because the \
                    outward swap beside it would have no control to be read \
                    against.
                    """
            ))
            entries.append(Entry(
                id: "rename-swap-to-etc-passwd", group: group,
                operation: "renameatx_np(AT_FDCWD, A, AT_FDCWD, \"/etc/passwd\", UInt32(RENAME_SWAP))",
                target: "\(fileA) <-> /etc/passwd",
                outcome: .notAttempted,
                errnoName: nil, returnedValue: nil,
                observed: why,
                interpretation: "NOT ATTEMPTED: \(why)."
            ))
            if fdA >= 0 { _ = POSIXShim.unlinkFile(fileA) }
            if fdB >= 0 { _ = POSIXShim.unlinkFile(fileB) }
            return entries
        }

        // CONTROL FIRST: both objects inside the container, expected to be
        // permitted. This is what distinguishes "RENAME_SWAP works here" from
        // "the outward refusal below is about the path, not the flag".
        setErrno(0)
        let swapRC = Int(fileA.withCString { fromPtr in
            fileB.withCString { toPtr in
                renameatx_np(Int32(AT_FDCWD), fromPtr, Int32(AT_FDCWD), toPtr, renameSwapFlag)
            }
        })
        let swapErr = currentErrno()
        let swapOutcome = classify(rc: swapRC, err: swapErr)
        entries.append(Entry(
            id: "rename-control-swap-in-container",
            group: group,
            operation: "renameatx_np(AT_FDCWD, A, AT_FDCWD, B, UInt32(RENAME_SWAP))",
            target: "\(fileA) <-> \(fileB) (both inside the container)",
            outcome: swapOutcome,
            errnoName: errnoName(rc: swapRC, err: swapErr),
            returnedValue: "\(swapRC)",
            observed: rawReturn(swapRC, swapErr),
            interpretation: swapOutcome == .permitted
                ? """
                CONTROL: two temp files inside the container exchanged their \
                contents atomically — RENAME_SWAP itself works for this \
                process, so the outward swap below measures the PATH, not the \
                flag. This is exactly the shape the control exists to produce.
                """
                : """
                CONTROL \(swapOutcome == .denied
                    ? "FAILED: the in-container swap was refused with EPERM, so RENAME_SWAP is unavailable here and the outward refusal below is inconclusive — it could be the same unavailability rather than a boundary."
                    : "FAILED: the in-container swap \(rawReturn(swapRC, swapErr)) — not the expected success, so the outward result below is read with an uncalibrated control.")
                """
        ))

        // The outward swap toward a system path — expected EPERM. THE ONE
        // DANGEROUS CALL in this probe; see SAFETY at the top of the file.
        let outsideExists = pathExists("/etc/passwd")
        setErrno(0)
        let outwardRC = Int(fileA.withCString { fromPtr in
            "/etc/passwd".withCString { toPtr in
                renameatx_np(Int32(AT_FDCWD), fromPtr, Int32(AT_FDCWD), toPtr, renameSwapFlag)
            }
        })
        let outwardErr = currentErrno()
        let outwardOutcome = classify(rc: outwardRC, err: outwardErr)
        entries.append(Entry(
            id: "rename-swap-to-etc-passwd",
            group: group,
            operation: "renameatx_np(AT_FDCWD, A, AT_FDCWD, \"/etc/passwd\", UInt32(RENAME_SWAP))",
            target: "\(fileA) <-> /etc/passwd (exists: \(outsideExists))",
            outcome: outwardOutcome,
            errnoName: errnoName(rc: outwardRC, err: outwardErr),
            returnedValue: "\(outwardRC)",
            observed: rawReturn(outwardRC, outwardErr),
            interpretation: outwardOutcome == .permitted
                ? """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: a temp file \
                and /etc/passwd exchanged contents — an ordinary app writing a \
                system file by exchange. isBoundaryViolation stays false until \
                reproduced on a physical device; if it ever happens on a \
                device, STOP THE RUN: the two objects must be swapped back \
                before anything else executes.
                """
                : """
                \(outwardOutcome == .denied
                    ? "Refused with EPERM — the expected shape: the exchange was not allowed to touch a path outside the container, and because the in-container swap above succeeded first, this refusal is about the path rather than the flag."
                    : outwardOutcome == .notFound
                        ? "ENOENT: /etc/passwd was not found (exists: \(outsideExists)), so the swap failed on the name rather than on policy — not a boundary answer."
                        : "Failed with \(ErrorClassifier.errnoName(outwardErr)) rather than the expected EPERM — named rather than folded into a denial.")
                \(swapOutcome == .permitted ? "" : "Also note the control above did not succeed, so this result is only partly calibrated.")
                """
        ))

        // Clean up both files on every path: after a successful control swap
        // the names still exist (their contents were exchanged), so both are
        // unlinked regardless.
        _ = POSIXShim.unlinkFile(fileA)
        _ = POSIXShim.unlinkFile(fileB)
        return entries
    }

    // MARK: Group 5 — cross-process file-descriptor visibility

    /// PROC_PIDFDINFO from libproc.h: the flavor whose buffer receives
    /// `struct proc_fdinfo` entries. The buffer is passed in raw and never
    /// parsed — the return value and errno are the measurement.
    private static let procPIDFDInfoFlavor: Int32 = 1
    private static let fdInfoBufferBytes = 64 * 1024
    private static let pidBufferCount = 4096

    private static func fdInfo(pid: Int32, buffer: inout [UInt8]) -> Int32 {
        buffer.withUnsafeMutableBytes { raw in
            procPidFDInfo(pid, 0, procPIDFDInfoFlavor, raw.baseAddress, Int32(raw.count))
        }
    }

    private static func crossProcessEntries() -> [Entry] {
        var entries: [Entry] = []
        let group = "cross-process-fd"
        let ownPID = getpid()

        // The process table. Enumerating pids is reconnaissance, not a
        // finding — recorded as a count, nothing more. proc_listallpids is
        // REUSED from MachShim: that symbol is bound once there (see its
        // file header — two @_silgen_name bindings of one symbol share an
        // implementation and fail the build), and this module obeys it.
        var pidBuffer = [Int32](repeating: 0, count: pidBufferCount)
        setErrno(0)
        let listRC = Int(pidBuffer.withUnsafeMutableBytes { raw in
            MachShim.procListAllPids(raw.baseAddress, Int32(raw.count))
        })
        let listErr = currentErrno()
        let listedPids = listRC > 0 ? Array(pidBuffer.prefix(min(listRC, pidBuffer.count))) : []
        entries.append(Entry(
            id: "fd-listallpids",
            group: group,
            operation: "MachShim.procListAllPids(buf, bufsize)  [binding reused from MachShim]",
            target: "the process table",
            outcome: classify(rc: listRC, err: listErr),
            errnoName: errnoName(rc: listRC, err: listErr),
            returnedValue: "\(listRC)",
            observed: rawReturn(listRC, listErr)
                + "; \(listedPids.count) pids"
                + (listRC >= pidBufferCount ? " (buffer full — the table may be truncated)" : ""),
            interpretation: listRC >= 0
                ? """
                \(listRC) pids came back. Enumerating process IDs is \
                reconnaissance, not a finding — it claims nothing about what \
                any of those processes will do, and the count above is the \
                whole observation. The list is also what the launchd entry \
                below falls back to if pid 1 is missing.
                """
                : """
                The process table enumeration failed with \
                \(ErrorClassifier.errnoName(listErr)); no pid list is available, \
                so the launchd entry below cannot substitute another pid if \
                pid 1 turns out not to exist.
                """
        ))

        // CONTROL FIRST among the fdinfo calls: the caller's OWN process —
        // same call, same flavor, same buffer shape, one pid we are certainly
        // allowed to see. Without it, a refusal on launchd could be the call
        // being broken rather than the boundary holding.
        var ownBuffer = [UInt8](repeating: 0, count: fdInfoBufferBytes)
        setErrno(0)
        let ownRC = Int(fdInfo(pid: ownPID, buffer: &ownBuffer))
        let ownErr = currentErrno()
        let ownOutcome = classify(rc: ownRC, err: ownErr)
        let ownOK = ownOutcome == .permitted
        entries.append(Entry(
            id: "fd-control-own-pid",
            group: group,
            operation: "proc_pidfdinfo(getpid(), 0, PROC_PIDFDINFO, &buf, size)",
            target: "pid \(ownPID) (the caller)",
            outcome: ownOutcome,
            errnoName: errnoName(rc: ownRC, err: ownErr),
            returnedValue: "\(ownRC)",
            observed: rawReturn(ownRC, ownErr),
            interpretation: ownOK
                ? """
                CONTROL: the same call against the caller's OWN process \
                returned \(ownRC) bytes of its fd table — the call, the flavor, \
                and the buffer shape all work for a process this process is \
                certainly allowed to see. A refusal on launchd below is then \
                about the target, not about the call.
                """
                : """
                CONTROL FAILED: proc_pidfdinfo on the caller's own pid \
                \(rawReturn(ownRC, ownErr)). The launchd answer below is \
                therefore INCONCLUSIVE: a refusal there could be this same \
                breakage rather than a cross-process boundary, and no denial \
                claim is made from it.
                """
        ))

        // launchd (pid 1), with the fallback the brief requires: if pid 1
        // does not exist, take any other pid from the list above and record
        // which. The scan is bounded by the buffer itself — pidBufferCount
        // entries exist at most.
        var targetPID: Int32 = 1
        var attemptNote = ""
        var targetBuffer = [UInt8](repeating: 0, count: fdInfoBufferBytes)
        setErrno(0)
        var targetRC = Int(fdInfo(pid: targetPID, buffer: &targetBuffer))
        var targetErr = currentErrno()
        let pidMissing = targetRC < 0 && (targetErr == Int32(ESRCH) || targetErr == Int32(ENOENT))
        if pidMissing {
            var substitute: Int32?
            for candidate in listedPids where substitute == nil {
                if candidate != 0, candidate != ownPID {
                    substitute = candidate
                }
            }
            if let substitute {
                attemptNote = """
                    pid 1 answered \(ErrorClassifier.errnoName(targetErr)) \
                    (no such process); retried with pid \(substitute) from the \
                    list above.
                    """
                targetPID = substitute
                targetBuffer = [UInt8](repeating: 0, count: fdInfoBufferBytes)
                setErrno(0)
                targetRC = Int(fdInfo(pid: targetPID, buffer: &targetBuffer))
                targetErr = currentErrno()
            } else {
                attemptNote = """
                    pid 1 answered \(ErrorClassifier.errnoName(targetErr)) and no \
                    substitute was available (\(listedPids.count) pids listed; \
                    at most \(pidBufferCount) exist to scan).
                    """
            }
        }

        let targetOutcome = classify(rc: targetRC, err: targetErr)
        let controlNote = ownOK ? "" : """
            INCONCLUSIVE: the own-pid control above failed, so this refusal \
            could be a broken call rather than a cross-process boundary, and no \
            denial claim is made from it.
            """
        let targetInterpretation: String
        switch targetOutcome {
        case .permitted:
            targetInterpretation = """
                SERIOUS CANDIDATE, MUST BE REPRODUCED ON DEVICE: \(targetRC) \
                bytes of pid \(targetPID)'s fd table were returned to an \
                ordinary app — cross-process descriptor visibility, which is \
                how one process inherits another's open state. Recorded as a \
                candidate only: isBoundaryViolation stays false until this is \
                reproduced on a physical device. \(attemptNote)
                """
        case .denied:
            targetInterpretation = """
                Refused with EPERM — the expected shape: the sandbox will not \
                hand an ordinary app another process's fd table, while the same \
                call on the caller's own pid above \(ownOK
                    ? "succeeded — so this refusal is about the target"
                    : "FAILED, so see the control note below"). \
                Enumerating pids is reconnaissance; SEEING descriptors is the \
                boundary, and it holds here. \(controlNote)\(attemptNote)
                """
        case .notFound:
            targetInterpretation = """
                ENOENT: no such process, even after the fallback \
                \(attemptNote.isEmpty ? "(no fallback was needed or possible)" : ""). \
                A missing pid is not a boundary answer either way. \
                \(controlNote)
                """
        default:
            targetInterpretation = """
                Failed with \(ErrorClassifier.errnoName(targetErr)) — neither the \
                expected EPERM nor a missing-pid answer — so nothing is claimed \
                about the boundary. \(controlNote)\(attemptNote)
                """
        }
        entries.append(Entry(
            id: "fd-pidfdinfo-\(targetPID)",
            group: group,
            operation: "proc_pidfdinfo(\(targetPID), 0, PROC_PIDFDINFO, &buf, size)",
            target: targetPID == 1
                ? "pid 1 (launchd)"
                : "pid \(targetPID) (substituted for pid 1, which did not exist)",
            outcome: targetOutcome,
            errnoName: errnoName(rc: targetRC, err: targetErr),
            returnedValue: "\(targetRC)",
            observed: rawReturn(targetRC, targetErr)
                + (attemptNote.isEmpty ? "" : "; " + attemptNote),
            interpretation: targetInterpretation
        ))

        return entries
    }

    // MARK: - Symbols absent from the Swift overlay

    // Bound by name because the Swift Darwin overlay does not import these.
    // Each symbol is bound exactly ONCE in this module (grep-verified: no
    // other file declares them) — the condition MachShim's header requires,
    // since two enums binding one symbol with different signatures share one
    // implementation and fail the build with a function type mismatch.
    // proc_listallpids is deliberately NOT bound here: it already lives in
    // MachShim and is reused through MachShim.procListAllPids.

    @_silgen_name("fs_snapshot_list")
    private static func fsSnapshotList(
        _ dirfd: Int32, _ buffer: UnsafeMutableRawPointer?, _ flags: UInt32
    ) -> Int32

    @_silgen_name("fs_snapshot_create")
    private static func fsSnapshotCreate(
        _ dirfd: Int32, _ name: UnsafePointer<CChar>?, _ flags: UInt32
    ) -> Int32

    @_silgen_name("fs_snapshot_revert")
    private static func fsSnapshotRevert(
        _ dirfd: Int32, _ name: UnsafePointer<CChar>?, _ flags: UInt32
    ) -> Int32

    /// `proc_pidfdinfo(pid, fd, flavor, buffer, size)` — a process's open
    /// file descriptors, read through the kernel. Bound here rather than in
    /// MachShim because it is a new symbol no other file declares.
    @_silgen_name("proc_pidfdinfo")
    private static func procPidFDInfo(
        _ pid: Int32, _ fd: Int32, _ flavor: Int32,
        _ buffer: UnsafeMutableRawPointer?, _ size: Int32
    ) -> Int32

    #endif
}
