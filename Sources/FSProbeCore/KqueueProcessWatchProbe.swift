//
//  KqueueProcessWatchProbe.swift
//  FSProbeCore — kqueue as a second, independent way to observe another process.
//
//  WHY THIS EXISTS
//  ---------------
//  This project has measured process introspection twice already: proc_pidpath
//  (which process can name which other process's binary) and task_for_pid
//  (which process can attach to which other task). Both answer a question
//  about READING another process. kqueue asks a different question about the
//  same relationship: can a process arrange to be TOLD something about another
//  process later, and can it be told when a file it can open changes? Those
//  are registration questions, not read questions, and no sandbox predicate
//  that governs proc_pidpath or task_for_pid is obviously the one that
//  governs them -- so an answer here is not implied by any earlier result,
//  and the earlier results imply no answer here.
//
//  Two filters are worth measuring, because they sit on opposite sides of
//  two different boundaries:
//
//    * EVFILT_PROC with NOTE_EXIT, registered against ANOTHER process's pid.
//      The only thing this project can compare it to is the same call
//      against the caller's own pid, which is the control below.
//    * EVFILT_VNODE with NOTE_WRITE|NOTE_DELETE|NOTE_RENAME on a descriptor.
//      Here the boundary is the descriptor: a file that cannot be opened is
//      a file whose changes you cannot be told about, so the open of the
//      target is the real test and the kqueue registration rides on its fd.
//
//  HYPOTHESIS
//  ----------
//  kqueue() and a self-pid EVFILT_PROC registration succeed unconditionally
//  (they are the app watching itself), and the interesting answers begin with
//  the first foreign pid. For EVFILT_VNODE, registration on the app's own
//  temp file succeeds and the /etc/passwd rows turn on whether the open
//  succeeds at all -- the registration being a question about an fd the app
//  may never get. Either way the result is expected to be a refusal or an
//  error return, and a refusal is a result.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether the sandbox gates EVFILT_PROC registration against foreign pids
//  (a process-watch predicate distinct from file access), and whether
//  obtaining a descriptor for a system file is what gates change watching on
//  it. Neither is the file-read or file-write predicate measured elsewhere,
//  so neither answer is implied by them.
//
//  CONTROL
//  -------
//  Three, run FIRST and unconditionally, one per failure mode:
//    1. kqueue() itself. -1 means the mechanism is absent and the whole
//       process-watch group is inconclusive -- not that anything was denied.
//    2. kevent(EVFILT_PROC, ..., NOTE_EXIT) on the CALLER'S OWN pid
//       (getpid()). This must succeed. Without it a refusal on a foreign pid
//       is ambiguous between "watching other processes is forbidden" and
//       "process watching does not work here at all", and the ambiguity is
//       exactly what turns a measurement into a claim.
//    3. The same EVFILT_PROC registration on pid 0, which cannot exist. It
//       must fail with ESRCH or EINVAL -- a real lookup failure on an
//       impossible target -- which is what proves the path validates its
//       ident and makes a refusal (or a success) on pid 1 target-specific.
//  Group 2's control is the app's OWN file under NSTemporaryDirectory(),
//  opened and registered before /etc/passwd is touched, so a failure there
//  can never be read as a property of the target.
//  If a control does not produce its expected shape the group is recorded as
//  inconclusive rather than converted into a denial claim.
//
//  SAFETY
//  ------
//  Registration only, and never a blocking one: every kevent call passes a
//  zeroed timespec, so it returns immediately after applying the changelist
//  and no event is ever waited for or delivered. Nothing is signalled, no
//  process is affected, no file is written (the /etc/passwd open is O_RDONLY),
//  and no watch outlives the group -- the kqueue and file descriptors are
//  closed on every path, and the probe's own temp file is removed. What a
//  successful registration MEANS is therefore bounded by what this probe can
//  actually see: acceptance of a request to be told later. That is recorded
//  loudly when it happens and never as a finding -- `isBoundaryViolation` is
//  ALWAYS false, including for pid 1 (launchd).
//

import Foundation

#if canImport(Darwin)
import Darwin
#endif

public enum KqueueProcessWatchProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The registration was accepted (the call returned >= 0).
        case registered
        /// The call returned -1 with EPERM — the seatbelt signature on iOS.
        case refused
        /// The call returned -1 with ESRCH/ENOENT — the target is not there.
        case notFound
        /// The call returned -1 for another recorded reason, named in `errnoName`.
        case otherError
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
        /// A required symbol is not present on this platform.
        case symbolUnavailable
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        /// Which of the two filters this row belongs to.
        public let group: String
        /// The operation exercised.
        public let operation: String
        /// The concrete object the operation named (pid, fd, path).
        public let target: String
        public let outcome: Outcome
        /// The errno name, when the call returned -1.
        public let errnoName: String?
        /// The raw return value as the platform reported it.
        public let returnedValue: String?
        /// What was observed, kept separate from interpretation.
        public let observed: String?
        /// What the observation means.
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

        /// Accepting a watch is reconnaissance, never a finding. Nothing here
        /// is waited for, delivered, or acted upon, so nothing here flags.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let entries: [Entry]
        public let violations: [Entry]

        public init(entries: [Entry], violations: [Entry]) {
            self.entries = entries
            self.violations = violations
        }

        public var violationsAlwaysEmpty: Bool { violations.isEmpty }
    }

    // MARK: - Shared constants

    private static let groupProcessExit = "cross-process exit watch (EVFILT_PROC)"
    private static let groupFileChange = "file-change notification (EVFILT_VNODE)"

    /// The file group's negative target: a system file the app may or may not
    /// be able to obtain a descriptor for. The open is the boundary; the
    /// kqueue registration rides on whatever fd (if any) comes back.
    private static let etcPasswd = "/etc/passwd"

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        // Each group runs its own controls first, unconditionally.
        entries.append(contentsOf: processExitGroup())
        entries.append(contentsOf: fileChangeGroup())

        // isBoundaryViolation is always false, so this is always empty -- but
        // it is computed rather than hard-coded so the invariant is testable.
        let violations = entries.filter { $0.isBoundaryViolation }
        return Result(entries: entries, violations: violations)
        #else
        // Both controls are still named here, recorded as not attempted, so a
        // report built on this branch reads as "unmeasured" rather than as a
        // run in which the controls were somehow absent.
        let entries: [Entry] = [
            Entry(
                id: "kq-proc-control-self",
                group: groupProcessExit,
                operation: """
                    kqueue() control, then kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, \
                    NOTE_EXIT) on the caller's own pid (control), then the same \
                    registration on pid 1 (launchd) and pid 0 (invalid)
                    """,
                target: "the calling process (getpid()), pid 1, pid 0",
                outcome: .notAttempted,
                errnoName: nil,
                returnedValue: nil,
                observed: "kqueue/kevent are not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: there is no kqueue process-watch mechanism \
                    here. The controls (kqueue() itself, and a NOTE_EXIT \
                    registration on the caller's own pid) are recorded rather \
                    than omitted so an absence of rows on this platform never \
                    reads as a measured refusal, and so no pid row can be \
                    mistaken for a result without them.
                    """
            ),
            Entry(
                id: "kq-vnode-control",
                group: groupFileChange,
                operation: """
                    create + open(O_CREAT|O_RDWR) a file under \
                    NSTemporaryDirectory() (control), then \
                    kevent(EVFILT_VNODE, EV_ADD, NOTE_WRITE|NOTE_DELETE|NOTE_RENAME) \
                    on it, then the same open+registration on /etc/passwd
                    """,
                target: "a file under NSTemporaryDirectory() and /etc/passwd",
                outcome: .notAttempted,
                errnoName: nil,
                returnedValue: nil,
                observed: "kqueue/kevent are not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: there is no kqueue vnode-watch mechanism \
                    here. The control -- the app's own temp file, which must \
                    register -- is recorded rather than omitted, because a \
                    /etc/passwd row without it would be uninterpretable even \
                    if it existed.
                    """
            ),
        ]
        return Result(entries: entries, violations: [])
        #endif
    }

    #if canImport(Darwin)
    // MARK: - Group 1: EVFILT_PROC cross-process exit watch

    private static func processExitGroup() -> [Entry] {
        var entries: [Entry] = []

        // Control 1, first and unconditional: the mechanism itself. Without a
        // kqueue descriptor nothing below can be asked at all, and a failure
        // here is the absence of a mechanism rather than the denial of a
        // target -- a distinction the rest of the group depends on.
        setErrno(0)
        let kq = kqueue()
        let kqErr = kq < 0 ? currentErrno() : 0
        entries.append(entry(
            id: "kq-proc-control-kqueue",
            group: groupProcessExit,
            operation: "kqueue()",
            target: "the calling process (mechanism control)",
            rc: kq, err: kqErr,
            observed: kq >= 0
                ? "kqueue() returned descriptor \(kq)"
                : "kqueue() returned -1, errno=\(ErrorClassifier.errnoName(kqErr))",
            interpretation: kq >= 0
                ? """
                CONTROL: the kqueue mechanism exists in this process and handed \
                back a usable descriptor. Without this row a refusal on a real \
                target would be indistinguishable from the mechanism being \
                absent entirely, which is why it is recorded first.
                """
                : """
                CONTROL FAILED — THIS GROUP IS INCONCLUSIVE. kqueue() itself \
                returned -1 (\(ErrorClassifier.errnoName(kqErr))), so no \
                process-watch question could be asked at all. This is a \
                statement about the mechanism being unavailable here, not about \
                any pid being denied, and the rows below are recorded as not \
                attempted for exactly that reason.
                """
        ))

        guard kq >= 0 else {
            // The mechanism is absent. The remaining operations are recorded
            // as not attempted rather than dropped, so the group still shows
            // what was NOT measured instead of quietly shrinking.
            entries.append(notAttempted(
                id: "kq-proc-control-self",
                group: groupProcessExit,
                operation: """
                    kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                    """,
                target: "pid \(getpid()) (the caller)",
                observed: "not attempted: kqueue() failed with \(ErrorClassifier.errnoName(kqErr))",
                interpretation: """
                    NOT ATTEMPTED: the control that makes a foreign-pid refusal \
                    interpretable could not be run, because kqueue() itself \
                    failed. Recorded rather than omitted so this run can never \
                    be read as a measurement of process watching.
                    """
            ))
            entries.append(notAttempted(
                id: "kq-proc-launchd",
                group: groupProcessExit,
                operation: """
                    kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                    """,
                target: "pid 1 (launchd)",
                observed: "not attempted: kqueue() failed with \(ErrorClassifier.errnoName(kqErr))",
                interpretation: """
                    NOT ATTEMPTED: with no kqueue there is no registration to \
                    accept or refuse, so nothing about watching launchd was \
                    measured on this run.
                    """
            ))
            entries.append(notAttempted(
                id: "kq-proc-invalid-pid",
                group: groupProcessExit,
                operation: """
                    kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                    """,
                target: "pid 0 (cannot exist)",
                observed: "not attempted: kqueue() failed with \(ErrorClassifier.errnoName(kqErr))",
                interpretation: """
                    NOT ATTEMPTED: the negative control could not be run \
                    without a kqueue, so this run establishes nothing about \
                    whether ident is validated.
                    """
            ))
            return entries
        }
        // Closed after the group's rows are built, on every path below.
        defer { POSIXShim.closeFile(kq) }

        // A zeroed timeout is what makes every kevent call here non-blocking:
        // the changelist is applied, nothing is waited for, and the call
        // returns immediately. No event is ever delivered to this probe.
        var timeout = timespec(tv_sec: 0, tv_nsec: 0)

        // Control 2: the SAME registration against the caller's own pid. It
        // must succeed. This is the row that turns a refusal on a foreign pid
        // into a statement about the TARGET instead of a statement about
        // kqueue not working in this process at all.
        let ownPID = Int32(getpid())
        var ownChange = keventStruct(
            ident: UInt(ownPID), filter: evFiltProc,
            flags: evAdd | evEnable, fflags: noteExit
        )
        setErrno(0)
        let ownRC = kevent(kq, &ownChange, 1, nil, 0, &timeout)
        let ownErr = ownRC < 0 ? currentErrno() : 0
        let controlOK = ownRC >= 0
        entries.append(entry(
            id: "kq-proc-control-self",
            group: groupProcessExit,
            operation: """
                kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                """,
            target: "pid \(ownPID) (the caller)",
            rc: ownRC, err: ownErr,
            observed: ownRC >= 0
                ? """
                kevent returned \(ownRC) for the caller's own pid; no event was \
                waited for or delivered (timeout zeroed by design)
                """
                : "kevent returned -1, errno=\(ErrorClassifier.errnoName(ownErr))",
            interpretation: controlOK
                ? """
                CONTROL OK: the app can register a NOTE_EXIT watch on its own \
                pid, so the mechanism works in this process and any refusal \
                below is about the TARGET rather than about kqueue. Note what \
                this does not show: the watch registered and was then thrown \
                away — nothing was waited for, and an exit event for a process \
                that does not exit during the probe is never delivered.
                """
                : """
                CONTROL FAILED — THIS GROUP IS INCONCLUSIVE. The registration \
                the whole group depends on did not succeed \
                (\(ErrorClassifier.errnoName(ownErr))). A refusal on a foreign \
                pid cannot be read as a foreign-process denial when the same \
                call on our own pid also fails, so the rows below are recorded \
                with that caveat attached instead of being converted into a \
                denial claim.
                """
        ))
        let controlNote = controlOK
            ? ""
            : """
            NOTE: the self-pid control did not succeed on this run, so the rows \
            in this group disagree about whether the mechanism works at all and \
            the group must be read as inconclusive until reproduced.
            """

        // The measurement: the same registration against pid 1 (launchd), a
        // process this app has no relationship with. A SUCCESS here is the
        // observation this group exists for and is recorded loudly -- still as
        // reconnaissance, never as a violation.
        var launchdChange = keventStruct(
            ident: 1, filter: evFiltProc,
            flags: evAdd | evEnable, fflags: noteExit
        )
        setErrno(0)
        let launchdRC = kevent(kq, &launchdChange, 1, nil, 0, &timeout)
        let launchdErr = launchdRC < 0 ? currentErrno() : 0
        entries.append(entry(
            id: "kq-proc-launchd",
            group: groupProcessExit,
            operation: """
                kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                """,
            target: "pid 1 (launchd)",
            rc: launchdRC, err: launchdErr,
            observed: launchdRC >= 0
                ? """
                MUST REPRODUCE ON DEVICE: kevent returned \(launchdRC) — an \
                ordinary app's kqueue ACCEPTED an exit-watch registration on \
                pid 1 (launchd)
                """
                : "kevent returned -1, errno=\(ErrorClassifier.errnoName(launchdErr))",
            interpretation: launchdObservation(
                rc: launchdRC, err: launchdErr, controlNote: controlNote
            )
        ))

        // Negative control: pid 0 cannot exist, so the registration must fail
        // with a lookup-shaped error. Its expected shape is what makes the
        // pid 1 row target-specific rather than blanket.
        var invalidChange = keventStruct(
            ident: 0, filter: evFiltProc,
            flags: evAdd | evEnable, fflags: noteExit
        )
        setErrno(0)
        let invalidRC = kevent(kq, &invalidChange, 1, nil, 0, &timeout)
        let invalidErr = invalidRC < 0 ? currentErrno() : 0
        entries.append(entry(
            id: "kq-proc-invalid-pid",
            group: groupProcessExit,
            operation: """
                kevent(EVFILT_PROC, EV_ADD|EV_ENABLE, NOTE_EXIT), zero timeout
                """,
            target: "pid 0 (cannot exist)",
            rc: invalidRC, err: invalidErr,
            observed: invalidRC >= 0
                ? "kevent returned \(invalidRC) for a pid that cannot exist"
                : "kevent returned -1, errno=\(ErrorClassifier.errnoName(invalidErr))",
            interpretation: invalidPidObservation(
                rc: invalidRC, err: invalidErr, controlNote: controlNote
            )
        ))

        // `defer` above closes the kqueue fd after the group.
        return entries
    }

    private static func launchdObservation(rc: Int32, err: Int32, controlNote: String) -> String {
        if rc >= 0 {
            return """
                MUST REPRODUCE ON DEVICE. An ordinary app's kqueue accepted an \
                EVFILT_PROC/NOTE_EXIT registration on launchd, the system's root \
                process -- the observation this group exists for. It is recorded \
                as reconnaissance with isBoundaryViolation false, and that is not \
                a technicality: a registration is only a request to be told \
                something later, this probe never waits for or receives an event \
                (zero timeout by design), and nothing about launchd's state was \
                observed here. What would raise this result, in order: the event \
                actually firing on device; the same registration accepted for \
                other apps' processes rather than only pid 1; the registration \
                surviving beyond this call. Until then this is a registration \
                result, not a disclosure. \(controlNote)
                """
        }
        switch err {
        case Int32(EPERM):
            return """
                EPERM is the seatbelt signature on iOS: watching launchd's exit \
                was denied while the self-pid registration above succeeded. The \
                result is that asymmetry -- same call, same kqueue, different \
                target -- and it names a sandbox predicate rather than a POSIX \
                permission. isBoundaryViolation stays false: a refusal is a \
                result, not a finding. \(controlNote)
                """
        case Int32(ESRCH), Int32(ENOENT):
            return """
                A not-found answer for a process that certainly exists means \
                launchd was not VISIBLE to this registration rather than absent: \
                either the process-lookup path behind EVFILT_PROC cannot reach it \
                from this context, or it is filtered from view. Named notFound \
                rather than refused because ESRCH is a lookup failure, not a \
                policy denial -- the difference matters, and it is why this is not \
                claimed as a sandbox refusal. \(controlNote)
                """
        default:
            return """
                Failed with \(ErrorClassifier.errnoName(err)), which is neither \
                EPERM nor a lookup failure, so it is not a policy-shaped refusal \
                and nothing is claimed about the boundary. The errno is named \
                exactly so a device run can compare it rather than guess. \
                \(controlNote)
                """
        }
    }

    private static func invalidPidObservation(rc: Int32, err: Int32, controlNote: String) -> String {
        if rc >= 0 {
            return """
                CONTROL FAILED: a watch on a pid that cannot exist was accepted, \
                so the registration path is not validating ident. That unmakes \
                the negative control -- neither the success on pid 1 above nor a \
                refusal on it can be read as target-specific while an impossible \
                target is also accepted, and this group's process-watch claims \
                are suspended until it is explained. \(controlNote)
                """
        }
        switch err {
        case Int32(ESRCH), Int32(ENOENT):
            return """
                CONTROL EXPECTED: pid 0 cannot exist, so a lookup failure is the \
                answer the control is supposed to produce. It shows the \
                registration path performs a real process lookup and reports a \
                real failure for an impossible target -- which is what makes a \
                refusal on pid 1 interpretable as target-specific rather than as \
                a blanket rejection of EVFILT_PROC. \(controlNote)
                """
        case Int32(EINVAL):
            return """
                CONTROL EXPECTED: EINVAL is the other documented answer for an \
                invalid ident -- also the control's expected shape, and it still \
                proves the path validates its target before registering. \
                \(controlNote)
                """
        case Int32(EPERM):
            return """
                CONTROL SHAPE UNEXPECTED: an impossible target answered EPERM. A \
                denial that does not depend on the target is not a statement \
                about the target, so if pid 1 also answers EPERM that row says \
                nothing specific about launchd -- it would read instead as a \
                blanket refusal of EVFILT_PROC registration, which the self-pid \
                control above either confirms or contradicts. Recorded as-is \
                rather than as a denial claim. \(controlNote)
                """
        default:
            return """
                CONTROL SHAPE UNEXPECTED: pid 0 answered \
                \(ErrorClassifier.errnoName(err)), which is neither a lookup \
                failure nor EINVAL, so the negative control did not produce its \
                expected shape and the pid 1 row must be read with that gap \
                visible. \(controlNote)
                """
        }
    }

    // MARK: - Group 2: EVFILT_VNODE file-change notification

    private static func fileChangeGroup() -> [Entry] {
        var entries: [Entry] = []
        entries.append(vnodeControlEntry())
        entries.append(contentsOf: etcPasswdEntries())
        return entries
    }

    /// The control: a file the app certainly owns, created, opened, and
    /// registered before /etc/passwd is touched anywhere. Every step is
    /// recorded in one row because the row IS the control -- if any step
    /// fails, the failure is the control's shape and the group is
    /// inconclusive rather than a denial claim about the real target.
    private static func vnodeControlEntry() -> Entry {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("fsprobe-kqueue-vnode-\(getpid())")

        setErrno(0)
        let kq = kqueue()
        guard kq >= 0 else {
            let err = currentErrno()
            return entry(
                id: "kq-vnode-control",
                group: groupFileChange,
                operation: """
                    kqueue() + open(O_CREAT|O_RDWR) + kevent(EVFILT_VNODE, EV_ADD, \
                    NOTE_WRITE|NOTE_DELETE|NOTE_RENAME)
                    """,
                target: path,
                rc: -1, err: err,
                observed: "kqueue() returned -1 before any file was created, errno=\(ErrorClassifier.errnoName(err))",
                interpretation: """
                    CONTROL NOT ESTABLISHED — THIS GROUP IS INCONCLUSIVE. The \
                    mechanism itself failed (\(ErrorClassifier.errnoName(err))), \
                    so no vnode watch could be asked about at all. That is a \
                    statement about kqueue being unavailable, not about any file \
                    being protected, and the /etc/passwd rows below must be read \
                    with the mechanism unmeasured.
                    """
            )
        }
        // Both descriptors are released on every path out of this function.
        defer { POSIXShim.closeFile(kq) }

        setErrno(0)
        let fd = POSIXShim.openFile(path, O_CREAT | O_RDWR | O_TRUNC, 0o600)
        guard fd >= 0 else {
            let err = currentErrno()
            return entry(
                id: "kq-vnode-control",
                group: groupFileChange,
                operation: """
                    kqueue() + open(O_CREAT|O_RDWR) + kevent(EVFILT_VNODE, EV_ADD, \
                    NOTE_WRITE|NOTE_DELETE|NOTE_RENAME)
                    """,
                target: path,
                rc: -1, err: err,
                observed: "opening the probe's own temp file failed, errno=\(ErrorClassifier.errnoName(err))",
                interpretation: """
                    CONTROL NOT ESTABLISHED — THIS GROUP IS INCONCLUSIVE. The \
                    app could not create and open its OWN file under \
                    NSTemporaryDirectory() \
                    (\(ErrorClassifier.errnoName(err))). A failure on \
                    /etc/passwd below could not be attributed to that target \
                    when the app's own file already fails, so nothing is claimed \
                    about the system file on this run.
                    """
            )
        }
        defer { POSIXShim.closeFile(fd) }
        // Removed on every path after the file exists; the registration above
        // is already recorded by then, and no event is being waited on.
        defer { POSIXShim.unlinkFile(path) }

        var change = keventStruct(
            ident: UInt(fd), filter: evFiltVnode,
            flags: evAdd, fflags: noteWrite | noteDelete | noteRename
        )
        setErrno(0)
        var timeout = timespec(tv_sec: 0, tv_nsec: 0)
        let rc = kevent(kq, &change, 1, nil, 0, &timeout)
        let err = rc < 0 ? currentErrno() : 0

        return entry(
            id: "kq-vnode-control",
            group: groupFileChange,
            operation: """
                kqueue() + open(O_CREAT|O_RDWR) + kevent(EVFILT_VNODE, EV_ADD, \
                NOTE_WRITE|NOTE_DELETE|NOTE_RENAME), zero timeout
                """,
            target: "\(path) (fd \(fd))",
            rc: rc, err: err,
            observed: rc >= 0
                ? """
                created and opened the probe's own temp file as fd \(fd); \
                kevent returned \(rc); the file was then unlinked and every \
                descriptor closed
                """
                : """
                created and opened the probe's own temp file as fd \(fd); kevent \
                returned -1, errno=\(ErrorClassifier.errnoName(err))
                """,
            interpretation: rc >= 0
                ? """
                CONTROL OK: a descriptor the app owns accepts an \
                EVFILT_VNODE watch for write/delete/rename, so the registration \
                path works here and the /etc/passwd rows below are about the \
                TARGET rather than about kqueue. Note what this does not show: \
                no event was ever waited for or delivered — the timeout is zero \
                by design — and the watch was torn down immediately, so this \
                measures registration, not notification.
                """
                : """
                CONTROL FAILED — THIS GROUP IS INCONCLUSIVE. The registration on \
                the app's OWN file was refused with \
                \(ErrorClassifier.errnoName(err)). Until that is explained, a \
                failure on /etc/passwd below could not be attributed to that \
                target, and it is recorded as measured-but-uninterpretable \
                rather than as a denial.
                """
        )
    }

    /// The measurement: the same open + registration on /etc/passwd. The open
    /// is recorded first and separately, because the open IS the boundary --
    /// a file you cannot open is a file whose changes you cannot be told
    /// about, and the kqueue registration rides entirely on that fd.
    private static func etcPasswdEntries() -> [Entry] {
        var entries: [Entry] = []

        setErrno(0)
        let fd = POSIXShim.openFile(etcPasswd, O_RDONLY, 0)
        let openErr = fd < 0 ? currentErrno() : 0

        entries.append(entry(
            id: "kq-vnode-etc-open",
            group: groupFileChange,
            operation: "open(O_RDONLY)",
            target: etcPasswd,
            rc: fd, err: openErr,
            observed: fd >= 0
                ? "open returned descriptor \(fd)"
                : "open returned -1, errno=\(ErrorClassifier.errnoName(openErr))",
            interpretation: fd >= 0
                ? """
                Opening a world-readable system file is the ordinary POSIX \
                answer and is recorded as reconnaissance: reading /etc/passwd is \
                not a finding, and isBoundaryViolation stays false. The boundary \
                this row actually tests is whether the DESCRIPTOR can be \
                obtained at all, because the vnode watch below rides entirely \
                on the fd — the access-control question for change notification \
                is settled here, before kqueue is involved. Keep the contrast \
                with the write-side probes of this project in mind: a file that \
                opens is not a file that can be written.
                """
                : """
                The open is the boundary: with no descriptor there is nothing to \
                register a watch on, so this row alone answers the group's \
                question about \(etcPasswd). \(errnoGloss(openErr)). Reading this \
                as a kqueue result would be wrong, which is why the registration \
                row below is recorded as not attempted rather than as a refusal.
                """
        ))

        guard fd >= 0 else {
            entries.append(notAttempted(
                id: "kq-vnode-etc-register",
                group: groupFileChange,
                operation: """
                    kqueue() + kevent(EVFILT_VNODE, EV_ADD, \
                    NOTE_WRITE|NOTE_DELETE|NOTE_RENAME), zero timeout
                    """,
                target: "\(etcPasswd) (no descriptor: open failed with \(ErrorClassifier.errnoName(openErr)))",
                observed: """
                    not attempted: open(O_RDONLY) on \(etcPasswd) failed with \
                    \(ErrorClassifier.errnoName(openErr)), so there was no fd \
                    for kevent to ride on
                    """,
                interpretation: """
                    NOT ATTEMPTED: the open is the boundary and it failed, so no \
                    registration was possible or meaningful. Recording this row \
                    rather than omitting it keeps the gap visible as unmeasured \
                    instead of leaving the report with an /etc/passwd open \
                    failure that could later be misread as a kqueue refusal.
                    """
            ))
            return entries
        }
        defer { POSIXShim.closeFile(fd) }

        setErrno(0)
        let kq = kqueue()
        guard kq >= 0 else {
            let err = currentErrno()
            entries.append(notAttempted(
                id: "kq-vnode-etc-register",
                group: groupFileChange,
                operation: """
                    kqueue() + kevent(EVFILT_VNODE, EV_ADD, \
                    NOTE_WRITE|NOTE_DELETE|NOTE_RENAME), zero timeout
                    """,
                target: "\(etcPasswd) (fd \(fd))",
                observed: """
                    not attempted: kqueue() returned -1 with \
                    \(ErrorClassifier.errnoName(err)) before kevent could be \
                    called, although open(O_RDONLY) on \(etcPasswd) succeeded as \
                    fd \(fd)
                    """,
                interpretation: """
                NOT ATTEMPTED: the descriptor half of the question was answered \
                (the open above), but the registration could not be asked \
                because the kqueue mechanism failed \
                (\(ErrorClassifier.errnoName(err))). Both halves are recorded \
                separately so neither is read as the other.
                """
            ))
            return entries
        }
        defer { POSIXShim.closeFile(kq) }

        var change = keventStruct(
            ident: UInt(fd), filter: evFiltVnode,
            flags: evAdd, fflags: noteWrite | noteDelete | noteRename
        )
        setErrno(0)
        var timeout = timespec(tv_sec: 0, tv_nsec: 0)
        let rc = kevent(kq, &change, 1, nil, 0, &timeout)
        let err = rc < 0 ? currentErrno() : 0

        entries.append(entry(
            id: "kq-vnode-etc-register",
            group: groupFileChange,
            operation: """
                kqueue() + kevent(EVFILT_VNODE, EV_ADD, \
                NOTE_WRITE|NOTE_DELETE|NOTE_RENAME), zero timeout
                """,
            target: "\(etcPasswd) (fd \(fd))",
            rc: rc, err: err,
            observed: rc >= 0
                ? """
                kevent returned \(rc) — the change watch on the /etc/passwd \
                descriptor was ACCEPTED; no event was waited for or delivered \
                (timeout zeroed) and everything was then closed
                """
                : "kevent returned -1, errno=\(ErrorClassifier.errnoName(err))",
            interpretation: rc >= 0
                ? """
                The descriptor obtained above carries a write/delete/rename \
                watch: an app that can open /etc/passwd read-only can also ask \
                to be told when it changes. Recorded as reconnaissance with \
                isBoundaryViolation false — a registration is a request to be \
                told later, no event was ever waited for or delivered (zero \
                timeout by design), and nothing about /etc/passwd's contents or \
                state was observed. The open above is where this result is \
                actually decided; this row only shows that kqueue itself does \
                not add a second gate on top of it.
                """
                : """
                The open succeeded and the registration did not, so the two \
                halves of this question disagree and the disagreement is the \
                result: reading \(etcPasswd) is permitted while watching it is \
                not (\(errnoGloss(err))). That is a predicate on change \
                notification rather than on file access, and it must be \
                reproduced on device before it means anything — an errno that is \
                neither EPERM nor a descriptor error would instead say the \
                registration failed for a mechanical reason.
                """
        ))
        return entries
    }

    // MARK: - Classification and construction helpers

    /// The classification rule, stated once: -1 with EPERM is a refusal,
    /// ESRCH/ENOENT is a missing target, >= 0 is a registration the kernel
    /// accepted, and everything else is reported under its own errno name
    /// rather than folded into a denial.
    private static func classify(_ rc: Int32, err: Int32) -> Outcome {
        if rc >= 0 { return .registered }
        switch err {
        case Int32(EPERM): return .refused
        case Int32(ESRCH), Int32(ENOENT): return .notFound
        default: return .otherError
        }
    }

    private static func entry(
        id: String,
        group: String,
        operation: String,
        target: String,
        rc: Int32,
        err: Int32,
        observed: String,
        interpretation: String
    ) -> Entry {
        Entry(
            id: id,
            group: group,
            operation: operation,
            target: target,
            outcome: classify(rc, err: err),
            errnoName: rc < 0 ? ErrorClassifier.errnoName(err) : nil,
            returnedValue: String(rc),
            observed: observed,
            interpretation: interpretation
        )
    }

    private static func notAttempted(
        id: String,
        group: String,
        operation: String,
        target: String,
        observed: String,
        interpretation: String
    ) -> Entry {
        Entry(
            id: id,
            group: group,
            operation: operation,
            target: target,
            outcome: .notAttempted,
            errnoName: nil,
            returnedValue: nil,
            observed: observed,
            interpretation: interpretation
        )
    }

    /// Which boundary an errno actually names, so no failure is described as
    /// a sandbox denial by accident: EPERM is the seatbelt, EACCES is
    /// POSIX/SIP, ENOENT is an absent path, and anything else is left as the
    /// plain fact it is.
    private static func errnoGloss(_ err: Int32) -> String {
        switch err {
        case Int32(EPERM):
            return "EPERM names the seatbelt sandbox, which is a policy denial"
        case Int32(EACCES):
            return "EACCES names POSIX permissions or SIP, not the sandbox"
        case Int32(ENOENT):
            return "ENOENT means the path is absent on this build"
        default:
            return "\(ErrorClassifier.errnoName(err)) is neither a policy denial nor a missing path"
        }
    }

    // MARK: - kevent constants and construction

    // <sys/event.h> spells all of these as plain integer macros, and the
    // Swift overlay imports each one with its own C type (EVFILT_PROC as
    // Int32, EV_ADD as Int32, NOTE_EXIT as UInt32), while the fields of
    // `struct kevent` are strictly typed (filter: Int16, flags: UInt16,
    // fflags: UInt32). They are therefore spelled once, here, with their
    // documented values, rather than converted ad hoc at every call site --
    // the project's rule for constants the overlay does not hand over in a
    // directly usable shape.
    private static let evFiltProc: Int16 = -5          // EVFILT_PROC
    private static let evFiltVnode: Int16 = -4         // EVFILT_VNODE
    private static let evAdd: UInt16 = 0x0001          // EV_ADD
    private static let evEnable: UInt16 = 0x0004       // EV_ENABLE
    private static let noteExit: UInt32 = 0x80000000   // NOTE_EXIT
    private static let noteWrite: UInt32 = 0x0002      // NOTE_WRITE
    private static let noteDelete: UInt32 = 0x0001     // NOTE_DELETE
    private static let noteRename: UInt32 = 0x0020     // NOTE_RENAME

    /// One changelist entry, with every field set explicitly so no field of
    /// the imported struct is left holding whatever the stack had in it.
    /// `udata` stays nil: nothing here correlates events through user data,
    /// and a non-nil pointer would be one more thing to keep alive.
    private static func keventStruct(
        ident: UInt,
        filter: Int16,
        flags: UInt16,
        fflags: UInt32
    ) -> kevent {
        kevent(
            ident: ident,
            filter: filter,
            flags: flags,
            fflags: fflags,
            data: 0,
            udata: nil
        )
    }
    #endif
}
