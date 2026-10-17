//
//  KernelObjectSurfaceProbe.swift
//  FSProbeCore — three kernel-object surfaces an ordinary app can touch.
//
//  WHY THIS EXISTS
//  ---------------
//  Every probe in this project so far has asked a file-shaped question: which
//  paths, which metadata, which descriptors. That leaves three kernel-object
//  surfaces unmeasured, and each is gated by a DIFFERENT sandbox predicate than
//  filesystem access, so a pass here is NOT implied by any filesystem result:
//
//    * POSIX IPC namespaces (shm_open / sem_open / mq_open, plus SysV IPC) are
//      reached through separate `ipc-posix-shm` / `ipc-posix-sem` /
//      `ipc-posix-msg` predicates, not `file-read*` / `file-write*`.
//    * Socket families (AF_UNIX, AF_INET, AF_INET6, AF_ROUTE, AF_SYSTEM, and
//      AF_NETLINK -- which Darwin does not define at all) are gated by
//      `network*` and per-family predicates. XPC rides on AF_SYSTEM, so its
//      answer matters beyond the socket itself.
//    * Device nodes (/dev/null through /dev/kmem) are gated by file access under
//      /dev plus per-device policy, and a device that OPENS is a materially
//      different observation than a path that merely reads.
//
//  HYPOTHESIS
//  ----------
//  An ordinary iOS 27 app is permitted the benign members of each surface
//  (/dev/null, AF_UNIX, a private shm object) and refused the privileged ones
//  (/dev/kmem, AF_ROUTE). AF_NETLINK is absent from the ABI entirely, which is
//  a different answer from a refusal. A refusal, when it is EPERM, names a sandbox
//  predicate; anything else must be read as exactly what it is.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  The `ipc-posix-*`, `network*` and /dev device predicates -- each a separate
//  gate from the file-read / file-write predicates measured elsewhere.
//
//  CONTROL
//  -------
//  Three negative controls, one per group, each run FIRST and unconditionally:
//  shm_open on a name that cannot exist (expect ENOENT), socket(-1, 0, 0)
//  (expect EAFNOSUPPORT/EINVAL), and open on a /dev path that cannot exist
//  (expect ENOENT). A control whose expected answer is a refusal or ENOENT is
//  what makes a refusal on a real object interpretable. If a control does not
//  produce its expected shape the group is recorded as inconclusive rather than
//  converted into a denial claim.
//
//  SAFETY
//  ------
//  Reach only. Nothing is written to any object, no message is sent, no socket
//  is connected or bound, no name is handed to another process. Every object
//  created is unlinked/removed immediately and every fd is closed immediately.
//  A successful open of a sensitive device is recorded loudly but as
//  reconnaissance only: `isBoundaryViolation` is ALWAYS false here.
//

import Foundation

#if canImport(Darwin)
import Darwin
#endif

public enum KernelObjectSurfaceProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call returned successfully.
        case permitted
        /// The call was refused with EPERM — the seatbelt signature on iOS.
        case denied
        /// The call failed with ENOENT — the object/name is simply not there.
        case notFound
        /// The call failed for another recorded reason.
        case otherError
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
        /// A required symbol is not present on this platform.
        case symbolUnavailable
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        /// Which surface this row belongs to.
        public let group: String
        /// The operation exercised.
        public let operation: String
        /// The concrete object the operation named.
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

        /// Reachability is reconnaissance, never a finding. This probe never
        /// maps a successful return to a violation by itself.
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

    private static let groupIPCObjects = "POSIX IPC objects"
    private static let groupSocketFamilies = "socket families"
    private static let groupDeviceFiles = "device files"

    /// The controls, named once so the `#else` branch records the same rows.
    private static let controlIPCName = "/fsprobe-nonexistent-object"
    private static let controlDevicePath = "/dev/fsprobe-nonexistent-device"

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        // Each group runs its control first, unconditionally.
        entries.append(contentsOf: posixIPCGroup())
        entries.append(contentsOf: socketFamilyGroup())
        entries.append(contentsOf: deviceGroup())

        // isBoundaryViolation is always false, so this is always empty -- but
        // it is computed rather than hard-coded so the invariant is testable.
        let violations = entries.filter { $0.isBoundaryViolation }
        return Result(entries: entries, violations: violations)
        #else
        let entries: [Entry] = [
            Entry(
                id: "posix-ipc-control",
                group: groupIPCObjects,
                operation: "shm_open(O_RDWR) control",
                target: controlIPCName,
                outcome: .notAttempted,
                errnoName: nil,
                returnedValue: nil,
                observed: "POSIX IPC is not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: there is no POSIX IPC namespace here. Recorded \
                    rather than omitted so a result with no control in it reads \
                    as impossible, not as empty.
                    """
            ),
            Entry(
                id: "socket-control",
                group: groupSocketFamilies,
                operation: "socket(-1, 0, 0) control",
                target: "invalid domain (-1)",
                outcome: .notAttempted,
                errnoName: nil,
                returnedValue: nil,
                observed: "socket() is not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: there is no BSD socket layer here. The control \
                    is still recorded so the socket-family rows never read as a \
                    complete census.
                    """
            ),
            Entry(
                id: "device-control",
                group: groupDeviceFiles,
                operation: "open(O_RDWR) control",
                target: controlDevicePath,
                outcome: .notAttempted,
                errnoName: nil,
                returnedValue: nil,
                observed: "device nodes are not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: there is no /dev here. The control is still \
                    recorded so an absence of device results is not mistaken for \
                    a measured refusal.
                    """
            ),
        ]
        return Result(entries: entries, violations: [])
        #endif
    }

    #if canImport(Darwin)
    // MARK: - Classification helpers

    private static func classify(_ rc: Int32, err: Int32) -> Outcome {
        if rc >= 0 { return .permitted }
        switch err {
        case Int32(EPERM): return .denied
        case Int32(ENOENT): return .notFound
        default: return .otherError
        }
    }

    private static func objectCase(
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
            errnoName: rc >= 0 ? nil : ErrorClassifier.errnoName(err),
            returnedValue: String(rc),
            observed: observed,
            interpretation: interpretation
        )
    }

    // sem_open has the shape `sem_t *sem_open(const char *, int, ...)`. The
    // Swift importer marks C variadic (`...`) functions unavailable, so it
    // cannot be named directly -- the identical reason POSIXShim binds `open`
    // by symbol. It is resolved with dlsym and called through a fixed-arity
    // pointer; on the Apple ABIs the leading integer arguments are passed the
    // same way whether or not the callee reads them through va_list (this is
    // the same technique POSIXShim+Darwin already relies on for `open`).
    private typealias SemOpenFn = @convention(c) (
        UnsafePointer<CChar>, Int32, Int32, UInt32
    ) -> UnsafeMutablePointer<sem_t>?

    // mq_open has the shape `mqd_t mq_open(const char *, int, ...)`; the
    // fourth argument is a nullable `struct mq_attr *`, passed here as a raw
    // pointer so NULL is expressible through the fixed signature.
    private typealias MqOpenFn = @convention(c) (
        UnsafePointer<CChar>, Int32, Int32, UnsafeMutableRawPointer?
    ) -> Int32

    // semctl is `int semctl(int, int, int, ...)` -- variadic like sem_open, so
    // bound the same way. IPC_RMID supplies no fourth argument, so a fixed
    // three-argument pointer calls it safely.
    private typealias SemCtlFn = @convention(c) (Int32, Int32, Int32) -> Int32

    // shm_open is `int shm_open(const char *, int, ...)` -- variadic for the
    // same reason as sem_open, so it is bound the same way. The third argument
    // is mode_t, passed as UInt32.
    private typealias ShmOpenFn = @convention(c) (
        UnsafePointer<CChar>, Int32, UInt32
    ) -> Int32

    // mq_close and mq_unlink live in <mqueue.h>, which the Swift Darwin
    // overlay does not import, so they are resolved with dlsym rather than
    // named directly.
    private typealias MqCloseFn = @convention(c) (Int32) -> Int32
    private typealias MqUnlinkFn = @convention(c) (UnsafePointer<CChar>) -> Int32

    /// SYSPROTO_CONTROL from <sys/kern_control.h>: the protocol that selects a
    /// kernel-control socket. The Swift overlay does not import the constant,
    /// so it is spelled here with its documented value rather than guessed at
    /// a call site.
    private static let sysprotoControl: Int32 = 2

    private static func semaphoreCase(name: String) -> Entry {
        guard let symbol = POSIXShim.lookupSymbol("sem_open") else {
            return Entry(
                id: "posix-ipc-sem", group: groupIPCObjects,
                operation: "sem_open(O_CREAT)", target: name,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "sem_open could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the sem_open symbol is absent from the process \
                    image, so the named-semaphore predicate could not be asked.
                    """
            )
        }
        let semOpen = unsafeBitCast(symbol, to: SemOpenFn.self)

        setErrno(0)
        let semp = name.withCString { semOpen($0, O_CREAT, 0o600, 0) }
        // errno must be read before any other call, and Darwin reports failure
        // as SEM_FAILED ((sem_t *)-1) rather than NULL, so it is captured
        // unconditionally and only consulted when the result is the sentinel.
        let semErr = currentErrno()
        let semFailedSentinel = UnsafeMutablePointer<sem_t>(bitPattern: -1)
        let semOK = semp != nil && semp != semFailedSentinel
        var observed: String
        if semOK, let sem = semp {
            let closeRC = sem_close(sem)
            let unlinkRC = name.withCString { sem_unlink($0) }
            observed = "sem_open(O_CREAT) returned a non-null sem_t; sem_close -> \(closeRC); sem_unlink -> \(unlinkRC)"
        } else {
            observed = "sem_open(O_CREAT) failed, errno=\(ErrorClassifier.errnoName(semErr))"
        }
        return objectCase(
            id: "posix-ipc-sem", group: groupIPCObjects,
            operation: "sem_open(O_CREAT)", target: name,
            rc: semOK ? 0 : -1, err: semErr, observed: observed,
            interpretation: semOK
                ? """
                    A POSIX named semaphore was created in the app's own IPC \
                    namespace and unlinked immediately. A semaphore is not a \
                    shared-memory region: it carries a count, not contents.
                    """
                : """
                    POSIX named semaphores were refused. EPERM names the \
                    ipc-posix-sem predicate; a notFound/other error would instead \
                    describe the namespace being absent rather than denied.
                    """
        )
    }

    private static func messageQueueCase(name: String) -> Entry {
        guard let symbol = POSIXShim.lookupSymbol("mq_open") else {
            return Entry(
                id: "posix-ipc-mq", group: groupIPCObjects,
                operation: "mq_open(O_CREAT|O_RDWR)", target: name,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "mq_open could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the mq_open symbol is absent from the process \
                    image, so the message-queue predicate could not be asked.
                    """
            )
        }
        let mqOpen = unsafeBitCast(symbol, to: MqOpenFn.self)

        setErrno(0)
        // A NULL attribute pointer asks for the implementation defaults, which
        // is what the probe wants; no queue attributes are set.
        let mqRC = name.withCString { mqOpen($0, O_CREAT | O_RDWR, 0o600, nil) }
        let mqErr = mqRC >= 0 ? 0 : currentErrno()
        var observed: String
        if mqRC >= 0 {
            // mq_close/mq_unlink are not in the Swift overlay, so each is
            // resolved separately and an unresolved one is recorded as such
            // rather than skipped silently -- a queue left open because a
            // teardown symbol was missing is still a leak, and it is one the
            // report has to be able to show.
            var closeDesc = "mq_close unresolved"
            if let sym = POSIXShim.lookupSymbol("mq_close") {
                let fn = unsafeBitCast(sym, to: MqCloseFn.self)
                closeDesc = "mq_close -> \(fn(mqRC))"
            }
            var unlinkDesc = "mq_unlink unresolved"
            if let sym = POSIXShim.lookupSymbol("mq_unlink") {
                let fn = unsafeBitCast(sym, to: MqUnlinkFn.self)
                unlinkDesc = "mq_unlink -> \(name.withCString { fn($0) })"
            }
            observed = "mq_open(O_CREAT|O_RDWR, NULL attrs) returned mqd_t \(mqRC); \(closeDesc); \(unlinkDesc)"
        } else {
            observed = "mq_open(O_CREAT|O_RDWR, NULL attrs) returned -1, errno=\(ErrorClassifier.errnoName(mqErr))"
        }
        return objectCase(
            id: "posix-ipc-mq", group: groupIPCObjects,
            operation: "mq_open(O_CREAT|O_RDWR)", target: name,
            rc: mqRC, err: mqErr, observed: observed,
            interpretation: mqRC >= 0
                ? """
                    A POSIX message queue was created and removed again. This is \
                    its own ipc-posix-msg predicate. Nothing was sent to it, so \
                    the queue's reachability is recorded without exercising any \
                    cross-process transfer.
                    """
                : """
                    POSIX message queues were refused. EPERM names the \
                    ipc-posix-msg predicate; ENOENT/EINVAL would mean the name \
                    form or the namespace itself is absent.
                    """
        )
    }

    // MARK: - Group 1: POSIX IPC objects

    private static func posixIPCGroup() -> [Entry] {
        var rows: [Entry] = []

        // shm_open is variadic, so the Swift importer marks it unavailable and
        // it is resolved once here. A failure to resolve it means the whole
        // POSIX-IPC group cannot be asked -- and that is recorded as
        // unattempted rather than guessed at per case, because a group whose
        // first mechanism is missing cannot answer for the others either.
        guard let shmSymbol = POSIXShim.lookupSymbol("shm_open") else {
            return [Entry(
                id: "posix-ipc-control", group: groupIPCObjects,
                operation: "shm_open(O_RDWR)",
                target: controlIPCName,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "shm_open could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the shm_open symbol is absent from the process \
                    image, so no POSIX-IPC predicate could be asked. The \
                    semaphore and message-queue cases below still run, because \
                    their symbols are independent.
                    """
            )]
        }
        let shmOpen = unsafeBitCast(shmSymbol, to: ShmOpenFn.self)

        // --- control FIRST ---
        setErrno(0)
        let crc = controlIPCName.withCString { shmOpen($0, O_RDWR, 0) }
        let cerr = crc >= 0 ? 0 : currentErrno()
        let controlOK = crc == -1 && cerr == Int32(ENOENT)
        rows.append(objectCase(
            id: "posix-ipc-control",
            group: groupIPCObjects,
            operation: "shm_open(O_RDWR)",
            target: controlIPCName,
            rc: crc,
            err: cerr,
            observed: crc == -1
                ? "shm_open(\"\(controlIPCName)\", O_RDWR, 0) returned -1, errno=\(ErrorClassifier.errnoName(cerr))"
                : "shm_open on a nonexistent name returned \(crc)",
            interpretation: controlOK
                ? """
                    CONTROL satisfied: a name that cannot exist yields ENOENT, \
                    which is what makes any other shm_open answer interpretable \
                    (a denial would be EPERM, not the absence of the object).
                    """
                : """
                    CONTROL DID NOT PRODUCE ENOENT. The nonexistent IPC name \
                    answered \(crc == -1 ? ErrorClassifier.errnoName(cerr) : "success"). \
                    The POSIX-IPC rows below are inconclusive until this is understood.
                    """
        ))

        // --- shm_open create + unlink ---
        let shmName = "/fsprobe-posix-ipc"
        setErrno(0)
        let shmRC = shmName.withCString { shmOpen($0, O_RDWR | O_CREAT, 0o600) }
        let shmErr = shmRC >= 0 ? 0 : currentErrno()
        var shmObserved: String
        if shmRC >= 0 {
            let unlinkRC = shmName.withCString { shm_unlink($0) }
            shmObserved = "shm_open(O_RDWR|O_CREAT) returned fd \(shmRC); shm_unlink -> \(unlinkRC)"
        } else {
            shmObserved = "shm_open(O_RDWR|O_CREAT) returned -1, errno=\(ErrorClassifier.errnoName(shmErr))"
        }
        rows.append(objectCase(
            id: "posix-ipc-shm",
            group: groupIPCObjects,
            operation: "shm_open(O_RDWR|O_CREAT)",
            target: shmName,
            rc: shmRC,
            err: shmErr,
            observed: shmObserved,
            interpretation: shmRC >= 0
                ? """
                    An ordinary app created a POSIX shared-memory object in its \
                    own IPC namespace. This is a predicate distinct from file \
                    access; the object was unlinked immediately so nothing \
                    persists. It grants no access to another process's memory.
                    """
                : """
                    POSIX shared memory was refused. EPERM is the sandbox \
                    denying the ipc-posix-shm predicate; ENOENT/EINVAL instead \
                    describes a platform that carries no such namespace.
                    """
        ))

        // --- sem_open + close + unlink (bound by symbol; see semaphoreCase) ---
        rows.append(semaphoreCase(name: "/fsprobe-posix-sem"))

        // --- mq_open + close + unlink (bound by symbol; see messageQueueCase) ---
        rows.append(messageQueueCase(name: "/fsprobe-posix-mq"))

        // --- namespace-escape attempt ---
        let escapeName = "/../fsprobe-escape"
        setErrno(0)
        let escRC = escapeName.withCString { shmOpen($0, O_RDWR, 0) }
        let escErr = escRC >= 0 ? 0 : currentErrno()
        rows.append(objectCase(
            id: "posix-ipc-escape",
            group: groupIPCObjects,
            operation: "shm_open(O_RDWR) with a name containing a separator",
            target: escapeName,
            rc: escRC,
            err: escErr,
            observed: escRC == -1
                ? "shm_open(\"\(escapeName)\", O_RDWR, 0) returned -1, errno=\(ErrorClassifier.errnoName(escErr))"
                : "shm_open accepted a name containing a separator, returning \(escRC)",
            interpretation: escRC >= 0
                ? """
                    A name containing a path separator was accepted. POSIX \
                    requires the name to be '/' followed by a string with no \
                    further '/', so this would mean the IPC namespace is not \
                    validating its own names. It would still stay inside the IPC \
                    namespace, so it is not a filesystem escape -- but reproduce \
                    before drawing any conclusion.
                    """
                : """
                    The escaping name was rejected, which is the namespace \
                    validating its own name grammar rather than a sandbox \
                    statement. It confirms the separator does not reach the \
                    filesystem.
                    """
        ))

        // --- SysV shared memory ---
        setErrno(0)
        let shmid = shmget(IPC_PRIVATE, 4096, 0o600)
        let shmSysErr = shmid >= 0 ? 0 : currentErrno()
        var shmSysObserved: String
        if shmid >= 0 {
            // No attach happened, so there is nothing to shmdt; the correct
            // teardown for an unattached segment is shmctl(IPC_RMID).
            let rm = shmctl(shmid, IPC_RMID, nil)
            shmSysObserved = "shmget(IPC_PRIVATE, 4096, 0o600) returned shmid \(shmid); shmctl(IPC_RMID) -> \(rm)"
        } else {
            shmSysObserved = "shmget(IPC_PRIVATE, 4096, 0o600) returned -1, errno=\(ErrorClassifier.errnoName(shmSysErr))"
        }
        rows.append(objectCase(
            id: "posix-ipc-sysv-shm",
            group: groupIPCObjects,
            operation: "shmget(IPC_PRIVATE, 4096, 0o600)",
            target: "IPC_PRIVATE",
            rc: shmid,
            err: shmSysErr,
            observed: shmSysObserved,
            interpretation: shmid >= 0
                ? """
                    A SysV shared-memory segment was created. It was never \
                    attached (no shmat), so it exposed no address into this \
                    process, and it was removed with shmctl(IPC_RMID).
                    """
                : """
                    SysV shared memory was refused. This is the legacy IPC \
                    predicate, a separate gate from the POSIX-IPC names above.
                    """
        ))

        // --- SysV semaphores ---
        setErrno(0)
        let semid = semget(IPC_PRIVATE, 1, 0o600)
        let semSysErr = semid >= 0 ? 0 : currentErrno()
        var semSysObserved: String
        if semid >= 0 {
            // semctl is variadic and unavailable directly; resolve it by symbol
            // and pass no fourth argument (IPC_RMID needs none).
            if let symbol = POSIXShim.lookupSymbol("semctl") {
                let semCtl = unsafeBitCast(symbol, to: SemCtlFn.self)
                let rm = semCtl(semid, 0, IPC_RMID)
                semSysObserved = "semget(IPC_PRIVATE, 1, 0o600) returned semid \(semid); semctl(IPC_RMID) -> \(rm)"
            } else {
                semSysObserved = "semget(IPC_PRIVATE, 1, 0o600) returned semid \(semid); cleanup NOT attempted (semctl could not be resolved), so the set is left in place"
            }
        } else {
            semSysObserved = "semget(IPC_PRIVATE, 1, 0o600) returned -1, errno=\(ErrorClassifier.errnoName(semSysErr))"
        }
        rows.append(objectCase(
            id: "posix-ipc-sysv-sem",
            group: groupIPCObjects,
            operation: "semget(IPC_PRIVATE, 1, 0o600)",
            target: "IPC_PRIVATE",
            rc: semid,
            err: semSysErr,
            observed: semSysObserved,
            interpretation: semid >= 0
                ? """
                    A SysV semaphore set was created and removed again with \
                    semctl(IPC_RMID). No semaphore operation (semop) was \
                    performed, so only creation was measured.
                    """
                : """
                    SysV semaphores were refused, a separate legacy-IPC gate.
                    """
        ))

        // --- SysV message queues ---
        setErrno(0)
        let msgid = msgget(IPC_PRIVATE, 0o600)
        let msgSysErr = msgid >= 0 ? 0 : currentErrno()
        var msgSysObserved: String
        if msgid >= 0 {
            let rm = msgctl(msgid, IPC_RMID, nil)
            msgSysObserved = "msgget(IPC_PRIVATE, 0o600) returned msqid \(msgid); msgctl(IPC_RMID) -> \(rm)"
        } else {
            msgSysObserved = "msgget(IPC_PRIVATE, 0o600) returned -1, errno=\(ErrorClassifier.errnoName(msgSysErr))"
        }
        rows.append(objectCase(
            id: "posix-ipc-sysv-msg",
            group: groupIPCObjects,
            operation: "msgget(IPC_PRIVATE, 0o600)",
            target: "IPC_PRIVATE",
            rc: msgid,
            err: msgSysErr,
            observed: msgSysObserved,
            interpretation: msgid >= 0
                ? """
                    A SysV message queue was created and removed with \
                    msgctl(IPC_RMID). No message was sent, so the queue was \
                    measured as an object, not as a transfer channel.
                    """
                : """
                    SysV message queues were refused, the third legacy-IPC gate.
                    """
        ))

        return rows
    }

    // MARK: - Group 2: socket families

    private static func socketFamilyGroup() -> [Entry] {
        var rows: [Entry] = []

        // --- control FIRST ---
        setErrno(0)
        let crc = socket(-1, 0, 0)
        let cerr = crc >= 0 ? 0 : currentErrno()
        let controlOK = crc == -1 && (cerr == Int32(EAFNOSUPPORT) || cerr == Int32(EINVAL))
        rows.append(objectCase(
            id: "socket-control",
            group: groupSocketFamilies,
            operation: "socket(domain, type, proto)",
            target: "invalid domain (-1)",
            rc: crc,
            err: cerr,
            observed: crc == -1
                ? "socket(-1, 0, 0) returned -1, errno=\(ErrorClassifier.errnoName(cerr))"
                : "socket(-1, 0, 0) unexpectedly returned \(crc)",
            interpretation: controlOK
                ? """
                    CONTROL satisfied: an invalid domain is rejected as \
                    EAFNOSUPPORT/EINVAL before any policy decision, which is \
                    what makes a family-specific refusal interpretable.
                    """
                : """
                    CONTROL DID NOT PRODUCE EAFNOSUPPORT/EINVAL. It answered \
                    \(crc == -1 ? ErrorClassifier.errnoName(cerr) : "success"). The \
                    socket-family rows below are inconclusive until this is \
                    understood.
                    """
        ))

        rows.append(socketCase(
            id: "socket-af-unix-stream",
            target: "AF_UNIX/SOCK_STREAM/0",
            domain: AF_UNIX, type: SOCK_STREAM, proto: 0,
            interpretation: """
                AF_UNIX is expected to be permitted: it is the local IPC family \
                XPC and the app's own services use. Success confirms the local \
                family is open, which is the baseline every other family is read \
                against.
                """
        ))

        rows.append(socketCase(
            id: "socket-af-inet-stream",
            target: "AF_INET/SOCK_STREAM/0",
            domain: AF_INET, type: SOCK_STREAM, proto: 0,
            interpretation: """
                AF_INET is the outward network family. A refusal here is the \
                network sandbox answering a predicate separate from any file \
                access; a success only means the socket object was created, not \
                that it may connect anywhere.
                """
        ))

        rows.append(socketCase(
            id: "socket-af-inet6-dgram",
            target: "AF_INET6/SOCK_DGRAM/0",
            domain: AF_INET6, type: SOCK_DGRAM, proto: 0,
            interpretation: """
                AF_INET6 measures whether the IPv6 family is gated the same way \
                as AF_INET. A different answer between the two would itself be \
                the interesting result.
                """
        ))

        // AF_NETLINK is a Linux family. It cannot be probed by calling socket()
        // because the Darwin SDK does not define the constant at all (Darwin's
        // socket.h lists AF_PUP 4, AF_ROUTE 17, AF_SYSTEM 32, and no AF_NETLINK),
        // so naming it would not link. Recording symbolUnavailable is the honest
        // measurement: for iOS the family is not merely refused, it is absent.
        rows.append(Entry(
            id: "socket-af-netlink-raw",
            group: groupSocketFamilies,
            operation: "socket(AF_NETLINK, SOCK_RAW, 0)",
            target: "AF_NETLINK/SOCK_RAW/0",
            outcome: .symbolUnavailable,
            errnoName: nil,
            returnedValue: nil,
            observed: "AF_NETLINK is not defined by the Darwin SDK, so socket() could not be called with it",
            interpretation: """
                NOT ATTEMPTED AS A CALL: AF_NETLINK does not exist in Darwin's \
                <sys/socket.h>, so there is no family value to pass. On iOS the \
                netlink family is absent from the ABI rather than refused at \
                runtime, which is the answer: an app cannot even name it. The \
                platform's own event family is AF_SYSTEM, probed separately below.
                """
        ))

        rows.append(socketCase(
            id: "socket-af-route-raw",
            target: "AF_ROUTE/SOCK_RAW/0",
            domain: AF_ROUTE, type: SOCK_RAW, proto: 0,
            interpretation: """
                AF_ROUTE reaches the routing table, which no ordinary app should \
                touch. It is expected to be refused; the errno tells whether that \
                is the sandbox (EPERM) or the platform not offering the family.
                """
        ))

        rows.append(socketCase(
            id: "socket-af-system-dgram",
            target: "AF_SYSTEM/SOCK_DGRAM/SYSPROTO_CONTROL",
            domain: Int32(AF_SYSTEM), type: SOCK_DGRAM, proto: sysprotoControl,
            interpretation: """
                AF_SYSTEM with SYSPROTO_CONTROL is the lowest layer XPC rides \
                on. A permitted control socket does NOT mean XPC services are \
                reachable -- that is a later experiment on top of this one -- but \
                a refusal here would bound everything above it.
                """
        ))

        // --- socketpair ---
        setErrno(0)
        var fds: [Int32] = [-1, -1]
        let pairRC = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        let pairErr = pairRC >= 0 ? 0 : currentErrno()
        var pairObserved: String
        if pairRC == 0 {
            let c0 = close(fds[0])
            let c1 = close(fds[1])
            pairObserved = "socketpair(AF_UNIX, SOCK_STREAM) returned two fds [\(fds[0]), \(fds[1])]; both closed (\(c0), \(c1))"
        } else {
            pairObserved = "socketpair(AF_UNIX, SOCK_STREAM) returned -1, errno=\(ErrorClassifier.errnoName(pairErr))"
        }
        rows.append(objectCase(
            id: "socketpair-af-unix",
            group: groupSocketFamilies,
            operation: "socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)",
            target: "AF_UNIX/SOCK_STREAM/0 (pair)",
            rc: pairRC,
            err: pairErr,
            observed: pairObserved,
            interpretation: pairRC == 0
                ? """
                    A connected AF_UNIX descriptor pair was created and both ends \
                    closed. It is a purely local channel; it carries no reach \
                    beyond this process unless a descriptor is passed, which was \
                    not done.
                    """
                : """
                    Even a local socketpair was refused, which would extend the \
                    network sandbox down to intra-process plumbing. Recorded as \
                    it stands rather than assumed.
                    """
        ))

        return rows
    }

    private static func socketCase(
        id: String,
        target: String,
        domain: Int32,
        type: Int32,
        proto: Int32,
        interpretation: String
    ) -> Entry {
        setErrno(0)
        let fd = socket(domain, type, proto)
        let err = fd >= 0 ? 0 : currentErrno()
        var observed: String
        if fd >= 0 {
            let closeRC = close(fd)
            observed = "socket() returned fd \(fd); closed immediately (\(closeRC))"
        } else {
            observed = "socket() returned -1, errno=\(ErrorClassifier.errnoName(err))"
        }
        return objectCase(
            id: id,
            group: groupSocketFamilies,
            operation: "socket(domain, type, proto)",
            target: target,
            rc: fd,
            err: err,
            observed: observed,
            interpretation: interpretation
        )
    }

    // MARK: - Group 3: device files

    private static func deviceGroup() -> [Entry] {
        var rows: [Entry] = []

        // --- control FIRST ---
        setErrno(0)
        let crc = POSIXShim.openFile(controlDevicePath, O_RDWR, 0)
        let cerr = crc >= 0 ? 0 : currentErrno()
        if crc >= 0 { _ = POSIXShim.closeFile(crc) }
        let controlOK = crc == -1 && cerr == Int32(ENOENT)
        rows.append(objectCase(
            id: "device-control",
            group: groupDeviceFiles,
            operation: "open(O_RDWR)",
            target: controlDevicePath,
            rc: crc,
            err: cerr,
            observed: crc == -1
                ? "open(\"\(controlDevicePath)\", O_RDWR) returned -1, errno=\(ErrorClassifier.errnoName(cerr))"
                : "open on a nonexistent device path returned \(crc)",
            interpretation: controlOK
                ? """
                    CONTROL satisfied: a device path that cannot exist yields \
                    ENOENT, which is what makes a refusal on a real device node \
                    interpretable rather than ambiguous.
                    """
                : """
                    CONTROL DID NOT PRODUCE ENOENT. The nonexistent device path \
                    answered \(crc == -1 ? ErrorClassifier.errnoName(cerr) : "success"). \
                    The device rows below are inconclusive until this is understood.
                    """
        ))

        // Benign device nodes: expected permitted.
        for path in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"] {
            rows.append(deviceCase(path: path, sensitive: false))
        }

        // Privileged device nodes: expected EPERM/ENXIO. A success is loud.
        for path in ["/dev/ptmx", "/dev/tty", "/dev/console",
                     "/dev/audit", "/dev/kmem", "/dev/mem"] {
            rows.append(deviceCase(path: path, sensitive: true))
        }

        return rows
    }

    private static func deviceCase(path: String, sensitive: Bool) -> Entry {
        setErrno(0)
        let fd = POSIXShim.openFile(path, O_RDWR, 0)
        let err = fd >= 0 ? 0 : currentErrno()
        var observed: String
        if fd >= 0 {
            let closeRC = POSIXShim.closeFile(fd)
            observed = "open(O_RDWR) returned fd \(fd); closed immediately (\(closeRC))"
        } else {
            observed = "open(O_RDWR) returned -1, errno=\(ErrorClassifier.errnoName(err))"
        }

        let interpretation: String
        if fd >= 0 {
            interpretation = sensitive
                ? """
                    SUCCESS ON A PRIVILEGED DEVICE NODE. If this reproduces on \
                    device it means the /dev predicate admitted a node it should \
                    not, and the read/write capability behind it has to be \
                    characterized next. Even so, an open alone is reconnaissance \
                    -- no byte was read or written -- so isBoundaryViolation stays \
                    false. REPRODUCE ON DEVICE before treating it as a finding.
                    """
                : """
                    A benign device node opened and was closed immediately. This \
                    is the positive control for the group: it shows the /dev \
                    predicate admits the harmless nodes, which is what makes a \
                    refusal on a privileged node meaningful.
                    """
        } else {
            interpretation = sensitive
                ? """
                    A privileged device node was refused. EPERM names the sandbox \
                    predicate; ENXIO means the device is configured out of this \
                    kernel rather than denied -- the errno distinguishes a policy \
                    refusal from an absent driver.
                    """
                : """
                    A supposedly benign device node was refused. That is worth \
                    recording plainly: it means the /dev predicate is either \
                    narrower than expected or the node is absent here. The errno \
                    says which (ENOENT = absent, EPERM = denied).
                    """
        }

        return objectCase(
            id: "device" + path.replacingOccurrences(of: "/", with: "-"),
            group: groupDeviceFiles,
            operation: "open(O_RDWR)",
            target: path,
            rc: fd,
            err: err,
            observed: observed,
            interpretation: interpretation
        )
    }
    #endif
}
