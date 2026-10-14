//
//  CrossProcessProbe.swift
//  FSProbeCore — IPC and cross-process authorization research.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far tested what *this process* can do to *the filesystem*.
//  The sandbox was uniformly enforced for those and holds. That says nothing about
//  two other authorization paths, neither of which has been measured yet:
//
//  1. MACH-LOOKUP. Can a sandboxed app reach a named system service and ask it to
//     act on the app's behalf? That is the confused-deputy shape. The iOS SDK
//     marks `NSXPCConnection(machServiceName:)` and
//     `xpc_connection_create_mach_service` unavailable, which prevents *linking*
//     them — but unavailability in a header is not the same as absence from the
//     runtime. If the symbol exists in libxpc and the process resolves it at
//     runtime, the real gate becomes launchd's mach-lookup sandbox check, and
//     THAT is what must be measured rather than asserted.
//
//  2. PROCESS INTROSPECTION. Can an ordinary app learn about, or obtain a task
//     port for, another process? `proc_pidpath` on another process discloses its
//     executable path; `task_for_pid` on another process would be a genuine
//     process-isolation violation, since it grants control over that process's
//     address space.
//
//  Both hypotheses are falsifiable, both are reachable from an ordinary app
//  without entitlements, and a negative result eliminates each hypothesis with
//  evidence rather than assumption.
//
//  EXPECTED RESULT
//  ---------------
//  Symbol resolution succeeds (the functions exist in the runtime), and the
//  operating system refuses the operations: launchd denies the mach lookup for
//  services the app's sandbox profile does not permit, and the kernel denies
//  cross-process introspection. A permitted result on either is a finding.
//
//  REACHABILITY IS NOT A VULNERABILITY. A connection that opens, or a path string
//  that is returned, proves only that the operation succeeded. The finding would
//  be an *effect* the caller was not authorized to produce.
//
//  CONTROLS
//  --------
//  Introspection includes self-targeting controls: `proc_pidpath` on this process
//  must return this binary's own path, or the negative result on another process
//  is not interpretable. Without that control a blanket refusal could mean the
//  API does not work at all rather than that the policy denies it. The mach-lookup
//  section likewise begins with a service name that cannot exist, so the
//  platform's "not found" signature can be told apart from a real answer.
//
//  SAFETY
//  ------
//  Every connection is bounded by a timeout, so a silent service cannot hang the
//  harness, and is cancelled afterwards. Requests carry no secrets and name no
//  unrelated private data. Only process identifiers are touched, never another
//  process's memory or files.
//

import Foundation

public enum CrossProcessProbe {

    // MARK: - Mach service reachability

    public enum MachReachability: String, Codable, Sendable {
        /// The C function could not be resolved at runtime, so the experiment was
        /// never attempted. This is a statement about the platform, not a denial.
        case symbolUnresolved
        /// The connection was refused, with the platform's own reason.
        case refused
        /// Nothing arrived within the bounded timeout.
        case noResponse
        /// No interruption arrived within the timeout: the lookup was permitted.
        case reachable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct MachServiceProbe: Sendable, Identifiable, Codable {
        public let serviceName: String
        /// Why this service is a candidate, in one line.
        public let rationale: String
        /// True when the C connection function resolved in this process.
        public let symbolResolved: Bool
        public let reachability: MachReachability
        /// The platform's own refusal reason, when it gave one.
        public let refusalReason: String?
        /// Round-trip time in milliseconds, when an event arrived.
        public let responseMilliseconds: Int?

        public init(
            serviceName: String,
            rationale: String,
            symbolResolved: Bool,
            reachability: MachReachability,
            refusalReason: String?,
            responseMilliseconds: Int?
        ) {
            self.serviceName = serviceName
            self.rationale = rationale
            self.symbolResolved = symbolResolved
            self.reachability = reachability
            self.refusalReason = refusalReason
            self.responseMilliseconds = responseMilliseconds
        }

        public var id: String { serviceName }
    }

    /// Candidates, prioritised by the filesystem work each performs on a caller's
    /// behalf. The first entry is a deliberate negative control: a service name
    /// that cannot exist, so that the platform's "not found" signature can be
    /// distinguished from a real answer. Without it, every candidate producing
    /// that same signature would be uninterpretable.
    public static func machServiceCandidates() -> [(name: String, rationale: String)] {
        [
            ("com.bbaobaob.fsprobe.nonexistent.control",
             "NEGATIVE CONTROL: a name that cannot exist, to calibrate what the platform's refusal looks like"),
            ("com.apple.FileCoordination",
             "NSFileCoordinator's backend: arbitrates reads and writes of named URLs on the caller's behalf"),
            ("com.apple.cfprefsd.daemon",
             "Writes preference files into the caller's container: a deputy that performs file writes"),
            ("com.apple.containermanagerd",
             "Resolves and creates app containers by name: a deputy that resolves resource references"),
            ("com.apple.containermanagerd.system",
             "The system-scope container manager: resolves shared and system containers"),
            ("com.apple.coreservices.quarantine-resolver",
             "LaunchServices quarantine resolution, operates on downloaded file paths"),
            ("com.apple.mobile.installation_proxy",
             "Installs and removes apps and their containers"),
            ("com.apple.LaunchServices",
             "Application and document-type resolution from a sandboxed caller"),
        ]
    }

    #if canImport(Darwin)

    // The connection factory is owned by XPCShim. Binding it here as well would
    // make the compiler share one implementation across two different signatures
    // and fail the build -- the same mistake the Mach shim already fixed once.

    /// True when the connection factory resolves in this process. On iOS this is
    /// the interesting question: the SDK forbids linking it, but the code may
    /// still be present in libxpc.
    public static var machSymbolResolved: Bool { XPCShim.connectionFactoryAvailable }

    /// True when this platform can attempt the mach-lookup experiment at all.
    public static var machReachabilityAvailable: Bool { true }

    /// Probe one service's reachability from this process.
    ///
    /// - Parameter timeout: seconds to wait before declaring no response. Bounded
    ///   so a silent service cannot hang the harness.
    public static func probeMachService(
        _ name: String,
        rationale: String = "",
        timeout: TimeInterval = 3.0
    ) -> MachServiceProbe {
        let started = Date()

        guard XPCShim.connectionFactoryAvailable else {
            // The symbol is absent from this runtime, so nothing was attempted.
            return MachServiceProbe(
                serviceName: name, rationale: rationale,
                symbolResolved: false,
                reachability: .symbolUnresolved,
                refusalReason: "xpc_connection_create_mach_service is not present in this runtime",
                responseMilliseconds: nil
            )
        }

        let connection = XPCShim.createConnection(name)

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var reachability: MachReachability = .noResponse
        var refusalReason: String?

        // An interruption means launchd refused the lookup, or the service died.
        // Its description string is the platform's own explanation, which is far
        // more informative than the mere fact of refusal.
        XPCShim.setEventHandler(connection) { event in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(event) {
                reachability = .refused
                refusalReason = XPCShim.errorDescription(event)
            } else {
                reachability = .reachable
            }
            semaphore.signal()
        }
        XPCShim.resume(connection)

        let waited = semaphore.wait(timeout: .now() + timeout)
        let elapsed = Int(Date().timeIntervalSince(started) * 1000)

        lock.lock()
        let finalReachability: MachReachability
        if waited == .timedOut {
            // No interruption arrived: the lookup was permitted and the service
            // simply did not answer a connection carrying no protocol.
            finalReachability = .reachable
        } else {
            finalReachability = reachability
        }
        let finalReason = refusalReason
        lock.unlock()

        XPCShim.cancel(connection)

        return MachServiceProbe(
            serviceName: name, rationale: rationale,
            symbolResolved: true,
            reachability: finalReachability,
            refusalReason: finalReason,
            responseMilliseconds: finalReachability == .noResponse ? nil : elapsed
        )
    }

    /// The key under which XPC stores an error's human-readable description.
    ///
    /// The literal was confirmed empirically rather than guessed: rendering a
    /// refused connection with `xpc_copy_description` showed the error
    /// dictionary's key as "XPCErrorDescription". The macro is not referenced by
    /// name because it is a preprocessor definition rather than an exported
    /// symbol, and the surrounding connection API is SDK-unavailable.
    private static let xpcErrorDescriptionKey = "XPCErrorDescription"

    // The XPC error description is produced by XPCShim, which owns the binding.

    #else

    /// The connection factory is not present on this platform, so no service can
    /// be probed. The empty result is the honest one.
    public static var machReachabilityAvailable: Bool { false }
    public static var machSymbolResolved: Bool { false }

    public static func probeMachService(
        _ name: String,
        rationale: String = "",
        timeout: TimeInterval = 3.0
    ) -> MachServiceProbe {
        MachServiceProbe(
            serviceName: name, rationale: rationale,
            symbolResolved: false,
            reachability: .notAttempted,
            refusalReason: "libxpc is not present on this platform",
            responseMilliseconds: nil
        )
    }

    #endif

    /// Probe every candidate's reachability from this process.
    public static func probeMachServices(
        timeout: TimeInterval = 3.0
    ) -> [MachServiceProbe] {
        machServiceCandidates().map { candidate in
            probeMachService(candidate.name, rationale: candidate.rationale, timeout: timeout)
        }
    }

    // MARK: - Cross-process introspection

    public enum IntrospectionOutcome: String, Codable, Sendable {
        /// The call returned success.
        case succeeded
        /// The call was refused, with the error recorded.
        case denied
        /// The operation does not apply to this call (for example, a process that
        /// has no executable path).
        case notApplicable
        /// The prerequisite was missing, or the call was not made.
        case notAttempted
    }

    public struct IntrospectionAttempt: Sendable, Identifiable, Codable {
        /// The API exercised.
        public let operation: String
        /// The target process, named by role so no private identifier is needed
        /// to interpret the result.
        public let target: String
        /// True when this call is a control whose success the interpretation of
        /// the real result depends on.
        public let isControl: Bool
        public let outcome: IntrospectionOutcome
        /// The return value as the platform reported it.
        public let returnValue: String?
        /// The error name, when the platform gave one.
        public let errorName: String?
        /// What was observed: a path string, a count, or a port.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            operation: String,
            target: String,
            isControl: Bool,
            outcome: IntrospectionOutcome,
            returnValue: String?,
            errorName: String?,
            observed: String?,
            interpretation: String
        ) {
            self.operation = operation
            self.target = target
            self.isControl = isControl
            self.outcome = outcome
            self.returnValue = returnValue
            self.errorName = errorName
            self.observed = observed
            self.interpretation = interpretation
        }

        public var id: String { "\(operation)|\(target)" }
    }

    public struct IntrospectionReport: Sendable, Codable {
        public let attempts: [IntrospectionAttempt]
        /// True when the self-control succeeded, which is what makes a refusal on
        /// another process interpretable as a policy denial.
        public let controlSucceeded: Bool
        /// Attempts that would be boundary violations if they succeeded.
        public let violations: [IntrospectionAttempt]

        public init(
            attempts: [IntrospectionAttempt],
            controlSucceeded: Bool,
            violations: [IntrospectionAttempt]
        ) {
            self.attempts = attempts
            self.controlSucceeded = controlSucceeded
            self.violations = violations
        }
    }

    #if canImport(Darwin)

    // The Mach and libproc symbols are bound once, in MachShim. Binding them
    // here as well would make the compiler share one implementation across two
    // different signatures and fail the build.

    /// Test whether an ordinary app can observe or control another process.
    ///
    /// The self-targeting control comes first: `proc_pidpath(getpid())` must
    /// return this binary's own path. If that fails, every refusal below means
    /// only that the API is unusable here, and none of it is evidence about the
    /// sandbox.
    public static func probeProcessIntrospection() -> IntrospectionReport {
        var attempts: [IntrospectionAttempt] = []
        let selfPID = Int32(getpid())

        // Control: this process's own path. Must succeed, or nothing below is
        // interpretable.
        let selfPath = readPidPath(selfPID)
        let controlSucceeded: Bool
        switch selfPath.outcome {
        case .succeeded:
            controlSucceeded = true
            attempts.append(IntrospectionAttempt(
                operation: "proc_pidpath",
                target: "self (pid \(selfPID))",
                isControl: true,
                outcome: .succeeded,
                returnValue: "\(selfPath.length) bytes",
                errorName: nil,
                observed: selfPath.value,
                interpretation: """
                    The control succeeded: this process can read its own executable \
                    path. Refusals below are therefore interpretable as denials rather \
                    than as a broken API.
                    """
            ))
        case .denied:
            controlSucceeded = false
            attempts.append(IntrospectionAttempt(
                operation: "proc_pidpath",
                target: "self (pid \(selfPID))",
                isControl: true,
                outcome: .denied,
                returnValue: "\(selfPath.length) bytes",
                errorName: selfPath.errorName,
                observed: nil,
                interpretation: """
                    The control FAILED: this process cannot read even its own path, so \
                    every other result below is uninterpretable. The experiment must be \
                    reported as inconclusive, not as a denial.
                    """
            ))
        case .notApplicable, .notAttempted:
            controlSucceeded = false
            attempts.append(IntrospectionAttempt(
                operation: "proc_pidpath",
                target: "self (pid \(selfPID))",
                isControl: true,
                outcome: selfPath.outcome,
                returnValue: nil,
                errorName: selfPath.errorName,
                observed: nil,
                interpretation: "The control could not be run."
            ))
        }

        // launchd is pid 1 on iOS. Reading its path would disclose a protected
        // process's executable location.
        for pid in [Int32(1), Int32(0)] {
            let result = readPidPath(pid)
            let target = pid == 1 ? "launchd (pid 1)" : "kernel (pid 0)"
            attempts.append(IntrospectionAttempt(
                operation: "proc_pidpath",
                target: target,
                isControl: false,
                outcome: result.outcome,
                returnValue: "\(result.length) bytes",
                errorName: result.errorName,
                observed: result.value,
                interpretation: introspectionInterpretation(
                    outcome: result.outcome,
                    errorName: result.errorName
                )
            ))
        }

        // Task ports: obtaining one for another process would grant control over
        // that process's address space, a genuine isolation violation.
        for pid in [Int32(1), Int32(0)] {
            let target = pid == 1 ? "launchd (pid 1)" : "kernel (pid 0)"
            var taskPort: mach_port_t = 0
            let kr = MachShim.taskForPid(MachShim.taskSelf, pid, &taskPort)
            let outcome: IntrospectionOutcome = kr == 0 ? .succeeded : .denied
            attempts.append(IntrospectionAttempt(
                operation: "task_for_pid",
                target: target,
                isControl: false,
                outcome: outcome,
                returnValue: "kern_return_t \(kr)",
                errorName: outcome == .denied ? machErrorName(kr) : nil,
                observed: outcome == .succeeded ? "task port \(taskPort)" : nil,
                interpretation: outcome == .succeeded
                    ? """
                    A task port for another process was obtained. That grants control \
                    over its address space and would be a process-isolation violation.
                    """
                    : """
                    Refused. The kernel did not hand out a task port for another \
                    process, which is the expected boundary; task_for_pid normally \
                    requires the task_for_pid-allow entitlement.
                    """
            ))
        }

        // Enumeration: how much of the process table can an ordinary app see?
        let listed = countAllProcesses()
        attempts.append(IntrospectionAttempt(
            operation: "proc_listallpids",
            target: "all processes",
            isControl: false,
            outcome: listed.outcome,
            returnValue: listed.outcome == .succeeded ? "\(listed.count) pids" : nil,
            errorName: listed.errorName,
            observed: listed.outcome == .succeeded ? "\(listed.count) pids visible" : nil,
            interpretation: listed.outcome == .succeeded
                ? """
                \(listed.count) process identifiers are visible. Visibility of \
                identifiers alone is not a boundary violation; it becomes one only if \
                those identifiers yield something the policy withholds, which is what \
                the attempts above test.
                """
                : """
                The process table is not visible to this process, so the identifier \
                question is moot here.
                """
        ))

        // A violation is a non-control operation that succeeded where the policy
        // predicts refusal.
        let violations = attempts.filter {
            !$0.isControl && $0.outcome == .succeeded
                && ($0.operation == "task_for_pid" || $0.operation == "proc_pidpath")
        }

        return IntrospectionReport(
            attempts: attempts,
            controlSucceeded: controlSucceeded,
            violations: violations
        )
    }

    private static func machErrorName(_ kr: kern_return_t) -> String {
        MachShim.machErrorString(Int32(kr))
    }

    /// Interpretation of a `proc_pidpath` result on a process other than the
    /// caller.
    ///
    /// The three non-success cases mean different things and must not be
    /// collapsed. A denial is a policy result. `ESRCH` means the process does
    /// not exist, which is not a security event at all and would be
    /// misrepresented if reported as a refusal.
    private static func introspectionInterpretation(
        outcome: IntrospectionOutcome,
        errorName: String?
    ) -> String {
        switch outcome {
        case .succeeded:
            return """
                The executable path of a protected process was disclosed to an \
                ordinary app. That is an information disclosure beyond the \
                caller's own process.
                """
        case .denied:
            return """
                Refused\(errorName.map { " (\($0))" } ?? ""). The path of a process \
                other than the caller is not disclosed, which is the expected boundary.
                """
        case .notApplicable:
            // Reached only when errno is clear, so no denial is implied and no
            // error name is available to quote.
            return """
                No path was returned and no error was reported, so this is not a \
                denial and not a security observation.
                """
        case .notAttempted:
            return "The call was not attempted, so nothing is claimed about the boundary."
        }
    }

    private struct PidPathResult {
        let outcome: IntrospectionOutcome
        let value: String?
        let length: Int
        let errorName: String?
    }

    /// PROC_PIDPATHINFO_SIZE is 4 * MAXPATHLEN; a fixed, generous buffer.
    private static let pidPathBufferSize = 1024

    private static func readPidPath(_ pid: Int32) -> PidPathResult {
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: pidPathBufferSize, alignment: 1
        )
        defer { buffer.deallocate() }

        // Clear errno first. Without this the value read after the call may be
        // stale from the previous attempt, which would make the reported error an
        // artifact of loop order rather than a measurement. This bit the
        // introspection experiment directly: pid 0 reported EPERM only because
        // pid 1 had just set it, so the "kernel has no executable path"
        // interpretation was derived from an inherited errno.
        setErrno(0)
        let rc = MachShim.procPidPath(pid, buffer, UInt32(pidPathBufferSize))
        if rc > 0 {
            let path = String(cString: buffer.assumingMemoryBound(to: CChar.self))
            return PidPathResult(
                outcome: .succeeded, value: path, length: Int(rc), errorName: nil
            )
        }

        // proc_pidpath returns 0 on failure and sets errno. A zero return with
        // errno set is a refusal: EPERM here is the sandbox signature, the same
        // one every other denied operation on this device produced. Only a zero
        // return with errno clear means "this process has no executable path",
        // which is not a security event.
        let err = currentErrno()
        if err != 0 {
            return PidPathResult(
                outcome: .denied, value: nil, length: 0,
                errorName: ErrorClassifier.errnoName(err)
            )
        }
        return PidPathResult(
            outcome: .notApplicable, value: nil, length: 0, errorName: nil
        )
    }

    private struct PidListResult {
        let outcome: IntrospectionOutcome
        let count: Int
        let errorName: String?
    }

    private static func countAllProcesses() -> PidListResult {
        // First call sizes the buffer, second fills it.
        let needed = MachShim.procListAllPids(nil, 0)
        guard needed > 0 else {
            let err = currentErrno()
            return PidListResult(
                outcome: .denied, count: 0,
                errorName: err == 0 ? nil : ErrorClassifier.errnoName(err)
            )
        }
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: Int(needed), alignment: MemoryLayout<Int32>.alignment
        )
        defer { buffer.deallocate() }
        let filled = MachShim.procListAllPids(buffer, needed)
        guard filled > 0 else {
            let err = currentErrno()
            return PidListResult(
                outcome: .denied, count: 0,
                errorName: err == 0 ? nil : ErrorClassifier.errnoName(err)
            )
        }
        return PidListResult(outcome: .succeeded, count: Int(filled), errorName: nil)
    }

    #else

    /// Process introspection is unavailable on this platform, so nothing is
    /// attempted and no result is fabricated.
    public static func probeProcessIntrospection() -> IntrospectionReport {
        IntrospectionReport(attempts: [], controlSucceeded: false, violations: [])
    }

    #endif
}
