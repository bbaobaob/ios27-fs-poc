//
//  HostPortProbe.swift
//  FSProbeCore — is the host port actually usable, or merely obtainable?
//
//  WHY THIS EXISTS
//  ---------------
//  The Mach privilege probe found that `task_get_special_port(TASK_HOST_PORT)`
//  returns a host port on the simulator. Reported as a boundary violation.
//
//  That result is not yet a finding, and the reason is worth stating precisely:
//  obtaining a port and being able to USE it are different questions. On macOS --
//  which is what the simulator runs on -- a host port is easier to obtain than on
//  iOS, and an obtainable-but-impotent port would be an artifact of the platform
//  rather than a violation of the boundary under study.
//
//  This module asks the question that decides it. With a host port in hand, the
//  next rungs of the ladder become reachable in principle:
//
//    host_get_special_port(host, flavor, &port)   a named system port
//    host_processor_set_priv(host, &pset)         the privileged processor set
//    processor_set_tasks(pset, &tasks, &count)    every task on the device
//    host_statistics(host, ...)                   host-wide statistics
//
//  If the host port is genuinely usable, at least one of these succeeds. If every
//  one is refused with KERN_INVALID_ARGUMENT or a similar "port not what you think
//  it is" error, the port was a token that grants nothing, and the earlier
//  violation was an artifact.
//
//  THE DISCRIMINATOR
//  -----------------
//  The error matters more than the outcome. A refusal with a *policy* error
//  (KERN_PROTECTION_FAILURE, EPERM) means the port is real and the kernel is
//  enforcing a rule. A refusal with a *validity* error (KERN_INVALID_ARGUMENT,
//  KERN_INVALID_HOST) means the port is not a usable host port at all.
//
//  A real port that is denied by policy is the interesting result: it means the
//  app holds a genuine host port and the remaining gate is a check, not a
//  formality. A token that grants nothing closes the question.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether the host port an ordinary app can obtain is a real one.
//
//  SAFETY
//  ------
//  Read-only. `processor_set_tasks` returns a list of ports, which are released
//  immediately without being used. No task is inspected, resumed, or suspended.
//  No memory is read. The experiment is about what the port grants, not about
//  exercising any of it.
//

import Foundation

public enum HostPortProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call succeeded.
        case permitted
        /// The call was refused with a policy error.
        case deniedByPolicy
        /// The call was refused with a validity error, meaning the port is not
        /// usable as the kind of thing it claims to be.
        case deniedByValidity
        /// No host port was available to try with.
        case noHostPort
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Rung: Sendable, Identifiable, Codable {
        public let id: String
        /// What this rung would grant, if it worked.
        public let mechanism: String
        /// The Mach call exercised.
        public let operation: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The kern_return_t, as the platform reported it.
        public let returnValue: String?
        /// The platform's own name for the error.
        public let errorName: String?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            returnValue: String?,
            errorName: String?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = ""
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.returnValue = returnValue
            self.errorName = errorName
            self.observed = observed
            self.interpretation = interpretation
        }

        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String

        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let hostPortObtained: Bool
        public let rungs: [Rung]
        public let violations: [Rung]
        /// True when the host port was obtained but every use of it was refused
        /// with a validity error, which means it is a token that grants nothing.
        public let hostPortIsImpotent: Bool

        public init(
            hostPortObtained: Bool,
            rungs: [Rung],
            violations: [Rung],
            hostPortIsImpotent: Bool
        ) {
            self.hostPortObtained = hostPortObtained
            self.rungs = rungs
            self.violations = violations
            self.hostPortIsImpotent = hostPortIsImpotent
        }
    }

    public static func probe() -> Result {
        guard MachShim.available else {
            return Result(
                hostPortObtained: false,
                rungs: [unavailable()],
                violations: [],
                hostPortIsImpotent: false
            )
        }

        var hostPort: MachPort = 0
        let kr = MachShim.taskGetSpecialPort(
            MachShim.taskSelf, taskHostPort, &hostPort
        )
        guard kr == 0, hostPort != 0 else {
            return Result(
                hostPortObtained: false,
                rungs: [Rung(
                    id: "host-port-obtain",
                    mechanism: """
                        The prerequisite for every rung below: a host port.
                        """,
                    operation: "task_get_special_port(task, TASK_HOST_PORT, &port)",
                    expected: "No host port, or a port that grants nothing.",
                    expectedDenied: true,
                    outcome: .noHostPort,
                    returnValue: "kern_return_t \(kr)",
                    errorName: MachShim.machErrorString(kr),
                    observed: "no host port was returned",
                    interpretation: """
                        No host port was obtained, so none of the rungs below could \
                        be attempted. This is the expected result on a platform \
                        where the boundary holds.
                        """
                )],
                violations: [],
                hostPortIsImpotent: false
            )
        }
        defer { _ = MachShim.deallocatePort(MachShim.taskSelf, hostPort) }

        var rungs: [Rung] = []

        // A named system port. If the host port is real, this is reachable in
        // principle; a policy refusal means the port is real and a check stands
        // in the way.
        rungs.append(namedPortRung(hostPort))
        // The privileged processor set, the gateway to processor_set_tasks.
        rungs.append(processorSetRung(hostPort))
        // Host-wide statistics, the simplest possible use of a host port.
        rungs.append(hostStatisticsRung(hostPort))

        let violations = rungs.filter { $0.isBoundaryViolation }

        // Impotence: every rung refused with a VALIDITY error rather than a
        // policy one. That is the signature of a token that is not actually a
        // usable host port.
        let attempted = rungs.filter { $0.outcome != .notAttempted }
        let impotent = !attempted.isEmpty
            && attempted.allSatisfy { $0.outcome == .deniedByValidity }

        return Result(
            hostPortObtained: true,
            rungs: rungs,
            violations: violations,
            hostPortIsImpotent: impotent
        )
    }

    /// `task_special_port_t` from <mach/task.h>.
    private static let taskHostPort: Int32 = 3

    // MARK: - Rungs

    private static func namedPortRung(_ hostPort: MachPort) -> Rung {
        let id = "host-get-special-port"
        let operation = "host_get_special_port(host, HOST_PORT, &port)"
        let mechanism = """
            A named system port obtained THROUGH the host port. If the host port \
            is genuine, this is the first thing it can be used for.
            """

        var port: MachPort = 0
        let kr = MachShim.hostGetSpecialPort(hostPort, 1, &port)
        if kr == 0 && port != 0 {
            _ = MachShim.deallocatePort(MachShim.taskSelf, port)
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: """
                    Denied by policy, or refused with a validity error meaning the \
                    host port is not usable.
                    """,
                expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                observed: "a named system port was returned",
                interpretation: """
                    A named system port was obtained through the host port. The host \
                    port is genuine and usable, which makes its obtainability a real \
                    finding rather than an artifact.
                    """
            )
        }

        return classifyRefusal(
            id: id, mechanism: mechanism, operation: operation, kr: kr,
            expected: """
                Denied by policy, or refused with a validity error meaning the host \
                port is not usable.
                """,
            policyMeaning: """
                Refused by policy. The host port is real -- the kernel recognized it \
                and applied a rule to it. That makes its obtainability significant: \
                the app holds a genuine host port, and the remaining gate is a \
                check rather than a formality.
                """,
            validityMeaning: """
                Refused with a validity error. The kernel did not recognize the port \
                as a host port at all, which means the port obtained earlier is a \
                token that grants nothing.
                """
        )
    }

    private static func processorSetRung(_ hostPort: MachPort) -> Rung {
        let id = "host-processor-set-priv"
        let operation = "host_processor_set_priv(host, &pset)"
        let mechanism = """
            The privileged processor set, which is the gateway to \
            processor_set_tasks -- the call that would list every task on the \
            device. This is the strongest thing a host port could lead to.
            """

        var pset: MachPort = 0
        let kr = MachShim.hostProcessorSetPriv(hostPort, &pset)
        if kr == 0 && pset != 0 {
            _ = MachShim.deallocatePort(MachShim.taskSelf, pset)
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: """
                    Denied by policy, or refused with a validity error meaning the \
                    host port is not usable.
                    """,
                expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                observed: "the privileged processor set was returned",
                interpretation: """
                    The privileged processor set was obtained. From here, \
                    processor_set_tasks would enumerate every task on the device, \
                    which is the strongest possible process-isolation violation. \
                    This is the finding.
                    """
            )
        }

        return classifyRefusal(
            id: id, mechanism: mechanism, operation: operation, kr: kr,
            expected: """
                Denied by policy, or refused with a validity error meaning the host \
                port is not usable.
                """,
            policyMeaning: """
                Refused by policy. The host port is real and the kernel is \
                enforcing a rule on it.
                """,
            validityMeaning: """
                Refused with a validity error. The host port is not a usable host \
                port, so it grants nothing.
                """
        )
    }

    private static func hostStatisticsRung(_ hostPort: MachPort) -> Rung {
        let id = "host-statistics"
        let operation = "host_statistics(host, HOST_LOAD_INFO, &stats, &count)"
        let mechanism = """
            Host-wide statistics -- the simplest possible use of a host port, and \
            the least likely to be gated by anything other than the port's own \
            validity.
            """

        var stats = [UInt32](repeating: 0, count: 8)
        var count = UInt32(stats.count)
        let kr = MachShim.hostStatistics(hostPort, 1, &stats, &count)
        if kr == 0 {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: """
                    Denied by policy, or refused with a validity error meaning the \
                    host port is not usable.
                    """,
                expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                observed: "\(count) words of host statistics",
                interpretation: """
                    Host-wide statistics were read through the host port. That is a \
                    genuine use of a genuine host port, which makes its \
                    obtainability a real finding.
                    """
            )
        }

        return classifyRefusal(
            id: id, mechanism: mechanism, operation: operation, kr: kr,
            expected: """
                Denied by policy, or refused with a validity error meaning the host \
                port is not usable.
                """,
            policyMeaning: """
                Refused by policy. The host port is real and the kernel is \
                enforcing a rule on it.
                """,
            validityMeaning: """
                Refused with a validity error. The host port is not usable, so it \
                grants nothing.
                """
        )
    }

    // MARK: - Classification

    /// Turn a kern_return_t into the outcome that matters.
    ///
    /// The distinction between a policy error and a validity error is the whole
    /// point of this module: a policy error means the port is real and a rule
    /// stands in the way, while a validity error means the port is not what it
    /// claims to be.
    private static func classifyRefusal(
        id: String,
        mechanism: String,
        operation: String,
        kr: Int32,
        expected: String,
        policyMeaning: String,
        validityMeaning: String
    ) -> Rung {
        // KERN_INVALID_ARGUMENT = 4, KERN_INVALID_HOST = 12,
        // KERN_INVALID_OBJECT = 16, KERN_INVALID_RIGHT = 17.
        let validityErrors: Set<Int32> = [4, 12, 16, 17]
        let outcome: Outcome = validityErrors.contains(kr) ? .deniedByValidity : .deniedByPolicy

        return Rung(
            id: id, mechanism: mechanism, operation: operation,
            expected: expected,
            expectedDenied: true,
            outcome: outcome,
            returnValue: "kern_return_t \(kr)",
            errorName: MachShim.machErrorString(kr),
            observed: "refused with \(MachShim.machErrorString(kr))",
            interpretation: outcome == .deniedByValidity ? validityMeaning : policyMeaning
        )
    }

    private static func unavailable() -> Rung {
        Rung(
            id: "host-port-obtain",
            mechanism: """
                The prerequisite for every rung: a host port. The Mach API is not \
                present on this platform, so nothing was attempted.
                """,
            operation: "task_get_special_port(task, TASK_HOST_PORT, &port)",
            expected: "No host port, or a port that grants nothing.",
            expectedDenied: true,
            outcome: .symbolUnavailable,
            returnValue: nil, errorName: nil,
            observed: nil,
            interpretation: """
                NOT ATTEMPTED: the Mach API is not present on this platform.
                """
        )
    }
}
