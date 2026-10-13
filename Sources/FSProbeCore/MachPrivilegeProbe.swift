//
//  MachPrivilegeProbe.swift
//  FSProbeCore — the Mach privilege primitives, none of which have been tried.
//
//  HYPOTHESIS
//  ----------
//  The cross-process experiment established that `task_for_pid` is refused and
//  `proc_pidpath` does not disclose another process. That closes one question and
//  leaves a much larger one untouched: the Mach privilege primitives.
//
//  Mach has a ladder of increasingly powerful ports, and an ordinary app sits at
//  the bottom of it. Each rung is a separate authorization:
//
//    task_get_special_port(TASK_HOST_PORT)     a host port
//    host_get_special_port(...)                a named system port
//    processor_set_tasks(...)                  every task on a processor
//    task_threads(other_task)                  another task's threads
//    mach_vm_read(other_task)                  another task's memory
//
//  `mach_host_self()` was tested and returned nothing. But `mach_host_self()` is
//  a convenience wrapper; `task_get_special_port` asks the kernel for the same
//  thing through a different call with a different check, and it has never been
//  tried.
//
//  `processor_set_tasks` is the one that matters most. It takes a processor-set
//  port and returns the list of every task in it. If an ordinary app can reach
//  it, the app can enumerate — and potentially control — every process on the
//  device, which is the strongest possible process-isolation violation.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether any rung of the Mach privilege ladder is reachable without the
//  entitlements that normally gate it.
//
//  CONTROL
//  -------
//  Every call runs first against this app's own task, where it must succeed. A
//  self-targeting `task_threads` or `task_info` is legitimate and proves the API
//  works; without that control a refusal elsewhere is uninterpretable.
//
//  SAFETY
//  ------
//  Nothing is done with any port obtained. Ports are released immediately. No
//  memory is read, no thread is resumed or suspended, no task is manipulated.
//  The experiment is about whether the port is obtainable, not about using it.
//

import Foundation

public enum MachPrivilegeProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call succeeded where denial was predicted.
        case permitted
        /// The call was refused.
        case denied
        /// A prerequisite port could not be obtained.
        case prerequisiteFailed
        /// The control did not produce the expected answer.
        case controlFailed
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Rung: Sendable, Identifiable, Codable {
        public let id: String
        /// The rung of the ladder, and what it would grant.
        public let mechanism: String
        /// The Mach call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
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
            arguments: String,
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
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.returnValue = returnValue
            self.errorName = errorName
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let rungs: [Rung]
        public let violations: [Rung]

        public init(rungs: [Rung], violations: [Rung]) {
            self.rungs = rungs
            self.violations = violations
        }
    }

    /// `task_special_port_t` values from <mach/task.h>. Spelled out rather than
    /// taken from the header so this compiles where the header is not imported.
    private static let taskHostPort: Int32 = 3
    private static let taskBootstrapPort: Int32 = 4

    public static func probe() -> Result {
        var rungs: [Rung] = []

        rungs.append(hostPortRung())
        rungs.append(threadsRung())
        rungs.append(taskInfoRung())

        let violations = rungs.filter { $0.isBoundaryViolation }
        return Result(rungs: rungs, violations: violations)
    }

    // MARK: - Rungs

    private static func hostPortRung() -> Rung {
        let id = "task_get_special_port-host"

        guard MachShim.available else {
            return unavailable(id, "task_get_special_port(task, TASK_HOST_PORT, &port)")
        }

        // Control: the bootstrap port, which an app legitimately holds. If this
        // fails, the API is not working and nothing below is interpretable.
        var controlPort: MachPort = 0
        let controlKR = MachShim.taskGetSpecialPort(
            MachShim.taskSelf, taskBootstrapPort, &controlPort
        )

        var port: MachPort = 0
        let kr = MachShim.taskGetSpecialPort(
            MachShim.taskSelf, taskHostPort, &port
        )
        let permitted = kr == 0 && port != 0
        if permitted {
            _ = MachShim.deallocatePort(MachShim.taskSelf, port)
        }

        let base = Rung(
            id: id,
            mechanism: """
                A host port is the strongest Mach primitive an app can hold: with \
                one, host-level services and, on platforms that allow it, other \
                tasks become reachable. mach_host_self() was already tested and \
                returned nothing; this asks the kernel for the same thing through a \
                different call with a different check.
                """,
            operation: "task_get_special_port(task, TASK_HOST_PORT, &port)",
            arguments: "self",
            expected: "No host port. An ordinary app must not hold one.",
            expectedDenied: true,
            outcome: permitted ? .permitted : .denied,
            returnValue: "kern_return_t \(kr)",
            errorName: permitted ? nil : MachShim.machErrorString(kr),
            observed: permitted ? "a host port was returned" : "no host port",
            interpretation: permitted
                ? """
                A host port was obtained. That is the strongest Mach primitive and \
                warrants immediate follow-up: host_get_special_port and \
                processor_set_tasks become reachable questions with one.
                """
                : """
                No host port. The rung holds, consistent with mach_host_self().
                """
        )

        guard controlKR == 0 && controlPort != 0 else {
            return Rung(
                id: id, mechanism: base.mechanism, operation: base.operation,
                arguments: base.arguments, expected: base.expected,
                expectedDenied: true, outcome: .controlFailed,
                returnValue: base.returnValue, errorName: base.errorName,
                observed: """
                    the control (TASK_BOOTSTRAP_PORT, which an app legitimately \
                    holds) itself failed
                    """,
                interpretation: """
                    The control failed, so the API is not producing meaningful \
                    answers here and the host-port result is uninterpretable. \
                    Nothing is claimed.
                    """
            )
        }
        return base
    }

    private static func threadsRung() -> Rung {
        let id = "task_threads-self"
        guard MachShim.available else {
            return unavailable(id, "task_threads(task, &list, &count)")
        }

        var list: MachPort = 0
        var count: Int32 = 0
        let kr = MachShim.taskThreads(MachShim.taskSelf, &list, &count)
        let permitted = kr == 0 && count > 0

        // This is the CONTROL, not a test: an app may legitimately enumerate its
        // own threads. It is reported as permitted with expectedDenied false, so
        // it proves the API works without being claimed as a finding.
        return Rung(
            id: id,
            mechanism: """
                CONTROL: enumerating this app's own threads. An app may legitimately \
                do this, so success proves the API works. The real question is \
                whether the same call on ANOTHER task is refused, which task_for_pid \
                already showed it is -- this rung establishes that the refusal is a \
                policy denial rather than a broken API.
                """,
            operation: "task_threads(task, &list, &count)",
            arguments: "self",
            expected: "Succeeds. An app may enumerate its own threads.",
            expectedDenied: false,
            outcome: permitted ? .permitted : .denied,
            returnValue: "kern_return_t \(kr)",
            errorName: permitted ? nil : MachShim.machErrorString(kr),
            observed: permitted ? "\(count) threads" : "no threads",
            interpretation: permitted
                ? """
                The API works: this app can enumerate its own threads. That makes \
                the task_for_pid refusal on other processes a policy denial rather \
                than a broken call, which is what the process-isolation result \
                depends on.
                """
                : """
                Even self-enumeration failed, so task_threads is not usable here and \
                nothing can be concluded about other tasks from it.
                """
        )
    }

    private static func taskInfoRung() -> Rung {
        let id = "task_info-self"
        guard MachShim.available else {
            return unavailable(id, "task_info(task, flavor, &info, &count)")
        }

        // TASK_DYLD_INFO = 17. A harmless, self-only flavor.
        var info = [UInt64](repeating: 0, count: 16)
        var count = UInt32(info.count)
        let kr = MachShim.taskInfo(
            MachShim.taskSelf, 17, &info, &count
        )
        let permitted = kr == 0

        return Rung(
            id: id,
            mechanism: """
                CONTROL: reading this app's own task info. Self-only and harmless. \
                Establishes that the Mach task-info path works here at all.
                """,
            operation: "task_info(task, TASK_DYLD_INFO, &info, &count)",
            arguments: "self",
            expected: "Succeeds. An app may read its own task info.",
            expectedDenied: false,
            outcome: permitted ? .permitted : .denied,
            returnValue: "kern_return_t \(kr)",
            errorName: permitted ? nil : MachShim.machErrorString(kr),
            observed: permitted ? "\(count) words" : "no info",
            interpretation: permitted
                ? """
                The API works on this app's own task.
                """
                : """
                task_info is not usable here even on self, so no conclusion can be \
                drawn from any task-info result.
                """
        )
    }

    // MARK: - Helpers

    private static func unavailable(_ id: String, _ operation: String) -> Rung {
        Rung(
            id: id,
            mechanism: """
                A rung of the Mach privilege ladder. The symbol is not present on \
                this platform, so the rung was never attempted.
                """,
            operation: operation,
            arguments: "",
            expected: "Denied. An ordinary app must not reach this rung.",
            expectedDenied: true,
            outcome: .symbolUnavailable,
            returnValue: nil, errorName: nil,
            observed: nil,
            interpretation: """
                The symbol could not be resolved, so no measurement was made. This \
                is a statement about the platform, not a denial.
                """
        )
    }
}
