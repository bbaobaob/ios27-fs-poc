//
//  ProcessorSetProbe.swift
//  FSProbeCore — the call that would list every task on the device.
//
//  HYPOTHESIS
//  ----------
//  The host-port module established whether an obtainable host port is real. If
//  it is, the next question has one answer worth chasing above all others:
//  `processor_set_tasks`.
//
//  It takes a processor-set port and returns the list of every task in it. A
//  processor set is a system-wide object, so on a successful call an ordinary app
//  would hold the task ports of every process on the device -- which is the
//  strongest possible process-isolation violation, and the foundation for
//  reading or controlling any of them.
//
//  This is the top of the ladder the Mach privilege module began climbing. The
//  rungs below it are already measured; this is the one that matters.
//
//  There are two ways in, and both are tested:
//
//    processor_set_default          the default processor set, no privilege
//    host_processor_set_priv        the privileged set, via a host port
//
//  The default set needs no host port and is the more interesting of the two,
//  because if an ordinary app can enumerate tasks through it, the boundary is
//  already gone and no host port is required at all.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether an ordinary app can enumerate the tasks of the whole device.
//
//  CONTROL
//  -------
//  `mach_task_self_` is enumerated through `task_threads`, which the Mach
//  privilege module already established works. That proves the enumeration API
//  functions; without it a refusal is uninterpretable.
//
//  SAFETY
//  ------
//  Nothing is done with any task port obtained. The returned array is released
//  immediately. No task is inspected, suspended, resumed, or read. The experiment
//  is about whether the list is obtainable, not about using any entry in it.
//

import Foundation

public enum ProcessorSetProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call succeeded and returned tasks.
        case permitted
        /// The call succeeded but returned no tasks.
        case empty
        /// The call was refused with a policy error.
        case deniedByPolicy
        /// The call was refused with a validity error.
        case deniedByValidity
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
        /// How many task ports were returned, when any were.
        public let taskCount: Int?
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
            taskCount: Int?,
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
            self.taskCount = taskCount
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
        public let rungs: [Rung]
        public let violations: [Rung]

        public init(rungs: [Rung], violations: [Rung]) {
            self.rungs = rungs
            self.violations = violations
        }
    }

    public static func probe() -> Result {
        guard MachShim.available else {
            return Result(rungs: [unavailable()], violations: [])
        }

        // Control first: enumerate this app's own threads. That the API works at
        // all is what makes a refusal elsewhere interpretable.
        var controlList: MachPort = 0
        var controlCount: Int32 = 0
        let controlKR = MachShim.taskThreads(MachShim.taskSelf, &controlList, &controlCount)
        let controlOK = controlKR == 0 && controlCount > 0
        if controlOK {
            // The thread list is an array of ports this app owns; release them.
            releasePortArray(controlList, count: Int(controlCount))
        }

        guard controlOK else {
            return Result(
                rungs: [Rung(
                    id: "task-threads-self",
                    mechanism: """
                        CONTROL: enumerating this app's own threads. Proves the \
                        enumeration API functions here at all.
                        """,
                    operation: "task_threads(task, &list, &count)",
                    expected: "Succeeds. An app may enumerate its own threads.",
                    expectedDenied: false,
                    outcome: .controlFailed,
                    returnValue: "kern_return_t \(controlKR)",
                    errorName: MachShim.machErrorString(controlKR),
                    taskCount: nil,
                    observed: "even self-enumeration failed",
                    interpretation: """
                        The control failed, so a refusal on any processor-set rung \
                        below is uninterpretable: it could mean the policy denies \
                        it, or that task enumeration does not work on this platform. \
                        Nothing is claimed.
                        """
                )],
                violations: []
            )
        }

        var rungs: [Rung] = []

        // The control, reported so the record shows it succeeded.
        rungs.append(Rung(
            id: "task-threads-self",
            mechanism: """
                CONTROL: enumerating this app's own threads. Proves the enumeration \
                API functions here, which is what makes a processor-set refusal \
                below a policy denial rather than a broken call.
                """,
            operation: "task_threads(task, &list, &count)",
            expected: "Succeeds. An app may enumerate its own threads.",
            expectedDenied: false,
            outcome: .permitted,
            returnValue: "kern_return_t 0", errorName: nil,
            taskCount: Int(controlCount),
            observed: "\(controlCount) threads",
            interpretation: """
                The API works on this app's own task. A processor-set refusal below \
                is therefore a policy denial.
                """
        ))

        // Rung one: the default processor set, which needs no host port at all.
        rungs.append(defaultProcessorSetRung())
        // Rung two: the privileged set, reached through a host port.
        rungs.append(privilegedProcessorSetRung())

        let violations = rungs.filter { $0.isBoundaryViolation }
        return Result(rungs: rungs, violations: violations)
    }

    // MARK: - Rungs

    private static func defaultProcessorSetRung() -> Rung {
        let id = "processor-set-tasks-default"
        let operation = "processor_set_tasks(processor_set_default(), &tasks, &count)"
        let mechanism = """
            Every task in the DEFAULT processor set. This rung needs no host port \
            and no privilege, which makes it the more interesting of the two: if an \
            ordinary app can enumerate tasks through it, the process-isolation \
            boundary is already gone.
            """

        var pset: MachPort = 0
        let psetKR = MachShim.processorSetDefault(&pset)
        guard psetKR == 0, pset != 0 else {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: "Denied. An ordinary app must not enumerate device tasks.",
                expectedDenied: true,
                outcome: .prerequisiteFailed,
                returnValue: "kern_return_t \(psetKR)",
                errorName: MachShim.machErrorString(psetKR),
                taskCount: nil,
                observed: "the default processor set could not be obtained",
                interpretation: """
                    NOT ATTEMPTED: the default processor set itself was unavailable, \
                    so the task list could not be requested.
                    """
            )
        }

        var tasks: MachPort = 0
        var count: Int32 = 0
        let kr = MachShim.processorSetTasks(pset, &tasks, &count)
        let permitted = kr == 0 && count > 0

        if permitted {
            releasePortArray(tasks, count: Int(count))
        }

        return classify(
            id: id, mechanism: mechanism, operation: operation, kr: kr,
            count: permitted ? Int(count) : nil,
            expected: "Denied. An ordinary app must not enumerate device tasks.",
            permittedMeaning: """
                Every task on the device was enumerated through the DEFAULT \
                processor set, with no host port and no privilege. That is the \
                strongest possible process-isolation violation, and the task ports \
                are the foundation for reading or controlling any of them.
                """,
            policyMeaning: """
                Refused by policy. Device-wide task enumeration is confined.
                """,
            validityMeaning: """
                Refused with a validity error, so the processor-set port was not \
                usable as one.
                """
        )
    }

    private static func privilegedProcessorSetRung() -> Rung {
        let id = "processor-set-tasks-privileged"
        let operation = "processor_set_tasks(host_processor_set_priv(host), &tasks, &count)"
        let mechanism = """
            Every task in the PRIVILEGED processor set, reached through a host \
            port. The gateway to this is whether the host port is usable, which \
            the host-port module measures.
            """

        var hostPort: MachPort = 0
        let hostKR = MachShim.taskGetSpecialPort(
            MachShim.taskSelf, taskHostPort, &hostPort
        )
        guard hostKR == 0, hostPort != 0 else {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: "Denied. An ordinary app must not enumerate device tasks.",
                expectedDenied: true,
                outcome: .prerequisiteFailed,
                returnValue: "kern_return_t \(hostKR)",
                errorName: MachShim.machErrorString(hostKR),
                taskCount: nil,
                observed: "no host port was available to reach the privileged set",
                interpretation: """
                    NOT ATTEMPTED: no host port was obtained, so the privileged \
                    processor set was unreachable and its task list could not be \
                    requested.
                    """
            )
        }
        defer { _ = MachShim.deallocatePort(MachShim.taskSelf, hostPort) }

        var pset: MachPort = 0
        let psetKR = MachShim.hostProcessorSetPriv(hostPort, &pset)
        guard psetKR == 0, pset != 0 else {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: "Denied. An ordinary app must not enumerate device tasks.",
                expectedDenied: true,
                outcome: .prerequisiteFailed,
                returnValue: "kern_return_t \(psetKR)",
                errorName: MachShim.machErrorString(psetKR),
                taskCount: nil,
                observed: "the privileged processor set could not be obtained",
                interpretation: """
                    NOT ATTEMPTED: the privileged processor set was unavailable, so \
                    its task list could not be requested. Whether the host port is \
                    real is measured by the host-port module.
                    """
            )
        }
        defer { _ = MachShim.deallocatePort(MachShim.taskSelf, pset) }

        var tasks: MachPort = 0
        var count: Int32 = 0
        let kr = MachShim.processorSetTasks(pset, &tasks, &count)
        let permitted = kr == 0 && count > 0

        if permitted {
            releasePortArray(tasks, count: Int(count))
        }

        return classify(
            id: id, mechanism: mechanism, operation: operation, kr: kr,
            count: permitted ? Int(count) : nil,
            expected: "Denied. An ordinary app must not enumerate device tasks.",
            permittedMeaning: """
                Every task on the device was enumerated through the PRIVILEGED \
                processor set, reached through a host port. That is the strongest \
                possible process-isolation violation.
                """,
            policyMeaning: """
                Refused by policy. Device-wide task enumeration is confined.
                """,
            validityMeaning: """
                Refused with a validity error, so the processor-set port was not \
                usable as one.
                """
        )
    }

    // MARK: - Helpers

    private static let taskHostPort: Int32 = 3

    // NOTE, and this cost a crash to learn: the arrays returned by task_threads and
    // processor_set_tasks are NOT plain arrays of send rights that can be released
    // one element at a time with mach_port_deallocate. They are vm-allocated
    // buffers of port NAMES, and the correct way to release them is
    // vm_deallocate on the buffer itself.
    //
    // The previous version of this function walked the buffer calling
    // mach_port_deallocate on each element. On macOS task_threads succeeds (it
    // returned seven threads), so the walk ran over a buffer whose contents are
    // not individually owned rights, and the macOS test runner died with SIGSEGV
    // in ProcessorSetProbeTests.
    //
    // The buffer is now released as a buffer, once, with vm_deallocate. No
    // element is touched, which also means nothing obtained is used.
    private static func releasePortArray(_ array: MachPort, count: Int) {
        guard count > 0, array != 0 else { return }
        _ = MachShim.vmDeallocate(MachShim.taskSelf, array, count)
    }

    private static func classify(
        id: String,
        mechanism: String,
        operation: String,
        kr: Int32,
        count: Int?,
        expected: String,
        permittedMeaning: String,
        policyMeaning: String,
        validityMeaning: String
    ) -> Rung {
        if kr == 0, let count, count > 0 {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: expected, expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                taskCount: count,
                observed: "\(count) task ports were returned",
                interpretation: permittedMeaning
            )
        }
        if kr == 0 {
            return Rung(
                id: id, mechanism: mechanism, operation: operation,
                expected: expected, expectedDenied: true,
                outcome: .empty,
                returnValue: "kern_return_t 0", errorName: nil,
                taskCount: 0,
                observed: "the call succeeded and returned no tasks",
                interpretation: """
                    The call succeeded but returned nothing. That is notable: the \
                    authorization check did not refuse it, which means an ordinary \
                    app may enumerate the processor set -- it simply found no tasks \
                    in it from this vantage point.
                    """
            )
        }

        // KERN_INVALID_ARGUMENT = 4, KERN_INVALID_HOST = 12,
        // KERN_INVALID_OBJECT = 16, KERN_INVALID_RIGHT = 17.
        let validityErrors: Set<Int32> = [4, 12, 16, 17]
        let outcome: Outcome = validityErrors.contains(kr) ? .deniedByValidity : .deniedByPolicy

        return Rung(
            id: id, mechanism: mechanism, operation: operation,
            expected: expected, expectedDenied: true,
            outcome: outcome,
            returnValue: "kern_return_t \(kr)",
            errorName: MachShim.machErrorString(kr),
            taskCount: nil,
            observed: "refused with \(MachShim.machErrorString(kr))",
            interpretation: outcome == .deniedByValidity ? validityMeaning : policyMeaning
        )
    }

    private static func unavailable() -> Rung {
        Rung(
            id: "processor-set-tasks-default",
            mechanism: """
                Every task in a processor set -- the strongest possible \
                process-isolation primitive. The Mach API is not present on this \
                platform, so nothing was attempted.
                """,
            operation: "processor_set_tasks(pset, &tasks, &count)",
            expected: "Denied. An ordinary app must not enumerate device tasks.",
            expectedDenied: true,
            outcome: .symbolUnavailable,
            returnValue: nil, errorName: nil, taskCount: nil,
            observed: nil,
            interpretation: """
                NOT ATTEMPTED: the Mach API is not present on this platform.
                """
        )
    }
}
