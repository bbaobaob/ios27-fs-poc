//
//  ForeignMemoryProbe.swift
//  FSProbeCore — reading another process's memory.
//
//  HYPOTHESIS
//  ----------
//  The processor-set module measures whether an ordinary app can enumerate the
//  task ports of every process on the device. If it can, the next question is
//  what those ports grant, and there is one answer above all others:
//  `mach_vm_read`.
//
//  It takes a task port and an address and returns the memory at that address.
//  With a task port for another process, it is that process's memory. That is
//  the strongest possible process-isolation violation, and it is the endpoint
//  the whole ladder has been climbing toward.
//
//  This module asks it directly, on the one target an ordinary app can name:
//  launchd, pid 1. It is the most privileged process on the system and the
//  least likely to be readable, which makes it the honest test -- a success
//  against launchd is unambiguous, and a refusal there does not close the
//  question for less privileged targets but does establish that the strongest
//  one is defended.
//
//  Two calls are tested, because they are separate predicates:
//
//    mach_vm_read(task, address, size, &data, &count)   read foreign memory
//    vm_read_overwrite(task, address, size, data, &count) the same, caller's buffer
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether an ordinary app can read another process's memory.
//
//  CONTROL
//  -------
//  `mach_vm_read` on this app's OWN task, which must succeed. Without that
//  control a refusal elsewhere is uninterpretable: it could mean the policy
//  denies it, or that the call does not work on this platform.
//
//  SAFETY
//  ------
//  This reads memory, which is exactly why the target is chosen deliberately
//  and the amount is minimal. The address asked for is page zero of the target,
//  a single page. Nothing is written. Any data obtained is discarded
//  immediately and is never printed, stored, or transmitted -- the experiment
//  records only whether the read was permitted and how many bytes came back.
//  Reading a single page from the most privileged process is the minimum that
//  answers the question, and it is deliberately not more than that.
//

import Foundation

public enum ForeignMemoryProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The read succeeded.
        case permitted
        /// The read was refused with a policy error.
        case deniedByPolicy
        /// The read was refused with a validity error.
        case deniedByValidity
        /// The task port for the target could not be obtained.
        case noTaskPort
        /// The control did not produce the expected answer.
        case controlFailed
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Read: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The Mach call exercised.
        public let operation: String
        /// The target, named by role.
        public let target: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The kern_return_t, as the platform reported it.
        public let returnValue: String?
        /// The platform's own name for the error.
        public let errorName: String?
        /// How many bytes came back, when any did. Never the bytes themselves.
        public let bytesRead: Int?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            target: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            returnValue: String?,
            errorName: String?,
            bytesRead: Int?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = "target=\(target)"
            self.target = target
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.returnValue = returnValue
            self.errorName = errorName
            self.bytesRead = bytesRead
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
        public let reads: [Read]
        public let violations: [Read]

        public init(reads: [Read], violations: [Read]) {
            self.reads = reads
            self.violations = violations
        }
    }

    /// One page, allocated in this app's own task so the control read has a real,
    /// mapped address to read.
    ///
    /// Address zero is not mapped in any task, so probing it makes the self-control
    /// fail on every platform -- which gates the whole experiment off behind a
    /// control that cannot pass, and reports "uninterpretable" for a question that
    /// was never actually asked. Allocating a page fixes that, and it is still the
    /// minimum that answers the question.
    private static let probeSize: Int = 4096

    /// A mapped page in this app's own address space, or 0 when allocation failed.
    ///
    /// Allocated per probe() call rather than once as a static. The earlier
    /// version allocated it as a static and released it in a defer, which meant
    /// the second and later calls read an address that had already been
    /// deallocated: the self-control failed, the foreign reads were gated off
    /// behind it, and the experiment silently reported "uninterpretable" on every
    /// run after the first. That is the same class of defect as reading address
    /// zero -- a control that cannot pass, hiding a question that was never asked.
    private static func allocateProbePage() -> UInt64 {
        var address: UInt64 = 0
        let kr = MachShim.vmAllocate(MachShim.taskSelf, &address, probeSize)
        return kr == 0 ? address : 0
    }

    /// Release the probe page. Called once, after every read in one probe() run.
    private static func releaseProbePage(_ address: UInt64) {
        guard address != 0 else { return }
        _ = MachShim.vmDeallocate(MachShim.taskSelf, MachPort(address), probeSize)
    }

    public static func probe() -> Result {
        guard MachShim.available else {
            return Result(reads: [unavailable()], violations: [])
        }
        let probeAddress = allocateProbePage()
        defer { releaseProbePage(probeAddress) }

        var reads: [Read] = []

        // Control: read this app's own memory. Must succeed.
        reads.append(selfRead(address: probeAddress))
        let controlOK = reads.first?.outcome == .permitted

        guard controlOK else {
            return Result(reads: reads, violations: [])
        }

        // The target: launchd, pid 1. The most privileged process on the system.
        reads.append(foreignRead(
            id: "mach-vm-read-launchd",
            operation: "mach_vm_read(task, <page>, 4096, &data, &count)",
            pid: 1,
            targetLabel: "launchd (pid 1)",
            address: probeAddress
        ))
        reads.append(foreignReadOverwrite(
            id: "vm-read-overwrite-launchd",
            operation: "vm_read_overwrite(task, <page>, 4096, buf, &count)",
            pid: 1,
            targetLabel: "launchd (pid 1)",
            address: probeAddress
        ))

        let violations = reads.filter { $0.isBoundaryViolation }
        return Result(reads: reads, violations: violations)
    }

    // MARK: - Reads

    private static func selfRead(address: UInt64) -> Read {
        let id = "mach-vm-read-self"
        let operation = "mach_vm_read(mach_task_self_, 0, 4096, &data, &count)"
        let mechanism = """
            CONTROL: reading this app's OWN memory. An app may legitimately do \
            this, so success proves the API works. That is what makes a refusal on \
            another process a policy denial rather than a broken call.
            """

        var data: MachPort = 0
        var count: UInt32 = 0
        let kr = MachShim.machVMRead(MachShim.taskSelf, address, probeSize, &data, &count)
        if kr == 0 && count > 0 {
            // `data` is a vm_address_t naming a vm-allocated buffer, not a send
            // right. Releasing it with mach_port_deallocate would be wrong -- the
            // same class of mistake that crashed the processor-set probe.
            _ = MachShim.vmDeallocate(MachShim.taskSelf, data, Int(count))
            return Read(
                id: id, mechanism: mechanism, operation: operation,
                target: "self",
                expected: "Succeeds. An app may read its own memory.",
                expectedDenied: false,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                bytesRead: Int(count),
                observed: "\(count) bytes read from this app's own memory",
                interpretation: """
                    The API works on this app's own memory. A refusal on another \
                    process is therefore a policy denial.
                    """
            )
        }

        return Read(
            id: id, mechanism: mechanism, operation: operation,
            target: "self",
            expected: "Succeeds. An app may read its own memory.",
            expectedDenied: false,
            outcome: .controlFailed,
            returnValue: "kern_return_t \(kr)",
            errorName: MachShim.machErrorString(kr),
            bytesRead: nil,
            observed: "even self-read failed",
            interpretation: """
                The control failed, so a refusal on another process is \
                uninterpretable: it could mean the policy denies it, or that the \
                call does not work on this platform. Nothing is claimed.
                """
        )
    }

    private static func foreignRead(
        id: String,
        operation: String,
        pid: Int32,
        targetLabel: String,
        address: UInt64
    ) -> Read {
        let mechanism = """
            Reading ANOTHER process's memory. With a task port for it, this is \
            that process's memory -- the strongest possible process-isolation \
            violation, and the endpoint the whole Mach ladder has been climbing \
            toward.
            """

        var task: MachPort = 0
        let taskKR = MachShim.taskForPid(MachShim.taskSelf, pid, &task)
        guard taskKR == 0, task != 0 else {
            return Read(
                id: id, mechanism: mechanism, operation: operation,
                target: targetLabel,
                expected: """
                    Denied. An ordinary app must not read another process's memory.
                    """,
                expectedDenied: true,
                outcome: .noTaskPort,
                returnValue: "kern_return_t \(taskKR)",
                errorName: MachShim.machErrorString(taskKR),
                bytesRead: nil,
                observed: "no task port for the target",
                interpretation: """
                    NOT ATTEMPTED: no task port was obtained for the target, which \
                    the cross-process experiment already established is refused. \
                    Without a port there is nothing to read through, so this call \
                    was never made.
                    """
            )
        }
        defer { _ = MachShim.deallocatePort(MachShim.taskSelf, task) }

        var data: MachPort = 0
        var count: UInt32 = 0
        let kr = MachShim.machVMRead(task, address, probeSize, &data, &count)
        if kr == 0 && count > 0 {
            // Discard the data immediately, as a vm buffer. It is never printed,
            // stored, or transmitted: the experiment records only that the read
            // was permitted and how many bytes came back.
            _ = MachShim.vmDeallocate(MachShim.taskSelf, data, Int(count))
            return Read(
                id: id, mechanism: mechanism, operation: operation,
                target: targetLabel,
                expected: """
                    Denied. An ordinary app must not read another process's memory.
                    """,
                expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                bytesRead: Int(count),
                observed: "\(count) bytes were read from another process",
                interpretation: """
                    Another process's memory was read. That is the strongest \
                    possible process-isolation violation, and the data itself was \
                    discarded rather than recorded -- the fact of the read is the \
                    finding.
                    """
            )
        }

        return classify(
            id: id, mechanism: mechanism, operation: operation,
            target: targetLabel, kr: kr,
            expected: """
                Denied. An ordinary app must not read another process's memory.
                """,
            policyMeaning: """
                Refused by policy. Another process's memory is not readable.
                """,
            validityMeaning: """
                Refused with a validity error, so the task port was not usable as \
                one.
                """
        )
    }

    private static func foreignReadOverwrite(
        id: String,
        operation: String,
        pid: Int32,
        targetLabel: String,
        address: UInt64
    ) -> Read {
        let mechanism = """
            The same read into a caller-supplied buffer. A separate predicate from \
            mach_vm_read, and never tested.
            """

        var task: MachPort = 0
        let taskKR = MachShim.taskForPid(MachShim.taskSelf, pid, &task)
        guard taskKR == 0, task != 0 else {
            return Read(
                id: id, mechanism: mechanism, operation: operation,
                target: targetLabel,
                expected: """
                    Denied. An ordinary app must not read another process's memory.
                    """,
                expectedDenied: true,
                outcome: .noTaskPort,
                returnValue: "kern_return_t \(taskKR)",
                errorName: MachShim.machErrorString(taskKR),
                bytesRead: nil,
                observed: "no task port for the target",
                interpretation: """
                    NOT ATTEMPTED: no task port was obtained for the target.
                    """
            )
        }
        defer { _ = MachShim.deallocatePort(MachShim.taskSelf, task) }

        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: probeSize, alignment: 16
        )
        defer { buffer.deallocate() }
        var count: UInt32 = 0
        let kr = MachShim.vmReadOverwrite(
            task, address, probeSize, buffer, &count
        )
        if kr == 0 && count > 0 {
            return Read(
                id: id, mechanism: mechanism, operation: operation,
                target: targetLabel,
                expected: """
                    Denied. An ordinary app must not read another process's memory.
                    """,
                expectedDenied: true,
                outcome: .permitted,
                returnValue: "kern_return_t 0", errorName: nil,
                bytesRead: Int(count),
                observed: "\(count) bytes were read into this app's buffer",
                interpretation: """
                    Another process's memory was read into this app's buffer. The \
                    buffer is discarded rather than recorded -- the fact of the \
                    read is the finding.
                    """
            )
        }

        return classify(
            id: id, mechanism: mechanism, operation: operation,
            target: targetLabel, kr: kr,
            expected: """
                Denied. An ordinary app must not read another process's memory.
                """,
            policyMeaning: """
                Refused by policy. Another process's memory is not readable.
                """,
            validityMeaning: """
                Refused with a validity error, so the task port was not usable as \
                one.
                """
        )
    }

    // MARK: - Helpers

    private static func classify(
        id: String,
        mechanism: String,
        operation: String,
        target: String,
        kr: Int32,
        expected: String,
        policyMeaning: String,
        validityMeaning: String
    ) -> Read {
        // KERN_INVALID_ARGUMENT = 4, KERN_INVALID_HOST = 12,
        // KERN_INVALID_OBJECT = 16, KERN_INVALID_RIGHT = 17,
        // KERN_MEMORY_ERROR = 3, KERN_PROTECTION_FAILURE = 8.
        let validityErrors: Set<Int32> = [4, 12, 16, 17]
        let outcome: Outcome = validityErrors.contains(kr) ? .deniedByValidity : .deniedByPolicy

        return Read(
            id: id, mechanism: mechanism, operation: operation,
            target: target,
            expected: expected, expectedDenied: true,
            outcome: outcome,
            returnValue: "kern_return_t \(kr)",
            errorName: MachShim.machErrorString(kr),
            bytesRead: nil,
            observed: "refused with \(MachShim.machErrorString(kr))",
            interpretation: outcome == .deniedByValidity ? validityMeaning : policyMeaning
        )
    }

    private static func unavailable() -> Read {
        Read(
            id: "mach-vm-read-launchd",
            mechanism: """
                Reading another process's memory. The Mach API is not present on \
                this platform, so nothing was attempted.
                """,
            operation: "mach_vm_read(task, 0, 4096, &data, &count)",
            target: "launchd (pid 1)",
            expected: """
                Denied. An ordinary app must not read another process's memory.
            """,
            expectedDenied: true,
            outcome: .symbolUnavailable,
            returnValue: nil, errorName: nil, bytesRead: nil,
            observed: nil,
            interpretation: """
                NOT ATTEMPTED: the Mach API is not present on this platform.
            """
        )
    }
}
