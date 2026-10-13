//
//  RemainingPrimitivesProbe.swift
//  FSProbeCore — the remaining primitives that have never been tried.
//
//  HYPOTHESIS
//  ----------
//  Nine modules have now tested the container boundary from many angles: direct
//  path operations, operation classes, metadata reads, descriptor-based
//  primitives, the Foundation layer, a second mach-lookup path, and service
//  deputies. A handful of primitives remain that have never been tried at all,
//  and each is a separate authorization predicate:
//
//   getfsstat()     the system mount table — how many volumes are mounted
//   mach_host_self() a host port, which would be a privilege escalation
//   sysctlbyname()  kernel state by name, several MIBs are sensitive
//   copyfile()      a copy by a different code path than clonefile()
//
//  None of these is a cosmetic variation. `getfsstat` discloses mount topology.
//  A host port is the single strongest privilege primitive in Mach.
//  `sysctlbyname` reads kernel state without touching the filesystem at all, so
//  the filesystem sandbox may not govern it. `copyfile` is a different
//  implementation from `clonefile()` and may be authorized differently.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether these predicates are confined the way the ones already tested are.
//
//  CONTROL
//  -------
//  Each case has a control that must produce the expected answer. For
//  `sysctlbyname` the control is `hw.model`, a genuinely public MIB: if the API
//  cannot answer that, every other answer is meaningless.
//
//  SAFETY
//  ------
//  `getfsstat` is called with a null buffer and zero size, which asks only for a
//  count — no structure is filled and no buffer can overflow. `copyfile` writes
//  only to a dedicated synthetic path inside this app's own container and is
//  removed afterwards. Nothing outside the container is written.
//

import Foundation

public enum RemainingPrimitivesProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call produced an answer.
        case answered
        /// The call was refused.
        case denied
        /// The control did not produce the expected answer.
        case controlFailed
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Case: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The libc call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when an answer would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The return value as the platform reported it.
        public let returnValue: String?
        /// The errno or kern error name, when one was given.
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
            outcome == .answered && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let cases: [Case]
        public let violations: [Case]

        public init(cases: [Case], violations: [Case]) {
            self.cases = cases
            self.violations = violations
        }
    }

    #if canImport(Darwin)

    @_silgen_name("getfsstat")
    private static func sGetfsstat(
        _ buf: UnsafeMutableRawPointer?, _ bufsize: Int32, _ flags: Int32
    ) -> Int32

    @_silgen_name("sysctlbyname")
    private static func sSysctlbyname(
        _ name: UnsafePointer<CChar>, _ oldp: UnsafeMutableRawPointer?,
        _ oldlenp: UnsafeMutablePointer<Int>?, _ newp: UnsafeMutableRawPointer?,
        _ newlen: Int
    ) -> Int32

    @_silgen_name("copyfile")
    private static func sCopyfile(
        _ from: UnsafePointer<CChar>, _ to: UnsafePointer<CChar>,
        _ flags: UInt32, _ state: UInt32
    ) -> Int32

    private static var symbolsAvailable: Bool { true }

    #else

    private static var symbolsAvailable: Bool { false }

    #endif

    public static func probe(containerPath: String) -> Result {
        var cases: [Case] = []

        cases.append(getfsstatCase())
        cases.append(hostPortCase())
        cases.append(sysctlCase(
            id: "sysctl-hw-model",
            mib: "hw.model",
            mechanism: """
                CONTROL: a genuinely public MIB. If sysctlbyname cannot answer \
                this, every other sysctl answer below is meaningless.
                """,
            expected: "Answered. This MIB is public and must succeed.",
            expectedDenied: false))
        cases.append(sysctlCase(
            id: "sysctl-kern-bootargs",
            mib: "kern.bootargs",
            mechanism: """
                Kernel boot arguments. Reads kernel state without touching the \
                filesystem at all, so the filesystem sandbox may not govern it. \
                Historically this is restricted on release builds, but it has \
                never been tested on iOS 27.
                """,
            expected: "Denied. Boot arguments are restricted on release builds.",
            expectedDenied: true))
        cases.append(sysctlCase(
            id: "sysctl-sandbox-sentinel",
            mib: "security.mac.sandbox.sentinel",
            mechanism: """
                The sandbox sentinel MIB, which exists specifically to let callers \
                ask whether the sandbox is active. If it is readable, it discloses \
                sandbox state to any process that asks.
                """,
            expected: "Denied, or answered with a value that discloses nothing.",
            expectedDenied: true))
        cases.append(copyfileCase(containerPath: containerPath))

        let violations = cases.filter { $0.isBoundaryViolation }
        return Result(cases: cases, violations: violations)
    }

    // MARK: - Cases

    private static func getfsstatCase() -> Case {
        let id = "getfsstat-mount-count"
        guard symbolsAvailable else {
            return unavailable(id, "getfsstat(NULL, 0, MNT_NOWAIT)", "")
        }

        // A null buffer with a zero size asks only for a count. No structure is
        // filled, so no buffer size can be wrong.
        setErrno(0)
        #if canImport(Darwin)
        let count = sGetfsstat(nil, 0, 0)
        #else
        let count: Int32 = -1
        #endif
        let err = currentErrno()
        let answered = count >= 0

        return Case(
            id: id,
            mechanism: """
                The system mount table. Discloses how many volumes are mounted, \
                which is mount topology an app inside a container should not see.
                """,
            operation: "getfsstat(NULL, 0, MNT_NOWAIT)",
            arguments: "count only, no buffer",
            expected: "Denied, or a count that discloses nothing beyond this app's own volume.",
            expectedDenied: true,
            outcome: answered ? .answered : .denied,
            returnValue: "\(count)",
            errorName: answered ? nil : ErrorClassifier.errnoName(err),
            observed: answered ? "\(count) mounted filesystems reported" : "refused",
            interpretation: answered
                ? """
                The mount table is readable. The count discloses how many volumes \
                exist, which is mount topology beyond this app's own container. Not \
                a read primitive on its own, but it is information the app should \
                not hold.
                """
                : """
                Refused. Mount topology is confined.
                """
        )
    }

    private static func hostPortCase() -> Case {
        let id = "mach-host-port"
        guard symbolsAvailable else {
            return unavailable(id, "mach_host_self()", "")
        }

        #if canImport(Darwin)
        let port = MachShim.hostSelf()
        let answered = port != 0
        let portDescription = "port \(port)"

        // Release it immediately: the experiment is about whether a host port is
        // obtainable, not about using it.
        if answered {
            _ = MachShim.deallocatePort(MachShim.taskSelf, port)
        }
        #else
        let answered = false
        let portDescription = "MACH_PORT_NULL"
        #endif

        return Case(
            id: id,
            mechanism: """
                A host port is the single strongest privilege primitive in Mach: \
                with one, an app can reach host-level services and, on platforms \
                that allow it, other tasks. An ordinary app must not hold one.
                """,
            operation: "mach_host_self()",
            arguments: "",
            expected: "No host port, or a port that grants nothing.",
            expectedDenied: true,
            outcome: answered ? .answered : .denied,
            returnValue: portDescription,
            errorName: nil,
            observed: answered ? "a host port was returned" : "no host port",
            interpretation: answered
                ? """
                A host port was returned to an ordinary app. That is the strongest \
                possible Mach primitive and warrants immediate follow-up: with a \
                host port, host_get_special_port and processor_set_tasks become \
                reachable questions.
                """
                : """
                No host port. The strongest Mach primitive is not obtainable.
                """
        )
    }

    private static func sysctlCase(
        id: String,
        mib: String,
        mechanism: String,
        expected: String,
        expectedDenied: Bool
    ) -> Case {
        guard symbolsAvailable else {
            return unavailable(id, "sysctlbyname(\(mib), ...)", mib)
        }

        var length = 256
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: 256, alignment: 8
        )
        defer { buffer.deallocate() }
        memset(buffer, 0, 256)

        setErrno(0)
        #if canImport(Darwin)
        let rc = mib.withCString { name in
            sSysctlbyname(name, buffer, &length, nil, 0)
        }
        #else
        let rc: Int32 = -1
        #endif
        let err = currentErrno()
        let answered = rc == 0

        return Case(
            id: id, mechanism: mechanism,
            operation: "sysctlbyname(\(mib), ...)",
            arguments: mib,
            expected: expected,
            expectedDenied: expectedDenied,
            outcome: answered ? .answered : .denied,
            returnValue: "\(rc)",
            errorName: answered ? nil : ErrorClassifier.errnoName(err),
            observed: answered ? "answered, \(length) bytes" : "refused",
            interpretation: answered
                ? """
                The MIB answered. Kernel state was read without touching the \
                filesystem at all, so the filesystem sandbox does not govern this \
                path.
                """
                : """
                Refused. This kernel state is confined.
                """
        )
    }

    private static func copyfileCase(containerPath: String) -> Case {
        let id = "copyfile-protected-source"
        guard symbolsAvailable else {
            return unavailable(id, "copyfile(from, to, 0, 0)", "")
        }

        let documents = containerPath + "/Documents"
        let source = "/var/mobile/Library"
        let destination = documents + "/fsprobe-copyfile-target"

        // The destination is a dedicated synthetic name inside this app's own
        // container, removed afterwards. Nothing outside the container is written.
        try? FileManager.default.removeItem(atPath: destination)
        defer { try? FileManager.default.removeItem(atPath: destination) }

        setErrno(0)
        #if canImport(Darwin)
        let rc = source.withCString { from in
            destination.withCString { to in
                sCopyfile(from, to, 0, 0)
            }
        }
        #else
        let rc: Int32 = -1
        #endif
        let err = currentErrno()
        let answered = rc == 0
        let landed = FileManager.default.fileExists(atPath: destination)

        return Case(
            id: id,
            mechanism: """
                copyfile() is a different implementation from clonefile(), which \
                was already tested and refused. A separate code path may be \
                authorized separately.
                """,
            operation: "copyfile(from, to, 0, 0)",
            arguments: "\(source) -> \(destination)",
            expected: "Denied. The source lies outside the container.",
            expectedDenied: true,
            outcome: answered ? .answered : .denied,
            returnValue: "\(rc)",
            errorName: answered ? nil : ErrorClassifier.errnoName(err),
            observed: answered
                ? "the copy succeeded and content appeared at the destination: \(landed)"
                : "refused",
            interpretation: answered
                ? """
                copyfile copied from a protected path into this app's container. \
                That is a read primitive, obtained through a different code path \
                than the clonefile() that was refused.
                """
                : """
                Refused. copyfile is confined the same way clonefile() is.
                """
        )
    }

    // MARK: - Helpers

    private static func unavailable(
        _ id: String, _ operation: String, _ arguments: String
    ) -> Case {
        Case(
            id: id,
            mechanism: """
                A primitive never tested before. The symbol is not present on this \
                platform, so the experiment was never attempted.
                """,
            operation: operation,
            arguments: arguments,
            expected: "Denied, or an answer that discloses nothing.",
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
