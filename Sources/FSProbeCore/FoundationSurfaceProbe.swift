//
//  FoundationSurfaceProbe.swift
//  FSProbeCore — the same boundary, reached through a different layer.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far called libc directly. Apple's sandbox authorizes
//  operations, not paths, and the operation is chosen by the *caller's layer* as
//  much as by the caller's intent. Foundation and CoreFoundation sit on top of
//  libc and sometimes reach the kernel through different primitives, or perform
//  extra work through system daemons on the caller's behalf.
//
//  Two things are untested here:
//
//  1. `access()` — a libc call never tested directly. `NSFileManager`'s
//     `isReadableFile`, `isWritableFile`, `isExecutableFile`, and
//     `isDeletableFile` are built on it. If `access()` is authorized differently
//     from `open()`, those four APIs become an oracle about protected paths.
//
//  2. `containerURL(forSecurityApplicationGroupIdentifier:)` — the public API
//     that reaches `com.apple.containermanagerd`, which the mach-lookup
//     experiment measured as REACHABLE from an ordinary app. It is the only
//     public surface that exercises that service. The question is whether the
//     daemon validates the caller's entitlement for the group it is asked to
//     resolve, or trusts the caller's reference — the confused-deputy shape.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether authorization depends on which layer makes the call, and whether a
//  reachable daemon validates the caller before resolving a resource reference.
//
//  CONTROL
//  -------
//  Every case runs first inside the app's own container, where it must produce
//  the expected answer. Without that control a refusal outside is
//  uninterpretable.
//
//  SAFETY
//  ------
//  Read-only. No file is written, created, or removed. The group identifier
//  requested is a synthetic one, chosen to probe the daemon's authorization
//  check rather than to name a real group whose contents might be sensitive.
//

import Foundation

public enum FoundationSurfaceProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call produced the answer that corresponds to access being granted.
        case granted
        /// The call produced the answer that corresponds to access being refused.
        case refused
        /// The call could not produce an answer at all.
        case noAnswer
        /// The control did not produce the expected answer.
        case controlFailed
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Case: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The API exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when a granted answer would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the underlying call, captured immediately afterwards.
        public let errnoName: String?
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
            errnoName: String?,
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
            self.errnoName = errnoName
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .granted && expectedDenied
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

    private static let protectedDirectories = [
        "/var/mobile/Library",
        "/var/mobile/Media",
    ]

    /// A synthetic group identifier. The name is arbitrary on purpose: what is
    /// measured is whether the daemon checks the caller's entitlement, not
    /// whether this particular group exists.
    private static let probeGroupIdentifier = "group.com.example.deputy-probe-target"

    #if canImport(Darwin)

    @_silgen_name("access")
    private static func sAccess(
        _ path: UnsafePointer<CChar>, _ mode: Int32
    ) -> Int32

    /// F_OK, R_OK, W_OK, X_OK from <unistd.h>.
    private static let fOK: Int32 = 0
    private static let rOK: Int32 = 0x04
    private static let wOK: Int32 = 0x02
    private static let xOK: Int32 = 0x01

    private static var symbolsAvailable: Bool { true }

    #else

    private static var symbolsAvailable: Bool { false }

    #endif

    public static func probe(containerPath: String) -> Result {
        var cases: [Case] = []
        let documents = containerPath + "/Documents"

        for directory in protectedDirectories {
            guard pathExists(directory) else {
                for id in ["access-read", "access-write", "access-execute",
                           "isReadableFile", "isWritableFile", "isDeletableFile",
                           "destinationOfSymbolicLink"] {
                    cases.append(missingPath("\(id)-\(directory)",
                                             "Foundation/access API", directory))
                }
                continue
            }

            cases.append(accessCase(
                id: "access-read-\(directory)", mode: .read,
                directory: directory, documents: documents))
            cases.append(accessCase(
                id: "access-write-\(directory)", mode: .write,
                directory: directory, documents: documents))
            cases.append(accessCase(
                id: "access-execute-\(directory)", mode: .execute,
                directory: directory, documents: documents))

            cases.append(fileManagerCase(
                id: "isReadableFile-\(directory)",
                mechanism: """
                    Foundation's readability oracle, built on access(). A different \
                    layer from the raw open() calls tested so far.
                    """,
                operation: "NSFileManager.isReadableFile(atPath:)",
                directory: directory, documents: documents,
                probe: { FileManager.default.isReadableFile(atPath: $0) },
                grantedMeaning: """
                    Foundation reports a protected directory as readable. The \
                    readability oracle disagrees with every direct call tested so \
                    far, which makes it either a weaker predicate or a false answer \
                    -- either way it needs following up.
                    """,
                refusedMeaning: """
                    Foundation reports the directory as not readable, consistent \
                    with the direct calls.
                    """))

            cases.append(fileManagerCase(
                id: "isWritableFile-\(directory)",
                mechanism: """
                    Foundation's writability oracle, built on access().
                    """,
                operation: "NSFileManager.isWritableFile(atPath:)",
                directory: directory, documents: documents,
                probe: { FileManager.default.isWritableFile(atPath: $0) },
                grantedMeaning: """
                    Foundation reports a protected directory as writable. That is a \
                    write oracle on a path open()+create refused.
                    """,
                refusedMeaning: """
                    Foundation reports the directory as not writable, consistent \
                    with the direct calls.
                    """))

            cases.append(fileManagerCase(
                id: "isDeletableFile-\(directory)",
                mechanism: """
                    Foundation's deletability oracle. Built on a different \
                    accessat() check than readability, and never tested.
                    """,
                operation: "NSFileManager.isDeletableFile(atPath:)",
                directory: directory, documents: documents,
                probe: { FileManager.default.isDeletableFile(atPath: $0) },
                grantedMeaning: """
                    Foundation reports a protected directory as deletable. That is a \
                    delete oracle on a path unlink() refused.
                    """,
                refusedMeaning: """
                    Foundation reports the directory as not deletable, consistent \
                    with the direct calls.
                    """))

            cases.append(fileManagerCase(
                id: "destinationOfSymbolicLink-\(directory)",
                mechanism: """
                    Foundation's symlink resolver. A different layer from the raw \
                    readlink() tested so far.
                    """,
                operation: "NSFileManager.destinationOfSymbolicLink(atPath:)",
                directory: directory, documents: documents,
                probe: { path in
                    (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) != nil
                },
                grantedMeaning: """
                    Foundation resolved a symlink at a protected path, which the raw \
                    readlink() refused.
                    """,
                refusedMeaning: """
                    Foundation could not resolve a symlink at the protected path, \
                    consistent with the direct calls.
                    """))
        }

        // The one public surface that reaches containermanagerd, which the
        // mach-lookup experiment measured as reachable. This is the confused-deputy
        // test for that service, and it has never been run.
        cases.append(containerURLCase(containerPath: containerPath))

        let violations = cases.filter { $0.isBoundaryViolation }
        return Result(cases: cases, violations: violations)
    }

    // MARK: - Cases

    private enum AccessMode {
        case read, write, execute
    }

    private static func accessCase(
        id: String, mode: AccessMode, directory: String, documents: String
    ) -> Case {
        guard symbolsAvailable else {
            return unavailable(id, "access(path, mode)", directory)
        }

        let controlRC = callAccess(documents, mode)
        let controlGranted = controlRC == 0
        let rc = callAccess(directory, mode)
        let granted = rc == 0
        let err = currentErrno()
        let errnoName = granted ? nil : ErrorClassifier.errnoName(err)

        let modeName: String
        switch mode {
        case .read: modeName = "R_OK"
        case .write: modeName = "W_OK"
        case .execute: modeName = "X_OK"
        }

        guard controlGranted else {
            return Case(
                id: id,
                mechanism: """
                    access(): a libc call never tested directly. The NSFileManager \
                    readability, writability, and deletability oracles are built on \
                    it, so its behaviour governs four public APIs.
                    """,
                operation: "access(path, \(modeName))",
                arguments: directory,
                expected: "Denied with EPERM on a protected path.",
                expectedDenied: true,
                outcome: .controlFailed,
                errnoName: errnoName,
                observed: "the control inside the container itself failed",
                interpretation: """
                    The control failed, so a refusal outside is uninterpretable. \
                    Nothing is claimed about the boundary.
                    """
            )
        }

        return Case(
            id: id,
            mechanism: """
                access(): a libc call never tested directly. The NSFileManager \
                readability, writability, and deletability oracles are built on it, \
                so its behaviour governs four public APIs.
                """,
            operation: "access(path, \(modeName))",
            arguments: directory,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: granted ? .granted : .refused,
            errnoName: errnoName,
            observed: granted ? "access granted" : "refused with \(errnoName ?? "an unknown errno")",
            interpretation: granted
                ? """
                access() reported the permission as held for a protected path. Every \
                direct open() on this path was refused with EPERM, so access() is \
                authorized by a different and weaker predicate than open().
                """
                : """
                Refused. access() is confined the same way open() is.
                """
        )
    }

    private static func fileManagerCase(
        id: String,
        mechanism: String,
        operation: String,
        directory: String,
        documents: String,
        probe: (String) -> Bool,
        grantedMeaning: String,
        refusedMeaning: String
    ) -> Case {
        let controlAnswer = probe(documents)
        let answer = probe(directory)

        guard controlAnswer else {
            return Case(
                id: id, mechanism: mechanism, operation: operation,
                arguments: directory,
                expected: "Denied on a protected path.",
                expectedDenied: true,
                outcome: .controlFailed,
                errnoName: nil,
                observed: "the control inside the container answered no",
                interpretation: """
                    The control answered no for a path this app owns, so the API is \
                    not producing meaningful answers here and nothing below is \
                    interpretable.
                    """
            )
        }

        return Case(
            id: id, mechanism: mechanism, operation: operation,
            arguments: directory,
            expected: "Denied on a protected path.",
            expectedDenied: true,
            outcome: answer ? .granted : .refused,
            errnoName: nil,
            observed: answer ? "answered yes" : "answered no",
            interpretation: answer ? grantedMeaning : refusedMeaning
        )
    }

    private static func containerURLCase(containerPath: String) -> Case {
        let id = "containerURL-app-group"
        let mechanism = """
            The one public surface that reaches com.apple.containermanagerd, which \
            the mach-lookup experiment measured as reachable from an ordinary app. \
            The daemon resolves and creates app containers on the caller's behalf, \
            which is the confused-deputy shape: the question is whether it validates \
            the caller's entitlement for the group it is asked to resolve, or trusts \
            the caller's reference.
            """

        #if !canImport(Darwin)
        // This API is Darwin-only. Withholding the case is honest; compiling it
        // away silently would leave the containermanagerd question unasked.
        return Case(
            id: id, mechanism: mechanism,
            operation: "NSFileManager.containerURL(forSecurityApplicationGroupIdentifier:)",
            arguments: "group=\(probeGroupIdentifier)",
            expected: "nil. The app holds no app-group entitlement.",
            expectedDenied: true,
            outcome: .notAttempted,
            errnoName: nil,
            observed: "the API is not present on this platform",
            interpretation: """
                NOT ATTEMPTED: this API is Darwin-only. The containermanagerd \
                question it asks is unanswered here and is answered on the device.
                """
        )
        #else

        // Control: a group identifier that cannot exist. The API must refuse it.
        // Without this control a nil for the probe group is uninterpretable -- it
        // could mean the daemon checked the entitlement, or that the daemon simply
        // refuses everything.
        let controlURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.example.nonexistent.control"
        )
        guard controlURL == nil else {
            return Case(
                id: id, mechanism: mechanism,
                operation: "NSFileManager.containerURL(forSecurityApplicationGroupIdentifier:)",
                arguments: "group=com.example.nonexistent.control",
                expected: "nil for a group that does not exist.",
                expectedDenied: true,
                outcome: .controlFailed,
                errnoName: nil,
                observed: "the control returned \(controlURL!.path)",
                interpretation: """
                    The control FAILED: the API returned a URL for a group identifier \
                    that cannot exist. That means the daemon resolves references \
                    without checking whether the group is real, which is itself a \
                    significant result and invalidates the test case below.
                    """
            )
        }

        let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: probeGroupIdentifier
        )

        return Case(
            id: id, mechanism: mechanism,
            operation: "NSFileManager.containerURL(forSecurityApplicationGroupIdentifier:)",
            arguments: "group=\(probeGroupIdentifier)",
            expected: """
                nil. The app holds no app-group entitlement, so the daemon must \
                refuse to resolve the reference.
                """,
            expectedDenied: true,
            outcome: url == nil ? .refused : .granted,
            errnoName: nil,
            observed: url.map { "returned \($0.path)" } ?? "returned nil",
            interpretation: url == nil
                ? """
                Refused. The daemon did not resolve a group reference for an app \
                holding no app-group entitlement, so the confused-deputy hypothesis \
                for containermanagerd is falsified for this identifier.
                """
                : """
                The daemon returned a container URL for a group this app holds no \
                entitlement for. That is an authorization failure at the service \
                boundary, and the returned path is the primitive to investigate.
                """
        )
        #endif
    }

    // MARK: - Raw calls and helpers

    private static func callAccess(_ path: String, _ mode: AccessMode) -> Int32 {
        #if canImport(Darwin)
        let flag: Int32
        switch mode {
        case .read: flag = rOK
        case .write: flag = wOK
        case .execute: flag = xOK
        }
        setErrno(0)
        return path.withCString { sAccess($0, flag) }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func pathExists(_ path: String) -> Bool {
        var buffer = StatBuffer()
        return POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0
    }

    private static func missingPath(
        _ id: String, _ operation: String, _ path: String
    ) -> Case {
        Case(
            id: id,
            mechanism: """
                The same boundary reached through Foundation rather than libc. The \
                target path does not exist on this platform, so the case was not run.
                """,
            operation: operation,
            arguments: path,
            expected: "Denied on a protected path.",
            expectedDenied: true,
            outcome: .notAttempted,
            errnoName: nil,
            observed: "the path does not exist here",
            interpretation: """
                NOT ATTEMPTED: this path is an iOS location and does not exist on \
                this platform. Running it would produce ENOENT and say nothing \
                about the sandbox.
                """
        )
    }

    private static func unavailable(
        _ id: String, _ operation: String, _ path: String
    ) -> Case {
        Case(
            id: id,
            mechanism: """
                access(): a libc call never tested directly. The symbol is not \
                present on this platform, so the case was never attempted.
                """,
            operation: operation,
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .notAttempted,
            errnoName: nil,
            observed: nil,
            interpretation: """
                The symbol could not be resolved, so no measurement was made. This \
                is a statement about the platform, not a denial.
                """
        )
    }
}
