//
//  DescriptorPrimitiveProbe.swift
//  FSProbeCore — primitives reachable through a descriptor rather than a path.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far asked for a path and was refused. There is one
//  mechanism that has never been tested and that works differently: obtaining a
//  *descriptor* for a protected object and then operating through the descriptor.
//
//  `O_EVTONLY` is a Darwin-specific open flag. It asks for an event-only
//  descriptor rather than a readable one — the man page describes it as requiring
//  only permission to receive notifications about the object, not permission to
//  read its contents. Whether the sandbox authorizes `O_EVTONLY` as a distinct,
//  weaker operation from `file-read-data` has never been tested here.
//
//  If an event-only descriptor for a protected directory can be obtained, a
//  second question follows immediately, and it is the one that matters: what can
//  be done *through that descriptor*? Several calls take a descriptor rather than
//  a path, and they are separate sandbox predicates:
//
//    fgetattrlist()      attributes through a descriptor
//    fgetxattr()         extended attributes through a descriptor
//    getdirentriesattr() directory entries through a descriptor
//
//  `getdirentriesattr` is the prize. If it works on a descriptor for a protected
//  directory, it enumerates that directory's entries — a read primitive on a path
//  this app cannot open, obtained without ever holding permission to read it.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether descriptor-based operations are authorized by the same rules as their
//  path-based equivalents, or by weaker separate rules.
//
//  CONTROL
//  -------
//  Every step runs first inside the app's own container, where it must succeed.
//  Without that control a refusal outside is uninterpretable: it could mean the
//  policy denies it, or that the operation does not work on this platform.
//
//  SAFETY
//  ------
//  Read-only. Descriptors are closed immediately. No file is written, created, or
//  removed. `getdirentriesattr` is asked only for entry names, which is the
//  minimum needed to learn whether enumeration is possible.
//

import Foundation

public enum DescriptorPrimitiveProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The step succeeded where denial was predicted.
        case permitted
        /// The step was refused, with the errno recorded.
        case denied
        /// A prerequisite step did not succeed, so this step could not run.
        case prerequisiteFailed
        /// The control did not succeed, so the result is not interpretable.
        case controlFailed
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The step was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Step: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The libc call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the call, captured immediately afterwards.
        public let errnoName: String?
        public let errnoNumber: Int32?
        /// How many entries the call reported, when it reported any.
        public let entryCount: Int?
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
            errnoNumber: Int32?,
            entryCount: Int?,
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
            self.errnoNumber = errnoNumber
            self.entryCount = entryCount
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let steps: [Step]
        public let violations: [Step]

        public init(steps: [Step], violations: [Step]) {
            self.steps = steps
            self.violations = violations
        }
    }

    /// Protected directories on the same volume as the container. `/var/tmp` is
    /// excluded: a rename to it returned EXDEV, so it is a different volume and a
    /// refusal there would not be attributable to policy.
    private static let protectedDirectories = [
        "/var/mobile/Library",
        "/var/mobile/Media",
    ]

    /// `O_EVTONLY` — request an event-only descriptor rather than a readable one.
    /// Darwin-specific, so it is spelled out rather than taken from the headers.
    private static let kO_EVTONLY: Int32 = 0x2000

    /// ATTR_BIT_MAP_COUNT on Darwin, and the single attribute requested.
    private static let attrBitMapCount: UInt16 = 5
    private static let attrCmnName: UInt32 = 0x00000001

    private static let attrlistBufferSize = 64
    private static let attributeBufferSize = 4096

    #if canImport(Darwin)

    @_silgen_name("fgetattrlist")
    private static func sFgetattrlist(
        _ fd: Int32, _ alist: UnsafeMutableRawPointer,
        _ attributeBuffer: UnsafeMutableRawPointer?, _ bufferSize: Int,
        _ options: UInt32
    ) -> Int32

    @_silgen_name("fgetxattr")
    private static func sFgetxattr(
        _ fd: Int32, _ name: UnsafePointer<CChar>,
        _ value: UnsafeMutableRawPointer?, _ size: Int,
        _ position: UInt32, _ options: UInt32
    ) -> Int32

    @_silgen_name("getdirentriesattr")
    private static func sGetdirentriesattr(
        _ fd: Int32, _ alist: UnsafeMutableRawPointer,
        _ buffer: UnsafeMutableRawPointer?, _ bufferSize: Int,
        _ count: UnsafeMutablePointer<UInt32>?, _ basep: UnsafeMutablePointer<UInt32>?,
        _ newState: UnsafeMutableRawPointer?, _ stateSize: Int
    ) -> Int32

    private static var symbolsAvailable: Bool { true }

    #else

    private static var symbolsAvailable: Bool { false }

    #endif

    public static func probe(containerPath: String) -> Result {
        var steps: [Step] = []
        let documents = containerPath + "/Documents"

        for directory in protectedDirectories {
            // Step one is the gate: without an event-only descriptor nothing
            // below can run.
            let controlFD = openEvtonly(documents)
            let controlOutcome = controlFD >= 0
            if controlFD >= 0 { _ = POSIXShim.closeFile(controlFD) }

            guard controlOutcome else {
                steps.append(controlFailed(
                    "open-evtonly-\(directory)", directory, documents))
                steps.append(prerequisiteFailed(
                    "fgetattrlist-fd-\(directory)", directory))
                steps.append(prerequisiteFailed(
                    "getdirentriesattr-fd-\(directory)", directory))
                steps.append(prerequisiteFailed(
                    "fgetxattr-fd-\(directory)", directory))
                continue
            }

            steps.append(openEvtonlyCase(directory: directory, documents: documents))
            steps.append(fgetattrlistCase(directory: directory, documents: documents))
            steps.append(getdirentriesattrCase(directory: directory, documents: documents))
            steps.append(fgetxattrCase(directory: directory, documents: documents))
        }

        let violations = steps.filter { $0.isBoundaryViolation }
        return Result(steps: steps, violations: violations)
    }

    // MARK: - Cases

    private static func openEvtonlyCase(directory: String, documents: String) -> Step {
        guard pathExists(directory) else {
            return missingPath("open-evtonly-\(directory)",
                               "open(path, O_EVTONLY)", directory)
        }
        let controlFD = openEvtonly(documents)
        if controlFD >= 0 { _ = POSIXShim.closeFile(controlFD) }

        let fd = openEvtonly(directory)
        // errno is read immediately, before the close can disturb it.
        let err = currentErrno()
        let errnoName = fd >= 0 ? nil : ErrorClassifier.errnoName(err)
        if fd >= 0 { _ = POSIXShim.closeFile(fd) }

        let permitted = fd >= 0
        return Step(
            id: "open-evtonly-\(directory)",
            mechanism: """
                O_EVTONLY: an event-only descriptor rather than a readable one. \
                Whether the sandbox authorizes this as a distinct, weaker \
                operation from file-read-data has never been tested.
                """,
            operation: "open(path, O_EVTONLY)",
            arguments: directory,
            expected: """
                Denied with EPERM. Obtaining a descriptor for a protected directory \
                is the prerequisite for every descriptor-based primitive below.
                """,
            expectedDenied: true,
            outcome: permitted ? .permitted : .denied,
            errnoName: errnoName,
            errnoNumber: permitted ? nil : err,
            entryCount: nil,
            observed: permitted ? "a descriptor was obtained" : "refused with \(errnoName ?? "an unknown errno")",
            interpretation: permitted
                ? """
                An event-only descriptor was obtained for a protected directory. \
                That alone is not a read primitive, but it is the prerequisite for \
                the steps below, each of which is a separate sandbox predicate.
                """
                : """
                Refused. O_EVTONLY is authorized exactly as a read is, so no \
                descriptor is available for a protected path.
                """
        )
    }

    private static func fgetattrlistCase(directory: String, documents: String) -> Step {
        guard symbolsAvailable, pathExists(directory) else {
            return unavailableOrMissing("fgetattrlist-fd-\(directory)",
                                        "fgetattrlist(fd, &alist, buf, size, 0)", directory)
        }
        let controlFD = openEvtonly(documents)
        guard controlFD >= 0 else {
            return prerequisiteFailed("fgetattrlist-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(controlFD) }
        let controlRC = callFgetattrlist(controlFD)

        let fd = openEvtonly(directory)
        guard fd >= 0 else {
            return prerequisiteFailed("fgetattrlist-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(fd) }
        let rc = callFgetattrlist(fd)

        return makeStep(
            id: "fgetattrlist-fd-\(directory)",
            mechanism: """
                Attributes read through a descriptor rather than by path. A \
                separate predicate from file-read-data, and the descriptor form \
                has never been tested.
                """,
            operation: "fgetattrlist(fd, &alist, buf, size, 0)",
            arguments: "fd for \(directory)",
            expected: """
                Denied with EPERM, or reachable only once an event-only descriptor \
                has been granted for the path.
                """,
            rc: rc,
            controlRC: controlRC,
            permittedMeaning: """
                Attributes were read through a descriptor for a protected \
                directory. That is a read primitive on a path this app cannot open \
                by name.
                """,
            deniedMeaning: """
                Refused. Descriptor-based attribute reads are confined the same way \
                the path-based ones are.
                """
        )
    }

    private static func getdirentriesattrCase(directory: String, documents: String) -> Step {
        guard symbolsAvailable, pathExists(directory) else {
            return unavailableOrMissing("getdirentriesattr-fd-\(directory)",
                                        "getdirentriesattr(fd, ...)", directory)
        }
        let controlFD = openEvtonly(documents)
        guard controlFD >= 0 else {
            return prerequisiteFailed("getdirentriesattr-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(controlFD) }
        let controlCount = callGetdirentriesattr(controlFD)

        let fd = openEvtonly(directory)
        guard fd >= 0 else {
            return prerequisiteFailed("getdirentriesattr-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(fd) }
        let count = callGetdirentriesattr(fd)

        return makeStep(
            id: "getdirentriesattr-fd-\(directory)",
            mechanism: """
                Directory entries read through a descriptor. This is the prize: if \
                it works on a descriptor for a protected directory, the directory \
                is enumerated without the app ever holding permission to read it \
                by path.
                """,
            operation: "getdirentriesattr(fd, &alist, buf, size, &count, ...)",
            arguments: "fd for \(directory)",
            expected: """
                Denied with EPERM, or reachable only once an event-only descriptor \
                has been granted for the path.
                """,
            rc: count,
            controlRC: controlCount,
            permittedMeaning: """
                The directory was enumerated through a descriptor. Entry names were \
                returned for a path this app cannot open, which is a read primitive \
                and the strongest possible result of this experiment.
                """,
            deniedMeaning: """
                Refused. Enumeration through a descriptor is confined the same way \
                opendir is.
                """
        )
    }

    private static func fgetxattrCase(directory: String, documents: String) -> Step {
        guard symbolsAvailable, pathExists(directory) else {
            return unavailableOrMissing("fgetxattr-fd-\(directory)",
                                        "fgetxattr(fd, name, NULL, 0, 0, 0)", directory)
        }
        let controlFD = openEvtonly(documents)
        guard controlFD >= 0 else {
            return prerequisiteFailed("fgetxattr-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(controlFD) }
        let controlRC = callFgetxattr(controlFD)

        let fd = openEvtonly(directory)
        guard fd >= 0 else {
            return prerequisiteFailed("fgetxattr-fd-\(directory)", directory)
        }
        defer { _ = POSIXShim.closeFile(fd) }
        let rc = callFgetxattr(fd)

        return makeStep(
            id: "fgetxattr-fd-\(directory)",
            mechanism: """
                An extended attribute read through a descriptor. Separate from \
                file-read-xattr's path form, which is tested in MetadataReadProbe.
                """,
            operation: "fgetxattr(fd, name, NULL, 0, 0, 0)",
            arguments: "fd for \(directory)",
            expected: """
                Denied with EPERM, or reachable only once an event-only descriptor \
                has been granted for the path.
                """,
            rc: rc,
            controlRC: controlRC,
            permittedMeaning: """
                An extended attribute was read through a descriptor for a protected \
                directory.
                """,
            deniedMeaning: """
                Refused. Descriptor-based attribute reads are confined the same way \
                the path-based ones are.
                """
        )
    }

    // MARK: - Raw calls

    private static func openEvtonly(_ path: String) -> Int32 {
        setErrno(0)
        return POSIXShim.openFile(path, kO_EVTONLY, 0)
    }

    private static func callFgetattrlist(_ fd: Int32) -> Int {
        #if canImport(Darwin)
        let attrlist = UnsafeMutableRawPointer.allocate(
            byteCount: attrlistBufferSize, alignment: 8
        )
        defer { attrlist.deallocate() }
        memset(attrlist, 0, attrlistBufferSize)
        attrlist.storeBytes(of: attrBitMapCount, toByteOffset: 0, as: UInt16.self)
        attrlist.storeBytes(of: attrCmnName, toByteOffset: 4, as: UInt32.self)

        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: attributeBufferSize, alignment: 8
        )
        defer { buffer.deallocate() }

        setErrno(0)
        return Int(sFgetattrlist(fd, attrlist, buffer, attributeBufferSize, 0))
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func callFgetxattr(_ fd: Int32) -> Int {
        #if canImport(Darwin)
        setErrno(0)
        return "com.apple.metadata".withCString { name in
            Int(sFgetxattr(fd, name, nil, 0, 0, 0))
        }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func callGetdirentriesattr(_ fd: Int32) -> Int {
        #if canImport(Darwin)
        let attrlist = UnsafeMutableRawPointer.allocate(
            byteCount: attrlistBufferSize, alignment: 8
        )
        defer { attrlist.deallocate() }
        memset(attrlist, 0, attrlistBufferSize)
        attrlist.storeBytes(of: attrBitMapCount, toByteOffset: 0, as: UInt16.self)
        attrlist.storeBytes(of: attrCmnName, toByteOffset: 4, as: UInt32.self)

        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: attributeBufferSize, alignment: 8
        )
        defer { buffer.deallocate() }

        var count: UInt32 = 0
        setErrno(0)
        let rc = sGetdirentriesattr(
            fd, attrlist, buffer, attributeBufferSize, &count, nil, nil, 0
        )
        if rc == 0 { return Int(count) }
        return -1
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    // MARK: - Shared helpers

    /// The errno is read immediately after the call, before anything else can
    /// disturb it.
    private static func makeStep(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expected: String,
        rc: Int,
        controlRC: Int,
        permittedMeaning: String,
        deniedMeaning: String
    ) -> Step {
        let err = currentErrno()
        let errnoName = rc < 0 ? ErrorClassifier.errnoName(err) : nil

        guard controlRC >= 0 else {
            return Step(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .controlFailed,
                errnoName: errnoName, errnoNumber: rc < 0 ? err : nil,
                entryCount: nil,
                observed: "the control inside the container itself failed",
                interpretation: """
                    The control failed, so a refusal outside is uninterpretable: \
                    it could mean the policy denies the operation, or that the \
                    operation does not work on this platform. Nothing is claimed.
                    """
            )
        }

        let permitted = rc >= 0
        return Step(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, expected: expected, expectedDenied: true,
            outcome: permitted ? .permitted : .denied,
            errnoName: errnoName,
            errnoNumber: permitted ? nil : err,
            entryCount: permitted ? rc : nil,
            observed: permitted ? "the call returned \(rc)" : "refused with \(errnoName ?? "an unknown errno")",
            interpretation: permitted ? permittedMeaning : deniedMeaning
        )
    }

    private static func pathExists(_ path: String) -> Bool {
        var buffer = StatBuffer()
        return POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0
    }

    private static func missingPath(
        _ id: String, _ operation: String, _ path: String
    ) -> Step {
        Step(
            id: id,
            mechanism: """
                A descriptor-based primitive. The target path does not exist on \
                this platform, so the experiment was not run.
                """,
            operation: operation,
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .notAttempted,
            errnoName: nil, errnoNumber: nil, entryCount: nil,
            observed: "the path does not exist here",
            interpretation: """
                NOT ATTEMPTED: this path is an iOS location and does not exist on \
                this platform. Running it would produce ENOENT and say nothing \
                about the sandbox.
                """
        )
    }

    private static func unavailableOrMissing(
        _ id: String, _ operation: String, _ path: String
    ) -> Step {
        if !symbolsAvailable {
            return Step(
                id: id,
                mechanism: """
                    A descriptor-based primitive. The symbol is not present on this \
                    platform, so the experiment was never attempted.
                    """,
                operation: operation,
                arguments: path,
                expected: "Denied with EPERM on a protected path.",
                expectedDenied: true,
                outcome: .symbolUnavailable,
                errnoName: nil, errnoNumber: nil, entryCount: nil,
                observed: nil,
                interpretation: """
                    The symbol could not be resolved, so no measurement was made. \
                    This is a statement about the platform, not a denial.
                    """
            )
        }
        return missingPath(id, operation, path)
    }

    private static func prerequisiteFailed(_ id: String, _ path: String) -> Step {
        Step(
            id: id,
            mechanism: """
                A descriptor-based primitive that requires an event-only \
                descriptor for the target path first.
                """,
            operation: "descriptor-based primitive",
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .prerequisiteFailed,
            errnoName: nil, errnoNumber: nil, entryCount: nil,
            observed: "no event-only descriptor was available for the path",
            interpretation: """
                NOT ATTEMPTED: the prerequisite open() did not produce a descriptor, \
                so this step could not run. A refusal here would say nothing about \
                this operation's own authorization.
                """
        )
    }

    private static func controlFailed(_ id: String, _ path: String, _ control: String) -> Step {
        Step(
            id: id,
            mechanism: """
                O_EVTONLY: an event-only descriptor rather than a readable one.
                """,
            operation: "open(path, O_EVTONLY)",
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .controlFailed,
            errnoName: nil, errnoNumber: nil, entryCount: nil,
            observed: "the control at \(control) itself failed",
            interpretation: """
                The control failed, so a refusal outside is uninterpretable. \
                Nothing is claimed about the boundary.
                """
        )
    }
}
