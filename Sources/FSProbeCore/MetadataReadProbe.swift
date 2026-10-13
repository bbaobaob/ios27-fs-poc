//
//  MetadataReadProbe.swift
//  FSProbeCore — read primitives that do not open the file.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far tested operations that *open* a file: open(),
//  opendir(), readdir(), lstat(), stat(), link(), rename(), clonefile(),
//  openbyid_np(). Apple's sandbox authorizes operations, not paths, and each of
//  those is a separate predicate.
//
//  There is a whole class of read primitives that never open a file and that
//  this project has never tested:
//
//    getxattr()    read an extended attribute without opening the file
//    listxattr()   list extended attribute names without opening the file
//    getattrlist() read an arbitrary set of attributes without opening the file
//    statfs()      read filesystem/mount information for a path
//
//  These are separate sandbox predicates from file-read-data. If any of them is
//  not confined to the container, an app obtains a read primitive on protected
//  paths without ever needing permission to open them.
//
//  THE DISCRIMINATING SIGNAL
//  -------------------------
//  EPERM means the policy refused. ENOENT, ENOATTR, or ENOTSUP mean something
//  quite different and far more interesting: the path was resolved and
//  authorized, and the call simply found nothing there. On a protected path,
//  an "absent" answer rather than a refusal is evidence that the authorization
//  check did not run, because an unauthorized path never reaches the point of
//  being found absent.
//
//  That distinction is the entire experiment. Reporting ENOATTR as a denial
//  would discard the finding; reporting EPERM as "absent" would fabricate one.
//
//  EXPECTED RESULT
//  ---------------
//  Every operation refused with EPERM on protected paths, exactly as the
//  open-based operations were.
//
//  CONTROL
//  -------
//  Each operation runs first on a path inside the container, where it must
//  return a meaningful answer. Without that control a refusal outside is
//  uninterpretable: it could mean the policy denies it, or that the operation
//  does not work on this platform at all.
//
//  SAFETY
//  ------
//  These are read-only calls on paths that exist. Nothing is written, created,
//  or removed. Attribute names requested are generic ones chosen to probe the
//  authorization check, not names chosen to extract private data.
//

import Foundation

public enum MetadataReadProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call returned a meaningful answer.
        case answered
        /// The call was refused with EPERM.
        case denied
        /// The path was resolved but the requested item was absent. On a
        /// protected path this means the authorization check did not run.
        case absent
        /// The control did not produce a meaningful answer, so the result is not
        /// interpretable.
        case controlFailed
        /// The symbol could not be resolved, so the operation was never attempted.
        case symbolUnavailable
        /// The operation was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        /// The sandbox operation class under test.
        public let mechanism: String
        /// The libc call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when a non-refusal answer would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the call, captured immediately afterwards.
        public let errnoName: String?
        public let errnoNumber: Int32?
        /// How many bytes of data the call reported, when it reported any.
        public let reportedBytes: Int?
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
            reportedBytes: Int?,
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
            self.reportedBytes = reportedBytes
            self.observed = observed
            self.interpretation = interpretation
        }

        /// A violation is a non-refusal answer where refusal was predicted.
        ///
        /// `answered` and `absent` both count: an "absent" answer on a protected
        /// path means the path was authorized and resolved, which is itself the
        /// authorization check failing to run.
        public var isBoundaryViolation: Bool {
            guard expectedDenied else { return false }
            return outcome == .answered || outcome == .absent
        }
    }

    public struct Result: Sendable, Codable {
        public let experiments: [Experiment]
        public let violations: [Experiment]

        public init(experiments: [Experiment], violations: [Experiment]) {
            self.experiments = experiments
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

    // MARK: - Resolved symbols

    private typealias GetxattrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafeMutableRawPointer?,
        Int, UInt32, UInt32
    ) -> Int

    private typealias ListxattrFn = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutableRawPointer?, Int, UInt32
    ) -> Int

    private typealias GetattrlistFn = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutableRawPointer, UnsafeMutableRawPointer?,
        Int, UInt32
    ) -> Int

    private typealias StatfsFn = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutableRawPointer
    ) -> Int

    private static func getxattrFn() -> GetxattrFn? {
        guard let sym = POSIXShim.lookupSymbol("getxattr") else { return nil }
        return unsafeBitCast(sym, to: GetxattrFn.self)
    }

    private static func listxattrFn() -> ListxattrFn? {
        guard let sym = POSIXShim.lookupSymbol("listxattr") else { return nil }
        return unsafeBitCast(sym, to: ListxattrFn.self)
    }

    private static func getattrlistFn() -> GetattrlistFn? {
        guard let sym = POSIXShim.lookupSymbol("getattrlist") else { return nil }
        return unsafeBitCast(sym, to: GetattrlistFn.self)
    }

    private static func statfsFn() -> StatfsFn? {
        // The 64-bit variant is the one that matters on a 64-bit device.
        guard let sym = POSIXShim.lookupSymbol("statfs64") else {
            guard let fallback = POSIXShim.lookupSymbol("statfs") else { return nil }
            return unsafeBitCast(fallback, to: StatfsFn.self)
        }
        return unsafeBitCast(sym, to: StatfsFn.self)
    }

    /// A generic attribute name. Chosen to probe the authorization check, not to
    /// extract private data.
    private static let probeAttributeName = "com.apple.metadata"

    /// ATTR_BIT_MAP_COUNT on Darwin: the number of attrgroup words that follow.
    private static let attrBitMapCount: UInt16 = 5
    /// ATTR_CMN_NAME.
    private static let attrCmnName: UInt32 = 0x00000001

    /// Buffer sizes. Generous, so a struct-size mismatch cannot overflow.
    private static let attrlistBufferSize = 64
    private static let attributeBufferSize = 4096
    private static let statfsBufferSize = 2048

    public static func probe(containerPath: String) -> Result {
        var experiments: [Experiment] = []
        let documents = containerPath + "/Documents"

        for directory in protectedDirectories {
            experiments.append(getxattrCase(
                directory: directory, documents: documents))
            experiments.append(listxattrCase(
                directory: directory, documents: documents))
            experiments.append(getattrlistCase(
                directory: directory, documents: documents))
            experiments.append(statfsCase(
                directory: directory, documents: documents))
        }

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(experiments: experiments, violations: violations)
    }

    // MARK: - Cases

    private static func getxattrCase(directory: String, documents: String) -> Experiment {
        guard let fn = getxattrFn() else {
            return unavailable("getxattr-\(directory)", "getxattr(path, name, NULL, 0, 0, 0)",
                              directory)
        }
        let controlRC = callGetxattr(fn, documents, probeAttributeName)
        let control = classify(controlRC)
        let rc = callGetxattr(fn, directory, probeAttributeName)
        return makeExperiment(
            id: "getxattr-\(directory)",
            mechanism: """
                file-read-xattr: reading an extended attribute without opening the \
                file. A separate sandbox predicate from file-read-data, and never \
                tested in this project.
                """,
            operation: "getxattr(path, name, NULL, 0, 0, 0)",
            arguments: "\(directory) xattr=\(probeAttributeName)",
            expected: """
                Denied with EPERM. An ENOATTR or success would mean the path was \
                resolved and authorized without the caller holding permission.
                """,
            rc: rc,
            control: control,
            controlPath: documents,
            answeredMeaning: """
                getxattr answered on a protected path. The attribute may or may not \
                exist, but the call reached the filesystem rather than being refused, \
                which means the file-read-xattr predicate is not confined to the \
                container.
                """,
            absentMeaning: """
                The path was resolved and the attribute was simply absent. On a \
                protected path an absence answer rather than a refusal is the \
                interesting result: the authorization check did not run, because an \
                unauthorized path never reaches the point of being found absent.
                """,
            deniedMeaning: """
                Refused. file-read-xattr is confined to the container, exactly as the \
                open-based read operations were.
                """
        )
    }

    private static func listxattrCase(directory: String, documents: String) -> Experiment {
        guard let fn = listxattrFn() else {
            return unavailable("listxattr-\(directory)", "listxattr(path, NULL, 0, 0)", directory)
        }
        let controlRC = callListxattr(fn, documents)
        let control = classify(controlRC)
        let rc = callListxattr(fn, directory)
        return makeExperiment(
            id: "listxattr-\(directory)",
            mechanism: """
                file-list-xattr: listing extended attribute names without opening the \
                file. Distinct from file-read-xattr and never tested.
                """,
            operation: "listxattr(path, NULL, 0, 0)",
            arguments: directory,
            expected: """
                Denied with EPERM. A byte count, or zero, would mean the path was \
                resolved and authorized without the caller holding permission.
                """,
            rc: rc,
            control: control,
            controlPath: documents,
            answeredMeaning: """
                listxattr reported a size on a protected path. The call reached the \
                filesystem rather than being refused, so file-list-xattr is not \
                confined to the container. Reading the names would be the follow-up.
                """,
            absentMeaning: """
                The path was resolved and there are simply no attributes. An absence \
                answer rather than a refusal is the interesting result: the \
                authorization check did not run.
                """,
            deniedMeaning: """
                Refused. file-list-xattr is confined to the container.
                """
        )
    }

    private static func getattrlistCase(directory: String, documents: String) -> Experiment {
        guard let fn = getattrlistFn() else {
            return unavailable("getattrlist-\(directory)",
                              "getattrlist(path, &attrlist, buf, size, 0)", directory)
        }
        let controlRC = callGetattrlist(fn, documents)
        let control = classify(controlRC)
        let rc = callGetattrlist(fn, directory)
        return makeExperiment(
            id: "getattrlist-\(directory)",
            mechanism: """
                A single call that can return an arbitrary set of attributes -- name, \
                object type, timestamps, identifiers -- without opening the file. The \
                getattrlistbulk variant is what FileManager uses for enumeration; the \
                scalar form on a specific path has never been tested here.
                """,
            operation: "getattrlist(path, &attrlist, buf, size, 0)",
            arguments: directory,
            expected: """
                Denied with EPERM. Any attribute data returned would mean the path was \
                resolved and authorized without the caller holding permission.
                """,
            rc: rc,
            control: control,
            controlPath: documents,
            answeredMeaning: """
                getattrlist returned attribute data on a protected path. That is a \
                read primitive on a path the app cannot open.
                """,
            absentMeaning: """
                The path was resolved but no attributes were produced. An absence \
                answer rather than a refusal is the interesting result: the \
                authorization check did not run.
                """,
            deniedMeaning: """
                Refused. getattrlist is confined to the container.
                """
        )
    }

    private static func statfsCase(directory: String, documents: String) -> Experiment {
        guard let fn = statfsFn() else {
            return unavailable("statfs-\(directory)", "statfs64(path, &buf)", directory)
        }
        let controlRC = callStatfs(fn, documents)
        let control = classify(controlRC)
        let rc = callStatfs(fn, directory)
        return makeExperiment(
            id: "statfs-\(directory)",
            mechanism: """
                Filesystem and mount information for a path: block size, free space, \
                mount point, filesystem type. A separate predicate from any file \
                operation, and never tested.
                """,
            operation: "statfs64(path, &buf)",
            arguments: directory,
            expected: """
                Denied with EPERM, or a result that discloses nothing beyond what the \
                app can already see for its own container.
                """,
            rc: rc,
            control: control,
            controlPath: documents,
            answeredMeaning: """
                statfs succeeded on a protected path. Mount metadata was disclosed \
                for a directory the app cannot enumerate.
                """,
            absentMeaning: """
                The path was resolved but no filesystem information was produced. An \
                absence answer rather than a refusal is the interesting result: the \
                authorization check did not run.
                """,
            deniedMeaning: """
                Refused. statfs is confined to the container.
                """
        )
    }

    // MARK: - Raw calls

    private static func callGetxattr(
        _ fn: GetxattrFn, _ path: String, _ name: String
    ) -> Int {
        setErrno(0)
        return path.withCString { p in
            name.withCString { n in
                fn(p, n, nil, 0, 0, 0)
            }
        }
    }

    private static func callListxattr(_ fn: ListxattrFn, _ path: String) -> Int {
        setErrno(0)
        return path.withCString { p in
            fn(p, nil, 0, 0)
        }
    }

    private static func callGetattrlist(_ fn: GetattrlistFn, _ path: String) -> Int {
        let attrlist = UnsafeMutableRawPointer.allocate(
            byteCount: attrlistBufferSize, alignment: 8
        )
        defer { attrlist.deallocate() }
        // Zero the request, then ask only for the name. An all-zero request is
        // well formed: it asks for nothing, which is enough to learn whether the
        // authorization check runs.
        memset(attrlist, 0, attrlistBufferSize)
        attrlist.storeBytes(
            of: attrBitMapCount, toByteOffset: 0, as: UInt16.self
        )
        attrlist.storeBytes(
            of: attrCmnName, toByteOffset: 4, as: UInt32.self
        )

        let attributeBuffer = UnsafeMutableRawPointer.allocate(
            byteCount: attributeBufferSize, alignment: 8
        )
        defer { attributeBuffer.deallocate() }

        setErrno(0)
        return path.withCString { p in
            fn(p, attrlist, attributeBuffer, attributeBufferSize, 0)
        }
    }

    private static func callStatfs(_ fn: StatfsFn, _ path: String) -> Int {
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: statfsBufferSize, alignment: 8
        )
        defer { buffer.deallocate() }
        memset(buffer, 0, statfsBufferSize)
        setErrno(0)
        return path.withCString { p in
            fn(p, buffer)
        }
    }

    // MARK: - Classification

    /// Turn a return code into the answer that matters.
    ///
    /// The errno is read immediately after the call, before anything else can
    /// disturb it.
    private static func classify(_ rc: Int) -> (answer: Answer, errnoName: String?) {
        if rc >= 0 {
            return (.answered, nil)
        }
        let err = currentErrno()
        let name = err == 0 ? nil : ErrorClassifier.errnoName(err)
        switch err {
        case Int32(EPERM): return (.denied, name)
        case Int32(EACCES): return (.denied, name)
        case Int32(ENOENT): return (.absent, name)
        #if canImport(Darwin)
        case Int32(ENOATTR): return (.absent, name)
        #else
        // ENOATTR is 93 on Darwin. On other platforms the branch cannot match,
        // which is correct: the value simply never occurs there.
        case 93: return (.absent, name)
        #endif
        case Int32(ENOTSUP): return (.absent, name)
        case Int32(EOPNOTSUPP): return (.absent, name)
        case Int32(EINVAL): return (.absent, name)
        default: return (.absent, name)
        }
    }

    private enum Answer {
        case answered, denied, absent
    }

    private static func makeExperiment(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expected: String,
        rc: Int,
        control: (answer: Answer, errnoName: String?),
        controlPath: String,
        answeredMeaning: String,
        absentMeaning: String,
        deniedMeaning: String
    ) -> Experiment {
        let (answer, errnoName) = classify(rc)
        let errnoNumber: Int32? = rc < 0 ? currentErrno() : nil

        guard control.answer != .denied else {
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .controlFailed,
                errnoName: errnoName, errnoNumber: errnoNumber,
                reportedBytes: nil,
                observed: """
                    the control at \(controlPath) was itself refused, so a refusal \
                    outside says nothing about policy
                    """,
                interpretation: """
                    The control failed, so this experiment cannot distinguish a policy \
                    denial from a broken operation. Nothing is claimed about the \
                    boundary.
                    """
            )
        }

        switch answer {
        case .answered:
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .answered,
                errnoName: errnoName, errnoNumber: errnoNumber,
                reportedBytes: rc,
                observed: "the call returned \(rc)",
                interpretation: answeredMeaning
            )
        case .absent:
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .absent,
                errnoName: errnoName, errnoNumber: errnoNumber,
                reportedBytes: nil,
                observed: "the path was resolved; the call reported \(errnoName ?? "nothing")",
                interpretation: absentMeaning
            )
        case .denied:
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .denied,
                errnoName: errnoName, errnoNumber: errnoNumber,
                reportedBytes: nil,
                observed: "refused with \(errnoName ?? "an unknown errno")",
                interpretation: deniedMeaning
            )
        }
    }

    private static func unavailable(
        _ id: String, _ operation: String, _ path: String
    ) -> Experiment {
        Experiment(
            id: id,
            mechanism: """
                A read primitive that does not open the file. The symbol is not \
                present on this platform, so the experiment was never attempted.
                """,
            operation: operation,
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .symbolUnavailable,
            errnoName: nil, errnoNumber: nil, reportedBytes: nil,
            observed: nil,
            interpretation: """
                The symbol could not be resolved, so no measurement was made. This is \
                a statement about the platform, not a denial.
                """
        )
    }
}
