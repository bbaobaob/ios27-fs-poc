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

    /// A byte count from a call, or zero.
    ///
    /// An "absent" answer is only meaningful when the path exists. If it does not,
    /// ENOENT is simply the truth about a missing path and says nothing whatever
    /// about the sandbox — reporting it as an authorization failure would
    /// fabricate a finding out of a path that was never there. This guard is what
    /// separates a measurement from an artifact, and it is why the macOS CI run
    /// does not produce violations: `/var/mobile/Library` does not exist there.
    private static func pathExists(_ path: String) -> Bool {
        var buffer = StatBuffer()
        return POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0
    }

    // MARK: - Resolved symbols
    //
    // These are bound by symbol name rather than resolved through dlsym. The
    // dlsym route was tried first and crashed the macOS test runner with SIGABRT:
    // a symbol address obtained that way is not verifiably a function pointer, and
    // calling it when it is not one aborts the process. Binding by name lets the
    // linker resolve the real symbol and the compiler type-check the signature,
    // which is the pattern the operation-class module already uses successfully.
    //
    // None of these exist on the non-Darwin verification host, so the whole
    // section is gated and the host reports the experiments as unattempted rather
    // than fabricating results.

    #if canImport(Darwin)

    @_silgen_name("getxattr")
    private static func sGetxattr(
        _ path: UnsafePointer<CChar>, _ name: UnsafePointer<CChar>,
        _ value: UnsafeMutableRawPointer?, _ size: Int,
        _ position: UInt32, _ options: UInt32
    ) -> Int

    @_silgen_name("listxattr")
    private static func sListxattr(
        _ path: UnsafePointer<CChar>, _ namebuf: UnsafeMutableRawPointer?,
        _ size: Int, _ options: UInt32
    ) -> Int

    @_silgen_name("getattrlist")
    private static func sGetattrlist(
        _ path: UnsafePointer<CChar>, _ alist: UnsafeMutableRawPointer,
        _ attributeBuffer: UnsafeMutableRawPointer?, _ bufferSize: Int,
        _ options: UInt32
    ) -> Int

    @_silgen_name("statfs64")
    private static func sStatfs64(
        _ path: UnsafePointer<CChar>, _ buf: UnsafeMutableRawPointer
    ) -> Int

    /// True when the platform provides these calls.
    private static var symbolsAvailable: Bool { true }

    #else

    /// None of these exist here, so no measurement is made.
    private static var symbolsAvailable: Bool { false }

    #endif

    /// A generic attribute name. Chosen to probe the authorization check, not to
    /// extract private data.
    private static let probeAttributeName = "com.apple.metadata"

    /// ATTR_BIT_MAP_COUNT on Darwin: the number of attrgroup words that follow.
    private static let attrBitMapCount: UInt16 = 5
    /// ATTR_CMN_NAME.
    private static let attrCmnName: UInt32 = 0x00000001

    /// Buffer sizes. Generous, so a struct-size mismatch cannot overflow.
    ///
    /// The statfs buffer has to be sized against the kernel's struct, not a
    /// guess. `struct statfs64` on Darwin carries two PATH_MAX (1024-byte) arrays
    /// for the mount-on and mount-from names plus the fixed fields, which comes to
    /// roughly 2160 bytes. A 2048-byte buffer overflowed the heap and aborted the
    /// macOS test runner with SIGABRT, non-deterministically -- one test passed and
    /// a later one crashed, which is the signature of heap corruption rather than a
    /// logic error. 8192 leaves ample headroom.
    private static let attrlistBufferSize = 64
    private static let attributeBufferSize = 4096
    private static let statfsBufferSize = 8192

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
        guard symbolsAvailable else {
            return unavailable("getxattr-\(directory)", "getxattr(path, name, NULL, 0, 0, 0)",
                              directory)
        }
        if !pathExists(directory) {
            return missingPath("getxattr-\(directory)",
                               "getxattr(path, name, NULL, 0, 0, 0)", directory)
        }
        let controlRC = callGetxattr(documents, probeAttributeName)
        let control = classify(controlRC)
        let rc = callGetxattr(directory, probeAttributeName)
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
        guard symbolsAvailable else {
            return unavailable("listxattr-\(directory)", "listxattr(path, NULL, 0, 0)", directory)
        }
        if !pathExists(directory) {
            return missingPath("listxattr-\(directory)",
                               "listxattr(path, NULL, 0, 0)", directory)
        }
        let controlRC = callListxattr(documents)
        let control = classify(controlRC)
        let rc = callListxattr(directory)
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
        guard symbolsAvailable else {
            return unavailable("getattrlist-\(directory)",
                              "getattrlist(path, &attrlist, buf, size, 0)", directory)
        }
        if !pathExists(directory) {
            return missingPath("getattrlist-\(directory)",
                               "getattrlist(path, &attrlist, buf, size, 0)", directory)
        }
        let controlRC = callGetattrlist(documents)
        let control = classify(controlRC)
        let rc = callGetattrlist(directory)
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
        guard symbolsAvailable else {
            return unavailable("statfs-\(directory)", "statfs64(path, &buf)", directory)
        }
        if !pathExists(directory) {
            return missingPath("statfs-\(directory)", "statfs64(path, &buf)", directory)
        }
        let controlRC = callStatfs(documents)
        let control = classify(controlRC)
        let rc = callStatfs(directory)
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
    //
    // Each call is gated to Darwin, where the symbols are bound by name. On the
    // verification host these functions are unreachable, because every case is
    // short-circuited by `symbolsAvailable` before reaching them.

    private static func callGetxattr(
        _ path: String, _ name: String
    ) -> Int {
        #if canImport(Darwin)
        setErrno(0)
        return path.withCString { p in
            name.withCString { n in
                sGetxattr(p, n, nil, 0, 0, 0)
            }
        }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func callListxattr(_ path: String) -> Int {
        #if canImport(Darwin)
        setErrno(0)
        return path.withCString { p in
            sListxattr(p, nil, 0, 0)
        }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func callGetattrlist(_ path: String) -> Int {
        #if canImport(Darwin)
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
            sGetattrlist(p, attrlist, attributeBuffer, attributeBufferSize, 0)
        }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    private static func callStatfs(_ path: String) -> Int {
        #if canImport(Darwin)
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: statfsBufferSize, alignment: 8
        )
        defer { buffer.deallocate() }
        memset(buffer, 0, statfsBufferSize)
        setErrno(0)
        return path.withCString { p in
            sStatfs64(p, buffer)
        }
        #else
        setErrno(ENOSYS)
        return -1
        #endif
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

    /// The path does not exist on this platform, so the experiment cannot run.
    ///
    /// This is deliberately NOT an "absent" answer. An absent answer means the
    /// path was resolved and the requested item was not found, which on a
    /// protected path is evidence the authorization check did not run. A path
    /// that does not exist at all is a different thing entirely, and treating
    /// the two alike is exactly how a platform artifact becomes a false finding.
    private static func missingPath(
        _ id: String, _ operation: String, _ path: String
    ) -> Experiment {
        Experiment(
            id: id,
            mechanism: """
                A read primitive that does not open the file. The target path does                 not exist on this platform, so the experiment was not run.
                """,
            operation: operation,
            arguments: path,
            expected: "Denied with EPERM on a protected path.",
            expectedDenied: true,
            outcome: .notAttempted,
            errnoName: nil, errnoNumber: nil, reportedBytes: nil,
            observed: "the path does not exist here",
            interpretation: """
                NOT ATTEMPTED: this path is an iOS location and does not exist on                 this platform. An ENOENT here would say nothing about the sandbox,                 so the experiment is withheld rather than reported as an absence                 finding.
                """
        )
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
