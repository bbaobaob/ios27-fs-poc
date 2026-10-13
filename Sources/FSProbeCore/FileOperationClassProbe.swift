//
//  FileOperationClassProbe.swift
//  FSProbeCore — untested sandbox operation classes.
//
//  HYPOTHESIS
//  ----------
//  Apple's sandbox authorizes *operations*, not paths. A profile grants or denies
//  `file-write-create`, `file-write-data`, `file-link`, `file-rename`,
//  `file-mkdir`, `file-write-symlink`, `file-mknod`, and so on, each as a
//  separate predicate. Every experiment so far tested a subset of them.
//
//  Tested and refused: `file-read*`, `file-write-create` and `file-write-data`
//  (open+create, open+write), `file-link` with a *protected source*
//  (`link("/usr/lib/dyld", container)`), and `file-rename` across the boundary.
//
//  NOT tested, each a distinct predicate that could be separately permitted:
//
//    - `file-mkdir`          mkdir() at a protected path
//    - `file-write-symlink`  symlink() creating a link AT a protected path
//    - `file-mknod`          mkfifo()/mknod() at a protected path
//    - `file-link`           link() with a protected DESTINATION
//
//  The last one matters most and is the genuine novelty here. The earlier
//  hard-link experiment linked *from* a protected source *into* the container and
//  was refused. The reverse direction — linking a file this app already owns to a
//  name inside a protected directory — has never been tested. If it were
//  permitted, the app would hold a writable inode reachable from a protected
//  path, which is a write primitive outside the container: the app writes its own
//  file normally, and the change is visible at the protected location because
//  both names refer to the same inode.
//
//  This is not a cosmetic variation of an earlier experiment. It tests a
//  different authorization predicate, and in the link case a different direction
//  of the same operation.
//
//  EXPECTED RESULT
//  ---------------
//  Every operation is refused with EPERM at the protected paths, exactly as the
//  tested classes were. A permitted result on any is a boundary violation.
//
//  CONTROLS
//  --------
//  Each operation runs first at a path inside the container, where it must
//  succeed. Without that control a refusal outside is uninterpretable: it could
//  mean the policy denies it, or that the operation is broken on this platform.
//
//  SAFETY
//  ------
//  Every target is a dedicated synthetic name in a directory this app cannot
//  write to, so nothing existing is modified, replaced, or removed. Creation
//  operations are used rather than modification operations (chmod, chown,
//  truncate, setxattr) deliberately: a modification of a protected file that
//  succeeded would itself be the harm the mission forbids, and on a non-existent
//  path it would be ambiguous, since lookup fails with ENOENT before the MAC
//  check runs. Anything this probe manages to create is removed immediately.
//

import Foundation

public enum FileOperationClassProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The operation succeeded where denial was predicted.
        case permitted
        /// The operation was refused, with the errno recorded.
        case denied
        /// The control for this operation did not succeed, so the result is not
        /// interpretable and nothing is claimed.
        case controlFailed
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
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the call, captured immediately afterwards.
        public let errnoName: String?
        public let errnoNumber: Int32?
        /// Whether anything this probe created was removed again.
        public let cleanedUp: Bool
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
            cleanedUp: Bool,
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
            self.cleanedUp = cleanedUp
            self.observed = observed
            self.interpretation = interpretation
        }

        /// A violation is a success where the policy predicted refusal.
        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
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

    /// The synthetic base name used for every target, so nothing existing is
    /// ever the subject of an operation.
    private static let syntheticName = "fsprobe-opclass"

    /// Protected directories on the same volume as the container. `/var/tmp` is
    /// deliberately excluded: a rename to it returned EXDEV, so it is a different
    /// volume and a refusal there would not be attributable to policy.
    private static let protectedDirectories = [
        "/var/mobile/Library",
        "/var/mobile/Media",
    ]

    // The three creation calls, bound by symbol name so the harness does not
    // depend on these headers being importable by Swift. All are ordinary
    // documented libSystem functions.
    @_silgen_name("mkdir")
    private static func cMkdir(_ path: UnsafePointer<CChar>, _ mode: UInt16) -> Int32

    @_silgen_name("symlink")
    private static func cSymlink(
        _ target: UnsafePointer<CChar>, _ linkpath: UnsafePointer<CChar>
    ) -> Int32

    @_silgen_name("mkfifo")
    private static func cMkfifo(_ path: UnsafePointer<CChar>, _ mode: UInt16) -> Int32

    /// Run every untested operation class, each with a control inside the
    /// container and a test at each protected directory.
    ///
    /// - Parameter containerPath: the app's own container, which supplies both
    ///   the control location and the file the reverse-direction link test uses.
    public static func probe(containerPath: String) -> Result {
        var experiments: [Experiment] = []
        let documents = containerPath + "/Documents"

        // A file this app owns, used as the source for the reverse-direction
        // hard-link test. Created with an ordinary write so the link test has a
        // real inode to point at.
        let sourcePath = documents + "/\(syntheticName)-linksource"
        let sourceCreated = createSyntheticFile(at: sourcePath)

        for directory in protectedDirectories {
            experiments.append(mkdirCase(directory: directory, documents: documents))
            experiments.append(symlinkCase(directory: directory, documents: documents))
            experiments.append(mkfifoCase(directory: directory, documents: documents))
            if sourceCreated {
                experiments.append(reverseLinkCase(
                    directory: directory,
                    documents: documents,
                    sourcePath: sourcePath
                ))
            } else {
                experiments.append(Experiment(
                    id: "link-reverse-destination-\(directory)",
                    mechanism: """
                        file-link with a protected destination: linking a file this \
                        app owns to a name inside a protected directory. If permitted, \
                        the app holds a writable inode reachable from a protected path.
                        """,
                    operation: "link()",
                    arguments: "\(sourcePath) -> \(directory)/\(syntheticName)-linkreverse",
                    expected: "Denied. The destination lies outside the container.",
                    expectedDenied: true,
                    outcome: .notAttempted,
                    errnoName: nil, errnoNumber: nil, cleanedUp: true,
                    observed: nil,
                    interpretation: """
                        The source file could not be created inside the container, so \
                        there was no inode to link from and the experiment was not run.
                        """
                ))
            }
        }

        if sourceCreated {
            _ = POSIXShim.unlinkFile(sourcePath)
        }

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(experiments: experiments, violations: violations)
    }

    // MARK: - Cases

    private static func mkdirCase(directory: String, documents: String) -> Experiment {
        let controlTarget = documents + "/\(syntheticName)-mkdir-control"
        let controlRC = performMkdir(at: controlTarget)
        let controlOK = controlRC == 0
        if controlOK { _ = rmdir(controlTarget) }

        let target = directory + "/\(syntheticName)-mkdir"
        let rc = performMkdir(at: target)
        // Always clean up, whichever way it went.
        var cleanedUp = true
        if rc == 0 { cleanedUp = rmdir(target) == 0 }

        return makeExperiment(
            id: "mkdir-\(directory)",
            mechanism: """
                file-mkdir: creating a directory at a protected path. A separate \
                sandbox predicate from file-write-create, and separately permitted \
                or denied.
                """,
            operation: "mkdir(path, 0755)",
            arguments: target,
            expected: "Denied. The path lies outside the container.",
            rc: rc,
            controlSucceeded: controlOK,
            controlDetail: "control mkdir inside the container \(controlOK ? "succeeded" : "failed")",
            cleanedUp: cleanedUp,
            permittedObservation: "A directory was created at a protected path.",
            deniedObservation: "mkdir was refused."
        )
    }

    private static func symlinkCase(directory: String, documents: String) -> Experiment {
        let controlTarget = documents + "/\(syntheticName)-symlink-control"
        let controlRC = performSymlink(target: "/", linkPath: controlTarget)
        let controlOK = controlRC == 0
        if controlOK { _ = POSIXShim.unlinkFile(controlTarget) }

        let target = directory + "/\(syntheticName)-symlink"
        // The link points at a harmless target: what is under test is whether the
        // link may be *created* at the protected path, not what it resolves to.
        let rc = performSymlink(target: "/", linkPath: target)
        var cleanedUp = true
        if rc == 0 { cleanedUp = POSIXShim.unlinkFile(target) == 0 }

        return makeExperiment(
            id: "symlink-\(directory)",
            mechanism: """
                file-write-symlink: creating a symbolic link AT a protected path. \
                Distinct from the earlier symlink-escape experiment, which read \
                THROUGH a link that lived inside the container. Here the link itself \
                would be created outside it, so anything reading the protected path \
                would follow a link this app controls.
                """,
            operation: "symlink(target, linkpath)",
            arguments: "/ -> \(target)",
            expected: "Denied. The link path lies outside the container.",
            rc: rc,
            controlSucceeded: controlOK,
            controlDetail: "control symlink inside the container \(controlOK ? "succeeded" : "failed")",
            cleanedUp: cleanedUp,
            permittedObservation: """
                A symbolic link was created at a protected path, so a protected path \
                now resolves through a link this app controls.
                """,
            deniedObservation: "symlink was refused."
        )
    }

    private static func mkfifoCase(directory: String, documents: String) -> Experiment {
        let controlTarget = documents + "/\(syntheticName)-fifo-control"
        let controlRC = performMkfifo(at: controlTarget)
        let controlOK = controlRC == 0
        if controlOK { _ = POSIXShim.unlinkFile(controlTarget) }

        let target = directory + "/\(syntheticName)-fifo"
        let rc = performMkfifo(at: target)
        var cleanedUp = true
        if rc == 0 { cleanedUp = POSIXShim.unlinkFile(target) == 0 }

        return makeExperiment(
            id: "mkfifo-\(directory)",
            mechanism: """
                file-mknod: creating a special file at a protected path. A distinct \
                predicate from file-write-create, and never tested before.
                """,
            operation: "mkfifo(path, 0644)",
            arguments: target,
            expected: "Denied. The path lies outside the container.",
            rc: rc,
            controlSucceeded: controlOK,
            controlDetail: "control mkfifo inside the container \(controlOK ? "succeeded" : "failed")",
            cleanedUp: cleanedUp,
            permittedObservation: "A FIFO was created at a protected path.",
            deniedObservation: "mkfifo was refused."
        )
    }

    private static func reverseLinkCase(
        directory: String,
        documents: String,
        sourcePath: String
    ) -> Experiment {
        // Control: the same operation in the reverse direction, inside the
        // container, so a refusal outside is interpretable.
        let controlTarget = documents + "/\(syntheticName)-linkreverse-control"
        let controlRC = performLink(from: sourcePath, to: controlTarget)
        let controlOK = controlRC == 0
        if controlOK { _ = POSIXShim.unlinkFile(controlTarget) }

        let target = directory + "/\(syntheticName)-linkreverse"
        let rc = performLink(from: sourcePath, to: target)
        var cleanedUp = true
        if rc == 0 {
            // Remove the name we created at the protected path. The source file's
            // own link count drops by one; the inode survives because the source
            // name still refers to it.
            cleanedUp = POSIXShim.unlinkFile(target) == 0
        }

        return makeExperiment(
            id: "link-reverse-destination-\(directory)",
            mechanism: """
                file-link with a protected destination: the reverse direction of the \
                hard-link experiment already run. That one linked FROM a protected \
                source INTO the container and was refused; this links a file the app \
                owns TO a name inside a protected directory. If permitted, the app \
                holds a writable inode reachable from a protected path, so writing \
                its own file changes what a protected path resolves to.
                """,
            operation: "link(existing, new)",
            arguments: "\(sourcePath) -> \(target)",
            expected: "Denied. The destination lies outside the container.",
            rc: rc,
            controlSucceeded: controlOK,
            controlDetail: "control link inside the container \(controlOK ? "succeeded" : "failed")",
            cleanedUp: cleanedUp,
            permittedObservation: """
                A hard link to a file this app owns was created at a protected path. \
                The app can now write its own file and have the change appear at a \
                protected location, because both names refer to the same inode.
                """,
            deniedObservation: "link was refused."
        )
    }

    // MARK: - Helpers

    /// Build an experiment from a return code, applying the control gate.
    ///
    /// The control gate is what keeps a broken operation from being reported as a
    /// sandbox denial: if the same call inside the container failed, the refusal
    /// outside says nothing about policy.
    private static func makeExperiment(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expected: String,
        rc: Int32,
        controlSucceeded: Bool,
        controlDetail: String,
        cleanedUp: Bool,
        permittedObservation: String,
        deniedObservation: String
    ) -> Experiment {
        // errno is read immediately, before any other call can disturb it.
        let err = currentErrno()
        let errnoName = rc == 0 ? nil : ErrorClassifier.errnoName(err)
        let errnoNumber: Int32? = rc == 0 ? nil : err

        guard controlSucceeded else {
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .controlFailed,
                errnoName: errnoName, errnoNumber: errnoNumber,
                cleanedUp: cleanedUp,
                observed: "\(controlDetail); the call outside returned rc=\(rc)",
                interpretation: """
                    The control failed, so a refusal outside is uninterpretable: it \
                    could mean the policy denies the operation, or that the operation \
                    does not work on this platform at all. Nothing is claimed about \
                    the boundary.
                    """
            )
        }

        if rc == 0 {
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments, expected: expected, expectedDenied: true,
                outcome: .permitted,
                errnoName: nil, errnoNumber: nil, cleanedUp: cleanedUp,
                observed: permittedObservation,
                interpretation: """
                    The operation succeeded at a path outside the container. \(permittedObservation) \
                    The artifact was \(cleanedUp ? "removed afterwards" : "NOT removed").
                    """
            )
        }

        return Experiment(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, expected: expected, expectedDenied: true,
            outcome: .denied,
            errnoName: errnoName, errnoNumber: errnoNumber, cleanedUp: cleanedUp,
            observed: "\(deniedObservation) \(controlDetail).",
            interpretation: """
                Refused with \(errnoName ?? "an unknown errno"), the sandbox signature. \
                The control succeeded, so this is a policy denial rather than a broken \
                operation.
                """
        )
    }

    private static func performMkdir(at path: String) -> Int32 {
        setErrno(0)
        return path.withCString { cMkdir($0, 0o755) }
    }

    private static func performSymlink(target: String, linkPath: String) -> Int32 {
        setErrno(0)
        return target.withCString { t in
            linkPath.withCString { l in
                cSymlink(t, l)
            }
        }
    }

    private static func performMkfifo(at path: String) -> Int32 {
        setErrno(0)
        return path.withCString { cMkfifo($0, 0o644) }
    }

    private static func performLink(from source: String, to destination: String) -> Int32 {
        setErrno(0)
        return POSIXShim.linkFile(source, destination)
    }

    /// Open flags. These differ between Darwin and the verification host, so they
    /// are spelled out per platform rather than assumed: on Linux `O_CREAT` is
    /// 0x40 and `O_TRUNC` is 0x200, while on Darwin `O_CREAT` is 0x200 and
    /// `O_TRUNC` is 0x400. Using the Darwin values everywhere silently failed to
    /// create the link source on the verification host, which then skipped the
    /// reverse-direction link experiment entirely -- a test that passed while
    /// measuring nothing.
    #if canImport(Darwin)
    private static let kO_RDWR: Int32 = 0x0002
    private static let kO_CREAT: Int32 = 0x0200
    private static let kO_TRUNC: Int32 = 0x0400
    #else
    private static let kO_RDWR: Int32 = 0x0002
    private static let kO_CREAT: Int32 = 0x0040
    private static let kO_TRUNC: Int32 = 0x0200
    #endif

    /// Create a synthetic file with an ordinary write, for the link source.
    private static func createSyntheticFile(at path: String) -> Bool {
        let payload = Array("fsprobe opclass link source\n".utf8)
        let fd = POSIXShim.openFile(
            path, kO_RDWR | kO_CREAT | kO_TRUNC, 0o600
        )
        guard fd >= 0 else { return false }
        defer { _ = POSIXShim.closeFile(fd) }
        let written = payload.withUnsafeBufferPointer { buffer in
            // withUnsafeBufferPointer yields an optional base address so an empty
            // buffer is representable; this payload is never empty.
            POSIXShim.writeFD(fd, buffer.baseAddress!, buffer.count)
        }
        return written == payload.count
    }

    @_silgen_name("rmdir")
    private static func rmdir(_ path: UnsafePointer<CChar>) -> Int32

    private static func rmdir(_ path: String) -> Int32 {
        setErrno(0)
        return path.withCString { rmdir($0) }
    }
}
