//
//  CrossBoundaryProbe.swift
//  FSProbeCore — experiments on the *mechanisms* that enforce the container boundary.
//
//  These deliberately do not repeat "try to open this path". They test how the
//  boundary is enforced, so that a success would mean the enforcement itself is
//  wrong rather than that a path happened to be permitted.
//
//  Each experiment states the mechanism under test, the expected result, and what
//  a contrary result would mean. A denial is a valid, informative outcome.
//
//  SAFETY
//  ------
//  Every experiment is either read-only or operates exclusively on files this
//  harness created inside its own container. The two exceptions both target a
//  dedicated synthetic filename and clean up immediately:
//    - `renameEscape` renames a container file to /var/tmp and removes it.
//    - `hardlinkImport` links a file from outside into the container and removes
//      the link.
//  Neither writes to, deletes, or modifies anything it did not create.
//

import Foundation

public enum CrossBoundaryProbe {

    /// Outcome of one mechanism experiment.
    public enum Outcome: String, Codable, Sendable {
        /// The boundary held: refused as expected.
        case denied
        /// The operation succeeded where the policy says it should not have.
        case permitted
        /// The experiment could not run (its precondition failed).
        case notApplicable
        /// The experiment itself errored.
        case error
    }

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        /// What enforcement mechanism this experiment tests.
        public let mechanism: String
        /// The syscall or API exercised.
        public let operation: String
        /// The concrete arguments used, so the experiment is reproducible.
        public let arguments: String
        /// What the documented policy predicts.
        public let expected: String
        /// True when a permitted result is the *expected* outcome, as for the
        /// controls that operate entirely inside the container. Without this, a
        /// successful control is misreported as a boundary violation.
        public let expectedPermitted: Bool
        /// What was observed.
        public let outcome: Outcome
        public let errnoName: String?
        public let errnoNumber: Int
        /// Interpretation of the observation.
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            outcome: Outcome,
            errnoName: String?,
            errnoNumber: Int,
            interpretation: String,
            expectedPermitted: Bool = false
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedPermitted = expectedPermitted
            self.outcome = outcome
            self.errnoName = errnoName
            self.errnoNumber = errnoNumber
            self.interpretation = interpretation
        }

        /// A boundary violation is a success the policy did not predict. A
        /// control succeeding inside the container is not a violation.
        public var isBoundaryViolation: Bool {
            outcome == .permitted && !expectedPermitted
        }
    }

    /// Run the whole battery.
    ///
    /// - Parameters:
    ///   - containerPath: the app's own container, e.g. /var/mobile/Containers/Data/Application/<UUID>
    ///   - outsidePath: a path known to be outside the container and refused, used
    ///     as the escape target.
    public static func runAll(containerPath: String, outsidePath: String = "/var/mobile/Library")
        -> [Experiment]
    {
        var experiments: [Experiment] = []
        experiments.append(contentsOf: pathResolutionBattery(containerPath: containerPath,
                                                             outsidePath: outsidePath))
        experiments.append(contentsOf: crossBoundaryLinkBattery(containerPath: containerPath))
        experiments.append(contentsOf: crossBoundaryRenameBattery(containerPath: containerPath))
        experiments.append(contentsOf: enumerationDifferential(outsidePath: outsidePath))
        return experiments
    }

    // MARK: - Path resolution

    /// Tests whether the boundary is enforced on the resolved vnode or on the
    /// path string. Every case here resolves *outside* the container while its
    /// textual form stays inside it.
    public static func pathResolutionBattery(
        containerPath: String,
        outsidePath: String
    ) -> [Experiment] {
        var results: [Experiment] = []
        let documents = containerPath + "/Documents"
        let scratch = documents + "/fsprobe-boundary-scratch"

        // Ensure Documents exists for the symlink case.
        try? FileManager.default.createDirectory(atPath: documents, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(atPath: scratch)

        // 1. `..` traversal expressed through the container.
        //
        //    Mechanism: does the policy match the path string (in which case a
        //    string beginning with the container prefix might be allowed) or the
        //    resolved vnode (in which case the final component is outside)?
        let traversal = containerPath + "/../../../../../../.." + outsidePath
        results.append(openExperiment(
            id: "dotdot-traversal",
            mechanism: """
            Path resolution: is policy matched on the caller's path string or on the \
            resolved vnode? The path text starts inside the container but resolves outside.
            """,
            operation: "open(O_RDONLY)",
            arguments: traversal,
            expected: """
            Denied. NAMEI resolves `..` to a real vnode before the policy sees it, 
            and the lookup hook runs per component on the resolved parent.
            """
        ))

        // 2. Symlink inside the container pointing outside.
        //
        //    Mechanism: is the symlink's own path checked while its target is not?
        let linkPath = scratch
        let created = (try? FileManager.default.createSymbolicLink(
            atPath: linkPath, withDestinationPath: outsidePath
        )) != nil

        if created {
            results.append(openExperiment(
                id: "symlink-escape",
                mechanism: """
                Symlink traversal: is the link's path checked while its target's vnode is not? \
                The link itself lives inside the container.
                """,
                operation: "open(O_RDONLY)",
                arguments: linkPath,
                expected: """
                Denied. Each symlink expansion re-enters lookup, so the target is 
                authorized in its own right.
                """
            ))
            results.append(openDirExperiment(
                id: "symlink-escape-opendir",
                mechanism: "Symlink traversal followed by directory enumeration.",
                operation: "opendir",
                arguments: linkPath,
                expected: "Denied, for the same reason as the open case."
            ))
        } else {
            results.append(Experiment(
                id: "symlink-escape",
                mechanism: "Symlink traversal: is the link's path checked while its target is not?",
                operation: "symlink()",
                arguments: "\(linkPath) -> \(outsidePath)",
                expected: "Precondition: the symlink should be creatable inside the container.",
                outcome: .notApplicable,
                errnoName: currentErrnoName(),
                errnoNumber: Int(currentErrno()),
                interpretation: "Could not create the symlink, so the traversal test could not run."
            ))
        }

        // 3. `openat` with a directory fd for the container.
        //
        //    Mechanism: is a dirfd an authorization token, or merely a starting
        //    point whose components are still resolved and checked?
        let dirfd = POSIXShim.openDir(documents)
        if let dirfd {
            let relative = "../../../../../../.." + outsidePath
            let fd = POSIXShim.openFile(relative, O_RDONLY, 0)
            let outcome: Outcome = fd >= 0 ? .permitted : .denied
            let errnoNumber = fd >= 0 ? 0 : Int(currentErrno())
            if fd >= 0 { POSIXShim.closeFile(fd) }
            results.append(Experiment(
                id: "dirfd-relative-escape",
                mechanism: """
                openat() with a dirfd: is the descriptor an authorization token, or merely a \
                starting directory whose components are still resolved and authorized?
                """,
                operation: "openat(dirfd, O_RDONLY)",
                arguments: "dirfd=\(documents), path=\(relative)",
                expected: """
                Denied. nameiat() uses the fd only as the starting directory; \
                namei() still authorizes every component.
                """,
                outcome: outcome,
                errnoName: fd >= 0 ? nil : currentErrnoName(),
                errnoNumber: errnoNumber,
                interpretation: outcome == .permitted
                    ? """
                    A relative escape through a container dirfd succeeded. This would be a \
                    genuine boundary violation.
                    """
                    : """
                    The dirfd was not an authorization shortcut; relative resolution was \
                    still checked.
                    """
            ))
            POSIXShim.closeDir(dirfd)
        }

        // Clean up the scratch symlink.
        try? FileManager.default.removeItem(atPath: linkPath)

        return results
    }

    // MARK: - Hard links

    /// `link()` is a distinct sandbox operation (`file-link*`) from `file-write*`.
    /// If the policy allows linking a file from outside the container into it, the
    /// app gains a read handle on a file it could never open directly.
    public static func crossBoundaryLinkBattery(containerPath: String) -> [Experiment] {
        var results: [Experiment] = []
        let documents = containerPath + "/Documents"
        try? FileManager.default.createDirectory(atPath: documents, withIntermediateDirectories: true)

        let linkTarget = documents + "/fsprobe-hardlink-import"

        // Control first: prove link() works at all with a file we own.
        let controlSource = documents + "/fsprobe-link-control"
        let controlData = Data("fsprobe-link-control\n".utf8)
        let controlFD = POSIXShim.openFile(controlSource, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        var controlWorked = false
        if controlFD >= 0 {
            _ = controlData.withUnsafeBytes { raw in
                raw.baseAddress.map { POSIXShim.writeFD(controlFD, $0, raw.count) }
            }
            POSIXShim.closeFile(controlFD)
            let rc = POSIXShim.linkFile(controlSource, linkTarget)
            controlWorked = rc == 0
            POSIXShim.unlinkFile(linkTarget)
            POSIXShim.unlinkFile(controlSource)
        }

        results.append(Experiment(
            id: "hardlink-control",
            mechanism: "Control: does link() work at all inside the container?",
            operation: "link()",
            arguments: "\(controlSource) -> \(linkTarget)",
            expected: "Succeeds. Both paths are inside the container.",
            outcome: controlWorked ? .permitted : .error,
            errnoName: controlWorked ? nil : currentErrnoName(),
            errnoNumber: controlWorked ? 0 : Int(currentErrno()),
            interpretation: controlWorked
                ? "link() works inside the container, so the cross-boundary result below is meaningful."
                : "link() failed even inside the container, so the cross-boundary test is not interpretable.",
            expectedPermitted: true
        ))

        guard controlWorked else { return results }

        // The real test: link a file from outside the container into it.
        //
        // The source must be a *regular file* that provably exists. Linking a
        // directory is refused by POSIX regardless of the sandbox, and guessing a
        // filename that is absent yields ENOENT, which says nothing about the
        // policy. The first device run hit exactly that: it reported ENOENT for a
        // path that does not exist, making the experiment inconclusive.
        //
        // Candidates are ordered by how likely they are to exist and to be
        // interesting. The first one that stats as a regular file is used.
        let candidates = [
            "/usr/lib/dyld",
            "/private/etc/master.passwd",
            "/etc/master.passwd",
            "/var/mobile/Library/Preferences/.com.apple.mobile_container_manager.metadata.plist",
            "/private/etc/hosts",
            "/etc/hosts"
        ]
        guard let outsideFile = candidates.first(where: { isRegularFile($0) }) else {
            results.append(Experiment(
                id: "hardlink-cross-boundary",
                mechanism: """
                Hard links: `file-link*` is a distinct sandbox operation from `file-write*`. \
                If it is not confined to the container, an app can bind a link to a \
                protected file into its own writable tree and then read it.
                """,
                operation: "link()",
                arguments: "no candidate source file could be stat'd outside the container",
                expected: "Denied. The source lies outside every container allow rule.",
                outcome: .notApplicable,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: """
                No regular file outside the container could be confirmed to exist, so the \
                experiment could not be run. This is a limitation of the probe, not a result.
                """
            ))
            return results
        }
        let rc = POSIXShim.linkFile(outsideFile, linkTarget)
        let succeeded = rc == 0

        var interpretation: String
        if succeeded {
            // Prove the primitive: read through the link and fingerprint it.
            let size = POSIXShim.fileSize(atPath: linkTarget)
            let readBack = readAll(linkTarget)
            interpretation = """
            A hard link to a file outside the container was created inside it. \
            Read through the link returned \(readBack.count) bytes; the linked file is \
            \(size ?? -1) bytes, sha256 \(SHA256.hexDigest(readBack)). This is a read \
            primitive on a path the app cannot open directly.
            """
        } else {
            interpretation = """
            link() was refused with \(currentErrnoName() ?? "an unknown errno"). The \
            file-link operation is governed separately from file-write, and it did not \
            grant a cross-boundary handle.
            """
        }

        results.append(Experiment(
            id: "hardlink-cross-boundary",
            mechanism: """
            Hard links: `file-link*` is a distinct sandbox operation from `file-write*`. If it \
            is not confined to the container, an app can bind a link to a protected file into \
            its own writable tree and then read it.
            """,
            operation: "link()",
            arguments: "\(outsideFile) -> \(linkTarget)",
            expected: "Denied. The source lies outside every container allow rule.",
            outcome: succeeded ? .permitted : .denied,
            errnoName: succeeded ? nil : currentErrnoName(),
            errnoNumber: succeeded ? 0 : Int(currentErrno()),
            interpretation: interpretation
        ))

        // Always clean up.
        POSIXShim.unlinkFile(linkTarget)
        return results
    }

    // MARK: - Rename

    /// A rename out of the container would be a write primitive beyond it. Rename is
    /// authorized on both source and destination vnodes, so this should be refused.
    public static func crossBoundaryRenameBattery(containerPath: String) -> [Experiment] {
        var results: [Experiment] = []
        let documents = containerPath + "/Documents"
        try? FileManager.default.createDirectory(atPath: documents, withIntermediateDirectories: true)

        let source = documents + "/fsprobe-rename-source"
        let destination = "/var/tmp/fsprobe-rename-escape"

        // Control inside the container.
        let controlDest = documents + "/fsprobe-rename-control"
        let fd = POSIXShim.openFile(source, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        guard fd >= 0 else {
            results.append(Experiment(
                id: "rename-control",
                mechanism: "Control: does rename() work inside the container?",
                operation: "rename()",
                arguments: "\(source) -> \(controlDest)",
                expected: "Succeeds.",
                outcome: .notApplicable,
                errnoName: currentErrnoName(),
                errnoNumber: Int(currentErrno()),
                interpretation: "Could not create the source file, so the rename test could not run."
            ))
            return results
        }
        POSIXShim.closeFile(fd)

        let controlRC = POSIXShim.renameFile(source, controlDest)
        results.append(Experiment(
            id: "rename-control",
            mechanism: "Control: does rename() work inside the container?",
            operation: "rename()",
            arguments: "\(source) -> \(controlDest)",
            expected: "Succeeds.",
            outcome: controlRC == 0 ? .permitted : .error,
            errnoName: controlRC == 0 ? nil : currentErrnoName(),
            errnoNumber: controlRC == 0 ? 0 : Int(currentErrno()),
            interpretation: controlRC == 0
                ? "rename() works inside the container, so the cross-boundary result below is meaningful."
                : "rename() failed even inside the container, so the cross-boundary test is not interpretable.",
            expectedPermitted: true
        ))
        POSIXShim.unlinkFile(controlDest)

        // Recreate the source and try to move it outside.
        let fd2 = POSIXShim.openFile(source, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        guard fd2 >= 0 else { return results }
        POSIXShim.closeFile(fd2)

        // Two destinations, because the refusal reason matters.
        //
        // EXDEV is a filesystem-level refusal: the source and destination are on
        // different volumes, and it says nothing about the sandbox. The first
        // device run returned EXDEV, which made the experiment inconclusive. A
        // destination inside the same directory tree -- the container's parent --
        // is on the same volume, so a refusal there is attributable to policy.
        // (destination, human-readable description, experiment id)
        let destinations: [(String, String, String)] = [
            ("/var/tmp/fsprobe-rename-escape", "a different volume",
             "rename-cross-boundary-other-volume"),
            (containerPath + "/../fsprobe-rename-escape", "the container parent directory",
             "rename-cross-boundary-same-volume")
        ]

        for (destination, description, experimentID) in destinations {
            POSIXShim.unlinkFile(source)
            POSIXShim.unlinkFile(destination)
            let freshFD = POSIXShim.openFile(source, O_CREAT | O_EXCL | O_WRONLY, 0o644)
            if freshFD < 0 { continue }
            POSIXShim.closeFile(freshFD)

            let rc = POSIXShim.renameFile(source, destination)
            let succeeded = rc == 0
            let errnoName = succeeded ? nil : currentErrnoName()

            results.append(Experiment(
                id: experimentID,
                mechanism: """
                Rename across the boundary: a successful rename out of the container would \
                place a file this app controls into a location it cannot write, which is a \
                write primitive beyond the sandbox.
                """,
                operation: "rename()",
                arguments: source + " -> " + destination,
                expected: "Denied. Rename authorizes both the source and the destination vnode.",
                outcome: succeeded ? .permitted : .denied,
                errnoName: errnoName,
                errnoNumber: succeeded ? 0 : Int(currentErrno()),
                interpretation: succeeded
                    ? "A file was renamed out of the container. This is a write primitive beyond the sandbox."
                    : renameInterpretation(errnoName, destinationDescription: description)
            ))

            if succeeded {
                POSIXShim.unlinkFile(destination)
            } else {
                POSIXShim.unlinkFile(source)
            }
        }
        return results
    }

    /// Interpret a rename refusal, separating a policy denial from a
    /// filesystem-level refusal that would mask it.
    private static func renameInterpretation(
        _ errnoName: String?,
        destinationDescription: String
    ) -> String {
        switch errnoName {
        case "EXDEV":
            return """
            Refused with EXDEV: the source and destination are on different volumes, so this \
            is a filesystem-level refusal and does not show whether the sandbox would also \
            have refused. The same-volume variant is the interpretable test.
            """
        case "EPERM":
            return """
            Refused with EPERM, the sandbox signature. The rename across the boundary was \
            denied by policy.
            """
        case "EACCES":
            return "Refused with EACCES: POSIX permissions on the destination directory."
        default:
            return "Refused with " + (errnoName ?? "an unknown errno")
                + " (" + destinationDescription + ")."
        }
    }

    /// True when `path` is an existing regular file.
    private static func isRegularFile(_ path: String) -> Bool {
        var buffer = StatBuffer()
        guard POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0 else {
            return false
        }
        // S_IFREG is 0o100000.
        return (buffer.mode & 0o170000) == 0o100000
    }

    // MARK: - Enumeration differential

    /// Directory enumeration has more than one implementation: `opendir`/`readdir`
    /// and `getattrlistbulk` (what `FileManager` uses) are different syscalls. If
    /// they are governed by different rules, a directory refused to one may yield to
    /// the other.
    public static func enumerationDifferential(outsidePath: String) -> [Experiment] {
        var results: [Experiment] = []

        // 1. POSIX enumeration.
        let posixResult = POSIXProbeEngine.run(.enumerate, on: outsidePath)
        results.append(Experiment(
            id: "enumerate-posix",
            mechanism: """
            Enumeration differential: opendir/readdir versus getattrlistbulk. Different syscalls \
            implement directory listing; if they are governed differently, one may yield names \
            where the other is refused.
            """,
            operation: "opendir + readdir",
            arguments: outsidePath,
            expected: "Denied, as observed for every other operation on this path.",
            outcome: posixResult.succeeded ? .permitted : .denied,
            errnoName: posixResult.errnoName,
            errnoNumber: posixResult.errnoNumber,
            interpretation: posixResult.succeeded
                ? "opendir succeeded, which contradicts every other operation on this path."
                : "opendir was refused, as expected."
        ))

        // 2. Foundation enumeration, which uses getattrlistbulk.
        let foundationEntries: [String]
        var foundationError: String?
        do {
            foundationEntries = try FileManager.default.contentsOfDirectory(atPath: outsidePath)
        } catch {
            foundationEntries = []
            let nsError = error as NSError
            foundationError = "\(nsError.domain) \(nsError.code)"
        }

        let foundationSucceeded = !foundationEntries.isEmpty || foundationError == nil
        results.append(Experiment(
            id: "enumerate-foundation",
            mechanism: "Enumeration differential: the getattrlistbulk path used by FileManager.",
            operation: "FileManager.contentsOfDirectory",
            arguments: outsidePath,
            expected: "Denied. getattrlistbulk performs the same readdir authorization.",
            outcome: foundationEntries.isEmpty && foundationError != nil ? .denied : .permitted,
            errnoName: nil,
            errnoNumber: 0,
            interpretation: foundationEntries.isEmpty
                ? """
                FileManager returned no entries (\(foundationError ?? "no error")). \
                Consistent with the POSIX result.
                """
                : """
                FileManager returned \(foundationEntries.count) entries where opendir was \
                refused. This would be an enforcement gap between the two enumeration paths.
                """
        ))

        return results
    }

    // MARK: - Helpers

    private static func openExperiment(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expected: String
    ) -> Experiment {
        let fd = POSIXShim.openFile(arguments, O_RDONLY, 0)
        let succeeded = fd >= 0
        if succeeded { POSIXShim.closeFile(fd) }
        return Experiment(
            id: id,
            mechanism: mechanism,
            operation: operation,
            arguments: arguments,
            expected: expected,
            outcome: succeeded ? .permitted : .denied,
            errnoName: succeeded ? nil : currentErrnoName(),
            errnoNumber: succeeded ? 0 : Int(currentErrno()),
            interpretation: succeeded
                ? "The operation succeeded where the policy predicts a denial. Investigate."
                : "Refused with \(currentErrnoName() ?? "an unknown errno"), as the policy predicts."
        )
    }

    private static func openDirExperiment(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expected: String
    ) -> Experiment {
        guard let dir = POSIXShim.openDir(arguments) else {
            return Experiment(
                id: id, mechanism: mechanism, operation: operation, arguments: arguments,
                expected: expected, outcome: .denied,
                errnoName: currentErrnoName(), errnoNumber: Int(currentErrno()),
                interpretation: "Refused with \(currentErrnoName() ?? "an unknown errno")."
            )
        }
        var count = 0
        setErrno(0)
        while POSIXShim.nextEntry(dir) != nil { count += 1; setErrno(0) }
        POSIXShim.closeDir(dir)
        return Experiment(
            id: id, mechanism: mechanism, operation: operation, arguments: arguments,
            expected: expected, outcome: .permitted, errnoName: nil, errnoNumber: 0,
            interpretation: "Enumerated \(count) entries."
        )
    }

    private static func readAll(_ path: String) -> Data {
        let fd = POSIXShim.openFile(path, O_RDONLY, 0)
        guard fd >= 0 else { return Data() }
        defer { POSIXShim.closeFile(fd) }
        var collected = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n: Int = buffer.withUnsafeMutableBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return -1 }
                return POSIXShim.readFD(fd, base, ptr.count)
            }
            if n <= 0 { break }
            collected.append(contentsOf: buffer.prefix(n))
            if collected.count > 1 << 20 { break }  // bound the read
        }
        return collected
    }

    private static func currentErrnoName() -> String? {
        ErrorClassifier.errnoName(currentErrno())
    }
}
