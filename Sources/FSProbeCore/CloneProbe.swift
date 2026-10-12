//
//  CloneProbe.swift
//  FSProbeCore — APFS clone across the container boundary.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far copied a file by opening the source, reading its bytes,
//  and writing them to the destination. Each of those syscalls is individually
//  authorized by the sandbox, which is why every attempt was refused with EPERM.
//
//  `clonefile()` does not work that way. It asks the filesystem to clone the
//  source vnode into the destination -- a copy by inode, with no read or write of
//  file contents at all. If the seatbelt profile is attached to the read and write
//  operations but not to the clone operation, cloning a protected file into the
//  app's own container yields its contents, and cloning a container file into a
//  protected directory yields a file outside the sandbox. Either direction is a
//  boundary violation.
//
//  EXPECTED RESULT
//  ---------------
//  Denied. Apple's own sandbox profiles include a `file-clone` operation, and the
//  kernel's clone path is MAC-checked, so both directions should be refused.
//
//  SAFETY
//  ------
//  This is a copy primitive. The source is never modified -- a clone reads the
//  source vnode and writes a new inode, so whether the call succeeds or fails the
//  protected file is untouched. The destinations are the app's own Documents
//  directory (for reading outward) and a scratch file inside a protected directory
//  (for writing outward), both removed immediately afterwards. Nothing outside
//  those destinations is touched.
//

import Foundation

public enum CloneProbe {

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        /// What the experiment tests about the boundary.
        public let mechanism: String
        /// The syscall exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the documented policy predicts.
        public let expected: String
        /// True when a permitted result here would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: CrossBoundaryProbe.Outcome
        public let errnoName: String?
        public let errnoNumber: Int
        /// Interpretation of the observation.
        public let interpretation: String
        /// Size of the clone, when it succeeded -- the evidence that content moved.
        public let clonedBytes: Int?
        /// SHA-256 of the cloned content, when it succeeded.
        public let clonedSHA256: String?

        public init(
            id: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: CrossBoundaryProbe.Outcome,
            errnoName: String?,
            errnoNumber: Int,
            interpretation: String,
            clonedBytes: Int? = nil,
            clonedSHA256: String? = nil
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
            self.interpretation = interpretation
            self.clonedBytes = clonedBytes
            self.clonedSHA256 = clonedSHA256
        }

        /// A boundary violation is a success the policy did not predict.
        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        /// Paths tried as the protected source, with the errno each returned.
        public let candidateSources: [String]
        public let experiments: [Experiment]
        public let violations: [Experiment]

        public init(
            candidateSources: [String],
            experiments: [Experiment],
            violations: [Experiment]
        ) {
            self.candidateSources = candidateSources
            self.experiments = experiments
            self.violations = violations
        }
    }

    /// Run the clone battery.
    ///
    /// - Parameters:
    ///   - containerPath: the app's own container.
    ///   - payload: deterministic content used for the write-outward direction.
    public static func run(
        containerPath: String,
        payload: Data = Data("fsprobe-clone-writeout\n".utf8)
    ) -> Result {
        let documents = containerPath + "/Documents"
        try? FileManager.default.createDirectory(
            atPath: documents, withIntermediateDirectories: true
        )

        // Find a protected regular file to clone from. Candidates are ordered by
        // how certainly they exist on iOS; the first one that stats as a regular
        // file is used. A path that does not exist would return ENOENT and say
        // nothing about the policy, exactly the trap that made the first hard-link
        // experiment inconclusive.
        let sourceCandidates = [
            "/usr/lib/dyld",
            "/private/etc/hosts",
            "/etc/hosts",
            "/usr/lib/libSystem.B.dylib",
            "/private/var/preferences/SystemConfiguration/preferences.plist",
            "/System/Library/CoreServices/SystemVersion.plist",
            "/usr/share/zoneinfo/UTC"
        ]

        var tried: [String] = []
        var source: String?
        for candidate in sourceCandidates {
            tried.append(candidate)
            if isRegularFile(candidate) {
                source = candidate
                break
            }
        }

        var experiments: [Experiment] = []

        // ---- Direction 1: clone a protected file into the container ----------
        guard let protectedSource = source else {
            experiments.append(Experiment(
                id: "clone-read-inward",
                mechanism: """
                APFS clone: is a copy-by-inode primitive that skips read and write \
                entirely covered by the sandbox?
                """,
                operation: "clonefile()",
                arguments: "no candidate source file could be stat'd outside the container",
                expected: "Precondition: a protected regular file must exist to clone.",
                expectedDenied: true,
                outcome: .notApplicable,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: """
                No protected regular file could be confirmed to exist, so the \
                experiment could not run. This is a limitation of the probe, not a result.
                """
            ))
            return Result(candidateSources: tried, experiments: experiments, violations: [])
        }

        let inwardDestination = documents + "/fsprobe-clone-inward.bin"
        POSIXShim.unlinkFile(inwardDestination)
        let inwardRC = POSIXShim.cloneFile(protectedSource, inwardDestination)

        if inwardRC == 0 {
            // Prove the clone carries content.
            let data = FileManager.default.contents(atPath: inwardDestination) ?? Data()
            let digest = SHA256.hexDigest(data)
            let size = data.count
            POSIXShim.unlinkFile(inwardDestination)
            experiments.append(Experiment(
                id: "clone-read-inward",
                mechanism: """
                APFS clone: is a copy-by-inode primitive that skips read and write \
                entirely covered by the sandbox?
                """,
                operation: "clonefile()",
                arguments: "\(protectedSource) -> \(inwardDestination)",
                expected: """
                Denied. The source lies outside every container allow rule, and the \
                kernel's clone path is MAC-checked.
                """,
                expectedDenied: true,
                outcome: .permitted,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: """
                A protected file was cloned into the app container by inode. The \
                clone is \(size) bytes, sha256 \(digest) -- content moved from a \
                location the app cannot open by path into one it can read.
                """,
                clonedBytes: size,
                clonedSHA256: digest
            ))
        } else {
            let errno = currentErrno()
            experiments.append(Experiment(
                id: "clone-read-inward",
                mechanism: """
                APFS clone: is a copy-by-inode primitive that skips read and write \
                entirely covered by the sandbox?
                """,
                operation: "clonefile()",
                arguments: "\(protectedSource) -> \(inwardDestination)",
                expected: """
                Denied. The source lies outside every container allow rule, and the \
                kernel's clone path is MAC-checked.
                """,
                expectedDenied: true,
                outcome: .denied,
                errnoName: ErrorClassifier.errnoName(errno),
                errnoNumber: Int(errno),
                interpretation: "Refused with \(ErrorClassifier.errnoName(errno) ?? "an unknown errno")."
            ))
        }

        // ---- Direction 2: clone a container file into a protected directory ----
        //
        // Target directories that are known to exist outside the container. The
        // destination file is removed immediately after the attempt.
        let destinationDirs = ["/var/mobile/Media", "/var/tmp", "/var/mobile/Library"]
        var outwardDestination: String?
        for dir in destinationDirs where directoryExists(dir) {
            outwardDestination = dir + "/fsprobe-clone-outward.tmp"
            break
        }

        guard let outward = outwardDestination else {
            experiments.append(Experiment(
                id: "clone-write-outward",
                mechanism: """
                APFS clone: does writing a clone outside the container require the \
                same authorization as writing it by path?
                """,
                operation: "clonefile()",
                arguments: "no destination directory could be confirmed outside the container",
                expected: "Precondition: a protected directory must exist to clone into.",
                expectedDenied: true,
                outcome: .notApplicable,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: """
                No protected directory could be confirmed to exist, so the write-outward \
                experiment could not run. This is a limitation of the probe, not a result.
                """
            ))
            return Result(candidateSources: tried, experiments: experiments, violations: [])
        }

        let outwardSource = documents + "/fsprobe-clone-source.bin"
        let sourceFD = POSIXShim.openFile(outwardSource, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        guard sourceFD >= 0 else {
            return Result(candidateSources: tried, experiments: experiments, violations: [])
        }
        let written: Int = payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return -1 }
            return POSIXShim.writeFD(sourceFD, base, raw.count)
        }
        POSIXShim.closeFile(sourceFD)
        guard written == payload.count else {
            try? FileManager.default.removeItem(atPath: outwardSource)
            return Result(candidateSources: tried, experiments: experiments, violations: [])
        }

        POSIXShim.unlinkFile(outward)
        let outwardRC = POSIXShim.cloneFile(outwardSource, outward)
        let outwardErrno = currentErrno()
        if outwardRC == 0 {
            let landed = FileManager.default.fileExists(atPath: outward)
            POSIXShim.unlinkFile(outward)
            try? FileManager.default.removeItem(atPath: outwardSource)
            experiments.append(Experiment(
                id: "clone-write-outward",
                mechanism: """
                APFS clone: does writing a clone outside the container require the \
                same authorization as writing it by path?
                """,
                operation: "clonefile()",
                arguments: "\(outwardSource) -> \(outward)",
                expected: """
                Denied. The destination lies outside the container, and a clone should \
                be authorized exactly as a create at the same path.
                """,
                expectedDenied: true,
                outcome: .permitted,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: landed
                    ? "A file was cloned to a location outside the app container, and was found there."
                    : "The clone call returned success but no file appeared at the destination."
            ))
        } else {
            POSIXShim.unlinkFile(outward)
            try? FileManager.default.removeItem(atPath: outwardSource)
            experiments.append(Experiment(
                id: "clone-write-outward",
                mechanism: """
                APFS clone: does writing a clone outside the container require the \
                same authorization as writing it by path?
                """,
                operation: "clonefile()",
                arguments: "\(outwardSource) -> \(outward)",
                expected: """
                Denied. The destination lies outside the container, and a clone should \
                be authorized exactly as a create at the same path.
                """,
                expectedDenied: true,
                outcome: .denied,
                errnoName: ErrorClassifier.errnoName(outwardErrno),
                errnoNumber: Int(outwardErrno),
                interpretation: "Refused with \(ErrorClassifier.errnoName(outwardErrno) ?? "an unknown errno")."
            ))
        }

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(candidateSources: tried, experiments: experiments, violations: violations)
    }

    // MARK: - Internals

    private static func isRegularFile(_ path: String) -> Bool {
        var buffer = StatBuffer()
        guard POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0 else {
            return false
        }
        return (buffer.mode & 0o170000) == 0o100000  // S_IFREG
    }

    private static func directoryExists(_ path: String) -> Bool {
        var buffer = StatBuffer()
        guard POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0 else {
            return false
        }
        return (buffer.mode & StatBuffer.modeTypeMask) == StatBuffer.modeDirectory
    }
}
