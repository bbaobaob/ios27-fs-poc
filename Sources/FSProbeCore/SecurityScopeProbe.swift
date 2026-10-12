//
//  SecurityScopeProbe.swift
//  FSProbeCore — test the boundary of a user-granted filesystem scope.
//
//  HYPOTHESIS
//  ----------
//  Every experiment so far has tested the *default* sandbox, which is uniform and
//  holds. But iOS has a second authorization path: a user can grant an app access
//  to files and directories outside its container through the document picker.
//  That grant is issued as a security-scoped URL backed by a sandbox extension.
//
//  The security question is not whether the grant works -- it does, by design --
//  but whether the grant is *confined to what the user picked*. Sandbox-extension
//  over-grant is a documented bug class: if the scope covers more than the chosen
//  item, the app gains access the user never approved.
//
//  EXPECTED RESULT
//  ---------------
//  The granted path is accessible; its parent, its siblings, and anything
//  reachable from it by `..` or symlink are refused; and access stops when the
//  scope is released.
//
//  A contrary result in any of those is a genuine boundary violation with a
//  clear user-visible consequence.
//
//  SAFETY
//  ------
//  Read-only by default. The only write attempt targets a dedicated synthetic
//  filename inside the granted directory and removes it afterwards.
//

import Foundation

public enum SecurityScopeProbe {

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        /// What the experiment tests about the grant.
        public let mechanism: String
        public let operation: String
        public let arguments: String
        public let expected: String
        /// True when a success here would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: CrossBoundaryProbe.Outcome
        public let errnoName: String?
        public let errnoNumber: Int
        public let interpretation: String

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
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        /// The path the user granted, as reported by the system.
        public let grantedPath: String
        /// The standardised path, which may differ (firmlinks, `..`).
        public let resolvedPath: String
        /// Whether the grant was held (startAccessingSecurityScopedResource).
        public let scopeActive: Bool
        public let experiments: [Experiment]
        /// Experiments that succeeded where the grant should have refused.
        public let violations: [Experiment]

        public init(
            grantedPath: String,
            resolvedPath: String,
            scopeActive: Bool,
            experiments: [Experiment],
            violations: [Experiment]
        ) {
            self.grantedPath = grantedPath
            self.resolvedPath = resolvedPath
            self.scopeActive = scopeActive
            self.experiments = experiments
            self.violations = violations
        }
    }

    /// Probe the extent of a user-granted scope.
    ///
    /// - Parameter grantedPath: the URL the user picked, as a filesystem path.
    ///   The caller must have called `startAccessingSecurityScopedResource()`.
    public static func probe(grantedPath: String) -> Result {
        let resolved = URL(fileURLWithPath: grantedPath).standardizedFileURL.path
        var experiments: [Experiment] = []

        // 1. The granted path itself must be accessible -- this is the control
        //    that proves the grant works and the rest of the battery is
        //    interpretable.
        experiments.append(openExperiment(
            id: "granted-path",
            mechanism: """
            Control: the granted path must be readable, or the grant did not take \
            effect and nothing below is interpretable.
            """,
            operation: "opendir",
            arguments: grantedPath,
            expectedDenied: false
        ))

        // 2. The parent of the granted path must NOT be accessible. The user
        //    granted one item, not its containing directory.
        let parent = parentOf(grantedPath)
        experiments.append(openExperiment(
            id: "granted-parent",
            mechanism: """
            Scope confinement: the user granted a single item. If its parent is \
            readable, the grant covers more than the user chose.
            """,
            operation: "opendir",
            arguments: parent,
            expectedDenied: true
        ))

        // 3. `..` traversal out of the granted path. This is the same mechanism
        //    that failed against the container, re-tested through a scope whose
        //    policy is generated per-grant rather than per-app.
        experiments.append(openExperiment(
            id: "granted-dotdot-escape",
            mechanism: """
            Scope confinement via path traversal: a path that starts inside the \
            granted directory but resolves above it.
            """,
            operation: "open(O_RDONLY)",
            arguments: grantedPath + "/../../../../../../var/mobile/Library",
            expectedDenied: true
        ))

        // 4. A symlink inside the granted directory pointing outside it.
        //
        //    Only meaningful when the granted directory is writable, because the
        //    symlink has to be created there. When it is not, the experiment
        //    reports that its precondition failed rather than claiming a result.
        let symlinkPath = grantedPath + "/fsprobe-scope-escape"
        let symlinkCreated = (try? FileManager.default.createSymbolicLink(
            atPath: symlinkPath, withDestinationPath: "/var/mobile/Library"
        )) != nil
        if symlinkCreated {
            experiments.append(openExperiment(
                id: "granted-symlink-escape",
                mechanism: """
                Scope confinement via symlink: the link lives inside the granted \
                directory but points outside it.
                """,
                operation: "open(O_RDONLY)",
                arguments: symlinkPath,
                expectedDenied: true
            ))
            try? FileManager.default.removeItem(atPath: symlinkPath)
        } else {
            experiments.append(Experiment(
                id: "granted-symlink-escape",
                mechanism: """
                Scope confinement via symlink: the link lives inside the granted \
                directory but points outside it.
                """,
                operation: "symlink()",
                arguments: "\(symlinkPath) -> /var/mobile/Library",
                expected: "Precondition: the granted directory must be writable.",
                expectedDenied: true,
                outcome: .notApplicable,
                errnoName: nil,
                errnoNumber: 0,
                interpretation: """
                The symlink could not be created in the granted directory, so the \
                traversal test could not run.
                """
            ))
        }

        // 5. Write inside the granted directory. A read-only grant should refuse
        //    a write, and a read-write grant should permit it -- either is
        //    informative, and both are recorded with the exact errno.
        experiments.append(writeExperiment(grantedPath: grantedPath))

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(
            grantedPath: grantedPath,
            resolvedPath: resolved,
            scopeActive: true,
            experiments: experiments,
            violations: violations
        )
    }

    /// Re-probe after the scope has been released, to confirm access actually
    /// stops rather than persisting in some cached descriptor.
    public static func probeAfterRelease(grantedPath: String) -> Result {
        let resolved = URL(fileURLWithPath: grantedPath).standardizedFileURL.path
        var experiments: [Experiment] = []

        experiments.append(openExperiment(
            id: "after-release",
            mechanism: """
            Scope release: after stopAccessingSecurityScopedResource(), the \
            previously granted path must become inaccessible again. A path that \
            stays readable means the grant outlived its scope.
            """,
            operation: "opendir",
            arguments: grantedPath,
            expectedDenied: true
        ))

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(
            grantedPath: grantedPath,
            resolvedPath: resolved,
            scopeActive: false,
            experiments: experiments,
            violations: violations
        )
    }

    // MARK: - Internals

    private static func openExperiment(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        expectedDenied: Bool
    ) -> Experiment {
        let fd = POSIXShim.openFile(arguments, O_RDONLY, 0)
        if fd >= 0 {
            POSIXShim.closeFile(fd)
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: expectedDenied
                    ? "Denied. The grant covers only the item the user chose."
                    : "Permitted. This is the control.",
                expectedDenied: expectedDenied,
                outcome: .permitted, errnoName: nil, errnoNumber: 0,
                interpretation: expectedDenied
                    ? "The operation succeeded where the grant should have refused it."
                    : "The granted path is accessible, as expected."
            )
        }
        let errno = currentErrno()
        return Experiment(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments,
            expected: expectedDenied
                ? "Denied. The grant covers only the item the user chose."
                : "Permitted. This is the control.",
            expectedDenied: expectedDenied,
            outcome: .denied,
            errnoName: ErrorClassifier.errnoName(errno),
            errnoNumber: Int(errno),
            interpretation: expectedDenied
                ? "Refused with \(ErrorClassifier.errnoName(errno) ?? "an unknown errno")."
                : "The granted path was refused, so the grant did not take effect."
        )
    }

    private static func writeExperiment(grantedPath: String) -> Experiment {
        let target = grantedPath + "/" + POSIXProbeEngine.syntheticFileName
        POSIXShim.unlinkFile(target)
        let fd = POSIXShim.openFile(target, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        guard fd >= 0 else {
            let errno = currentErrno()
            return Experiment(
                id: "granted-write",
                mechanism: """
                Whether the grant is read-only or read-write. Either is valid; what \
                matters is recording which, with the errno.
                """,
                operation: "open(O_CREAT|O_EXCL|O_WRONLY)",
                arguments: target,
                expected: "Denied for a read-only grant, permitted for a read-write one.",
                expectedDenied: false,
                outcome: .denied,
                errnoName: ErrorClassifier.errnoName(errno),
                errnoNumber: Int(errno),
                interpretation: """
                Refused with \(ErrorClassifier.errnoName(errno) ?? "an unknown errno"): the \
                grant is read-only.
                """
            )
        }
        let payload = Data("fsprobe-scope-writetest\n".utf8)
        let written: Int = payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return -1 }
            return POSIXShim.writeFD(fd, base, raw.count)
        }
        POSIXShim.closeFile(fd)
        let removed = POSIXShim.unlinkFile(target) == 0
        let cleanup = removed ? "cleanup ok" : "cleanup FAILED"
        return Experiment(
            id: "granted-write",
            mechanism: """
            Whether the grant is read-only or read-write. Either is valid; what \
            matters is recording which, with the errno.
            """,
            operation: "open(O_CREAT|O_EXCL|O_WRONLY)",
            arguments: target,
            expected: "Denied for a read-only grant, permitted for a read-write one.",
            expectedDenied: false,
            outcome: .permitted, errnoName: nil, errnoNumber: 0,
            interpretation: """
            Wrote \(written) bytes and removed the file again (\(cleanup)): the grant is \
            read-write.
            """
        )
    }

    private static func parentOf(_ path: String) -> String {
        URL(fileURLWithPath: path).deletingLastPathComponent().path
    }

    // `currentErrno()` is the portable accessor defined in ErrnoAccess.swift,
    // in this same module.
}
