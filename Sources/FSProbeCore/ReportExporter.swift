//
//  ReportExporter.swift
//  FSProbeCore — deterministic JSON and plain-text export of the capability matrix.
//

import Foundation

public enum ReportExporter {

    /// Encode the matrix as pretty-printed JSON with sorted keys.
    public static func json(_ matrix: CapabilityMatrix) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let payload = MatrixPayload(matrix: matrix)
        return try encoder.encode(payload)
    }

    /// Render a fixed-width plain-text table for terminal/report use.
    public static func text(_ matrix: CapabilityMatrix, targets: [FSTarget]) -> String {
        var lines: [String] = []
        lines.append("FSProbe capability matrix")
        lines.append("platform: \(matrix.environment.osName) \(matrix.environment.osVersion)")
        lines.append("build:    \(matrix.environment.osBuild)")
        lines.append("device:   \(matrix.environment.deviceModel)")
        lines.append("process:  \(matrix.environment.processPath)")
        lines.append("captured: \(matrix.environment.timestampUTC)")
        lines.append("")

        let ops = FSOperation.allCases
        let pathWidth = max(28, (targets.map { $0.path.count }.max() ?? 28))
        var header = "path".padding(toLength: pathWidth, withPad: " ", startingAt: 0)
        for op in ops {
            header += " " + op.rawValue.padding(toLength: 12, withPad: " ", startingAt: 0)
        }
        lines.append(header)
        lines.append(String(repeating: "-", count: header.count))

        for row in matrix.rows(targets: targets) {
            var line = row.path.padding(toLength: pathWidth, withPad: " ", startingAt: 0)
            for op in ops {
                let cell: String
                if let outcome = row.cells[op] {
                    cell = outcome.rawValue
                } else {
                    cell = "-"
                }
                line += " " + cell.padding(toLength: 12, withPad: " ", startingAt: 0)
            }
            lines.append(line)
        }

        if !matrix.ancestors.isEmpty {
            lines.append("")
            lines.append("Ancestor ascent (read-only: lstat / opendir / readdir):")
            for step in matrix.ancestors {
                let detail = step.fullyVisible
                    ? "visible"
                    : "lstat=\(step.lstat.rawValue) opendir=\(step.openDirectory.rawValue) readdir=\(step.enumerate.rawValue)"
                let entries = step.entryCount.map { " (\($0) entries)" } ?? ""
                let errno = step.errnoName.map { " [\($0)]" } ?? ""
                lines.append("  \(step.depth) \(step.path) — \(detail)\(entries)\(errno)")
                if let reason = step.stopReason {
                    lines.append("      stopped: \(reason)")
                }
            }
            if let boundary = AncestorProbe.boundary(in: matrix.ancestors) {
                lines.append("  boundary: first not-fully-visible ancestor is depth \(boundary.depth) (\(boundary.path))")
            }
        }

        if let profile = matrix.sandboxProfile {
            lines.append("")
            lines.append("Sandbox profile (read from the app's own container metadata):")
            lines.append("  readable:        \(profile.readable)")
            lines.append("  metadata size:   \(profile.metadataSizeBytes.map { "\($0) bytes" } ?? "unknown")")
            lines.append("  identifier:      \(profile.metadataIdentifier ?? "unknown")")
            lines.append("  metadata keys:   \(profile.metadataKeys.joined(separator: ", "))")
            lines.append("  MCMMetadataInfo: \(profile.infoKeys.joined(separator: ", "))")
            lines.append("  has profile:     \(profile.hasSandboxProfileData)")
            if let bytes = profile.sandboxProfileBytes {
                lines.append("  profile size:    \(bytes) bytes")
            }
            if let digest = profile.sandboxProfileSHA256 {
                lines.append("  profile sha256:  \(digest)")
            }
            lines.append("  parses as plist: \(profile.profileParsesAsPlist)")
            if !profile.profileTopLevelKeys.isEmpty {
                lines.append("  profile keys:    \(profile.profileTopLevelKeys.joined(separator: ", "))")
            }
            if let errno = profile.readErrnoName {
                lines.append("  read errno:      \(errno)")
            }
            lines.append("  writable:        \(profile.writable)")
            if let errno = profile.writeErrnoName {
                lines.append("  write errno:     \(errno)")
            }
            lines.append("  note:            \(profile.note)")
        }

        if let cw = matrix.containerWrite {
            lines.append("")
            lines.append("Container write boundary (synthetic file, verified, removed):")
            lines.append("  container: \(cw.containerPath)")
            for entry in cw.entries {
                let verdict = entry.writable
                    ? "WRITABLE"
                    : (entry.readableButNotWritable ? "read-only" : "not probed")
                let mode = entry.modeOctal.map { " mode=\($0)" } ?? ""
                let count = entry.entryCount.map { " entries=\($0)" } ?? ""
                let errno = entry.createErrnoName.map { " [\($0)]" } ?? ""
                lines.append("  \(entry.depth) \(entry.path) — \(verdict)\(mode)\(count)\(errno)")
            }
            lines.append("  writable:                \(cw.writablePaths.joined(separator: ", "))")
            lines.append("  readable but not writable: \(cw.readableButNotWritablePaths.joined(separator: ", "))")
            if !cw.inconclusivePaths.isEmpty {
                lines.append("  inconclusive:            \(cw.inconclusivePaths.joined(separator: ", "))")
            }
        }

        if let io = matrix.inodeOpen {
            lines.append("")
            lines.append("Open-by-inode (openbyid_np: no path traversal at all):")
            lines.append("  symbol available: \(io.symbolAvailable)")
            if !io.symbolAvailable {
                lines.append("  openbyid_np is not present on this platform, so the experiment could not run.")
            }
            for attempt in io.attempts {
                let flag = attempt.enumeratedByInode ? "  <-- ENUMERATED BY INODE" : ""
                lines.append("  \(attempt.path)")
                // A nil errno means the open succeeded *only* when the attempt was
                // actually made. Without identifiers there is nothing to report,
                // and printing "ok" there would present a missing measurement as a
                // successful one.
                func inodeResult(_ errnoName: String?) -> String {
                    guard attempt.identifiersAvailable else { return "not attempted" }
                    return errnoName ?? "ok"
                }
                func pathResult(_ errnoName: String?) -> String {
                    errnoName ?? "ok"
                }
                lines.append("      inode: dev=\(attempt.deviceID) ino=\(attempt.inode)")
                lines.append("      by inode:  evtonly=\(inodeResult(attempt.evtonlyErrnoName)) "
                    + "readonly=\(inodeResult(attempt.readonlyErrnoName)) "
                    + "directory=\(inodeResult(attempt.directoryErrnoName))")
                lines.append("      by path:   open=\(pathResult(attempt.pathOpenErrnoName)) "
                    + "enumerate=\(pathResult(attempt.pathEnumerationErrnoName))")
                if let count = attempt.enumeratedEntries {
                    lines.append("      enumerated \(count) entries by inode\(flag)")
                    if let names = attempt.sampleEntryNames, !names.isEmpty {
                        lines.append("      sample: \(names.joined(separator: ", "))")
                    }
                }
                if attempt.inodeOpenSucceededWherePathFailed {
                    lines.append("      VERDICT: inode open succeeded where the path open was refused.")
                }
            }
            if !io.violations.isEmpty {
                lines.append("  VIOLATIONS: \(io.violations.map { $0.path }.joined(separator: ", "))")
            } else {
                lines.append("  no inode-based open succeeded where the path-based one was refused")
            }
        }

        for (label, scope) in [("while the scope is held", matrix.securityScope),
                               ("after the scope was released", matrix.securityScopeAfterRelease)] {
            guard let scope else { continue }
            lines.append("")
            lines.append("User-granted scope (\(label)):")
            lines.append("  granted:  \(scope.grantedPath)")
            lines.append("  resolved: \(scope.resolvedPath)")
            lines.append("  active:   \(scope.scopeActive)")
            for experiment in scope.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let errno = experiment.errnoName {
                    lines.append("      errno: \(errno) (\(experiment.errnoNumber))")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !scope.violations.isEmpty {
                lines.append("  VIOLATIONS: \(scope.violations.map { $0.id }.joined(separator: ", "))")
            } else {
                lines.append("  no experiment succeeded where the grant should have refused it")
            }
        }

        if !matrix.boundaryExperiments.isEmpty {
            lines.append("")
            lines.append("Boundary-mechanism experiments:")
            for experiment in matrix.boundaryExperiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      mechanism: \(experiment.mechanism)")
                lines.append("      operation: \(experiment.operation)  args: \(experiment.arguments)")
                lines.append("      expected:  \(experiment.expected)")
                if let errno = experiment.errnoName {
                    lines.append("      errno:     \(errno) (\(experiment.errnoNumber))")
                }
                lines.append("      result:    \(experiment.interpretation)")
            }
        }

        lines.append("")
        lines.append("Discrepancies:")
        let discrepancies = matrix.discrepancies()
        if discrepancies.isEmpty {
            lines.append("  none")
        } else {
            for d in discrepancies {
                lines.append("  - [\(d.path)] \(d.description)")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// JSON payload shape. Kept explicit so the format is stable across versions.
    private struct MatrixPayload: Encodable {
        let schema: String
        let environment: CapabilityMatrix.EnvironmentRecord
        let results: [ProbeResult]
        let ancestors: [AncestorStep]
        let boundaryExperiments: [CrossBoundaryProbe.Experiment]
        let sandboxProfile: SandboxProfileProbe.Result?
        let containerWrite: ContainerWriteProbe.Result?
        let inodeOpen: InodeOpenProbe.Result?
        let securityScope: SecurityScopeProbe.Result?
        let securityScopeAfterRelease: SecurityScopeProbe.Result?

        init(matrix: CapabilityMatrix) {
            self.schema = "fsprobe.capability-matrix.v6"
            self.environment = matrix.environment
            self.results = matrix.results
            self.ancestors = matrix.ancestors
            self.boundaryExperiments = matrix.boundaryExperiments
            self.sandboxProfile = matrix.sandboxProfile
            self.containerWrite = matrix.containerWrite
            self.inodeOpen = matrix.inodeOpen
            self.securityScope = matrix.securityScope
            self.securityScopeAfterRelease = matrix.securityScopeAfterRelease
        }
    }
}
