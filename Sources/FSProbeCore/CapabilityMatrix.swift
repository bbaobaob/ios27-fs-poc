//
//  CapabilityMatrix.swift
//  FSProbeCore — runs the probe set and derives the capability matrix.
//
//  The matrix records an independent result for every (path, operation) pair.
//  It also performs discrepancy analysis: e.g. a successful read whose parent
//  directory cannot be enumerated is a distinct, reportable observation.
//

import Foundation

public struct CapabilityMatrix: Sendable {
    /// All results, in run order.
    public private(set) var results: [ProbeResult]

    /// Environment record: results are meaningless without the exact platform.
    public let environment: EnvironmentRecord

    /// Directory-ascent steps, when an ascent was requested. Nearest ancestor
    /// first; empty when no ascent was run.
    public let ancestors: [AncestorStep]

    public init(
        results: [ProbeResult],
        environment: EnvironmentRecord,
        ancestors: [AncestorStep] = []
    ) {
        self.results = results
        self.environment = environment
        self.ancestors = ancestors
    }

    /// Platform context captured at run time.
    public struct EnvironmentRecord: Codable, Sendable {
        public let osName: String
        public let osVersion: String
        public let osBuild: String
        public let deviceModel: String
        public let processPath: String
        public let timestampUTC: String

        public init(
            osName: String = ProcessInfo.processInfo.operatingSystemVersionString,
            osVersion: String,
            osBuild: String,
            deviceModel: String,
            processPath: String = CommandLine.arguments.first ?? "unknown",
            timestampUTC: String = ISO8601DateFormatter().string(from: Date())
        ) {
            self.osName = osName
            self.osVersion = osVersion
            self.osBuild = osBuild
            self.deviceModel = deviceModel
            self.processPath = processPath
            self.timestampUTC = timestampUTC
        }
    }

    /// Results for one investigation target, keyed by operation.
    public func results(for path: String) -> [FSOperation: ProbeResult] {
        var map: [FSOperation: ProbeResult] = [:]
        for r in results where r.targetPath == path {
            map[r.operation] = r
        }
        return map
    }

    /// A row in the matrix: one path, one outcome per operation.
    public struct Row: Identifiable {
        public let path: String
        public let label: String
        public let isBaseline: Bool
        public let cells: [FSOperation: ProbeOutcome]

        public var id: String { path }

        /// Capability summary for the row.
        public var summary: String {
            var parts: [String] = []
            for op in FSOperation.allCases {
                if let outcome = cells[op] {
                    parts.append("\(op.rawValue)=\(outcome.rawValue)")
                }
            }
            return parts.joined(separator: " ")
        }
    }

    public func rows(targets: [FSTarget]) -> [Row] {
        targets.map { target in
            let perPath = results(for: target.path)
            var cells: [FSOperation: ProbeOutcome] = [:]
            for (op, result) in perPath {
                cells[op] = result.outcome
            }
            return Row(path: target.path, label: target.label, isBaseline: target.isBaseline, cells: cells)
        }
    }

    /// A discrepancy between two related operations on the same path.
    public struct Discrepancy: Identifiable, Sendable {
        public let path: String
        public let description: String
        public var id: String { "\(path)|\(description)" }
    }

    /// Detect operation-level discrepancies that are worth reporting.
    ///
    /// Each discrepancy is a *question*, not a finding: it identifies where the
    /// authorization surface is inconsistent and therefore worth investigating.
    public func discrepancies() -> [Discrepancy] {
        var found: [Discrepancy] = []
        var seenPaths = Set<String>()
        for result in results {
            guard !seenPaths.contains(result.targetPath) else { continue }
            seenPaths.insert(result.targetPath)
            let perPath = results(for: result.targetPath)

            // 1. File readable but parent directory not enumerable.
            if let read = perPath[.readFile], read.succeeded,
               let enumerate = perPath[.enumerate], !enumerate.succeeded {
                found.append(Discrepancy(
                    path: result.targetPath,
                    description: "File readable but target directory enumeration failed (\(enumerate.errnoName ?? "?")). Read-without-enumeration discrepancy."
                ))
            }

            // 2. Directory enumerable but not openable (should not happen with
            //    POSIX semantics; if observed, it indicates a caching/path artefact).
            if let enumerate = perPath[.enumerate], enumerate.succeeded,
               let open = perPath[.openDirectory], !open.succeeded {
                found.append(Discrepancy(
                    path: result.targetPath,
                    description: "Enumeration succeeded but opendir failed (\(open.errnoName ?? "?")). Inconsistent directory access."
                ))
            }

            // 3. Writable but not readable — asymmetric access.
            //    Reading a *directory* with open+read legitimately fails with
            //    EISDIR, so this check only applies to non-directory targets.
            if let write = perPath[.writeFile], write.succeeded,
               let read = perPath[.readFile], !read.succeeded,
               let stat = perPath[.stat], stat.succeeded,
               stat.evidence.statIsDirectory != true {
                found.append(Discrepancy(
                    path: result.targetPath,
                    description: "Write succeeded but read failed (\(read.errnoName ?? "?")). Asymmetric access on the same path."
                ))
            }

            // 4. lstat succeeds but stat fails — a symlink whose target is not
            //    resolvable by this process.
            if let lstat = perPath[.stat], lstat.succeeded,
               let stat = perPath[.statFollow], !stat.succeeded {
                found.append(Discrepancy(
                    path: result.targetPath,
                    description: "lstat succeeded but stat failed (\(stat.errnoName ?? "?")). Symlink target not resolvable by this process."
                ))
            }
        }
        return found
    }
}
