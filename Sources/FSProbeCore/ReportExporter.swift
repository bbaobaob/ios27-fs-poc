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

        init(matrix: CapabilityMatrix) {
            self.schema = "fsprobe.capability-matrix.v1"
            self.environment = matrix.environment
            self.results = matrix.results
        }
    }
}
