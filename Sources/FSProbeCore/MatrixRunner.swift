//
//  MatrixRunner.swift
//  FSProbeCore — runs the full probe set against a target list.
//

import Foundation

public struct MatrixRunner: Sendable {

    public init() {}

    /// Run every operation against every target.
    ///
    /// - Parameters:
    ///   - targets: paths to probe
    ///   - recordEntryNames: record sample entry names. Enable only when the
    ///     target list contains directories this harness created.
    ///   - environment: platform context recorded with the results
    public func run(
        targets: [FSTarget],
        recordEntryNames: Bool = false,
        environment: CapabilityMatrix.EnvironmentRecord? = nil
    ) -> CapabilityMatrix {
        var results: [ProbeResult] = []
        for target in targets {
            for operation in FSOperation.allCases {
                let result = POSIXProbeEngine.run(
                    operation,
                    on: target.path,
                    recordEntryNames: recordEntryNames && target.isBaseline
                )
                results.append(result)
            }
        }
        let env = environment ?? CapabilityMatrix.EnvironmentRecord(
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            osBuild: "unknown",
            deviceModel: "unknown"
        )
        return CapabilityMatrix(results: results, environment: env)
    }
}
