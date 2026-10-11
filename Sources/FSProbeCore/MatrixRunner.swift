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
    ///   - ascendFrom: when set, also run the read-only directory-ascent
    ///     experiment starting at this path. The app passes its own container,
    ///     which makes the ancestors the real research surface: on a device they
    ///     are the /var/mobile/Containers chain.
    public func run(
        targets: [FSTarget],
        recordEntryNames: Bool = false,
        environment: CapabilityMatrix.EnvironmentRecord? = nil,
        ascendFrom: String? = nil
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
        let ancestors = ascendFrom.map { AncestorProbe.ascend(from: $0) } ?? []
        return CapabilityMatrix(results: results, environment: env, ancestors: ancestors)
    }
}
