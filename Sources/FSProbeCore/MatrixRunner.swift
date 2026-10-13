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
    ///   - runBoundaryExperiments: when true, run the boundary-mechanism battery
    ///     (path resolution, hard links, rename, enumeration differential) and
    ///     read the app's own sandbox profile out of its container metadata.
    public func run(
        targets: [FSTarget],
        recordEntryNames: Bool = false,
        environment: CapabilityMatrix.EnvironmentRecord? = nil,
        ascendFrom: String? = nil,
        runBoundaryExperiments: Bool = false
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

        var boundary: [CrossBoundaryProbe.Experiment] = []
        var profile: SandboxProfileProbe.Result?
        var containerWrite: ContainerWriteProbe.Result?
        var inodeOpen: InodeOpenProbe.Result?
        var clone: CloneProbe.Result?
        var xpcServices: [XPCProbe.ServiceProbe]?
        var fileCoordinator: XPCProbe.CoordinatorResult?
        if runBoundaryExperiments {
            // The container is the app's own home; every experiment is scoped to
            // it and to paths it cannot reach.
            let container = ascendFrom ?? NSHomeDirectory()
            boundary = CrossBoundaryProbe.runAll(containerPath: container)
            let documents = FileManager.default
                .urls(for: .documentDirectory, in: .userDomainMask).first
            profile = SandboxProfileProbe.probe(
                containerPath: container,
                documentsDirectory: documents
            )
            containerWrite = ContainerWriteProbe.probe(containerPath: container)
            inodeOpen = InodeOpenProbe.probe(paths: InodeOpenProbe.defaultTargets())
            clone = CloneProbe.run(containerPath: container)

            // Service-mediated authorization: which XPC services this process can
            // reach, and whether NSFileCoordinator performs unauthorized work on
            // the caller's behalf.
            //
            // `xpcAvailable` is a compile-time SDK-availability fact, not a
            // measurement, so the service list stays nil and the report labels the
            // section NOT_ATTEMPTED rather than drawing a reachability conclusion.
            xpcServices = XPCProbe.xpcAvailable
                ? XPCProbe.probeServices(timeout: 3.0)
                : nil
            fileCoordinator = XPCProbe.probeFileCoordinator(
                containerPath: container,
                outsideDirectory: "/var/mobile/Library"
            )
        }

        return CapabilityMatrix(
            results: results,
            environment: env,
            ancestors: ancestors,
            boundaryExperiments: boundary,
            sandboxProfile: profile,
            containerWrite: containerWrite,
            inodeOpen: inodeOpen,
            clone: clone,
            xpcServices: xpcServices,
            fileCoordinator: fileCoordinator
        )
    }
}
