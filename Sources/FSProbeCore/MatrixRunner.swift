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
        var machServices: [CrossProcessProbe.MachServiceProbe]?
        var processIntrospection: CrossProcessProbe.IntrospectionReport?
        var preferenceDeputy: PreferenceDeputyProbe.Result?
        var operationClasses: FileOperationClassProbe.Result?
        var metadataReads: MetadataReadProbe.Result?
        var descriptorPrimitives: DescriptorPrimitiveProbe.Result?
        var foundationSurface: FoundationSurfaceProbe.Result?
        var alternateLookups: AlternateLookupProbe.Result?
        var remainingPrimitives: RemainingPrimitivesProbe.Result?
        var searchFS: SearchFSProbe.Result?
        var machPrivilege: MachPrivilegeProbe.Result?
        var xpcReplies: XPCReplyProbe.Result?
        var ipcSurface: IPCSurfaceProbe.Result?
        var hostPort: HostPortProbe.Result?
        var processorSets: ProcessorSetProbe.Result?
        var foreignMemory: ForeignMemoryProbe.Result?
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

            // The mach-lookup experiment resolves the connection factory at
            // runtime instead of linking it, because the SDK marks it
            // unavailable. Whether the symbol is present, and whether the
            // operating system then permits the lookup, is measured here rather
            // than inferred from header availability.
            //
            // The negative control is the first candidate by design, so a real
            // answer can be told apart from the platform's "not found".
            machServices = CrossProcessProbe.machReachabilityAvailable
                ? CrossProcessProbe.probeMachServices(timeout: 3.0)
                : nil

            // Cross-process introspection. The self-targeting control runs
            // first and gates the interpretation of every other attempt.
            processIntrospection = CrossProcessProbe.probeProcessIntrospection()

            // cfprefsd is reachable (measured), and it writes files on the
            // caller's behalf. Test whether it resolves a caller-supplied suite
            // name against this container or against a global location.
            preferenceDeputy = PreferenceDeputyProbe.probe(containerPath: container)

            // Sandbox operation classes not previously tested. Each is a
            // distinct authorization predicate, and the reverse-direction link
            // case has never been run in either direction before.
            operationClasses = FileOperationClassProbe.probe(containerPath: container)

            // Read primitives that never open the file. Separate sandbox
            // predicates from file-read-data, and never tested in this project.
            metadataReads = MetadataReadProbe.probe(containerPath: container)

            // Descriptor-based primitives. Obtaining an event-only descriptor for
            // a protected object and then operating through it is a separate
            // authorization question from every path-based experiment so far.
            descriptorPrimitives = DescriptorPrimitiveProbe.probe(containerPath: container)

            // The same boundary through Foundation and CoreFoundation instead of
            // libc. Includes access(), never tested directly, and the one public
            // API that reaches containermanagerd.
            foundationSurface = FoundationSurfaceProbe.probe(containerPath: container)

            // A different path to a mach service than the XPC connection factory.
            // If the mach-lookup gate depends on which API asks, a service XPC
            // refused may be resolvable here.
            alternateLookups = AlternateLookupProbe.probe()

            // Primitives never tried before, each a separate authorization
            // predicate: the mount table, a host port, kernel MIBs, and copyfile.
            remainingPrimitives = RemainingPrimitivesProbe.probe(containerPath: container)

            // A volume-wide name search, which is a different VFS operation from
            // reading a directory and has never been tested.
            searchFS = SearchFSProbe.probe(containerPath: container)

            // The Mach privilege ladder. A host port or a processor-set task list
            // would be the strongest possible process-isolation violation.
            machPrivilege = MachPrivilegeProbe.probe()

            // Reachability is not the same as answering. This asks the second
            // question of the services the lookup experiment reached.
            xpcReplies = XPCReplyProbe.probe()

            // The remaining IPC surface, including a THIRD name-resolution path.
            ipcSurface = IPCSurfaceProbe.probe()

            // An obtainable host port is not the same as a usable one. This asks
            // the question that decides whether the earlier violation was real.
            hostPort = HostPortProbe.probe()

            // The call that would list every task on the device.
            processorSets = ProcessorSetProbe.probe()

            // The endpoint of the whole ladder: another process's memory.
            foreignMemory = ForeignMemoryProbe.probe()
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
            fileCoordinator: fileCoordinator,
            machServices: machServices,
            processIntrospection: processIntrospection,
            preferenceDeputy: preferenceDeputy,
            operationClasses: operationClasses,
            metadataReads: metadataReads,
            descriptorPrimitives: descriptorPrimitives,
            foundationSurface: foundationSurface,
            alternateLookups: alternateLookups,
            remainingPrimitives: remainingPrimitives,
            searchFS: searchFS,
            machPrivilege: machPrivilege,
            xpcReplies: xpcReplies,
            ipcSurface: ipcSurface,
            hostPort: hostPort,
            processorSets: processorSets,
            foreignMemory: foreignMemory
        )
    }
}
