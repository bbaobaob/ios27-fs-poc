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
    ///   - onProgress: called after each phase with the results so far. The full
    ///     battery takes minutes, and until this existed the matrix was written
    ///     exactly once, at the end -- so a run that was killed, suspended, or
    ///     interrupted produced NO evidence at all rather than partial evidence.
    ///     All-or-nothing is the one shape this project cannot accept: an
    ///     interrupted run and a run that found nothing are different facts, and
    ///     only an incremental write keeps them apart.
    public func run(
        targets: [FSTarget],
        recordEntryNames: Bool = false,
        environment: CapabilityMatrix.EnvironmentRecord? = nil,
        ascendFrom: String? = nil,
        runBoundaryExperiments: Bool = false,
        onProgress: ((_ stage: String, _ matrix: CapabilityMatrix) -> Void)? = nil
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
        var xpcReplyContents: XPCReplyContentsProbe.Result?
        var processExecution: ProcessExecutionProbe.Result?
        var profileSpawn: SandboxProfileSpawnProbe.Result?
        var machServiceCensus: MachServiceEnumerationProbe.Result?
        var embeddedXPCServices: EmbeddedXPCServiceProbe.Result?
        var keychainIsolation: KeychainIsolationProbe.Result?
        var ioKitCensus: IOKitCensusProbe.Result?
        var spotlightEnumeration: SpotlightEnumerationProbe.Result?

        /// The matrix as it stands right now.
        ///
        /// Defined before the phases run and capturing every result variable, so
        /// a snapshot taken mid-run is the same shape as the final one. A phase
        /// that never ran stays nil, and the report already renders a nil section
        /// as NOT_ATTEMPTED -- so an interrupted run reads as "these phases did
        /// not happen" rather than as "these phases found nothing".
        func snapshot() -> CapabilityMatrix {
            CapabilityMatrix(
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
                foreignMemory: foreignMemory,
                xpcReplyContents: xpcReplyContents,
                processExecution: processExecution,
                profileSpawn: profileSpawn,
                machServiceCensus: machServiceCensus,
                embeddedXPCServices: embeddedXPCServices,
                keychainIsolation: keychainIsolation,
                ioKitCensus: ioKitCensus,
                spotlightEnumeration: spotlightEnumeration
            )
        }

        func reportProgress(_ stage: String) {
            onProgress?(stage, snapshot())
        }

        // The filesystem matrix is the base layer and is cheap; report it first so
        // that even a run interrupted after a second has produced something.
        reportProgress("filesystem-matrix")

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
            reportProgress("boundary-and-container")

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
            reportProgress("introspection")

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
            reportProgress("metadata-and-descriptors")

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
            reportProgress("foundation-and-alternate-lookups")

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
            reportProgress("mach-ladder")

            // A reply is not a primitive. What the reply contains decides it.
            xpcReplyContents = XPCReplyContentsProbe.probe()
            // One marker per module through the death window, not one per
            // group. The simulator run that validates every commit once died
            // between "mach-ladder" and "execution-and-profile-spawn" with three
            // modules in between and no way to tell which one killed it. A
            // progress marker is nearly free and turns the next death from a
            // three-suspect mystery into a named module.
            reportProgress("xpc-reply-contents")

            // The most consequential untested thing: can an ordinary app run a
            // system binary? A spawn is the primitive every escalation needs.
            processExecution = ProcessExecutionProbe.probe()
            reportProgress("process-execution")

            // CVE-2026-20628: naming a built-in sandbox profile for a child. The
            // advisory covers 26.3 and earlier; iOS 27.0 is later, so the fix is
            // expected -- but expected is not measured.
            profileSpawn = SandboxProfileSpawnProbe.probe()
            reportProgress("execution-and-profile-spawn")

            // A census of reachable services rather than the hand-written list of
            // eight. The published method: parse launchd.plist and try each name.
            machServiceCensus = MachServiceEnumerationProbe.probe()

            // XPC services inside system frameworks. These register into the
            // loading app's PID domain, so launchd lookup never sees them and the
            // sandbox profile never names them.
            embeddedXPCServices = EmbeddedXPCServiceProbe.probe()
            reportProgress("embedded-xpc-services")

            // A different data boundary with the same shape as the container:
            // the keychain isolates apps by access group. A broad query that
            // names no group must return only the caller's own items.
            keychainIsolation = KeychainIsolationProbe.probe()
            reportProgress("keychain-isolation")

            // The census half of the kernel surface: which IORegistry entries
            // are enumerable from the sandbox. No user client is opened and no
            // external method is called -- visibility is reconnaissance, and a
            // later experiment aimed by this list would test what any of them
            // will do for an unidentified caller.
            ioKitCensus = IOKitCensusProbe.probe()
            reportProgress("iokit-census")

            // A third party that already walked the whole volume: the metadata
            // index. If it answers names outside the container, it tells what
            // the sandbox refuses to tell. The sentinel control proves the
            // mechanism works before the broad query is read.
            spotlightEnumeration = SpotlightEnumerationProbe.probe(containerPath: container)
            reportProgress("spotlight-enumeration")
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
            foreignMemory: foreignMemory,
            xpcReplyContents: xpcReplyContents,
            processExecution: processExecution,
            profileSpawn: profileSpawn,
            machServiceCensus: machServiceCensus,
            embeddedXPCServices: embeddedXPCServices,
            keychainIsolation: keychainIsolation,
            ioKitCensus: ioKitCensus,
            spotlightEnumeration: spotlightEnumeration
        )
    }
}
