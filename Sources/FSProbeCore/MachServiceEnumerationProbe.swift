//
//  MachServiceEnumerationProbe.swift
//  FSProbeCore — enumerate the reachable mach services instead of guessing.
//
//  WHY THIS EXISTS
//  ---------------
//  Every service experiment so far used a hand-written list of eight candidates.
//  That list was assembled from what the app already uses and from names in public
//  documentation, which means it measures what I already suspected rather than
//  what is actually reachable.
//
//  The published method for answering the real question is different, and it is
//  public: parse `/System/Library/xpc/launchd.plist`, and for every entry in each
//  `MachServices` dictionary, attempt a lookup. Success means the service is
//  reachable from this sandbox. Two independent iOS enumerations used exactly
//  this method (iOS 16.1 and 16.3.1), and the technique is documented at
//  jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/.
//
//  That turns an eight-name guess into a census. A service nobody has written
//  about is exactly the kind that has not had its caller validation looked at,
//  which is the point.
//
//  HYPOTHESIS
//  ----------
//  The set of mach services reachable from an ordinary sandboxed app is larger
//  and different from the eight names tested so far, and it can be enumerated
//  from inside the app rather than assumed.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Which named services an ordinary app can reach, measured rather than guessed.
//
//  CONTROL
//  -------
//  A service name that cannot exist, which must fail to resolve. Without it a
//  failure to resolve is uninterpretable: it could mean the policy denied it, or
//  that the name was wrong.
//
//  SAFETY
//  ------
//  Read-only enumeration. A lookup resolves a port and releases it immediately.
//  No message is sent to any service, so nothing is asked of any of them.
//

import Foundation

public enum MachServiceEnumerationProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The service name resolved to a port.
        case reachable
        /// The lookup was refused.
        case refused
        /// The manifest could not be read, so no enumeration was possible.
        case manifestUnreadable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Service: Sendable, Identifiable, Codable {
        public let serviceName: String
        public let outcome: Outcome
        /// The errno or kern error, as the platform reported it.
        public let errorName: String?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            serviceName: String,
            outcome: Outcome,
            errorName: String?,
            observed: String?,
            interpretation: String
        ) {
            self.serviceName = serviceName
            self.outcome = outcome
            self.errorName = errorName
            self.observed = observed
            self.interpretation = interpretation
        }

        public var id: String { serviceName }

        /// Reachability is reconnaissance, not a finding. The finding would be an
        /// effect a reachable service produces for an unidentified caller.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let manifestReadable: Bool
        /// How many service names the manifest contained.
        public let manifestEntryCount: Int
        public let services: [Service]
        /// The names that resolved, for follow-up.
        public let reachableNames: [String]
        /// The names that were refused.
        public let refusedCount: Int

        public init(
            manifestReadable: Bool,
            manifestEntryCount: Int,
            services: [Service],
            reachableNames: [String],
            refusedCount: Int
        ) {
            self.manifestReadable = manifestReadable
            self.manifestEntryCount = manifestEntryCount
            self.services = services
            self.reachableNames = reachableNames
            self.refusedCount = refusedCount
        }

        public var violations: [Service] { [] }
    }

    /// The launchd manifest that lists every registered mach service.
    private static let manifestPath = "/System/Library/xpc/launchd.plist"

    /// A service name that cannot exist, which must fail to resolve.
    private static let controlName = "com.bbaobaob.fsprobe.nonexistent.control"

    /// Names already tested by the reachability experiment. Reported separately so
    /// the census can be compared against what was already known.
    /// Exposed so the report can mark which reachable names are new.
    public static let alreadyTested: Set<String> = [
        "com.apple.FileCoordination",
        "com.apple.cfprefsd.daemon",
        "com.apple.containermanagerd",
        "com.apple.containermanagerd.system",
        "com.apple.coreservices.quarantine-resolver",
        "com.apple.mobile.installation_proxy",
        "com.apple.LaunchServices",
    ]

    /// How many names to probe. The manifest lists hundreds; the lookup is cheap
    /// but not free, and a bounded census is more useful than an unbounded one.
    private static let maxProbes = 250

    public static func probe() -> Result {
        #if canImport(Darwin)
        // The control first. A failure to resolve is only interpretable once the
        // platform's "not found" signature is known.
        let control = lookupService(controlName)

        guard manifestReadable() else {
            return Result(
                manifestReadable: false,
                manifestEntryCount: 0,
                services: [control],
                reachableNames: [],
                refusedCount: 0
            )
        }

        let names = manifestServiceNames()
        let probed = Array(names.prefix(maxProbes))
        let services = probed.map { name in
            if name == controlName { return control }
            return lookupService(name)
        }

        let reachable = services.filter { $0.outcome == .reachable }
        let refused = services.filter { $0.outcome == .refused }

        return Result(
            manifestReadable: true,
            manifestEntryCount: names.count,
            services: services,
            reachableNames: reachable.map { $0.serviceName }.sorted(),
            refusedCount: refused.count
        )
        #else
        return Result(
            manifestReadable: false,
            manifestEntryCount: 0,
            services: [Service(
                serviceName: controlName, outcome: .notAttempted,
                errorName: nil, observed: nil,
                interpretation: """
                    NOT ATTEMPTED: the Mach bootstrap API is not present on this \
                    platform.
                    """
            )],
            reachableNames: [],
            refusedCount: 0
        )
        #endif
    }

    #if canImport(Darwin)

    /// True when the launchd manifest can be read from this sandbox.
    ///
    /// This is itself a measurement worth recording: iOS has no SBPL text for its
    /// default container profile, so whether the manifest is readable is not
    /// something that can be reasoned about from documentation. If it is not
    /// readable, the census cannot run and that fact is reported rather than
    /// worked around silently.
    private static func manifestReadable() -> Bool {
        FileManager.default.isReadableFile(atPath: manifestPath)
    }

    /// Every service name in the manifest's MachServices dictionaries.
    private static func manifestServiceNames() -> [String] {
        guard let data = FileManager.default.contents(atPath: manifestPath),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
              ),
              let root = plist as? [String: Any] else {
            return []
        }

        var names: [String] = []
        for (_, value) in root {
            guard let entry = value as? [String: Any],
                  let machServices = entry["MachServices"] as? [String: Any] else {
                continue
            }
            for (name, _) in machServices {
                names.append(name)
            }
        }
        return Array(Set(names)).sorted()
    }

    /// Resolve one service name, releasing the port immediately.
    private static func lookupService(_ name: String) -> Service {
        var bootstrapPort: MachPort = 0
        let portKR = MachShim.taskGetBootstrapPort(MachShim.taskSelf, &bootstrapPort)
        guard portKR == 0, bootstrapPort != 0 else {
            return Service(
                serviceName: name, outcome: .notAttempted,
                errorName: MachShim.machErrorString(portKR),
                observed: "no bootstrap port",
                interpretation: """
                    NOT ATTEMPTED: this task has no bootstrap port, so no lookup \
                    could be made.
                    """
            )
        }

        var servicePort: MachPort = 0
        setErrno(0)
        let kr = name.withCString { cName in
            MachShim.bootstrapLookUp(bootstrapPort, cName, &servicePort)
        }

        if kr == 0 && servicePort != 0 {
            _ = MachShim.deallocatePort(MachShim.taskSelf, servicePort)
            let known = alreadyTested.contains(name)
            return Service(
                serviceName: name, outcome: .reachable,
                errorName: nil,
                observed: "resolved to a port",
                interpretation: known
                    ? """
                        Reachable. This name was already tested by the reachability \
                        experiment, so the census agrees with it.
                        """
                    : """
                        Reachable, and NOT in the set of names tested so far. This \
                        is a service nobody has looked at in this project, which is \
                        exactly the kind worth examining for caller validation.
                        """
            )
        }

        let err = currentErrno()
        return Service(
            serviceName: name, outcome: .refused,
            errorName: kr != 0 ? MachShim.machErrorString(kr) : ErrorClassifier.errnoName(err),
            observed: "lookup refused",
            interpretation: """
                Refused. The mach-lookup gate holds for this name.
                """
        )
    }

    #endif
}
