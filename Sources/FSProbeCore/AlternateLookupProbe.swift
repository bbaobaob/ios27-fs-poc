//
//  AlternateLookupProbe.swift
//  FSProbeCore — reaching a mach service by a different path than XPC.
//
//  HYPOTHESIS
//  ----------
//  The mach-lookup experiment established that `xpc_connection_create_mach_service`
//  reaches some named services from an ordinary app and is refused for others. The
//  negative control proved the refusals are real: a service name that cannot exist
//  produced the same signature as the refused ones.
//
//  That experiment tested ONE path to a mach service: the XPC connection factory.
//  There is an older and entirely separate path that has never been tested here:
//
//   `bootstrap_look_up(bootstrap_port, service_name, &service_port)`
//
//  This is the pre-XPC way to resolve a mach service by name. It goes through the
//  task's bootstrap port rather than through libxpc's connection machinery, and it
//  is a different code path with a different authorization check. If the sandbox
//  profile permits the lookup for one path and not the other, a service refused to
//  XPC may be resolvable through `bootstrap_look_up` — a bypass of the mach-lookup
//  gate, and the means to reach a deputy the app was supposed to be unable to talk
//  to.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  launchd's mach-lookup authorization, and whether it depends on which API asks.
//
//  CONTROL
//  -------
//  A service name that cannot exist, which must fail to resolve. Without it, a
//  failure to resolve is uninterpretable — it could mean the policy denied it, or
//  that the name was simply wrong.
//
//  THE DISCRIMINATING COMPARISON
//  -----------------------------
//  This experiment is only interesting next to the XPC result. The service list is
//  the same one the mach-lookup experiment used, so each name has a known XPC
//  outcome. A name that XPC refused but `bootstrap_look_up` resolves is the
//  finding. A name that both refuse is consistent. A name that XPC reached and
//  `bootstrap_look_up` also reaches is consistent.
//
//  SAFETY
//  ------
//  This resolves a *port* and does nothing with it. No message is sent, no service
//  is invoked, no file is touched. Ports are released immediately.
//

import Foundation

public enum AlternateLookupProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The service name resolved to a port.
        case resolved
        /// The lookup was refused.
        case refused
        /// The bootstrap port could not be obtained, so the experiment could not
        /// run at all.
        case noBootstrapPort
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Lookup: Sendable, Identifiable, Codable {
        public let serviceName: String
        /// Why this service is a candidate.
        public let rationale: String
        /// What the XPC path produced for this name, when it is known. This is
        /// what makes a result here interpretable at all.
        public let xpcOutcome: String?
        public let outcome: Outcome
        /// The kern_return_t, or the errno, as the platform reported it.
        public let returnValue: String?
        public let errorName: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            serviceName: String,
            rationale: String,
            xpcOutcome: String?,
            outcome: Outcome,
            returnValue: String?,
            errorName: String?,
            interpretation: String
        ) {
            self.serviceName = serviceName
            self.rationale = rationale
            self.xpcOutcome = xpcOutcome
            self.outcome = outcome
            self.returnValue = returnValue
            self.errorName = errorName
            self.interpretation = interpretation
        }

        public var id: String { serviceName }

        /// The finding is a name the XPC path refused but this path resolves.
        ///
        /// Without the XPC outcome recorded alongside, a resolved port says nothing
        /// — plenty of services are legitimately reachable, and the whole point is
        /// the *difference* between the two paths.
        public var isBoundaryViolation: Bool {
            guard outcome == .resolved else { return false }
            guard let xpcOutcome else { return false }
            return xpcOutcome == "refused"
        }
    }

    public struct Result: Sendable, Codable {
        public let lookups: [Lookup]
        public let violations: [Lookup]
        /// True when the bootstrap port itself was unavailable, which makes every
        /// result below uninterpretable.
        public let bootstrapPortAvailable: Bool

        public init(
            lookups: [Lookup],
            violations: [Lookup],
            bootstrapPortAvailable: Bool
        ) {
            self.lookups = lookups
            self.violations = violations
            self.bootstrapPortAvailable = bootstrapPortAvailable
        }
    }

    /// The service list, with the XPC outcome each produced on the device.
    ///
    /// These are recorded results from the mach-lookup experiment, not guesses.
    /// The negative control leads, so the platform's "not found" signature is
    /// calibrated before anything is interpreted.
    /// Exposed so a test can assert the negative control leads and that every
    /// entry carries the XPC outcome that makes its result interpretable.
    public static let serviceList: [(name: String, rationale: String, xpc: String)] = [
        ("com.bbaobaob.fsprobe.nonexistent.control",
         "NEGATIVE CONTROL: a name that cannot exist, to calibrate the failure signature",
         "refused"),
        ("com.apple.FileCoordination",
         "NSFileCoordinator's backend", "reachable"),
        ("com.apple.cfprefsd.daemon",
         "Preference writes on the caller's behalf", "reachable"),
        ("com.apple.containermanagerd",
         "Container resolution on the caller's behalf", "reachable"),
        ("com.apple.containermanagerd.system",
         "System-scope container resolution", "reachable"),
        ("com.apple.coreservices.quarantine-resolver",
         "LaunchServices quarantine resolution", "refused"),
        ("com.apple.mobile.installation_proxy",
         "App installation", "refused"),
        ("com.apple.LaunchServices",
         "Application and document-type resolution", "refused"),
    ]

    #if canImport(Darwin)

    @_silgen_name("task_get_bootstrap_port")
    private static func sTaskGetBootstrapPort(
        _ task: mach_port_t, _ bootstrapPort: UnsafeMutablePointer<mach_port_t>
    ) -> Int32

    @_silgen_name("bootstrap_look_up")
    private static func sBootstrapLookUp(
        _ bp: mach_port_t, _ serviceName: UnsafePointer<CChar>,
        _ servicePort: UnsafeMutablePointer<mach_port_t>
    ) -> Int32

    private static var symbolsAvailable: Bool { true }

    #else

    private static var symbolsAvailable: Bool { false }

    #endif

    public static func probe() -> Result {
        #if canImport(Darwin)
        var bootstrapPort: mach_port_t = 0
        let kr = sTaskGetBootstrapPort(mach_task_self_, &bootstrapPort)
        guard kr == 0, bootstrapPort != 0 else {
            // Without a bootstrap port nothing can be looked up, and every result
            // below would be an artifact of that rather than a measurement.
            return Result(
                lookups: serviceList.map { entry in
                    Lookup(
                        serviceName: entry.name, rationale: entry.rationale,
                        xpcOutcome: entry.xpc, outcome: .noBootstrapPort,
                        returnValue: "kern_return_t \(kr)",
                        errorName: machErrorName(kr),
                        interpretation: """
                            NOT ATTEMPTED: this task has no bootstrap port \
                            (kern_return_t \(kr)), so no lookup could be made. Nothing is \
                            claimed about the mach-lookup gate.
                            """
                    )
                },
                violations: [],
                bootstrapPortAvailable: false
            )
        }

        let lookups = serviceList.map { entry in
            lookup(entry, bootstrapPort: bootstrapPort)
        }
        #else
        let lookups = serviceList.map { entry in
            Lookup(
                serviceName: entry.name, rationale: entry.rationale,
                xpcOutcome: entry.xpc, outcome: .notAttempted,
                returnValue: nil, errorName: nil,
                interpretation: """
                    NOT ATTEMPTED: the Mach bootstrap API is not present on this \
                    platform, so no lookup was made.
                    """
            )
        }
        #endif

        let violations = lookups.filter { $0.isBoundaryViolation }
        return Result(
            lookups: lookups,
            violations: violations,
            bootstrapPortAvailable: true
        )
    }

    #if canImport(Darwin)

    private static func lookup(
        _ entry: (name: String, rationale: String, xpc: String),
        bootstrapPort: mach_port_t
    ) -> Lookup {
        var servicePort: mach_port_t = 0
        setErrno(0)
        let kr = entry.name.withCString { name in
            sBootstrapLookUp(bootstrapPort, name, &servicePort)
        }

        if kr == 0 && servicePort != 0 {
            // A port was resolved. Release it immediately: the experiment is about
            // whether the lookup was permitted, not about using the service.
            _ = mach_port_deallocate(mach_task_self_, servicePort)

            let bypassed = entry.xpc == "refused"
            return Lookup(
                serviceName: entry.name, rationale: entry.rationale,
                xpcOutcome: entry.xpc, outcome: .resolved,
                returnValue: "kern_return_t 0", errorName: nil,
                interpretation: bypassed
                    ? """
                    BYPASS: the XPC path refused this service name, but \
                    bootstrap_look_up resolved it to a port. The mach-lookup \
                    authorization depends on which API asks, and this path is \
                    weaker. This is the finding: a service the app was supposed to \
                    be unable to reach is now reachable.
                    """
                    : """
                    Resolved, consistent with the XPC path, which also reached it.
                    """
            )
        }

        let err = currentErrno()
        let errnoName = err == 0 ? nil : ErrorClassifier.errnoName(err)
        return Lookup(
            serviceName: entry.name, rationale: entry.rationale,
            xpcOutcome: entry.xpc, outcome: .refused,
            returnValue: "kern_return_t \(kr)",
            errorName: kr != 0 ? machErrorName(kr) : errnoName,
            interpretation: """
                Refused, consistent with the XPC path \
                (\(entry.xpc)). The mach-lookup gate holds for this name on both \
                paths.
                """
        )
    }

    @_silgen_name("mach_error_string")
    private static func sMachErrorString(_ error: mach_error_t) -> UnsafePointer<CChar>?

    @_silgen_name("mach_port_deallocate")
    private static func mach_port_deallocate(_ task: mach_port_t, _ name: mach_port_t) -> Int32

    private static func machErrorName(_ kr: Int32) -> String {
        guard let ptr = sMachErrorString(mach_error_t(kr)) else {
            return "kern_return_t \(kr)"
        }
        return String(cString: ptr)
    }

    #endif
}
