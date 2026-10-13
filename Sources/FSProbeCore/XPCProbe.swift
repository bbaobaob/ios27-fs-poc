//
//  XPCProbe.swift
//  FSProbeCore — service-mediated authorization research.
//
//  HYPOTHESIS
//  ----------
//  Every filesystem experiment so far tested what *this process* can do. The
//  sandbox is uniformly enforced for those and holds. That says nothing about the
//  other authorization path: system services that perform filesystem work on a
//  caller's behalf.
//
//  A confused deputy arises when such a service acts on a resource the caller
//  names but does not own, without checking that the caller is authorized for it.
//  The service is privileged; the caller is not; if the service trusts the
//  caller's resource reference, the caller inherits the service's authority.
//
//  This module maps the reachable surface first — which services a sandboxed app
//  can actually talk to — and then tests the highest-value public-API deputy,
//  `NSFileCoordinator`, against URLs outside the container.
//
//  EXPECTED RESULT
//  ---------------
//  Reachable services are those the platform profile explicitly permits, and each
//  validates the caller independently. A reachable service that performs an
//  unauthorized filesystem operation on the caller's behalf is a finding.
//
//  REACHABILITY IS NOT A VULNERABILITY. A connection that opens, or a request that
//  is accepted, proves only that the service exists and answered. The finding
//  would be an *effect* the caller was not authorized to produce.
//
//  SAFETY
//  ------
//  Every request is bounded by a timeout, so a silent service cannot hang the
//  harness. Requests carry no secrets and name no unrelated private data. The
//  file-coordination tests target paths this harness created, and clean up.
//

import Foundation

public enum XPCProbe {

    // MARK: - Service reachability
    //
    // Gated to Darwin: libxpc exists only there. The Android verification host has
    // no XPC at all, so the service-reachability half of this module is compiled
    // out and reports itself unavailable rather than failing to build. The device
    // is where this research actually runs.

    #if canImport(Darwin)

    public enum Reachability: String, Codable, Sendable {
        /// No error arrived within the timeout: the service exists and accepted
        /// the connection.
        case reachable
        /// The connection was refused, with the platform's own reason.
        case refused
        /// Nothing arrived within the timeout.
        case noResponse
        /// The connection could not be created at all.
        case notCreated
    }

    public struct ServiceProbe: Sendable, Identifiable, Codable {
        public let serviceName: String
        /// Why this service is a candidate, in one line.
        public let rationale: String
        public let reachability: Reachability
        /// The platform's own refusal reason, when it gave one.
        public let refusalReason: String?
        /// Round-trip time in milliseconds, when a response arrived.
        public let responseMilliseconds: Int?

        public init(
            serviceName: String,
            rationale: String,
            reachability: Reachability,
            refusalReason: String?,
            responseMilliseconds: Int?
        ) {
            self.serviceName = serviceName
            self.rationale = rationale
            self.reachability = reachability
            self.refusalReason = refusalReason
            self.responseMilliseconds = responseMilliseconds
        }

        public var id: String { serviceName }
    }

    /// Candidates, prioritised by the filesystem work each performs on a caller's
    /// behalf. Ordered by promise, not by name.
    public static func serviceCandidates() -> [(name: String, rationale: String)] {
        [
            ("com.apple.FileCoordination",
             "NSFileCoordinator's backend: arbitrates reads and writes of named URLs on the caller's behalf"),
            ("com.apple.cfprefsd.daemon",
             "Writes preference files into the caller's container: a deputy that performs file writes"),
            ("com.apple.containermanagerd",
             "Resolves and creates app containers by name: a deputy that resolves resource references"),
            ("com.apple.containermanagerd.system",
             "The system-scope container manager: resolves shared and system containers"),
            ("com.apple.coreservices.quarantine-resolver",
             "LaunchServices quarantine resolution, operates on downloaded file paths"),
            ("com.apple.mobile.installation_proxy",
             "Installs and removes apps and their containers"),
            ("com.apple.LaunchServices",
             "Application and document-type resolution from a sandboxed caller"),
            ("com.apple.SharedFileList",
             "Shared file-list persistence across login sessions"),
            ("com.apple.xpc.role.account.stationary",
             "Per-user XPC domain"),
            ("com.apple.networkextension",
             "Network extension configuration"),
            ("com.apple.aggregated",
             "Aggregated logging and metrics"),
            ("com.apple.PerfPowerTelemetry",
             "Performance telemetry client"),
        ]
    }

    /// True when this platform provides XPC. The device does; the verification
    /// host does not.
    public static var xpcAvailable: Bool { true }

    /// Probe each candidate's reachability from this process.
    ///
    /// - Parameter timeout: seconds to wait for a service to answer before
    ///   declaring no response. Bounded so a silent service cannot hang the run.
    public static func probeServices(timeout: TimeInterval = 3.0) -> [ServiceProbe] {
        serviceCandidates().map { candidate in
            probeService(candidate.name, rationale: candidate.rationale, timeout: timeout)
        }
    }

    private static func probeService(
        _ name: String,
        rationale: String,
        timeout: TimeInterval
    ) -> ServiceProbe {
        let started = Date()

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var reachability: Reachability = .noResponse
        var refusalReason: String?

        // Signature: xpc_connection_create_mach_service(name, target_queue, flags).
        // NULL means the default queue. The flags argument is a UInt64 bitfield;
        // zero requests a plain connection with no listener semantics.
        // nil for the target queue means "the default queue" in Swift; NULL would
        // be imported as the empty tuple, which is not a queue.
        // NSXPCConnection is the supported, portable way to reach a mach service
        // from an app. The C connection API is unavailable on iOS.
        let connection = NSXPCConnection(machServiceName: name)

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var reachability: Reachability = .noResponse
        var refusalReason: String?

        // An interruption handler fires when launchd refuses the lookup or the
        // service dies. Its NSError carries the platform's own reason.
        connection.interruptionHandler = {
            lock.lock()
            reachability = .refused
            lock.unlock()
            semaphore.signal()
        }
        connection.invalidationHandler = {
            lock.lock()
            if reachability != .reachable { reachability = .refused }
            lock.unlock()
            semaphore.signal()
        }
        connection.resume()

        // A connection that survives without interruption means launchd handed
        // out the send right: the service is reachable from this process.
        let waited = semaphore.wait(timeout: .now() + timeout)
        let elapsed = Int(Date().timeIntervalSince(started) * 1000)

        lock.lock()
        let finalReachability: Reachability
        if waited == .timedOut {
            // No interruption arrived: the lookup was permitted and the service
            // simply did not answer a connection with no protocol.
            finalReachability = .reachable
        } else {
            finalReachability = reachability
        }
        let finalReason = refusalReason
        lock.unlock()

        // Invalidate so the connection does not outlive the probe.
        connection.invalidate()

        return ServiceProbe(
            serviceName: name,
            rationale: rationale,
            reachability: finalReachability,
            refusalReason: finalReason,
            responseMilliseconds: finalReachability == .noResponse ? nil : elapsed
        )
    }

    #else

    /// XPC is unavailable on this platform, so no service can be probed.
    public static var xpcAvailable: Bool { false }

    public static func probeServices(timeout: TimeInterval = 3.0) -> [ServiceProbe] { [] }

    public enum Reachability: String, Codable, Sendable {
        case unavailable
    }

    public struct ServiceProbe: Sendable, Identifiable, Codable {
        public let serviceName: String
        public let rationale: String
        public let reachability: Reachability
        public let refusalReason: String?
        public let responseMilliseconds: Int?

        public init(
            serviceName: String,
            rationale: String,
            reachability: Reachability,
            refusalReason: String?,
            responseMilliseconds: Int?
        ) {
            self.serviceName = serviceName
            self.rationale = rationale
            self.reachability = reachability
            self.refusalReason = refusalReason
            self.responseMilliseconds = responseMilliseconds
        }

        public var id: String { serviceName }
    }

    public static func serviceCandidates() -> [(name: String, rationale: String)] { [] }

    #endif

    // MARK: - NSFileCoordinator as a confused deputy
    //
    // Gated to Darwin: NSFileCoordinator is part of Apple's Foundation and is not
    // present in swift-corelibs-foundation, so the verification host cannot compile
    // it. The experiment runs on the device.

    #if canImport(Darwin)

    public enum Outcome: String, Codable, Sendable {
        case permitted
        case denied
        case notApplicable
        case error
    }

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        /// The security invariant under test.
        public let mechanism: String
        /// The API exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when a permitted result would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The error's domain and code, when one was returned.
        public let errorDomain: String?
        public let errorCode: Int?
        public let errorDescription: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            errorDomain: String?,
            errorCode: Int?,
            errorDescription: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.errorDomain = errorDomain
            self.errorCode = errorCode
            self.errorDescription = errorDescription
            self.interpretation = interpretation
        }

        /// A boundary violation is a success the policy did not predict.
        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct CoordinatorResult: Sendable, Codable {
        public let experiments: [Experiment]
        public let violations: [Experiment]

        public init(experiments: [Experiment], violations: [Experiment]) {
            self.experiments = experiments
            self.violations = violations
        }
    }

    /// Test `NSFileCoordinator` as a deputy.
    ///
    /// `NSFileCoordinator` is a public API whose work is performed by a system
    /// service on the caller's behalf. The question is whether the service
    /// authorizes the URL it is asked to coordinate, or trusts the caller's
    /// reference.
    ///
    /// The control coordinates a file inside the app container, which must
    /// succeed; without it a refusal on an outside path is not interpretable.
    public static func probeFileCoordinator(
        containerPath: String,
        outsideDirectory: String
    ) -> CoordinatorResult {
        var experiments: [Experiment] = []
        let outsideURL = URL(fileURLWithPath: outsideDirectory)

        // Control: a file inside the container. Must succeed.
        let controlURL = URL(fileURLWithPath: containerPath + "/Documents/fsprobe-fc-control")
        let controlData = Data("fsprobe coordinator control\n".utf8)
        let controlWritten = FileManager.default.createFile(
            atPath: controlURL.path, contents: controlData
        )
        if controlWritten {
            experiments.append(coordinateReadExperiment(
                id: "coordinator-control",
                url: controlURL,
                mechanism: """
                Control: NSFileCoordinator on a file inside the app container. Must \
                succeed, or the deputy itself is unavailable and nothing below is \
                interpretable.
                """,
                expectedDenied: false
            ))
            try? FileManager.default.removeItem(atPath: controlURL.path)
        } else {
            experiments.append(Experiment(
                id: "coordinator-control",
                mechanism: """
                Control: NSFileCoordinator on a file inside the app container. Must \
                succeed, or the deputy itself is unavailable.
                """,
                operation: "createFile",
                arguments: controlURL.path,
                expected: "The control file must be creatable inside the container.",
                expectedDenied: false,
                outcome: .notApplicable,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                interpretation: "The control file could not be created, so the control could not run."
            ))
        }

        // The real test: coordinate a read of a URL outside the container.
        experiments.append(coordinateReadExperiment(
            id: "coordinator-read-outside",
            url: outsideURL,
            mechanism: """
                Confused deputy: NSFileCoordinator asks a system service to \
                coordinate access to a URL the caller names. Does the service \
                authorize that URL, or trust the caller's reference?
                """,
            expectedDenied: true
        ))

        // And a write: can the deputy create a file outside the container on our
        // behalf? A dedicated synthetic name in the target directory, removed
        // afterwards.
        let writeTarget = outsideURL.appendingPathComponent(
            POSIXProbeEngine.syntheticFileName
        )
        experiments.append(coordinateWriteExperiment(
            id: "coordinator-write-outside",
            url: writeTarget,
            mechanism: """
                Confused deputy, write direction: can a system service create a \
                file outside the app container on the caller's behalf?
                """,
            expectedDenied: true
        ))

        let violations = experiments.filter { $0.isBoundaryViolation }
        return CoordinatorResult(experiments: experiments, violations: violations)
    }

    private static func coordinateReadExperiment(
        id: String,
        url: URL,
        mechanism: String,
        expectedDenied: Bool
    ) -> Experiment {
        var coordinatorError: NSError?
        var accessorRan = false
        var readBytes = 0

        let coordinator = NSFileCoordinator()
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordinatorError) { readURL in
            accessorRan = true
            // The accessor is handed a URL; reading it is the effect that matters.
            if let handle = try? FileHandle(forReadingFrom: readURL) {
                let data = handle.readData(ofLength: 4096)
                readBytes = data.count
                try? handle.close()
            }
        }

        if let error = coordinatorError {
            return Experiment(
                id: id, mechanism: mechanism,
                operation: "NSFileCoordinator.coordinate(readingItemAt:)",
                arguments: url.path,
                expected: expectedDenied
                    ? "Denied. The URL lies outside the container and the caller holds no grant for it."
                    : "Permitted. The URL is inside the container.",
                expectedDenied: expectedDenied,
                outcome: .denied,
                errorDomain: error.domain,
                errorCode: error.code,
                errorDescription: error.localizedDescription,
                interpretation: expectedDenied
                    ? "Refused with \(error.domain) \(error.code): the deputy authorized the URL."
                    : "The control was refused, so the deputy is not usable here."
            )
        }

        return Experiment(
            id: id, mechanism: mechanism,
            operation: "NSFileCoordinator.coordinate(readingItemAt:)",
            arguments: url.path,
            expected: expectedDenied
                ? "Denied. The URL lies outside the container and the caller holds no grant for it."
                : "Permitted. The URL is inside the container.",
            expectedDenied: expectedDenied,
            outcome: .permitted,
            errorDomain: nil, errorCode: nil,
            errorDescription: nil,
            interpretation: """
                Coordination succeeded (accessor ran: \(accessorRan), \(readBytes) bytes read). \
                The deputy coordinated a URL the caller cannot open by path.
                """
        )
    }

    private static func coordinateWriteExperiment(
        id: String,
        url: URL,
        mechanism: String,
        expectedDenied: Bool
    ) -> Experiment {
        let payload = Data("fsprobe coordinator write test\n".utf8)

        // Clean any prior attempt so the test is deterministic.
        try? FileManager.default.removeItem(atPath: url.path)

        var coordinatorError: NSError?
        var accessorRan = false

        let coordinator = NSFileCoordinator()
        coordinator.coordinate(writingItemAt: url, options: [], error: &coordinatorError) { writeURL in
            accessorRan = true
            try? payload.write(to: writeURL, options: .atomic)
        }

        let landed = FileManager.default.fileExists(atPath: url.path)
        // Always clean up, whichever way it went.
        try? FileManager.default.removeItem(atPath: url.path)

        if let error = coordinatorError {
            return Experiment(
                id: id, mechanism: mechanism,
                operation: "NSFileCoordinator.coordinate(writingItemAt:)",
                arguments: url.path,
                expected: expectedDenied
                    ? "Denied. The destination lies outside the container."
                    : "Permitted. The destination is inside the container.",
                expectedDenied: expectedDenied,
                outcome: .denied,
                errorDomain: error.domain,
                errorCode: error.code,
                errorDescription: error.localizedDescription,
                interpretation: expectedDenied
                    ? "Refused with \(error.domain) \(error.code): the deputy authorized the write."
                    : "The control was refused, so the deputy is not usable here."
            )
        }

        return Experiment(
            id: id, mechanism: mechanism,
            operation: "NSFileCoordinator.coordinate(writingItemAt:)",
            arguments: url.path,
            expected: expectedDenied
                ? "Denied. The destination lies outside the container."
                : "Permitted. The destination is inside the container.",
            expectedDenied: expectedDenied,
            outcome: .permitted,
            errorDomain: nil, errorCode: nil,
            errorDescription: nil,
            interpretation: """
                Coordination succeeded (accessor ran: \(accessorRan), file appeared at the \
                destination: \(landed)). A file was created outside the app container by a \
                system service acting on the caller's behalf.
                """
        )
    }

    #else

    /// NSFileCoordinator is unavailable on this platform, so no deputy can be tested.
    public enum Outcome: String, Codable, Sendable {
        case unavailable
    }

    public struct Experiment: Sendable, Identifiable, Codable {
        public let id: String
        public let mechanism: String
        public let operation: String
        public let arguments: String
        public let expected: String
        public let expectedDenied: Bool
        public let outcome: Outcome
        public let errorDomain: String?
        public let errorCode: Int?
        public let errorDescription: String?
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            errorDomain: String?,
            errorCode: Int?,
            errorDescription: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.errorDomain = errorDomain
            self.errorCode = errorCode
            self.errorDescription = errorDescription
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool { false }
    }

    public struct CoordinatorResult: Sendable, Codable {
        public let experiments: [Experiment]
        public let violations: [Experiment]
        public init(experiments: [Experiment], violations: [Experiment]) {
            self.experiments = experiments
            self.violations = violations
        }
    }

    public static func probeFileCoordinator(
        containerPath: String,
        outsideDirectory: String
    ) -> CoordinatorResult {
        CoordinatorResult(experiments: [], violations: [])
    }

    #endif
}
