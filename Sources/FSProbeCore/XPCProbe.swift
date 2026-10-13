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
    // IMPORTANT PLATFORM CONSTRAINT, established on the iOS SDK:
    //
    // `NSXPCConnection(machServiceName:options:)` is API_UNAVAILABLE(ios, watchos,
    // tvos), and the C connection API (`xpc_connection_create_mach_service`) is
    // likewise unavailable on iOS. An ordinary iOS app therefore cannot open a
    // connection to an arbitrary mach service by name. The supported path is a
    // listener whose endpoint a service hands the app explicitly, which requires
    // the service to cooperate.
    //
    // Consequence for this research: the "enumerate reachable services" plan is
    // not implementable from a sandboxed app on iOS. That is recorded here as a
    // rejected hypothesis with its evidence, rather than left as an untested
    // aspiration. The confused-deputy direction that remains viable is the one
    // where the app asks a *documented public API* to act on a resource, and the
    // API's backing service does the work -- which is what the NSFileCoordinator
    // section below tests.

    public enum Reachability: String, Codable, Sendable {
        /// The platform does not permit opening a mach service by name from an app.
        case notPermittedOnIOS
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

    /// The candidates that would have been probed, kept as the documented attack
    /// surface with the reason each was interesting. No claim is made that any of
    /// them is reachable.
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
        ]
    }

    /// Always empty: iOS does not permit reaching a mach service by name from an
    /// app, so no service can be probed. The empty result is the honest one, and
    /// the report labels it as not attempted rather than as a reachability finding.
    public static func probeServices(timeout: TimeInterval = 3.0) -> [ServiceProbe] { [] }

    /// False on the basis of SDK availability, not of any attempted connection.
    public static var xpcAvailable: Bool { false }

    /// Why no service could be probed, for the report. This is an availability
    /// fact about the SDK, not an observation of this process's access.
    public static var xpcUnavailableReason: String {
        "NSXPCConnection(machServiceName:) is API_UNAVAILABLE(ios, watchos, tvos) and the C connection API is likewise unavailable, so an app cannot open a mach service by name on iOS."
    }

    // MARK: - NSFileCoordinator as a confused deputy
    //
    // Gated to Darwin: NSFileCoordinator is part of Apple's Foundation and is not
    // present in swift-corelibs-foundation, so the verification host cannot compile
    // it. The experiment runs on the device.

    #if canImport(Darwin)

    public enum Outcome: String, Codable, Sendable {
        case permitted
        /// The coordination itself was refused — an NSError came back from
        /// NSFileCoordinator and the accessor never ran.
        case denied
        /// Coordination was granted, but the operation underneath produced no
        /// effect. Distinct from `denied`: the deputy said yes and the filesystem
        /// still said no, and reporting that as a refusal would overstate what
        /// was refused.
        case grantedNoEffect
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
        var accessorError: NSError?
        var accessorRan = false
        var readBytes = 0

        let coordinator = NSFileCoordinator()
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordinatorError) { readURL in
            accessorRan = true
            // The accessor is handed a URL; reading it is the effect that matters.
            // Each step's error is kept: "could not open" and "could not read"
            // are different facts, and neither is "read 0 bytes".
            do {
                let handle = try FileHandle(forReadingFrom: readURL)
                defer { try? handle.close() }
                do {
                    let data = try handle.readData(ofLength: 4096)
                    readBytes = data.count
                } catch {
                    accessorError = error as NSError
                }
            } catch {
                accessorError = error as NSError
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

        // Coordination succeeding is NOT read access. NSFileCoordinator arbitrates
        // access to a URL; it does not grant it. What matters is whether the bytes
        // could actually be read inside the accessor, so the effect is reported
        // separately from the coordination outcome.
        let effect: String
        if readBytes > 0 {
            effect = """
                \(readBytes) bytes were read inside the accessor, which is the security-relevant \
                effect: content from a path the caller cannot open was obtained.
                """
        } else if let error = accessorError {
            effect = """
                Coordination was granted, but the read underneath failed with \
                \(error.domain) \(error.code): \(error.localizedDescription) \
                Coordination is not authorization, so this is the expected shape \
                and is not a read primitive.
                """
        } else if accessorRan {
            effect = """
                The accessor ran but read 0 bytes with no error: coordination was granted while the \
                underlying read was not. Coordination is not authorization, so this is \
                the expected shape and is not a read primitive.
                """
        } else {
            effect = "The accessor did not run."
        }

        return Experiment(
            id: id, mechanism: mechanism,
            operation: "NSFileCoordinator.coordinate(readingItemAt:)",
            arguments: url.path,
            expected: expectedDenied
                ? "Denied, or granted without read access: coordination is not authorization."
                : "Permitted. The URL is inside the container.",
            expectedDenied: expectedDenied,
            // A violation requires the effect, not merely the coordination, and
            // "granted but ineffective" is its own verdict rather than a denial:
            // the deputy granted the coordination and the filesystem refused it.
            outcome: readBytes > 0 ? .permitted : .grantedNoEffect,
            errorDomain: accessorError?.domain,
            errorCode: accessorError?.code,
            errorDescription: accessorError?.localizedDescription,
            interpretation: """
                Coordination succeeded (accessor ran: \(accessorRan), \(readBytes) bytes read). \
                \(effect)
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
        var accessorError: NSError?
        var accessorRan = false

        let coordinator = NSFileCoordinator()
        coordinator.coordinate(writingItemAt: url, options: [], error: &coordinatorError) { writeURL in
            accessorRan = true
            do {
                try payload.write(to: writeURL, options: .atomic)
            } catch {
                // The underlying failure is recorded in its own right: it is what
                // refused the write, independently of what coordination said.
                accessorError = error as NSError
            }
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

        // A violation requires the file to actually exist at the destination.
        // Coordination succeeding while nothing lands is not a write primitive.
        return Experiment(
            id: id, mechanism: mechanism,
            operation: "NSFileCoordinator.coordinate(writingItemAt:)",
            arguments: url.path,
            expected: expectedDenied
                ? "Denied, or granted without the file landing: coordination is not authorization."
                : "Permitted. The destination is inside the container.",
            expectedDenied: expectedDenied,
            outcome: landed ? .permitted : .grantedNoEffect,
            errorDomain: accessorError?.domain,
            errorCode: accessorError?.code,
            errorDescription: accessorError?.localizedDescription,
            interpretation: landed
                ? """
                Coordination succeeded and the file appeared at the destination. A file was \
                created outside the app container by a system service acting on the \
                caller's behalf.
                """
                : """
                Coordination succeeded (accessor ran: \(accessorRan)) but no file appeared at \
                the destination: the write was refused underneath\(accessorError.map { " with \($0.domain) \($0.code)" } ?? ""). \
                Coordination is not authorization, so this is the expected shape and is not \
                a write primitive.
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
