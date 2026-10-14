//
//  XPCReplyProbe.swift
//  FSProbeCore — do the reachable services actually answer?
//
//  HYPOTHESIS
//  ----------
//  The mach-lookup experiment established that four named services are reachable
//  from an ordinary app: FileCoordination, cfprefsd.daemon, containermanagerd, and
//  containermanagerd.system. Three others were refused, with a negative control
//  proving the refusals are real.
//
//  "Reachable" meant one thing: a connection was established and no interruption
//  arrived within the timeout. That is the *lookup* being permitted. It says
//  nothing about whether the service will *answer*.
//
//  This experiment asks the second question. A trivial message is sent to each
//  reachable service and the harness waits, bounded, for a reply. Three outcomes
//  are distinguishable:
//
//    a reply arrives                 the service processes messages from this app
//    the connection is interrupted   the service rejected the connection or died
//    nothing arrives                 the service accepted the connection and is
//                                    silent to a message carrying no protocol
//
//  The third outcome is the expected one, and it is what "reachable but unusable"
//  looks like. A reply to a message carrying no protocol would be notable: it
//  would mean the service responds to callers it has not identified, which is the
//  shape a confused deputy takes.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether a reachable service performs work for a caller whose identity it has
//  not validated.
//
//  CONTROL
//  -------
//  The negative control is the same nonexistent service name the mach-lookup
//  experiment used. It must be interrupted, which calibrates what a rejection
//  looks like as distinct from silence.
//
//  SAFETY
//  ------
//  The message is empty. It carries no path, no identifier, no resource reference,
//  and no secret. Nothing is asked of the service beyond a reply. Connections are
//  cancelled afterwards. This is a liveness probe, not an attempt to invoke any
//  operation.
//

import Foundation

public enum XPCReplyProbe {

    public enum Reply: String, Codable, Sendable {
        /// A reply arrived.
        case replied
        /// The connection was interrupted or invalidated.
        case interrupted
        /// Nothing arrived within the bounded wait.
        case silent
        /// The connection could not be created.
        case notCreated
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Probe: Sendable, Identifiable, Codable {
        public let serviceName: String
        /// Why this service is a candidate.
        public let rationale: String
        /// What the mach-lookup experiment measured for this name.
        public let lookupOutcome: String
        public let reply: Reply
        /// Round-trip time in milliseconds, when a reply arrived.
        public let responseMilliseconds: Int?
        /// The platform's own error description, when it gave one.
        public let interruptionReason: String?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            serviceName: String,
            rationale: String,
            lookupOutcome: String,
            reply: Reply,
            responseMilliseconds: Int?,
            interruptionReason: String?,
            observed: String?,
            interpretation: String
        ) {
            self.serviceName = serviceName
            self.rationale = rationale
            self.lookupOutcome = lookupOutcome
            self.reply = reply
            self.responseMilliseconds = responseMilliseconds
            self.interruptionReason = interruptionReason
            self.observed = observed
            self.interpretation = interpretation
        }

        public var id: String { serviceName }

        /// A violation is a reply from a service the caller has not identified
        /// itself to. Silence is the expected outcome and is not a finding.
        public var isBoundaryViolation: Bool {
            reply == .replied && lookupOutcome == "reachable"
        }
    }

    public struct Result: Sendable, Codable {
        public let probes: [Probe]
        public let violations: [Probe]

        public init(probes: [Probe], violations: [Probe]) {
            self.probes = probes
            self.violations = violations
        }
    }

    /// The reachable services, with the outcome the mach-lookup experiment
    /// recorded for each. The negative control leads.
    /// Exposed so a test can assert the negative control leads and that every
    /// entry carries the lookup outcome that makes its result interpretable.
    public static let targets: [(name: String, rationale: String, lookup: String)] = [
        ("com.bbaobaob.fsprobe.nonexistent.control",
         "NEGATIVE CONTROL: a name that cannot exist, to calibrate rejection",
         "refused"),
        ("com.apple.FileCoordination",
         "NSFileCoordinator's backend: arbitrates reads and writes of named URLs",
         "reachable"),
        ("com.apple.cfprefsd.daemon",
         "Writes preference files on the caller's behalf",
         "reachable"),
        ("com.apple.containermanagerd",
         "Resolves and creates app containers by name",
         "reachable"),
        ("com.apple.containermanagerd.system",
         "System-scope container resolution",
         "reachable"),
        ("com.apple.coreservices.quarantine-resolver",
         "LaunchServices quarantine resolution",
         "refused"),
        ("com.apple.mobile.installation_proxy",
         "App installation",
         "refused"),
        ("com.apple.LaunchServices",
         "Application and document-type resolution",
         "refused"),
    ]

    /// Seconds to wait for a reply. Bounded, so a silent service cannot hang the
    /// harness.
    public static let replyTimeout: TimeInterval = 3.0

    public static func probe(timeout: TimeInterval = XPCReplyProbe.replyTimeout) -> Result {
        #if canImport(Darwin)
        let probes = targets.map { target in
            probeService(target.name, rationale: target.rationale,
                         lookup: target.lookup, timeout: timeout)
        }
        #else
        let probes = targets.map { target in
            Probe(
                serviceName: target.name, rationale: target.rationale,
                lookupOutcome: target.lookup, reply: .notAttempted,
                responseMilliseconds: nil, interruptionReason: nil,
                observed: nil,
                interpretation: """
                    NOT ATTEMPTED: XPC is not present on this platform, so no \
                    message was sent.
                    """
            )
        }
        #endif

        let violations = probes.filter { $0.isBoundaryViolation }
        return Result(probes: probes, violations: violations)
    }

    #if canImport(Darwin)

    private static func probeService(
        _ name: String,
        rationale: String,
        lookup: String,
        timeout: TimeInterval
    ) -> Probe {
        let started = Date()

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var reply: Reply = .silent
        var reason: String?

        // The connection factory is resolved at runtime, as in the mach-lookup
        // experiment: the SDK marks it unavailable, which prevents linking it by
        // name but says nothing about whether it exists in the runtime.
        guard let create = XPCShim.connectionFactory else {
            return Probe(
                serviceName: name, rationale: rationale, lookupOutcome: lookup,
                reply: .notAttempted, responseMilliseconds: nil,
                interruptionReason: nil, observed: nil,
                interpretation: """
                    NOT ATTEMPTED: the XPC connection factory is not present in \
                    this runtime, so no message could be sent.
                    """
            )
        }

        let connection = name.withCString { cName in create(cName, nil, 0) }
        guard let connection else {
            return Probe(
                serviceName: name, rationale: rationale, lookupOutcome: lookup,
                reply: .notCreated, responseMilliseconds: nil,
                interruptionReason: nil, observed: nil,
                interpretation: """
                    NOT ATTEMPTED: the connection factory returned no object, so \
                    no message could be sent.
                    """
            )
        }

        // An interruption means the service rejected the connection or died.
        // Its description string is the platform's own explanation.
        XPCShim.setEventHandler(connection) { event in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(event) {
                reply = .interrupted
                reason = XPCShim.errorDescription(event)
            } else {
                // Any non-error event is a message arriving, which is the reply.
                reply = .replied
            }
            semaphore.signal()
        }
        XPCShim.resume(connection)

        // An empty message: no path, no identifier, no resource reference. This
        // asks only whether the service answers a caller it has not identified.
        let message = xpc_dictionary_create(nil, nil, 0)
        cSendMessageWithReply(connection, message, nil) { replyEvent in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(replyEvent) {
                reply = .interrupted
                reason = XPCShim.errorDescription(replyEvent)
            } else {
                reply = .replied
            }
            semaphore.signal()
        }

        let waited = semaphore.wait(timeout: .now() + timeout)
        let elapsed = Int(Date().timeIntervalSince(started) * 1000)

        lock.lock()
        let finalReply: Reply = waited == .timedOut ? .silent : reply
        let finalReason = reason
        lock.unlock()

        XPCShim.cancel(connection)

        let interpretation: String
        switch finalReply {
        case .replied:
            interpretation = """
                A reply arrived from a service that had received only an empty \
                message from a caller it had not identified. That is the confused- \
                deputy shape: the service performs work for a caller whose identity \
                it has not validated, and the reply is the evidence to follow up.
                """
        case .interrupted:
            interpretation = """
                The connection was interrupted. The service rejected the connection \
                or died, which is a rejection rather than a silent acceptance.
                """
        case .silent:
            interpretation = """
                The connection was accepted and the service stayed silent to a \
                message carrying no protocol. That is the expected shape for a \
                service that does not act on callers it has not identified, and it \
                is what "reachable but unusable" looks like.
                """
        case .notCreated, .notAttempted:
            interpretation = """
                No message was sent, so nothing is claimed about the service.
                """
        }

        return Probe(
            serviceName: name, rationale: rationale, lookupOutcome: lookup,
            reply: finalReply,
            responseMilliseconds: finalReply == .silent ? nil : elapsed,
            interruptionReason: finalReason,
            observed: finalReply == .silent
                ? "no reply within \(Int(timeout))s"
                : (finalReason ?? "a reply arrived"),
            interpretation: interpretation
        )
    }

    // The XPC connection factory and the error-description helper are owned by
    // XPCShim. Binding them here as well would make the compiler share one
    // implementation across two different signatures and fail the build -- the
    // same mistake the Mach shim already fixed once.

    #endif
}
