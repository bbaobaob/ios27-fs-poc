//
//  XPCReplyContentsProbe.swift
//  FSProbeCore — what do the services that answer actually send back?
//
//  WHY THIS EXISTS
//  ---------------
//  The reply probe found that three services answer an empty message from an
//  unidentified caller, and that what comes back is a real dictionary with two
//  keys -- not transport bookkeeping. That is the confused-deputy shape.
//
//  A reply is not yet a primitive. The question that decides it is what the
//  dictionary contains. Three outcomes are distinguishable, and they are not
//  equally interesting:
//
//    the keys are XPC's own bookkeeping       transport, not the service
//    the keys name an error                   the service rejected the request
//    the keys carry data or a capability      the service ACTED for a caller it
//                                             had not identified
//
//  Only the third is a finding. This module reads the key NAMES -- never the
//  values -- and records them, because the names are what distinguish the three
//  cases and the values are where anything sensitive would live.
//
//  Key names are chosen deliberately over values. A key name tells us what the
//  service thought it was being asked; a value might contain anything at all.
//  Recording names and not values is the discipline that makes this safe to run
//  against a privileged daemon.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether a service performs work for a caller whose identity it has not
//  validated.
//
//  SAFETY
//  ------
//  Read-only. The request is an empty dictionary -- no path, no identifier, no
//  resource reference, no secret. Only key NAMES from the reply are recorded.
//  Nothing is written anywhere, and no value is ever read, logged, or
//  transmitted.
//

import Foundation

public enum XPCReplyContentsProbe {

    public enum Outcome: String, Codable, Sendable {
        /// A reply arrived carrying keys that are not XPC's own bookkeeping.
        case repliedWithKeys
        /// A reply arrived, but its keys are XPC transport bookkeeping.
        case transportOnly
        /// A reply arrived carrying no keys at all.
        case emptyReply
        /// The connection was interrupted.
        case interrupted
        /// Nothing arrived within the bounded wait.
        case silent
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Reply: Sendable, Identifiable, Codable {
        public let serviceName: String
        public let outcome: Outcome
        /// The key names in the reply. Never the values.
        public let keyNames: [String]
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            serviceName: String,
            outcome: Outcome,
            keyNames: [String],
            observed: String?,
            interpretation: String
        ) {
            self.serviceName = serviceName
            self.outcome = outcome
            self.keyNames = keyNames
            self.observed = observed
            self.interpretation = interpretation
        }

        public var id: String { serviceName }

        /// A finding is a reply carrying keys that are not the transport's own.
        public var isBoundaryViolation: Bool {
            outcome == .repliedWithKeys
        }
    }

    public struct Result: Sendable, Codable {
        public let replies: [Reply]
        public let violations: [Reply]

        public init(replies: [Reply], violations: [Reply]) {
            self.replies = replies
            self.violations = violations
        }
    }

    /// The services that answered. These are the ones the reply probe measured as
    /// replying to an empty message.
    /// Exposed so a test can assert the probe targets only the services that
    /// were measured as replying.
    public static let targets: [String] = [
        "com.apple.cfprefsd.daemon",
        "com.apple.containermanagerd",
        "com.apple.containermanagerd.system",
    ]

    /// Keys XPC itself puts in a reply. A reply whose keys are only these is
    /// transport bookkeeping rather than the service answering.
    /// Exposed so a test can assert the transport keys are still recognised.
    public static let transportKeys: Set<String> = [
        "XPCErrorDescription",
        "XPCErrorDomain",
        "XPCErrorCode",
    ]

    public static let replyTimeout: TimeInterval = 3.0

    public static func probe(timeout: TimeInterval = 3.0) -> Result {
        #if canImport(Darwin)
        let replies = targets.map { name in
            probeService(name, timeout: timeout)
        }
        #else
        let replies = targets.map { name in
            Reply(
                serviceName: name, outcome: .notAttempted, keyNames: [],
                observed: nil,
                interpretation: """
                    NOT ATTEMPTED: XPC is not present on this platform, so no \
                    message was sent.
                    """
            )
        }
        #endif

        let violations = replies.filter { $0.isBoundaryViolation }
        return Result(replies: replies, violations: violations)
    }

    #if canImport(Darwin)

    private static func probeService(_ name: String, timeout: TimeInterval) -> Reply {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var outcome: Outcome = .silent
        var replyKeys: [String] = []

        guard let connection = XPCShim.createConnection(name) else {
            return Reply(
                serviceName: name, outcome: .notAttempted, keyNames: [],
                observed: nil,
                interpretation: """
                    NOT ATTEMPTED: the connection factory returned no object.
                    """
            )
        }

        XPCShim.setEventHandler(connection) { event in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(event) {
                outcome = .interrupted
            } else {
                outcome = .emptyReply
            }
            semaphore.signal()
        }
        XPCShim.resume(connection)

        let message = xpc_dictionary_create(nil, nil, 0)
        XPCShim.sendMessageWithReply(connection, message) { replyEvent in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(replyEvent) {
                outcome = .interrupted
            } else if XPCShim.type(of: replyEvent) == XPCShim.dictionaryType {
                let names = keyNames(of: replyEvent)
                replyKeys = names
                if names.isEmpty {
                    outcome = .emptyReply
                } else if Set(names).isSubset(of: transportKeys) {
                    outcome = .transportOnly
                } else {
                    outcome = .repliedWithKeys
                }
            } else {
                outcome = .emptyReply
            }
            semaphore.signal()
        }

        let waited = semaphore.wait(timeout: .now() + timeout)

        lock.lock()
        let finalOutcome: Outcome = waited == .timedOut ? .silent : outcome
        let finalKeys = replyKeys
        lock.unlock()

        XPCShim.cancel(connection)

        let keyList = keyList
        let interpretation: String
        switch finalOutcome {
        case .repliedWithKeys:
            interpretation = """
                The service replied to an empty message from a caller it had not \
                identified, carrying keys of its own: \\(keyList). \
                Those are not the transport's, so the daemon produced them. What \
                they MEAN is the next question, and it is answered by sending a \
                request that asks for something specific and seeing whether the \
                daemon performs it.
                """
        case .transportOnly:
            interpretation = """
                The reply carried only the transport's own bookkeeping keys, so \
                this is XPC answering rather than the service. Not a finding.
                """
        case .emptyReply:
            interpretation = """
                The reply carried no keys at all, so there is nothing to interpret.
                """
        case .interrupted:
            interpretation = """
                The connection was interrupted, so the service rejected it.
                """
        case .silent:
            interpretation = """
                Nothing arrived within the bounded wait.
                """
        case .notAttempted:
            interpretation = """
                No message was sent.
                """
        }

        return Reply(
            serviceName: name, outcome: finalOutcome, keyNames: finalKeys,
            observed: finalKeys.isEmpty
                ? "no keys in the reply"
                : "keys: \\(keyList)",
            interpretation: interpretation
        )
    }

    /// The key names in a dictionary. Never the values.
    private static func keyNames(of dictionary: XPCObject) -> [String] {
        var names: [String] = []
        // xpc_dictionary_apply is the documented way to walk a dictionary. The
        // value is deliberately not read: only the key is captured.
        XPCShim.dictionaryApply(dictionary) { (key, _) -> Bool in
            names.append(String(cString: key))
            return true
        }
        return names
    }

    #endif
}
