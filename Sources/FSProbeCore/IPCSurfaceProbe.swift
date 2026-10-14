//
//  IPCSurfaceProbe.swift
//  FSProbeCore — the IPC mechanisms an ordinary app can actually reach.
//
//  HYPOTHESIS
//  ----------
//  The mission asked for IPC mechanisms to be investigated, and the honest state
//  of that is now measurable rather than assumed:
//
//  - `NSXPCConnection(machServiceName:)` is API_UNAVAILABLE on iOS.
//  - `xpc_connection_create_mach_service` is unavailable in the SDK but PRESENT in
//    the runtime, and through it four services were measured reachable.
//  - `bootstrap_look_up` is a second path to a mach service, now tested.
//
//  What has never been tested is the remaining IPC surface available to an
//  ordinary app, each of which is a separate mechanism with its own reach:
//
//   CFMessagePortCreateRemote   a Mach message port by NAME, registered locally
//   Darwin notifications        cross-process broadcast, no payload
//   NSMachPort                  a raw Mach port the app can register
//   openURL                     the scheme-based path to another app
//
//  `CFMessagePortCreateRemote` is the interesting one. It is a public,
//  long-standing CoreFoundation API that resolves a Mach port by name, and it is
//  a *different* resolution path from both XPC and bootstrap_look_up. If it
//  resolves a service name that the other two paths refuse, it is a third bypass
//  of the mach-lookup gate.
//
//  Darwin notifications are included for completeness and are explicitly NOT a
//  security boundary: they carry no payload and grant no capability. They are
//  recorded as reachable so that "we tested IPC" means something specific.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether a third name-resolution path reaches services the first two refuse.
//
//  CONTROL
//  -------
//  A port name that cannot exist, which must fail to resolve. Without it, a
//  failure to resolve is uninterpretable.
//
//  SAFETY
//  ------
//  Nothing is sent on any port obtained. Ports are invalidated immediately. No
//  notification is posted to any process but this one. No URL is opened to any
//  application.
//

import Foundation

public enum IPCSurfaceProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The mechanism resolved or registered successfully.
        case reachable
        /// The mechanism was refused.
        case refused
        /// The mechanism is not present on this platform.
        case unavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Mechanism: Sendable, Identifiable, Codable {
        public let id: String
        /// The IPC mechanism.
        public let mechanism: String
        /// The API exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when reachability would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// What was observed.
        public let observed: String?
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
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .reachable && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let mechanisms: [Mechanism]
        public let violations: [Mechanism]

        public init(mechanisms: [Mechanism], violations: [Mechanism]) {
            self.mechanisms = mechanisms
            self.violations = violations
        }
    }

    /// Port names to try through CFMessagePortCreateRemote. The first is a
    /// negative control. The rest are the same services the other two lookup
    /// paths used, so the three paths can be compared directly.
    /// Exposed so a test can assert the negative control leads and that the list
    /// includes a name the other lookup paths refused -- which is the name that
    /// would make a third bypass visible.
    public static let portNames: [(name: String, rationale: String, refused: Bool)] = [
        ("com.bbaobaob.fsprobe.nonexistent.control",
         "NEGATIVE CONTROL: a port name that cannot exist, to calibrate failure",
         true),
        ("com.apple.FileCoordination",
         "NSFileCoordinator's backend; reachable through the XPC path",
         false),
        ("com.apple.cfprefsd.daemon",
         "Preference writes; reachable through the XPC path",
         false),
        ("com.apple.LaunchServices",
         "Application resolution; REFUSED through the XPC path -- this is the name that would make a third bypass visible",
         true),
        ("com.apple.mobile.installation_proxy",
         "App installation; REFUSED through the XPC path",
         true),
    ]

    public static func probe() -> Result {
        var mechanisms: [Mechanism] = []

        #if canImport(Darwin)
        for entry in portNames {
            mechanisms.append(messagePortCase(entry))
        }
        #else
        for entry in portNames {
            mechanisms.append(Mechanism(
                id: "cfmessageport-\(entry.name)",
                mechanism: """
                    CFMessagePortCreateRemote resolves a Mach port by NAME, a third \
                    resolution path distinct from XPC and bootstrap_look_up.
                    """,
                operation: "CFMessagePortCreateRemote(name)",
                arguments: entry.name,
                expected: "Unavailable on this platform.",
                expectedDenied: entry.refused,
                outcome: .unavailable,
                observed: nil,
                interpretation: """
                    NOT ATTEMPTED: CoreFoundation's message-port API is not present \
                    on this platform.
                    """
            ))
        }
        #endif

        mechanisms.append(darwinNotifyCase())

        let violations = mechanisms.filter { $0.isBoundaryViolation }
        return Result(mechanisms: mechanisms, violations: violations)
    }

    // MARK: - Cases

    #if canImport(Darwin)

    private static func messagePortCase(
        _ entry: (name: String, rationale: String, refused: Bool)
    ) -> Mechanism {
        let id = "cfmessageport-\(entry.name)"
        let mechanism = """
            CFMessagePortCreateRemote resolves a Mach port by NAME. It is a public, \
            long-standing CoreFoundation API and a THIRD resolution path, distinct \
            from both the XPC connection factory and bootstrap_look_up. If it \
            resolves a name the other two refuse, it is a third bypass of the \
            mach-lookup gate.
            """

        let port = CFMessagePortCreateRemote(nil, entry.name as CFString)

        guard let port else {
            return Mechanism(
                id: id, mechanism: mechanism,
                operation: "CFMessagePortCreateRemote(name)",
                arguments: entry.name,
                expected: entry.refused
                    ? "Refused, as the other two lookup paths refused it."
                    : "Reachable, as the XPC path reached it.",
                expectedDenied: entry.refused,
                outcome: .refused,
                observed: "returned nil",
                interpretation: """
                    Refused, consistent with the other lookup paths. The mach-lookup \
                    gate holds for this name on a third path as well.
                    """
            )
        }

        // Nothing is sent on the port. It is invalidated immediately: the
        // experiment is about whether the name resolves, not about using it.
        CFMessagePortInvalidate(port)
        Unmanaged<CFMessagePort>.fromOpaque(port).release()

        return Mechanism(
            id: id, mechanism: mechanism,
            operation: "CFMessagePortCreateRemote(name)",
            arguments: entry.name,
            expected: entry.refused
                ? "Refused. This name was refused by the other two lookup paths."
                : "Reachable, as the XPC path reached it.",
            expectedDenied: entry.refused,
            outcome: .reachable,
            observed: "resolved to a message port",
            interpretation: entry.refused
                ? """
                BYPASS: this name was refused by both the XPC connection factory \
                and bootstrap_look_up, but CFMessagePortCreateRemote resolved it. \
                The mach-lookup authorization depends on which API asks, and this \
                third path is weaker.
                """
                : """
                Resolved, consistent with the XPC path, which also reached it.
                """
        )
    }

    #endif

    #if canImport(Darwin)

    @_silgen_name("notify_register_dispatch")
    private static func cNotifyRegisterDispatch(
        _ name: UnsafePointer<CChar>, _ token: UnsafeMutablePointer<Int32>,
        _ queue: DispatchQueue?, _ handler: @escaping @convention(block) (Int32) -> Void
    ) -> UInt32

    @_silgen_name("notify_cancel")
    private static func cNotifyCancel(_ token: Int32) -> UInt32

    #endif

    private static func darwinNotifyCase() -> Mechanism {
        let id = "darwin-notification"
        let mechanism = """
            Darwin notifications: a cross-process broadcast mechanism. Included \
            for completeness, and explicitly NOT a security boundary -- they carry \
            no payload and grant no capability. Recorded as reachable so that \
            "IPC was tested" means something specific rather than gesturing at it.
            """

        #if canImport(Darwin)
        let name = "com.bbaobaob.fsprobe.deputy-probe.notify"
        var token: Int32 = 0
        let rc = name.withCString { cName in
            cNotifyRegisterDispatch(cName, &token, nil) { _ in }
        }
        if rc == 0 {
            cNotifyCancel(token)
            return Mechanism(
                id: id, mechanism: mechanism,
                operation: "notify_register_dispatch(name, &token, queue)",
                arguments: name,
                expected: "Reachable. This is a broadcast mechanism, not a boundary.",
                expectedDenied: false,
                outcome: .reachable,
                observed: "registered a notification token",
                interpretation: """
                    Reachable, as expected. Darwin notifications carry no payload and \
                    grant no capability, so this is not a boundary crossing -- it is \
                    recorded so the IPC surface is measured rather than assumed.
                    """
            )
        }
        return Mechanism(
            id: id, mechanism: mechanism,
            operation: "notify_register_dispatch(name, &token, queue)",
            arguments: name,
            expected: "Reachable.",
            expectedDenied: false,
            outcome: .refused,
            observed: "registration failed",
            interpretation: """
                Registration failed. Darwin notifications are not available here, \
                which removes one IPC mechanism from the surface.
                """
        )
        #else
        return Mechanism(
            id: id, mechanism: mechanism,
            operation: "notify_register_dispatch(name, &token, queue)",
            arguments: "com.bbaobaob.fsprobe.deputy-probe.notify",
            expected: "Reachable.",
            expectedDenied: false,
            outcome: .unavailable,
            observed: nil,
            interpretation: """
                NOT ATTEMPTED: the Darwin notification API is not present on this \
                platform.
                """
        )
        #endif
    }
}
