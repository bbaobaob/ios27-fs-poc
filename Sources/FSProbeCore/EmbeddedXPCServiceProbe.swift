//
//  EmbeddedXPCServiceProbe.swift
//  FSProbeCore — XPC services shipped inside system frameworks.
//
//  WHY THIS EXISTS
//  ---------------
//  The mach-lookup experiments reached services by NAME through launchd. There
//  is a second and quite different surface that none of them touches: XPC
//  services that live INSIDE a system framework's bundle.
//
//  A service with Service Type `Application` inside a system private framework
//  is registered into the CALLING APP'S PID DOMAIN the moment the app loads that
//  framework -- `[[NSBundle bundleWithPath:...] load]` is enough. It is not a
//  global mach service, so launchd lookup never sees it, and the sandbox profile
//  never names it.
//
//  The published method for finding them is a filesystem walk:
//   find /System/Library/Frameworks /System/Library/PrivateFrameworks -name '*.xpc'
//  and the technique is documented at jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/.
//
//  This class of bug produced a run of CVEs in 2023 -- CVE-2022-26712,
//  CVE-2023-27944, CVE-2023-32414, CVE-2023-32404, CVE-2023-41077, CVE-2023-42961,
//  CVE-2023-42977, CVE-2024-27864 -- and the writeup states explicitly of
//  CVE-2023-42961 that it "can also be exploited on iOS". The mechanism there
//  was a path traversal in `filePathForImageWithFileName`, giving an arbitrary
//  `.png` read and an arbitrary file delete.
//
//  The recurring root cause across every one of them is the same: the service
//  did not check the CLIENT's code signature for a dedicated entitlement in
//  `acceptConnection:`. Apple's universal fix was to add exactly that check.
//
//  HYPOTHESIS
//  ----------
//  System frameworks ship XPC services that an ordinary app can register by
//  loading the framework, and at least one of them performs filesystem work on
//  the caller's behalf without validating the caller's identity.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether an app can reach a privileged helper through a framework it loads,
//  rather than through a service launchd permits it to name.
//
//  CONTROL
//  -------
//  A framework path that does not exist. Loading it must fail, which is what
//  makes a successful load of a real framework meaningful.
//
//  SAFETY
//  ------
//  Step one only enumerates the filesystem and loads a framework. Loading a
//  system framework is something every app does implicitly and constantly; it
//  runs no attacker-supplied code. Step two, which runs only if a service is
//  found, connects to it and sends an EMPTY message -- no path, no identifier,
//  no resource reference -- and records only whether it replies and the shape of
//  the reply. Nothing is asked of any service.
//

import Foundation

public enum EmbeddedXPCServiceProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The framework loaded and a service was found in it.
        case found
        /// The framework loaded but contained no XPC service.
        case noService
        /// The framework could not be loaded.
        case loadFailed
        /// The framework path does not exist.
        case notFound
        /// The service was found and replied to an empty message.
        case replied
        /// The service was found and stayed silent or refused.
        case refused
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Service: Sendable, Identifiable, Codable {
        public let id: String
        /// The framework that carries the service.
        public let framework: String
        /// The mechanism under test.
        public let mechanism: String
        /// The operation exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// What was observed.
        public let observed: String?
        /// The shape of any reply -- its type and key count, never its values.
        public let replyShape: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            framework: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            observed: String?,
            replyShape: String?,
            interpretation: String
        ) {
            self.id = id
            self.framework = framework
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.observed = observed
            self.replyShape = replyShape
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .replied && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let services: [Service]
        public let violations: [Service]
        /// How many frameworks were examined.
        public let frameworksExamined: Int
        /// How many XPC service bundles were found.
        public let serviceBundlesFound: Int

        public init(
            services: [Service],
            violations: [Service],
            frameworksExamined: Int,
            serviceBundlesFound: Int
        ) {
            self.services = services
            self.violations = violations
            self.frameworksExamined = frameworksExamined
            self.serviceBundlesFound = serviceBundlesFound
        }
    }

    /// Directories to walk for XPC service bundles.
    private static let frameworkDirectories = [
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
    ]

    /// How many frameworks to examine. The walk is cheap but loading a framework
    /// is not free, and a bounded census is more useful than an unbounded one.
    private static let maxFrameworks = 60

    /// A framework path that cannot exist, used as the load control.
    private static let controlFramework =
        "/System/Library/Frameworks/FSProbeNonexistent.framework"

    public static func probe() -> Result {
        let bundles = findServiceBundles()
        let examined = Array(bundles.prefix(maxFrameworks))

        // The control goes first. A successful load of a real framework means
        // nothing until a load of a path that cannot exist has been seen to fail.
        let loadControl = loadFramework(controlFramework)

        var services: [Service] = [loadControl]
        services.append(contentsOf: examined.map { probeBundle($0) })

        let violations = services.filter { $0.isBoundaryViolation }
        return Result(
            services: services,
            violations: violations,
            frameworksExamined: examined.count,
            serviceBundlesFound: bundles.count
        )
    }

    /// dlopen a framework's binary and report what happened.
    ///
    /// Loading the framework IS the mechanism under test: a service with type
    /// `Application` registers itself into the loading process's PID domain from
    /// the framework's own initialiser, so connecting without loading would be
    /// testing nothing. Loading a system framework runs no caller-supplied code,
    /// which is why this step is safe to run unconditionally.
    private static func loadFramework(_ frameworkPath: String) -> Service {
        let exists = FileManager.default.fileExists(atPath: frameworkPath)
        guard exists else {
            return Service(
                id: "embedded-xpc-load-control",
                framework: frameworkPath,
                mechanism: """
                    Loading a system framework, which is what registers the XPC \
                    services it carries into the loading app's PID domain.
                    """,
                operation: "dlopen(<framework binary>)",
                arguments: frameworkPath,
                expected: "The load fails, because the path does not exist.",
                expectedDenied: false,
                outcome: .notFound,
                observed: "the framework path does not exist",
                replyShape: nil,
                interpretation: """
                    CONTROL: the framework path does not exist, so the load could \
                    not have succeeded. This is what makes a successful load of a \
                    real framework meaningful rather than ambiguous.
                    """
            )
        }

        #if canImport(Darwin)
        // The binary inside a framework bundle is named after the framework with
        // the extension removed: Foo.framework/Foo.
        let stem = (frameworkPath as NSString).deletingPathExtension
            .lastPathComponent
        let binary = frameworkPath + "/" + stem
        let handle = binary.withCString { dlopen($0, RTLD_LAZY) }
        if handle != nil {
            dlclose(handle)
        }
        setErrno(0)
        return Service(
            id: "embedded-xpc-load-control",
            framework: frameworkPath,
            mechanism: "Loading a system framework.",
            operation: "dlopen(<framework binary>)",
            arguments: binary,
            expected: "A real framework loads, which is what makes a connection to it meaningful.",
            expectedDenied: false,
            outcome: .loadFailed,
            observed: handle == nil
                ? "dlopen failed with \(ErrorClassifier.errnoName(currentErrno()))"
                : "the framework loaded",
            replyShape: nil,
            interpretation: handle == nil
                ? """
                    The framework could not be loaded, so no service it carries \
                    could have been registered. Recorded as unattempted rather than \
                    as a refusal.
                    """
                : """
                    A real system framework loaded successfully. The load control \
                    therefore has a known-good counterpart, and any connection \
                    result below is about the service rather than about the load.
                    """
        )
        #else
        return Service(
            id: "embedded-xpc-load-control",
            framework: frameworkPath,
            mechanism: "Loading a system framework.",
            operation: "dlopen(<framework binary>)",
            arguments: frameworkPath,
            expected: "A real framework loads.",
            expectedDenied: false,
            outcome: .notAttempted,
            observed: "dynamic loading is not present on this platform",
            replyShape: nil,
            interpretation: "NOT ATTEMPTED: dynamic loading is not present here."
        )
        #endif
    }

    // MARK: - Discovery

    /// Every `.xpc` bundle inside a system framework's `XPCServices` directory.
    ///
    /// This is the published method: a filesystem walk, not a guess. The
    /// frameworks are enumerated first so the count of what was examined is
    /// recorded rather than implied.
    private static func findServiceBundles() -> [String] {
        var bundles: [String] = []
        let manager = FileManager.default

        for directory in frameworkDirectories {
            guard let frameworks = try? manager.contentsOfDirectory(atPath: directory) else {
                continue
            }
            for framework in frameworks where framework.hasSuffix(".framework") {
                let servicesPath = directory + "/" + framework + "/XPCServices"
                guard let entries = try? manager.contentsOfDirectory(atPath: servicesPath) else {
                    continue
                }
                for entry in entries where entry.hasSuffix(".xpc") {
                    bundles.append(servicesPath + "/" + entry)
                }
            }
        }
        return bundles.sorted()
    }

    // MARK: - Probing

    /// The `.framework` root that contains a given service bundle.
    ///
    /// .../Foo.framework/XPCServices/Bar.xpc -> .../Foo.framework
    /// Exposed so a test can assert the walk-back, which is easy to get wrong and
    /// impossible to notice from the results: every service would simply read as
    /// "load failed".
    public static func frameworkRootPathForTesting(_ bundlePath: String) -> String {
        frameworkRootPath(for: bundlePath)
    }

    private static func frameworkRootPath(for bundlePath: String) -> String {
        var path = (bundlePath as NSString).deletingLastPathComponent
        while (path as NSString).lastPathComponent == "XPCServices" {
            path = (path as NSString).deletingLastPathComponent
        }
        return path
    }

    private static func probeBundle(_ bundlePath: String) -> Service {
        let id = "embedded-xpc-\(URL(fileURLWithPath: bundlePath).deletingPathExtension().lastPathComponent)"
        let framework = URL(fileURLWithPath: bundlePath)
            .pathComponents
            .suffix(3)
            .joined(separator: "/")

        let mechanism = """
            An XPC service shipped INSIDE a system framework. Loading the \
            framework registers the service into the calling app's PID domain, \
            which launchd lookup never sees and the sandbox profile never names. \
            The recurring root cause in this class is a service that does not check \
            the client's code signature in acceptConnection:.
            """

        // The framework is loaded first: registration happens from the
        // framework's initialiser, so a connection attempted before the load
        // would be testing a service that has not been registered yet.
        let frameworkRoot = frameworkRootPath(for: bundlePath)
        _ = loadFramework(frameworkRoot)

        // The service's own bundle identifier is the name it registers under.
        guard let info = Bundle(path: bundlePath),
              let serviceName = info.bundleIdentifier else {
            return Service(
                id: id, framework: framework, mechanism: mechanism,
                operation: "read the service's bundle identifier",
                arguments: bundlePath,
                expected: "The bundle carries an identifier.",
                expectedDenied: true,
                outcome: .notAttempted,
                observed: "the bundle identifier could not be read",
                replyShape: nil,
                interpretation: """
                    NOT ATTEMPTED: the service bundle's identifier could not be \
                    read, so there is no name to connect to.
                    """
            )
        }

        #if canImport(Darwin)
        // Connect to the service in this app's PID domain and send an EMPTY
        // message: no path, no identifier, no resource reference. That asks only
        // whether the service answers a caller it has not identified.
        //
        // The connection factory is resolved at runtime through XPCShim rather
        // than through NSXPCConnection, because the iOS SDK marks the latter
        // unavailable -- which prevents linking it, and says nothing about whether
        // the runtime has it. Binding by name is what lets the kernel answer.
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var replied = false
        var interrupted = false
        var reason: String?
        var shape: String?

        guard let connection = XPCShim.createConnection(serviceName) else {
            return Service(
                id: id, framework: framework, mechanism: mechanism,
                operation: "create an XPC connection to the service",
                arguments: serviceName,
                expected: "Refused, or reachable only behind a code-signature check.",
                expectedDenied: true,
                outcome: .notAttempted,
                observed: "the connection factory is not present in this runtime",
                replyShape: nil,
                interpretation: """
                    NOT ATTEMPTED: the XPC connection factory is not present in \
                    this runtime, so no message could be sent. That is a statement \
                    about the platform, not a refusal by the service.
                    """
            )
        }

        // An interruption is the service rejecting the connection or dying; the
        // description string is the platform's own explanation of why.
        XPCShim.setEventHandler(connection) { event in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(event) {
                interrupted = true
                reason = XPCShim.errorDescription(event)
            } else {
                replied = true
            }
            semaphore.signal()
        }
        XPCShim.resume(connection)

        let message = xpc_dictionary_create(nil, nil, 0)
        XPCShim.sendMessageWithReply(connection, message) { replyEvent in
            lock.lock()
            defer { lock.unlock() }
            if XPCShim.isError(replyEvent) {
                interrupted = true
                reason = XPCShim.errorDescription(replyEvent)
            } else {
                replied = true
                // The reply's TYPE and KEY COUNT only, never its values. A reply the
                // service produced and one XPC produced on its behalf are
                // indistinguishable from outside, and recording the shape is the
                // only way to tell them apart afterwards.
                shape = "type=\(XPCShim.type(of: replyEvent).map { String(describing: $0) } ?? "unknown")"
                    + " keys=\(XPCShim.dictionaryCount(replyEvent))"
            }
            semaphore.signal()
        }

        let waited = semaphore.wait(timeout: .now() + 2.0)
        lock.lock()
        let finalReplied = waited != .timedOut && replied
        let finalInterrupted = interrupted
        let finalReason = reason
        let finalShape = shape
        lock.unlock()
        XPCShim.cancel(connection)

        let outcome: Outcome
        if finalReplied { outcome = .replied }
        else if finalInterrupted { outcome = .refused }
        else { outcome = .refused }

        let observed: String
        if finalReplied {
            observed = "the service accepted a connection and answered an empty message"
        } else if finalInterrupted {
            observed = "the service rejected the connection: \(finalReason ?? "no reason given")"
        } else {
            observed = "the service did not answer within the timeout"
        }

        return Service(
            id: id, framework: framework, mechanism: mechanism,
            operation: "create an XPC connection and send an empty message",
            arguments: serviceName,
            expected: """
                Refused, or reachable only after the caller's code signature is \
                checked for a dedicated entitlement.
                """,
            expectedDenied: true,
            outcome: outcome,
            observed: observed,
            replyShape: finalShape,
            interpretation: finalReplied
                ? """
                    The service accepted a connection from an ordinary app and \
                    answered a request carrying no arguments. That is not yet a \
                    finding on its own -- it is the same reachable-but-unprivileged \
                    shape already measured for four named services. What would make \
                    it a finding is a request that names a resource and a reply that \
                    shows the service did work for a caller it never identified, \
                    which is the follow-up and requires knowing the service's real \
                    protocol rather than guessing at one.
                    """
                : """
                    Refused or silent. The service did not answer an argument-free \
                    request from an unidentified caller, which is the expected \
                    shape for one that validates its caller.
                    """
        )
        #else
        return Service(
            id: id, framework: framework, mechanism: mechanism,
            operation: "NSXPCConnection(serviceName:)",
            arguments: serviceName,
            expected: "Refused.",
            expectedDenied: true,
            outcome: .notAttempted,
            observed: "XPC is not present on this platform",
            replyShape: nil,
            interpretation: """
                NOT ATTEMPTED: XPC is not present on this platform.
                """
        )
        #endif
    }
}
