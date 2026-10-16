//
//  SpotlightEnumerationProbe.swift
//  FSProbeCore — does the metadata index leak names outside the container?
//
//  WHY THIS EXISTS
//  ---------------
//  Every enumeration experiment so far asked the filesystem or the kernel
//  directly. The Spotlight metadata index is a THIRD party that already
//  walked the whole volume: if an ordinary app can query it for names
//  outside its container, the index answers a question the sandbox refuses
//  to answer itself. A file name is not file contents, but a name outside
//  the container -- another app's database, a profile, a token file -- is
//  a leak across the isolation boundary, and it aims every later attack
//  (a name is what a confused deputy needs to be told).
//
//  HYPOTHESIS
//  ----------
//  An NSMetadataQuery from an ordinary sandboxed app returns items whose
//  paths lie outside the app's container.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether the metadata index enforces the same container isolation as the
//  filesystem, measured rather than assumed.
//
//  CONTROL
//  -------
//  A sentinel file with a unique name, created in Documents and queried by
//  exact name. It must be found: that proves the query mechanism works inside
//  this sandbox, so an empty broad query reads as "nothing outside" rather
//  than "the mechanism is broken". The sentinel is deleted afterwards, so no
//  run leaves state for the next one to find.
//
//  SAFETY
//  ------
//  Read-only against the index; the only write is the sentinel inside the
//  app's own Documents, removed before the probe returns. Result paths are
//  recorded (a path outside the container IS the evidence), never opened.
//

import Foundation

public enum SpotlightEnumerationProbe {

    public enum Outcome: String, Codable, Sendable {
        /// Items outside the container were returned.
        case outsideItems
        /// Only container items, or nothing, were returned.
        case isolated
        /// The query could not run on this platform.
        case notAttempted
    }

    public struct Query: Sendable, Identifiable, Codable {
        public let id: String
        /// The API exercised.
        public let operation: String
        /// The concrete predicate, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when outside items would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// How many items the query gathered.
        public let matchCount: Int?
        /// How many gathered items sit outside the container.
        public let outsideCount: Int?
        /// The outside paths, so the claim is checkable, not just counted.
        public let outsidePaths: [String]
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            matchCount: Int?,
            outsideCount: Int?,
            outsidePaths: [String],
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.matchCount = matchCount
            self.outsideCount = outsideCount
            self.outsidePaths = outsidePaths
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .outsideItems && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let queries: [Query]
        public let violations: [Query]

        public init(queries: [Query], violations: [Query]) {
            self.queries = queries
            self.violations = violations
        }
    }

    /// Seconds to let one query gather. Bounded, so a slow index cannot hang
    /// the harness; the count gathered in the window is what is reported, and
    /// a truncated gather reads as truncated.
    public static let gatherTimeout: TimeInterval = 5.0

    /// How many outside paths to record. Enough to check, not enough to dump
    /// the index into the report.
    private static let maxOutsidePaths = 10

    public static func probe(containerPath: String) -> Result {
        #if canImport(Darwin)
        var queries: [Query] = []

        // The control: a sentinel this run creates, queries by exact name,
        // and deletes. Found means the mechanism works in this sandbox.
        queries.append(sentinelControl(containerPath: containerPath))

        // The broad query: everything the index will admit to, then sorted
        // into inside-container and outside-container by path.
        queries.append(broadQuery(containerPath: containerPath))

        let violations = queries.filter { $0.isBoundaryViolation }
        return Result(queries: queries, violations: violations)
        #else
        return Result(
            queries: [Query(
                id: "spotlight-control", operation: "NSMetadataQuery",
                arguments: "sentinel by exact name",
                expected: "The sentinel is found.",
                expectedDenied: false, outcome: .notAttempted,
                matchCount: nil, outsideCount: nil, outsidePaths: [],
                observed: "Spotlight is not present on this platform",
                interpretation: "NOT ATTEMPTED: there is no metadata index here."
            )],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)
    /// Create a uniquely-named sentinel, query it by exact name, delete it.
    private static func sentinelControl(containerPath: String) -> Query {
        let id = "spotlight-control"
        let operation = "NSMetadataQuery(predicate: kMDItemFSName == name)"
        let sentinel = "fsprobe-sentinel-\(UUID().uuidString).txt"
        let url = URL(fileURLWithPath: containerPath).appendingPathComponent(sentinel)

        guard (try? "".write(to: url, atomically: true, encoding: .utf8)) != nil else {
            return Query(
                id: id, operation: operation, arguments: sentinel,
                expected: "The sentinel is found.",
                expectedDenied: false, outcome: .notAttempted,
                matchCount: nil, outsideCount: nil, outsidePaths: [],
                observed: "the sentinel could not be created",
                interpretation: """
                    NOT ATTEMPTED: the container itself was not writable, so the \
                    control could not be set up and the broad query below has no \
                    calibration.
                    """
            )
        }
        defer { try? FileManager.default.removeItem(at: url) }

        let found = gather(
            predicate: NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, sentinel),
            timeout: gatherTimeout
        )

        // Results are NSMetadataItem objects, not paths: the path comes out
        // through value(forAttribute:), and anything that is not an item with
        // a path is not evidence of anything.
        let hit = paths(of: found).contains {
            URL(fileURLWithPath: $0).lastPathComponent == sentinel
        }
        return Query(
            id: id, operation: operation, arguments: sentinel,
            expected: "The sentinel is found.",
            expectedDenied: false, outcome: hit ? .isolated : .notAttempted,
            matchCount: found.count, outsideCount: 0, outsidePaths: [],
            observed: hit
                ? "the sentinel was found by exact name"
                : "the sentinel was NOT found (\(found.count) items gathered)",
            interpretation: hit
                ? """
                CONTROL: the query mechanism works inside this sandbox -- an \
                exact-name query finds what is there. That is what makes an \
                empty broad query meaningful rather than ambiguous.
                """
                : """
                The control failed: a file this run just created was not \
                returned by exact name. Either the index had not picked it up \
                within the gather window or queries do not see this sandbox \
                at all -- and the broad query below must be read with that \
                calibration, not as evidence of isolation.
                """
        )
    }

    /// Everything the index admits to, sorted by container membership.
    ///
    /// The predicate is a name match-all, not TRUEPREDICATE: NSMetadataQuery
    /// rejects TRUEPREDICATE outright (NSInvalidArgumentException, measured on
    /// the macOS runner), so "everything" is spelled as "every named item".
    /// Items without a filesystem name are outside what this question can ask
    /// -- and that limitation is stated here rather than hidden, because a
    /// broad query that silently covers less than "all" would overclaim its
    /// isolation verdict.
    private static func broadQuery(containerPath: String) -> Query {
        let id = "spotlight-broad-query"
        let operation = "NSMetadataQuery(predicate: kMDItemFSName LIKE *)"
        let arguments = "all named indexed items, sorted by container membership"

        let found = gather(
            predicate: NSPredicate(format: "%K LIKE %@", NSMetadataItemFSNameKey, "*"),
            timeout: gatherTimeout
        )

        let paths = paths(of: found)
        let outside = paths.filter { !$0.hasPrefix(containerPath) }
        let sample = Array(outside.prefix(maxOutsidePaths))

        if outside.isEmpty {
            return Query(
                id: id, operation: operation, arguments: arguments,
                expected: "Only container items, or nothing.",
                expectedDenied: true, outcome: .isolated,
                matchCount: paths.count, outsideCount: 0, outsidePaths: [],
                observed: "\(paths.count) item(s) gathered, all inside the container",
                interpretation: """
                    The index admitted to \(paths.count) items and none lies \
                    outside the container. Nothing crossed the boundary through \
                    the index in this window.
                    """
            )
        }

        return Query(
            id: id, operation: operation, arguments: arguments,
            expected: "Only container items, or nothing.",
            expectedDenied: true, outcome: .outsideItems,
            matchCount: paths.count, outsideCount: outside.count, outsidePaths: sample,
            observed: "\(outside.count) of \(paths.count) gathered item(s) lie outside the container",
            interpretation: """
                The metadata index returned paths outside the app's container \
                to an ordinary query -- names the sandbox refuses to answer \
                for directly. A name is not contents, but it is a leak across \
                the isolation boundary, and it is also aim: a confused deputy \
                needs to be told a name. The claim is the PATHS, sampled \
                above -- check them, because an index alias or a shared \
                container spelling unmakes the finding.
                """
        )
    }

    /// The filesystem paths of gathered items. Anything without a path is
    /// dropped rather than interpreted: a result the index cannot place is not
    /// a name inside the container and not a name outside it.
    private static func paths(of items: [NSMetadataItem]) -> [String] {
        items.compactMap { $0.value(forAttribute: NSMetadataItemPathKey) as? String }
    }

    /// Run one query synchronously for up to `timeout` seconds and return the
    /// gathered items. The query is stopped and discarded on every path, so no
    /// run leaves a live query behind.
    ///
    /// The finished flag crosses threads -- the gathering notification posts
    /// on whatever thread the query uses while this thread pumps its own
    /// runloop -- so it lives behind a lock. An unlocked flag here would be a
    /// data race that reads as a hang or a missed gather depending on timing.
    private static func gather(predicate: NSPredicate, timeout: TimeInterval) -> [NSMetadataItem] {
        let query = NSMetadataQuery()
        query.predicate = predicate
        // The app's own container is always in scope; the question is what
        // ELSE the index admits to, so no search scopes are set -- the default
        // scopes decide, and whatever they admit is the measurement.
        let center = NotificationCenter.default
        let lock = NSLock()
        var finished = false
        let observer = center.addObserver(
            forName: .NSMetadataQueryDidFinishGathering,
            object: query, queue: nil
        ) { _ in
            lock.lock()
            finished = true
            lock.unlock()
        }
        defer {
            center.removeObserver(observer)
            query.stop()
        }
        query.start()
        // Pump this thread's runloop while waiting: without it the gathering
        // notifications this thread subscribed to would never arrive.
        let deadline = Date().addingTimeInterval(timeout)
        var done = false
        while !done && Date() < deadline {
            _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
            lock.lock()
            done = finished
            lock.unlock()
        }
        query.stop()
        query.disableUpdates()
        return query.results.compactMap { $0 as? NSMetadataItem }
    }
    #endif
}
