//
//  KeychainIsolationProbe.swift
//  FSProbeCore — does the keychain isolate apps by access group?
//
//  WHY THIS EXISTS
//  ---------------
//  Every filesystem experiment so far tested the container boundary. The
//  keychain is a DIFFERENT data boundary with the same shape: items are
//  isolated by access group, and an ordinary app holds only its own group.
//  A query that names no group must return only the caller's items. Items
//  from another group in the answer would be a data crossing -- credentials,
//  tokens, and secrets read across an isolation boundary -- which is the same
//  class of finding as reading another app's files, through a store this
//  project has never tested.
//
//  HYPOTHESIS
//  ----------
//  A broad keychain query from an ordinary app returns items from access
//  groups it does not hold.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Keychain access-group isolation for generic-password items.
//
//  CONTROL
//  -------
//  A query for a service name that cannot exist. Its expected answer is
//  errSecItemNotFound, which is what makes any other answer interpretable:
//  "not found" means the query ran and matched nothing, anything else means
//  the query was answered differently.
//
//  SAFETY
//  ------
//  Read-only. Nothing is added, modified, or deleted. Attributes only --
//  service names and account names, never secret data -- and only enough to
//  tell the caller's own items (of which there should be none) from anyone
//  else's. An item this app did not create, in an access group this app does
//  not hold, is the violation; its secret bytes are never requested.
//

import Foundation

#if canImport(Security)
import Security
#endif

public enum KeychainIsolationProbe {

    public enum Outcome: String, Codable, Sendable {
        /// Items from an access group this app does not hold were returned.
        case foreignItems
        /// Only the caller's own items, or nothing, were returned.
        case isolated
        /// The query was refused.
        case denied
        /// The query matched nothing (the control's expected answer).
        case notFound
        /// The Security framework call could not be made on this platform.
        case notAttempted
    }

    public struct Query: Sendable, Identifiable, Codable {
        public let id: String
        /// The Security call exercised.
        public let operation: String
        /// The concrete query, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when foreign items would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The OSStatus, as the platform reported it.
        public let statusName: String?
        /// How many items matched.
        public let matchCount: Int?
        /// Whether any matched item sits outside the caller's access group.
        public let foreignMatchCount: Int?
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
            statusName: String?,
            matchCount: Int?,
            foreignMatchCount: Int?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.statusName = statusName
            self.matchCount = matchCount
            self.foreignMatchCount = foreignMatchCount
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .foreignItems && expectedDenied
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

    /// A service name that cannot exist. Its expected answer is
    /// errSecItemNotFound, which calibrates every other answer.
    private static let nonexistentService = "com.bbaobaob.fsprobe.nonexistent-control"

    public static func probe() -> Result {
        var queries: [Query] = []

        // The control first: a service that cannot exist must answer "not
        // found". Without it, an empty answer on the broad query could mean
        // the query ran and matched nothing, or that the whole mechanism is
        // absent on this platform.
        queries.append(queryService(nonexistentService, expectedDenied: false))

        // The broad query: every generic-password item, no access group named.
        // The expected answer is isolation -- only the caller's own items, of
        // which a fresh probe app holds none.
        queries.append(broadQuery())

        let violations = queries.filter { $0.isBoundaryViolation }
        return Result(queries: queries, violations: violations)
    }

    // MARK: - Cases

    private static func queryService(_ service: String, expectedDenied: Bool) -> Query {
        let id = service == nonexistentService
            ? "keychain-nonexistent-control"
            : "keychain-service-\(service)"
        let operation = "SecItemCopyMatching({kSecClass, kSecAttrService, kSecReturnAttributes, kSecMatchLimitOne})"

        #if canImport(Darwin)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if service == nonexistentService {
            let notFound = (status == errSecItemNotFound)
            return Query(
                id: id, operation: operation,
                arguments: "service=\(service)",
                expected: "errSecItemNotFound. The service does not exist, which calibrates the broad query.",
                expectedDenied: false,
                outcome: notFound ? .notFound : .denied,
                statusName: statusName(status),
                matchCount: nil, foreignMatchCount: nil,
                observed: notFound
                    ? "errSecItemNotFound"
                    : "answered \(statusName(status)) instead of not-found",
                interpretation: notFound
                    ? """
                    CONTROL: the query ran and matched nothing, which is what \
                    makes an empty answer on the broad query meaningful rather \
                    than ambiguous.
                    """
                    : """
                    The control did not answer not-found, so the query mechanism \
                    itself behaves differently than assumed on this platform and \
                    the broad query must be read with that in mind.
                    """
            )
        }

        return classify(id: id, operation: operation, arguments: "service=\(service)",
                        status: status, item: item, expectedDenied: expectedDenied)
        #else
        return Query(
            id: id, operation: operation, arguments: "service=\(service)",
            expected: "Isolation: only the caller's own items.",
            expectedDenied: expectedDenied,
            outcome: .notAttempted,
            statusName: nil, matchCount: nil, foreignMatchCount: nil,
            observed: "the Security framework is not present on this platform",
            interpretation: "NOT ATTEMPTED: no keychain exists here."
        )
        #endif
    }

    private static func broadQuery() -> Query {
        let id = "keychain-broad-query"
        let operation = "SecItemCopyMatching({kSecClass, kSecReturnAttributes, kSecMatchLimitAll})"

        #if canImport(Darwin)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        return classify(id: id, operation: operation,
                        arguments: "all generic-password items, no access group",
                        status: status, item: items, expectedDenied: true)
        #else
        return Query(
            id: id, operation: operation,
            arguments: "all generic-password items, no access group",
            expected: "Isolation: only the caller's own items (none).",
            expectedDenied: true,
            outcome: .notAttempted,
            statusName: nil, matchCount: nil, foreignMatchCount: nil,
            observed: "the Security framework is not present on this platform",
            interpretation: "NOT ATTEMPTED: no keychain exists here."
        )
        #endif
    }

    // MARK: - Classification

    #if canImport(Darwin)
    /// Turn an OSStatus and any returned attributes into the outcome that
    /// matters. Only ATTRIBUTES are inspected -- never secret bytes -- and
    /// only far enough to tell the caller's own access group from any other.
    private static func classify(
        id: String, operation: String, arguments: String,
        status: OSStatus, item: CFTypeRef?, expectedDenied: Bool
    ) -> Query {
        let expected = """
            Isolation: only items in the caller's own access group (of which a \
            fresh probe app holds none), or errSecItemNotFound.
            """

        guard status == errSecSuccess else {
            let notFound = (status == errSecItemNotFound)
            return Query(
                id: id, operation: operation, arguments: arguments,
                expected: expected, expectedDenied: expectedDenied,
                outcome: notFound ? .notFound : .denied,
                statusName: statusName(status), matchCount: 0, foreignMatchCount: 0,
                observed: "answered \(statusName(status)) with no items",
                interpretation: notFound
                    ? """
                    No items matched. For the broad query that is the isolated \
                    shape: nothing outside the caller's group was reachable.
                    """
                    : """
                    The query was refused with \(statusName(status)). A refusal \
                    is not a crossing -- nothing was returned -- so nothing is \
                    claimed about isolation either way beyond the refusal itself.
                    """
            )
        }

        // Success: count what came back and check every item's access group.
        // This app's own group is unknown at compile time and unneeded: a
        // fresh probe app created no items, so ANY returned item is either the
        // app's own (impossible without a prior write) or foreign. The access
        // group attribute decides it without touching secret data.
        let array: [[String: Any]] = {
            if let list = item as? [[String: Any]] { return list }
            if let single = item as? [String: Any] { return [single] }
            return []
        }()

        // The caller's own default group is its application identifier
        // (team seed + bundle id), read out of its own entitlements at runtime
        // rather than assumed. Items in that group are the caller's own even if
        // this run never wrote them -- a previous run, or the platform itself,
        // could have -- and counting them as foreign would be a fabricated
        // crossing. Only groups that are NOT the caller's own count.
        let ownGroup = applicationIdentifier()
        let groups = Set(array.compactMap { $0[kSecAttrAccessGroup as String] as? String })
        let foreignGroups = ownGroup == nil
            ? groups
            : groups.filter { $0 != ownGroup }
        let foreign = array.filter { item in
            guard let group = item[kSecAttrAccessGroup as String] as? String else { return false }
            return ownGroup == nil || group != ownGroup
        }

        if array.isEmpty {
            return Query(
                id: id, operation: operation, arguments: arguments,
                expected: expected, expectedDenied: expectedDenied,
                outcome: .isolated,
                statusName: statusName(status), matchCount: 0, foreignMatchCount: 0,
                observed: "success with no items",
                interpretation: """
                    The query succeeded and matched nothing. Nothing crossed the \
                    boundary.
                    """
            )
        }

        // An item WITHOUT an access-group attribution, or IN the caller's own
        // group, is not evidence of a crossing: unattributed items are the
        // platform's default handling, and own-group items are the caller's
        // even if this run never wrote them. Only items in groups that are not
        // the caller's own count as foreign, and the group names are recorded
        // so the claim is checkable rather than trusted.
        if foreign.isEmpty {
            return Query(
                id: id, operation: operation, arguments: arguments,
                expected: expected, expectedDenied: expectedDenied,
                outcome: .isolated,
                statusName: statusName(status),
                matchCount: array.count, foreignMatchCount: 0,
                observed: "\(array.count) item(s), all unattributed or in the caller's own group"
                    + (ownGroup.map { " (\($0))" } ?? " (own group unreadable)"),
                interpretation: """
                    Items were returned but none sits in a group outside the \
                    caller's own, so no crossing is demonstrated. The \
                    attribution -- or its absence -- is recorded verbatim so a \
                    later run can compare rather than re-argue.
                    """
            )
        }

        return Query(
            id: id, operation: operation, arguments: arguments,
            expected: expected, expectedDenied: expectedDenied,
            outcome: .foreignItems,
            statusName: statusName(status),
            matchCount: array.count, foreignMatchCount: foreign.count,
            observed: "\(foreign.count) item(s) in foreign groups: \(foreignGroups.sorted().joined(separator: ", "))"
                + (ownGroup.map { " (caller: \($0))" } ?? " (caller's own group unreadable)"),
            interpretation: """
                Items in access groups outside the caller's own were returned to \
                a caller that never wrote them. That is the data crossing this \
                probe exists to detect: another group's items answered a query \
                that named no group. The claim is the group NAMES, recorded \
                above -- check them against this app's entitlements, because a \
                name that turns out to be the caller's own under a different \
                spelling unmakes the finding.
                """
        )
    }
    #endif

    /// The caller's own application identifier (team seed + bundle id), which
    /// is also its default keychain access group. Read from the caller's own
    /// entitlements at runtime via SecTask -- the task is this process itself,
    /// so no other process is touched. Nil when the entitlement is unreadable,
    /// in which case every attributed group is treated as foreign and said so.
    private static func applicationIdentifier() -> String? {
        #if canImport(Darwin)
        // Bound at runtime rather than imported: one SDK in this project's
        // build matrix declares these symbols and another does not, and the
        // import is what the SDK permits while the runtime is what the kernel
        // answers. dlsym resolves what is really there; absence reads as an
        // unreadable group rather than a compile failure.
        typealias CreateTaskFn = @convention(c) (UnsafeRawPointer?) -> OpaquePointer?
        // The key is a CFString OBJECT, not a C string: the callee reads an
        // isa pointer out of it, so a char buffer in its place dereferences
        // attacker-shaped memory and the caller dies with SIGSEGV. That is not
        // hypothetical -- it is what the first version of this binding did on
        // the macOS runner. OpaquePointer carries the object without claiming
        // a type the binding cannot prove.
        typealias CopyEntitlementFn = @convention(c) (
            OpaquePointer?, OpaquePointer?, UnsafeMutableRawPointer?
        ) -> Unmanaged<CFString>?
        guard let createPtr = POSIXShim.lookupSymbol("SecTaskCreateFromSelf"),
              let copyPtr = POSIXShim.lookupSymbol("SecTaskCopyValueForEntitlement")
        else { return nil }
        let createTask = unsafeBitCast(createPtr, to: CreateTaskFn.self)
        let copyEntitlement = unsafeBitCast(copyPtr, to: CopyEntitlementFn.self)
        // The allocator is nil (the default); the error-out pointer is nil
        // (errors surface as a nil return, which is all this caller needs).
        guard let task = createTask(nil) else { return nil }
        let key: CFString = "application-identifier" as CFString
        let keyPtr = Unmanaged.passUnretained(key).toOpaque()
        guard let value = withExtendedLifetime(key, {
            copyEntitlement(task, keyPtr, nil)
        }) else { return nil }
        // Retained by the call; taken into ARC once, which owns it after.
        return value.takeRetainedValue() as String
        #else
        return nil
        #endif
    }

    /// The platform's own name for a keychain status. errSecSuccess is 0;
    /// the rest are negative OSStatus values the framework defines.
    ///
    /// Gated on the framework, not the platform: without Security there is no
    /// OSStatus to name and no caller that could ask.
    #if canImport(Security)
    private static func statusName(_ status: OSStatus) -> String {
        switch status {
        case errSecSuccess: return "errSecSuccess"
        case errSecItemNotFound: return "errSecItemNotFound"
        case errSecAuthFailed: return "errSecAuthFailed"
        case errSecParam: return "errSecParam"
        case errSecAllocate: return "errSecAllocate"
        case errSecNotAvailable: return "errSecNotAvailable"
        case errSecMissingEntitlement: return "errSecMissingEntitlement"
        default: return "OSStatus(\(status))"
        }
    }
    #endif
}
