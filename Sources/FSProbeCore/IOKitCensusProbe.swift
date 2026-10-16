//
//  IOKitCensusProbe.swift
//  FSProbeCore — which kernel services are visible from the sandbox?
//
//  WHY THIS EXISTS
//  ---------------
//  Public iOS exploit history keeps returning to the same place: IOKit user
//  clients reachable from a sandboxed process (the in-the-wild chain through
//  ProvInfoIOKitUserClient is the documented example). Every one of those
//  chains starts with the same question this project asks about everything:
//  what can an ordinary app REACH? For Mach services that question is now a
//  census. For the kernel registry it has never been asked here at all.
//
//  This probe is the census half only: enumerate the IOService plane and
//  record which service classes are visible. It opens NO user client and
//  calls NO external method. Enumerating names is to IOKit what resolving
//  Mach names is to launchd -- reconnaissance, not a finding -- and it is
//  treated that way: visibility never flags a violation here. What would be
//  a finding is a service DOING something for an unidentified caller, which
//  is a later experiment that this census exists to aim.
//
//  HYPOTHESIS
//  ----------
//  The set of kernel services visible from an ordinary sandboxed app is
//  enumerable from inside the app, and it differs from what documentation
//  implies.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Which IORegistry entries an ordinary app can enumerate -- measured, not
//  assumed.
//
//  CONTROL
//  -------
//  A matching dictionary for a class name that cannot exist. It must yield an
//  empty iterator (or a refused call), which is what makes a populated
//  iterator for IOService meaningful rather than ambiguous.
//
//  SAFETY
//  ------
//  Read-only enumeration. Every iterated object is released. No user client
//  is opened, no external method is called, no state changes anywhere. The
//  IOKit functions are resolved at runtime through dlopen+dlsym so a platform
//  without the framework reports unattempted instead of failing to link.
//

import Foundation

public enum IOKitCensusProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The service class matched entries, which were enumerated.
        case enumerated
        /// The class matched nothing.
        case empty
        /// The call was refused.
        case refused
        /// The IOKit framework or a symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        /// The IOService class the matching dictionary named.
        public let serviceClass: String
        /// The operation exercised.
        public let operation: String
        public let outcome: Outcome
        /// How many registry entries matched.
        public let matchCount: Int?
        /// Whether the iterator was walked to exhaustion.
        public let exhausted: Bool?
        /// The first names seen, so the census is checkable, not just counted.
        public let sampleNames: [String]
        /// The kern return or errno, as the platform reported it.
        public let errorName: String?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            serviceClass: String,
            operation: String,
            outcome: Outcome,
            matchCount: Int?,
            exhausted: Bool?,
            sampleNames: [String],
            errorName: String?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.serviceClass = serviceClass
            self.operation = operation
            self.outcome = outcome
            self.matchCount = matchCount
            self.exhausted = exhausted
            self.sampleNames = sampleNames
            self.errorName = errorName
            self.observed = observed
            self.interpretation = interpretation
        }

        /// Visibility is reconnaissance, never a finding -- the same rule as
        /// the Mach-service census, which would otherwise produce a false
        /// finding for every visible service at once.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let entries: [Entry]
        public let violations: [Entry]

        public init(entries: [Entry], violations: [Entry]) {
            self.entries = entries
            self.violations = violations
        }

        public var violationsAlwaysEmpty: Bool { violations.isEmpty }
    }

    /// A class name that cannot exist. Its expected answer is an empty
    /// iterator, which calibrates every populated one.
    private static let controlClass = "FSProbeNonexistentIOServiceClass"

    /// The root of the plane. Matching it enumerates everything visible.
    private static let rootClass = "IOService"

    /// How many names to record. The walk is bounded so a large registry
    /// cannot turn the census into a hang; the count is recorded alongside
    /// so a truncated walk reads as truncated, not complete.
    public static let maxNames = 300

    /// How many sample names to keep per entry. Enough to check, not enough
    /// to dump the registry into the report.
    private static let maxSamples = 20

    public static func probe() -> Result {
        #if canImport(Darwin)
        guard let kit = IOKitShim.open() else {
            return Result(
                entries: [Entry(
                    id: "iokit-framework", serviceClass: "(framework)",
                    operation: "dlopen IOKit.framework",
                    outcome: .symbolUnavailable,
                    matchCount: nil, exhausted: nil, sampleNames: [],
                    errorName: nil, observed: "the IOKit framework could not be loaded",
                    interpretation: """
                        NOT ATTEMPTED: IOKit is not loadable in this runtime, so \
                        no registry question could be asked. A statement about \
                        the platform, not a refusal by it.
                        """
                )],
                violations: []
            )
        }

        var entries: [Entry] = [enumerateClass(controlClass, kit: kit)]
        entries.append(enumerateClass(rootClass, kit: kit))
        return Result(entries: entries, violations: [])
        #else
        return Result(
            entries: [Entry(
                id: "iokit-framework", serviceClass: "(framework)",
                operation: "dlopen IOKit.framework",
                outcome: .notAttempted,
                matchCount: nil, exhausted: nil, sampleNames: [],
                errorName: nil, observed: "IOKit is not present on this platform",
                interpretation: "NOT ATTEMPTED: there is no kernel registry here."
            ), Entry(
                id: "iokit-control", serviceClass: controlClass,
                operation: "IOServiceMatching(class) + IOServiceGetMatchingServices + walk",
                outcome: .notAttempted,
                matchCount: nil, exhausted: nil, sampleNames: [],
                errorName: nil, observed: "IOKit is not present on this platform",
                interpretation: """
                    NOT ATTEMPTED: the control needs a kernel registry, and \
                    there is none here. It is still recorded -- rather than \
                    omitted -- so a result with no control in it reads as \
                    impossible, not as empty.
                    """
            )],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)
    private static func enumerateClass(_ name: String, kit: IOKitShim) -> Entry {
        let id = name == controlClass ? "iokit-control" : "iokit-IOService-plane"
        let operation = "IOServiceMatching(class) + IOServiceGetMatchingServices + walk"

        let iterator: UInt32
        switch kit.matchingServices(className: name) {
        case .iterator(let it):
            iterator = it
        case .refused(let reason):
            return Entry(
                id: id, serviceClass: name, operation: operation,
                outcome: .refused,
                matchCount: nil, exhausted: nil, sampleNames: [],
                errorName: reason,
                observed: "the matching call was refused: \(reason)",
                interpretation: name == controlClass
                    ? """
                    The control was refused rather than answered empty. That \
                    still calibrates the root enumeration -- a refusal and an \
                    empty iterator are different facts -- but it means the \
                    control's shape on this platform is refusal, and the root \
                    result must be read with that in mind.
                    """
                    : """
                    Refused. The registry would not answer even for the root \
                    class, so visibility ends here.
                    """
            )
        }
        // Every object the iterator hands out is released on every path,
        // including the drain: an unreleased service object holds a kernel
        // reference, and a census that leaks hundreds of them is not
        // read-only in any honest sense. A null iterator (the matched-nothing
        // shape) walks nowhere and releases nothing -- there is no object to
        // release, and calling into the kernel with a null iterator to find
        // that out would be the wrong way to learn it.
        var names: [String] = []
        var count = 0
        var exhausted = true
        if iterator == 0 {
            exhausted = true
        } else {
            defer { kit.releaseObject(iterator) }
            while let service = kit.nextService(iterator) {
            defer { kit.releaseObject(service) }
            if count < maxNames {
                if names.count < maxSamples {
                    // The loop variable is the class under test; the registry
                    // entry's own name is what the census samples.
                    if let entryName = kit.registryName(service) {
                        names.append(entryName)
                    }
                }
                count += 1
            } else {
                exhausted = false
                // Drain the rest without recording, so the iterator is still
                // walked to exhaustion and the count stays exact.
                count += 1
                while let rest = kit.nextService(iterator) {
                    count += 1
                    kit.releaseObject(rest)
                }
                break
            }
            }
        }

        if name == controlClass {
            return Entry(
                id: id, serviceClass: name, operation: operation,
                outcome: count == 0 ? .empty : .enumerated,
                matchCount: count, exhausted: exhausted, sampleNames: names,
                errorName: nil,
                observed: count == 0
                    ? "empty iterator for a class that cannot exist"
                    : "\(count) entries matched a class that cannot exist",
                interpretation: count == 0
                    ? """
                    CONTROL: a nonexistent class matches nothing, which is what \
                    makes a populated root iterator meaningful rather than \
                    ambiguous.
                    """
                    : """
                    A class that cannot exist matched entries. That unmakes the \
                    control -- the matcher is not answering the question asked \
                    -- and the root enumeration below cannot be trusted until \
                    this is understood.
                    """
            )
        }

        return Entry(
            id: id, serviceClass: name, operation: operation,
            outcome: count == 0 ? .empty : .enumerated,
            matchCount: count, exhausted: exhausted, sampleNames: names,
            errorName: nil,
            observed: "\(count) registry entries visible"
                + (exhausted ? "" : " (walk truncated at \(maxNames))"),
            interpretation: """
                \(count) kernel services are enumerable from an ordinary app. \
                That is reconnaissance -- the census this probe exists to take \
                -- and it claims nothing about what any of them will DO. Names \
                are sampled above so the census is checkable; a service that \
                answers an unidentified caller is a later experiment, aimed by \
                this list.
                """
        )
    }
    #endif
}

#if canImport(Darwin)
// MARK: - Runtime bindings

/// IOKit resolved at runtime, so a platform without the framework reports
/// unattempted instead of failing to link. The app never links IOKit; every
/// function below is a dlsym lookup that may be absent, and every call site
/// treats absence as a recorded answer rather than a crash.
///
/// Memory rule, stated once because getting it wrong crashes: the matching
/// dictionary comes back +1 (Create rule). IOServiceGetMatchingServices
/// CONSUMES it on success (kr == 0) and does not on failure. So the failure
/// path releases and the success path touches nothing. Releasing on success
/// would over-release into the kernel's hands; not releasing on failure would
/// leak. There is no third case.
final class IOKitShim: Sendable {
    private let handle: UnsafeMutableRawPointer

    /// What a matching attempt produced. An empty-but-valid iterator is
    /// `.iterator` with nothing in it -- which is exactly the control's
    /// expected shape -- while `.refused` carries the reason.
    enum MatchOutcome: Sendable {
        case iterator(UInt32)
        case refused(String)
    }

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    /// Load the framework. Nil when it cannot be loaded -- which is itself
    /// the first measurement, not a failure to measure.
    static func open() -> IOKitShim? {
        let paths = [
            "/System/Library/Frameworks/IOKit.framework/IOKit",
            "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
        ]
        for path in paths {
            let handle = path.withCString { dlopen($0, RTLD_LAZY) }
            if let handle {
                return IOKitShim(handle: handle)
            }
        }
        return nil
    }

    private func symbol<T>(_ name: String) -> T? {
        guard let ptr = name.withCString({ dlsym(self.handle, $0) }) else {
            return nil
        }
        return unsafeBitCast(ptr, to: T.self)
    }

    // IOMainPort(bootstrap, &mainPort) -> kern_return_t
    private typealias MainPortFn = @convention(c) (
        UInt32, UnsafeMutablePointer<UInt32>
    ) -> Int32
    // IOServiceMatching(name) -> retained CFDictionaryRef (nullable)
    private typealias MatchingFn = @convention(c) (
        UnsafePointer<CChar>
    ) -> Unmanaged<CFDictionary>?
    // IOServiceGetMatchingServices(mainPort, matching, &iterator) -> kern_return_t
    private typealias GetMatchingFn = @convention(c) (
        UInt32, Unmanaged<CFDictionary>, UnsafeMutablePointer<UInt32>
    ) -> Int32
    // IOIteratorNext(iterator) -> object or 0
    private typealias NextFn = @convention(c) (UInt32) -> UInt32
    // IOObjectRelease(object) -> kern_return_t
    private typealias ReleaseFn = @convention(c) (UInt32) -> Int32
    // IORegistryEntryGetName(entry, nameOut[128]) -> kern_return_t
    private typealias GetNameFn = @convention(c) (
        UInt32, UnsafeMutablePointer<CChar>
    ) -> Int32

    /// The iterator for a service class. The matching dictionary is consumed
    /// by the call on success and released here on failure, so neither path
    /// leaks it and neither path frees what the kernel owns.
    func matchingServices(className: String) -> MatchOutcome {
        // IOMainPort is the modern entry point; IOMasterPort is its
        // predecessor, and either may be the one a given OS ships. Trying
        // both in order keeps one renamed symbol from reading as a refusal.
        let mainPort: MainPortFn? =
            symbol("IOMainPort") ?? symbol("IOMasterPort")
        guard let mainPort,
              let matching: MatchingFn = symbol("IOServiceMatching"),
              let getMatching: GetMatchingFn = symbol("IOServiceGetMatchingServices")
        else {
            return .refused("a required symbol is absent")
        }
        var port: UInt32 = 0
        guard mainPort(0, &port) == 0, port != 0 else {
            return .refused("no IOKit main port")
        }
        guard let dict = className.withCString({ matching($0) }) else {
            return .refused("the matching dictionary could not be built")
        }
        var iterator: UInt32 = 0
        let kr = getMatching(port, dict, &iterator)
        if kr != 0 {
            // CFRelease is unavailable in Swift (CF objects are automatically
            // managed), so the +1 from the Create rule is surrendered through
            // the Unmanaged value itself.
            dict.release()
            return .refused("kern_return_t \(kr)")
        }
        // Success: consumed by the call. A null iterator with kr == 0 is the
        // "matched nothing" shape -- success with nowhere to walk -- and it is
        // exactly the control's expected answer, so it is an (empty) iterator
        // rather than a refusal. Collapsing it into refusal would destroy the
        // distinction the control exists to draw.
        return .iterator(iterator)
    }

    func nextService(_ iterator: UInt32) -> UInt32? {
        guard let next: NextFn = symbol("IOIteratorNext") else { return nil }
        let object = next(iterator)
        return object == 0 ? nil : object
    }

    func releaseObject(_ object: UInt32) {
        guard let release: ReleaseFn = symbol("IOObjectRelease") else { return }
        _ = release(object)
    }

    /// The registry name of one entry, if it has one.
    func registryName(_ service: UInt32) -> String? {
        guard let getName: GetNameFn = symbol("IORegistryEntryGetName") else { return nil }
        var buffer = [CChar](repeating: 0, count: 128)
        guard getName(service, &buffer) == 0 else { return nil }
        return String(cString: buffer)
    }
}
#endif
