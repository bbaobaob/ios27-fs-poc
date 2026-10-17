//
//  IOKitUserClientOpenProbe.swift
//  FSProbeCore — can an ordinary sandboxed app OPEN an IOKit user client?
//
//  WHY THIS EXISTS
//  ---------------
//  IOKitCensusProbe answered "which kernel services can an ordinary app SEE?"
//  and deliberately opened nothing: it enumerated registry names the way the
//  Mach census resolves names, and stopped there. Visibility was never going
//  to be the interesting question on its own. Every public iOS chain through
//  IOKit starts one step further in, at IOServiceOpen -- a sandboxed process
//  has to turn a visible service into a user-client connect port before any
//  driver code runs on its behalf, and that step, not the name, is where the
//  classic entry surface begins.
//
//  So this probe takes the census's list and asks the next question of it,
//  once per visible service: can this app OPEN a user client here? The answer
//  is a kern_return_t per attempt, recorded verbatim. Mostly refusals are the
//  expectation, and a refusal is a result; an open is a result too, and is
//  recorded as reachable attack surface rather than as a finding.
//
//  HYPOTHESIS
//  ----------
//  Whether an ordinary sandboxed app can open a user client is decided per
//  driver rather than once for the platform, so the question is measurable
//  from inside the app: attempt IOServiceOpen on each visible IOService with
//  user-client type 0 and record what the kernel returns. The working
//  expectation is refusals dominate with at least the possibility of an open,
//  and that both outcomes can be counted in one bounded walk.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether visibility of a kernel service can be converted into an OPEN
//  user-client connection from an ordinary sandboxed app -- measured by
//  calling IOServiceOpen, not inferred from entitlement documentation or from
//  the census's list of names.
//
//  CONTROL
//  -------
//  A matching dictionary for a class name that cannot exist, run first and
//  unconditionally. Its expected shape is an empty iterator (or a refused
//  call). Only that makes a populated IOService iterator -- and therefore
//  every open attempted on it -- interpretable instead of ambiguous. If the
//  control comes back non-empty it is recorded plainly as FAILED, the run
//  reads as inconclusive, and nothing is converted into a denial claim.
//
//  SAFETY
//  ------
//  ONLY IOServiceOpen, then -- immediately, before anything else -- the
//  matching IOServiceClose. NO external method is called on any connection:
//  IOConnectCallMethod, IOConnectCallScalarMethod, IOConnectCallAsync,
//  IOConnectGetNumberOfMethods, IOConnectSetMethod, IOConnectMapMemory and
//  the rest are all OUT OF SCOPE for this round. A connection is opened,
//  recorded, and closed, and nothing is ever said to the driver through it,
//  so no driver method executes on this app's behalf. Every service object
//  and every iterator is released on every path. Open attempts are bounded at
//  maxServices = 40; after the bound the iterator is only counted and drained,
//  so the total stays exact without more opens happening. Opening is
//  RECONNAISSANCE: isBoundaryViolation is always false, because a reachable
//  user client is an attack surface, not a finding. IOKit itself is resolved
//  at runtime with dlopen+dlsym, so a platform without the framework reports
//  symbolUnavailable instead of failing to link.
//

import Foundation

public enum IOKitUserClientOpenProbe {

    public enum Outcome: String, Codable, Sendable {
        /// IOServiceOpen returned KERN_SUCCESS and a non-null connect port
        /// (closed immediately), or -- on the summary -- at least one did.
        case opened
        /// The call was refused (kern_return_t recorded), or a matching
        /// attempt was refused before any open could be made.
        case refused
        /// Nothing matched, or a success produced no connection at all.
        case empty
        /// The IOKit framework or a symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        /// The registry entry the open was attempted against, when the entry
        /// describes one service. nil for the control and the plane summary.
        public let serviceName: String?
        /// The operation exercised.
        public let operation: String
        public let outcome: Outcome
        /// The kern_return_t, as the kernel reported it.
        public let kernReturn: Int32?
        /// Whether a user-client connect port was obtained (and closed at once).
        public let openedConnect: Bool
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            serviceName: String?,
            operation: String,
            outcome: Outcome,
            kernReturn: Int32?,
            openedConnect: Bool,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.serviceName = serviceName
            self.operation = operation
            self.outcome = outcome
            self.kernReturn = kernReturn
            self.openedConnect = openedConnect
            self.observed = observed
            self.interpretation = interpretation
        }

        /// Opening a user client is reachability, never a finding -- the same
        /// rule as the two censuses, and stricter here: a connect port is an
        /// attack SURFACE, which is still not an attack. The finding would be
        /// an effect an open user client produces for an unidentified caller,
        /// and no such effect is ever requested in this probe.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let entries: [Entry]
        public let violations: [Entry]

        public init(entries: [Entry], violations: [Entry]) {
            self.entries = entries
            self.violations = violations
        }
    }

    /// A class name that cannot exist. Its expected answer is an empty
    /// iterator, which calibrates every open attempted against the real plane.
    private static let controlClass = "FSProbeNonexistentIOServiceClass"

    /// The root of the plane. Matching it enumerates everything visible, and
    /// every visible service is asked for a user client.
    private static let rootClass = "IOService"

    /// How many user clients may be opened in one run. The walk is bounded so
    /// a large registry cannot turn the experiment into a hang or an
    /// unbounded stream of kernel calls; what was seen beyond the bound is
    /// still counted and drained, and the truncation is recorded.
    public static let maxServices = 40

    /// The interpretation given to every service whose user client opened,
    /// stated once so no opened entry can drift into calling itself a
    /// vulnerability.
    private static let openedProse = """
        REACHABLE ATTACK SURFACE: an ordinary sandboxed app obtained a \
        user-client connect port from this service. This is reconnaissance, \
        not an exploit -- the connection was closed immediately and NO method \
        was ever called on it, so the driver did nothing for this app. A \
        finding would require this driver to DO something dangerous for an \
        unidentified caller, which is a later experiment and not this one. \
        Recorded as reachable, with isBoundaryViolation false, because reach \
        and exploit are different claims.
        """

    public static func probe() -> Result {
        #if canImport(Darwin)
        guard let kit = IOKitShim.open() else {
            return Result(
                entries: [Entry(
                    id: "iokit-open-framework",
                    serviceName: nil,
                    operation: "dlopen IOKit.framework",
                    outcome: .symbolUnavailable,
                    kernReturn: nil,
                    openedConnect: false,
                    observed: "the IOKit framework could not be loaded",
                    interpretation: """
                        NOT ATTEMPTED: IOKit is not loadable in this runtime, so \
                        no service could be enumerated and no user client was \
                        opened. A statement about the platform, not a refusal by \
                        it.
                        """
                )],
                violations: []
            )
        }

        // The control first, unconditionally. Its shape is what makes every
        // open attempt below interpretable rather than merely countable.
        var entries: [Entry] = [controlEntry(kit: kit)]
        entries.append(contentsOf: rootEntries(kit: kit))
        return Result(entries: entries, violations: [])
        #else
        return Result(
            entries: [
                Entry(
                    id: "iokit-open-control",
                    serviceName: nil,
                    operation: "IOServiceMatching(\(controlClass)) + IOServiceGetMatchingServices + walk",
                    outcome: .notAttempted,
                    kernReturn: nil,
                    openedConnect: false,
                    observed: "IOKit is not present on this platform",
                    interpretation: """
                        NOT ATTEMPTED: the control needs a kernel registry, and \
                        there is none here. It is still recorded -- rather than \
                        omitted -- so a result with no control in it reads as \
                        impossible, not as empty.
                        """
                ),
                Entry(
                    id: "iokit-open-root",
                    serviceName: nil,
                    operation: "IOServiceMatching(\(rootClass)) + walk + IOServiceOpen + IOServiceClose",
                    outcome: .notAttempted,
                    kernReturn: nil,
                    openedConnect: false,
                    observed: "IOKit is not present on this platform",
                    interpretation: """
                        NOT ATTEMPTED: there is no kernel registry here, so no \
                        service could be enumerated and no user client was \
                        opened. Nothing was refused, because nothing was asked.
                        """
                ),
            ],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)

    /// The control: a class name that cannot exist, matched and walked without
    /// opening anything. Its expected answer is an empty iterator or a
    /// refusal; anything else unmakes the calibration.
    private static func controlEntry(kit: IOKitShim) -> Entry {
        let operation = "IOServiceMatching(\(controlClass)) + IOServiceGetMatchingServices + walk"

        switch kit.matchingServices(className: controlClass) {
        case .refused(let reason):
            return Entry(
                id: "iokit-open-control",
                serviceName: nil,
                operation: operation,
                outcome: .refused,
                kernReturn: nil,
                openedConnect: false,
                observed: "the matching call was refused: \(reason)",
                interpretation: """
                    CONTROL, refused rather than answered empty. Refusal and an \
                    empty iterator are different facts, so the walk below must \
                    be read knowing that this platform's control shape is \
                    refusal -- a refusal here calibrates, it does not deny, \
                    and no open was attempted against this control.
                    """
            )

        case .iterator(let iterator):
            // Released exactly once, on every path out of this scope --
            // including the paths that return immediately.
            defer { kit.releaseObject(iterator) }

            // Counting is bounded; the drain is not, because every object the
            // iterator hands out has to be released or the control would leak
            // kernel references while checking that nothing matched.
            var count = 0
            var capped = false
            while let service = kit.nextService(iterator) {
                kit.releaseObject(service)
                if count < maxServices {
                    count += 1
                } else {
                    capped = true
                }
            }

            if count == 0 {
                return Entry(
                    id: "iokit-open-control",
                    serviceName: nil,
                    operation: operation,
                    outcome: .empty,
                    kernReturn: nil,
                    openedConnect: false,
                    observed: "empty iterator for a class that cannot exist",
                    interpretation: """
                        CONTROL: a class that cannot exist matches nothing, \
                        which is what makes a populated IOService iterator -- \
                        and any open attempted on it below -- meaningful \
                        rather than ambiguous.
                        """
                )
            }

            let matchedText = capped ? "at least \(maxServices)" : "\(count)"
            return Entry(
                id: "iokit-open-control",
                serviceName: nil,
                operation: operation,
                outcome: .refused,
                kernReturn: nil,
                openedConnect: false,
                observed: "CONTROL FAILED: a class that cannot exist matched \(matchedText) entries",
                interpretation: """
                    CONTROL FAILED: recorded as refused -- refused of its \
                    expected empty shape, not refused by the kernel, since \
                    this control only matched and never opened. The matcher is \
                    not answering the question asked, so the run is \
                    INCONCLUSIVE rather than a denial claim: an open or a \
                    refusal elsewhere in this result cannot be attributed to \
                    anything until this is understood. Not crashed on, and not \
                    quietly dropped either.
                    """
            )
        }
    }

    /// The experiment: walk the whole IOService plane and attempt one
    /// bounded, immediately-closed open per visible service. Per-service
    /// entries carry each attempt's own outcome and kern_return_t; the
    /// trailing `iokit-open-root` entry records the totals, including how
    /// much of the plane was seen beyond the open bound.
    private static func rootEntries(kit: IOKitShim) -> [Entry] {
        let operation = "IOServiceMatching(\(rootClass)) + walk + IOServiceOpen + IOServiceClose"

        let iterator: UInt32
        switch kit.matchingServices(className: rootClass) {
        case .refused(let reason):
            return [Entry(
                id: "iokit-open-root",
                serviceName: nil,
                operation: operation,
                outcome: .refused,
                kernReturn: nil,
                openedConnect: false,
                observed: "the matching call was refused: \(reason)",
                interpretation: """
                    Refused at the matching step, before a single open was \
                    attempted: the registry would not hand over an iterator \
                    even for the root class, so no user client could be \
                    reached. That is a refusal of enumeration, not of a \
                    connection, and it claims nothing about drivers.
                    """
            )]
        case .iterator(let it):
            iterator = it
        }

        // Released exactly once, on every path out of this walk. A null
        // iterator is the "matched nothing" shape: it walks nowhere, and
        // IOObjectRelease on 0 answers bad-argument without touching state.
        defer { kit.releaseObject(iterator) }

        var entries: [Entry] = []
        var totalSeen = 0
        var attempted = 0
        var openedCount = 0
        var refusedCount = 0
        var firstRefusedKR: Int32?
        var truncated = false

        while let service = kit.nextService(iterator) {
            totalSeen += 1

            // Bound reached: keep walking only to count and drain. totalSeen
            // stays exact instead of becoming a lower bound, every remaining
            // object is still released, and no further open happens.
            guard attempted < maxServices else {
                truncated = true
                kit.releaseObject(service)
                continue
            }
            attempted += 1

            let (connect, kr) = kit.openService(service, type: 0, task: MachShim.taskSelf)

            if kr == 0 && connect != 0 {
                // Close IMMEDIATELY, before anything else -- before the name
                // lookup, before the record, before the next service. The
                // connection lives exactly as long as it takes to learn that
                // it could be made, and no method is ever called on it.
                let closeKR = kit.closeService(connect)
                let name = kit.registryName(service)
                openedCount += 1
                entries.append(Entry(
                    id: "iokit-open-\(attempted - 1)",
                    serviceName: name,
                    operation: operation,
                    outcome: .opened,
                    kernReturn: nil,
                    openedConnect: true,
                    observed: """
                        IOServiceOpen returned connect port \(connect); \
                        IOServiceClose returned \(closeKR) immediately after; \
                        no method was called on the connection
                        """,
                    interpretation: openedProse
                ))
            } else if kr != 0 {
                refusedCount += 1
                if firstRefusedKR == nil {
                    firstRefusedKR = kr
                }
                let name = kit.registryName(service)
                entries.append(Entry(
                    id: "iokit-open-\(attempted - 1)",
                    serviceName: name,
                    operation: operation,
                    outcome: .refused,
                    kernReturn: kr,
                    openedConnect: false,
                    observed: "IOServiceOpen returned kern_return_t \(kr)",
                    interpretation: """
                        Refused. The kernel answered this open attempt with \
                        kern_return_t \(kr), recorded verbatim: it is a kernel \
                        code, not an errno, and no sandbox-denial claim is \
                        read out of it. A refusal is a result -- this service \
                        stayed closed for an ordinary app -- and it says \
                        nothing about the services that did open.
                        """
                ))
            } else {
                // kr == 0 with a null connect: success that produced no
                // connection. Recorded as empty rather than refused, because
                // refusing it would misreport a kern_return_t of 0.
                let name = kit.registryName(service)
                entries.append(Entry(
                    id: "iokit-open-\(attempted - 1)",
                    serviceName: name,
                    operation: operation,
                    outcome: .empty,
                    kernReturn: 0,
                    openedConnect: false,
                    observed: """
                        IOServiceOpen returned KERN_SUCCESS with a null \
                        connect port; nothing was opened, so nothing was closed
                        """,
                    interpretation: """
                        Nothing opened: the call reported success but handed \
                        back no connect port, so there was no connection to \
                        close. Recorded as empty rather than refused because \
                        the kern_return_t was 0 -- an anomaly to note, not a \
                        denial and not a reach.
                        """
                ))
            }

            // Always released after handling that service, on every branch.
            kit.releaseObject(service)
        }

        let summaryOutcome: Outcome
        if openedCount > 0 {
            summaryOutcome = .opened
        } else if refusedCount > 0 {
            summaryOutcome = .refused
        } else {
            summaryOutcome = .empty
        }

        let truncationNote: String
        if truncated {
            truncationNote = """
                The open bound of \(maxServices) was reached, so the iterator \
                was then walked only to count and drain: totalSeen \
                (\(totalSeen)) is exact while opens stayed bounded at \
                \(attempted).
                """
        } else {
            truncationNote = """
                The whole iterator was walked to exhaustion with \(attempted) \
                open attempts, so nothing was truncated.
                """
        }

        let firstKRText: String
        if let kr = firstRefusedKR {
            firstKRText = String(kr)
        } else {
            firstKRText = "none"
        }

        let summaryInterpretation: String
        if openedCount > 0 {
            summaryInterpretation = """
                SUMMARY: \(openedCount) of \(attempted) attempted user clients \
                OPENED from an ordinary sandboxed app, across \(totalSeen) \
                services seen. An opened user client is REACHABLE ATTACK \
                SURFACE and reconnaissance, not an exploit: every connection \
                was closed immediately and no external method was called on \
                any of them, so no driver did anything for this app. A finding \
                would require a driver doing something dangerous for an \
                unidentified caller -- a later experiment this probe does not \
                run. \(truncationNote)
                """
        } else if refusedCount > 0 {
            summaryInterpretation = """
                SUMMARY: \(attempted) open attempts across \(totalSeen) \
                services seen, and not one connect port was granted; the first \
                kern_return_t was \
                \(firstKRText). Every connection \
                stayed closed, which is a result rather than a vulnerability, \
                and it claims nothing about services that were only seen, not \
                attempted. \(truncationNote)
                """
        } else {
            summaryInterpretation = """
                SUMMARY: \(totalSeen) services seen and \(attempted) open \
                attempts made, none of which produced a connect port. No user \
                client was opened on this run, so the boundary question was \
                asked and answered empty rather than skipped. \(truncationNote)
                """
        }

        entries.append(Entry(
            id: "iokit-open-root",
            serviceName: nil,
            operation: operation,
            outcome: summaryOutcome,
            kernReturn: openedCount > 0 ? nil : firstRefusedKR,
            openedConnect: openedCount > 0,
            observed: """
                \(totalSeen) services seen; \(attempted) open attempts \
                (\(openedCount) opened and closed at once, \(refusedCount) \
                refused); totalSeen=\(totalSeen), truncated=\(truncated)
                """,
            interpretation: summaryInterpretation
        ))

        return entries
    }
    #endif
}
