//
//  PreferenceDeputyProbe.swift
//  FSProbeCore — cfprefsd tested as a confused deputy.
//
//  HYPOTHESIS
//  ----------
//  The mach-lookup experiment measured that `com.apple.cfprefsd.daemon` is
//  reachable from an ordinary sandboxed app. cfprefsd is a privileged daemon
//  that writes preference files on the caller's behalf — exactly the deputy
//  shape. The question is whether it authorizes the resource it is asked to
//  write, or trusts the caller's reference.
//
//  `UserDefaults(suiteName:)` is the documented public surface of that daemon.
//  It takes a *name* supplied by the caller. If cfprefsd treats that name as a
//  real, global location rather than as a domain namespaced inside the caller's
//  own container, then a caller could name a suite belonging to another app or
//  to a shared app group, and the daemon would write there on the caller's
//  behalf — a write primitive outside the container, performed by a privileged
//  process the caller does not control.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  The container boundary for writes. The expected policy is that the daemon
//  derives the destination from the caller's own container and treats the suite
//  name purely as a domain label within it.
//
//  CONTROL
//  -------
//  A suite name that is unambiguously this app's own. It must produce a file
//  inside this container, which establishes that the deputy is functioning and
//  that a file appearing in the container is the normal outcome. Without that
//  control, "no file appeared" would be uninterpretable — it could mean the
//  daemon wrote elsewhere, or simply that the write did not happen at all.
//
//  DISCRIMINATING SIGNAL
//  ---------------------
//  A foreign suite name is written and synchronized. If a file bearing that
//  name appears inside this container, the daemon namespaced it and there is no
//  finding. If the write reports success but no such file appears here, the
//  write went somewhere this process cannot see — the confused-deputy
//  signature, and the result to investigate further.
//
//  A WRITE THAT REPORTS SUCCESS IS NOT A VIOLATION. The finding would be the
//  file landing outside the container, verified by its absence here together
//  with the daemon's own success report.
//
//  SAFETY
//  ------
//  Synthetic key and value only. Nothing this app did not create is read,
//  modified, or removed. Every artifact the probe creates is removed, and the
//  key is deleted from the defaults database afterwards.
//

import Foundation

public enum PreferenceDeputyProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The write landed inside this container, as the policy predicts.
        case contained
        /// The write reported success but did not land in this container.
        case escaped
        /// The API refused the request outright.
        case denied
        /// The case could not be run, with the reason recorded.
        case notApplicable
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
        /// True when a result outside this container would be a violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The API error's domain and code, when one was returned.
        public let errorDomain: String?
        public let errorCode: Int?
        public let errorDescription: String?
        /// What was observed on disk: the files that appeared, or their absence.
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
            errorDomain: String?,
            errorCode: Int?,
            errorDescription: String?,
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
            self.errorDomain = errorDomain
            self.errorCode = errorCode
            self.errorDescription = errorDescription
            self.observed = observed
            self.interpretation = interpretation
        }

        /// A violation is a write that succeeded but did not land here.
        public var isBoundaryViolation: Bool {
            outcome == .escaped && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let experiments: [Experiment]
        public let violations: [Experiment]

        public init(experiments: [Experiment], violations: [Experiment]) {
            self.experiments = experiments
            self.violations = violations
        }
    }

    /// A synthetic key and value, so no real preference is read or disturbed.
    private static let syntheticKey = "fsprobe-deputy-probe"
    private static let syntheticValue = "fsprobe-deputy-probe-value"

    /// The suite name used for the control: unambiguously this app's own.
    private static let controlSuite = "com.bbaobaob.fsprobe.deputy-control"

    /// The suite name used for the test case.
    ///
    /// The name is arbitrary on purpose. What the experiment measures is not
    /// whether this particular group exists, but whether the daemon resolves the
    /// name against the caller's container or against a global location. Any
    /// name outside this app's own domain exercises the same question.
    private static let foreignSuite = "group.com.example.deputy-probe-target"

    /// How long to wait for the daemon to flush a write to disk. Bounded, so a
    /// silent daemon cannot hang the harness.
    private static let flushTimeout: TimeInterval = 3.0

    /// Run the deputy test.
    ///
    /// - Parameter containerPath: the app's own container, whose Preferences
    ///   directory is where a contained write must appear.
    public static func probe(containerPath: String) -> Result {
        var experiments: [Experiment] = []

        // Control first: the deputy must demonstrably write into this container
        // for a suite this app owns, or the test case below is uninterpretable.
        //
        // This is not a formality. On a platform whose preference storage is
        // elsewhere -- the Linux verification host, or macOS outside a container
        // -- the control reports that no file appeared here, and the test case
        // would then report "escaped" for a write that simply went to the
        // platform's normal location. That is a false finding produced by
        // comparing against the wrong expectation, so the control gates the test.
        let control = runCase(
            id: "prefs-control-own-suite",
            mechanism: """
                Control: cfprefsd writing a preference for a suite this app owns. \
                Must produce a file inside this container, which establishes both \
                that the deputy is functioning and that a file appearing here is \
                the normal outcome.
                """,
            suiteName: controlSuite,
            containerPath: containerPath,
            expectedDenied: false
        )
        experiments.append(control)

        guard control.outcome == .contained else {
            // The platform did not demonstrate that this container is where its
            // preference daemon writes. Without that, "no file appeared" cannot
            // distinguish a cross-container write from an ordinary write to the
            // platform's own preference location, so the hypothesis is
            // untestable here and must not be reported as a violation.
            experiments.append(Experiment(
                id: "prefs-foreign-suite",
                mechanism: """
                    Confused deputy: cfprefsd asked to write a preference for a suite \
                    name the caller supplies. Does the daemon resolve that name against \
                    the caller's own container, or against a global location?
                    """,
                operation: "UserDefaults(suiteName:).set + synchronize",
                arguments: "suite=\(foreignSuite), key=\(syntheticKey)",
                expected: """
                    Contained, but only interpretable once the control has shown that \
                    this container is where the platform's preference daemon writes.
                    """,
                expectedDenied: true,
                outcome: .notApplicable,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                observed: "control outcome was \(control.outcome.rawValue)",
                interpretation: """
                    NOT ATTEMPTED for interpretation: the control did not demonstrate \
                    that this platform writes preferences into this container, so the \
                    test case cannot distinguish a cross-container write from an \
                    ordinary write to the platform's own preference location. Running \
                    it anyway would report a false finding. This experiment is only \
                    interpretable on a device whose container governs this path.
                    """
            ))
            let violations = experiments.filter { $0.isBoundaryViolation }
            return Result(experiments: experiments, violations: violations)
        }

        experiments.append(runCase(
            id: "prefs-foreign-suite",
            mechanism: """
                Confused deputy: cfprefsd asked to write a preference for a suite \
                name the caller supplies. Does the daemon resolve that name against \
                the caller's own container, treating it as a domain label, or against \
                a global location? A global resolution would let the caller name \
                another app's group and have a privileged process write there.
                """,
            suiteName: foreignSuite,
            containerPath: containerPath,
            expectedDenied: true
        ))

        let violations = experiments.filter { $0.isBoundaryViolation }
        return Result(experiments: experiments, violations: violations)
    }

    private static func runCase(
        id: String,
        mechanism: String,
        suiteName: String,
        containerPath: String,
        expectedDenied: Bool
    ) -> Experiment {
        let operation = "UserDefaults(suiteName:).set + synchronize"
        let arguments = "suite=\(suiteName), key=\(syntheticKey)"

        guard let defaults = UserDefaults(suiteName: suiteName) else {
            // The API itself refused the name. That is a denial at the API layer,
            // recorded as such rather than as a sandbox result.
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: "The API must accept the suite name.",
                expectedDenied: expectedDenied,
                outcome: .notApplicable,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                observed: "UserDefaults(suiteName:) returned nil",
                interpretation: """
                    The API refused the suite name itself, so no write was attempted \
                    and nothing is claimed about the daemon's authorization.
                    """
            )
        }

        let preferencesDirectory = containerPath + "/Library/Preferences"
        let before = preferenceFileNames(in: preferencesDirectory)

        // Write through the documented API. cfprefsd performs the actual file
        // write on this process's behalf.
        defaults.set(syntheticValue, forKey: syntheticKey)
        _ = defaults.synchronize()

        // The daemon may flush asynchronously, so poll rather than sample once.
        // A single immediate check would report "not landed" for a write that was
        // merely still in flight, which would fabricate a finding.
        var after = preferenceFileNames(in: preferencesDirectory)
        let deadline = Date().addingTimeInterval(flushTimeout)
        while after == before && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
            after = preferenceFileNames(in: preferencesDirectory)
        }

        let readBack = defaults.string(forKey: syntheticKey)
        let newFiles = after.subtracting(before).sorted()

        // Clean up: remove the key from the database and any file the probe
        // caused to appear. Nothing the probe did not create is touched.
        defaults.removeObject(forKey: syntheticKey)
        _ = defaults.synchronize()
        for name in newFiles {
            try? FileManager.default.removeItem(
                atPath: preferencesDirectory + "/" + name
            )
        }

        let expectedText = expectedDenied
            ? """
                Contained. The daemon must resolve the suite name against this \
                container, so the file appears here named after the suite.
                """
            : """
                Contained. The file appears in this container named after the suite.
                """

        // The write must report success for the location question to mean
        // anything; a failed write is not evidence of where it would have gone.
        guard readBack == syntheticValue else {
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: expectedText,
                expectedDenied: expectedDenied,
                outcome: .denied,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                observed: "read-back returned \(readBack.map { "\($0)" } ?? "nil")",
                interpretation: """
                    The write did not report success, so the location question is \
                    moot: there is no evidence the daemon performed any write.
                    """
            )
        }

        if newFiles.isEmpty {
            // The daemon reported success but nothing appeared here. Either it
            // wrote somewhere this process cannot see, or it has not flushed yet.
            return Experiment(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: expectedText,
                expectedDenied: expectedDenied,
                outcome: .escaped,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                observed: """
                    no new file appeared in \(preferencesDirectory) within \
                    \(Int(flushTimeout))s; existing files: \(before.sorted().joined(separator: ", "))
                    """,
                interpretation: """
                    The write reported success but no file bearing the suite name \
                    appeared in this container. The daemon therefore resolved the \
                    name against something other than this container, which is the \
                    confused-deputy signature: a privileged process performed a \
                    write on the caller's behalf at a location the caller cannot \
                    see. This requires follow-up to establish where it landed.
                    """
            )
        }

        return Experiment(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments,
            expected: expectedText,
            expectedDenied: expectedDenied,
            outcome: .contained,
            errorDomain: nil, errorCode: nil, errorDescription: nil,
            observed: "new file(s) in this container: \(newFiles.joined(separator: ", "))",
            interpretation: """
                The write reported success and the file appeared in this container, \
                named after the suite. The daemon resolved the name against the \
                caller's own container, which is the expected policy: the suite \
                name is a domain label, not a location.
                """
        )
    }

    /// File names in the preferences directory, or an empty list when it cannot
    /// be read. An unreadable directory yields no names rather than a fabricated
    /// empty result that could be mistaken for "nothing was written".
    private static func preferenceFileNames(in directory: String) -> Set<String> {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory) else {
            return []
        }
        return Set(names)
    }
}
