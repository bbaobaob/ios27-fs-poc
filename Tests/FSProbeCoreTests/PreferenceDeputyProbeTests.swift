import XCTest
@testable import FSProbeCore

/// Tests for the cfprefsd confused-deputy experiment.
///
/// The experiment's value is the *location* a write lands in, which is only
/// observable on a device where the sandbox governs the container. What these
/// tests establish is that the module cannot express a violation without the
/// discriminating evidence, that it cleans up after itself, and that it does not
/// fabricate a finding when the daemon has merely not flushed yet.
final class PreferenceDeputyProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-prefs-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Library/Preferences", withIntermediateDirectories: true
        )
        return root
    }

    func testProbeRunsBothCasesAndCleansUp() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = PreferenceDeputyProbe.probe(containerPath: root)

        // The control must run first: without it the test case is uninterpretable.
        XCTAssertEqual(result.experiments.first?.id, "prefs-control-own-suite")
        XCTAssertTrue(result.experiments.contains { $0.id == "prefs-foreign-suite" })

        // Every artifact the probe created must be gone afterwards. A leaked
        // preference file would be the probe modifying state it does not own.
        let leftovers = (try? FileManager.default.contentsOfDirectory(
            atPath: root + "/Library/Preferences"
        )) ?? []
        XCTAssertTrue(leftovers.isEmpty, "the probe left files behind: \(leftovers)")
    }

    func testControlGatesTheTestCase() throws {
        // The control's job is to establish that this platform writes preferences
        // into this container. When it does not, the test case must be withheld
        // rather than reported as an escape -- otherwise a platform whose
        // preference storage lives elsewhere produces a false finding.
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = PreferenceDeputyProbe.probe(containerPath: root)
        let control = result.experiments.first { $0.id == "prefs-control-own-suite" }
        let test = result.experiments.first { $0.id == "prefs-foreign-suite" }
        XCTAssertNotNil(control)
        XCTAssertNotNil(test)

        if control?.outcome != .contained {
            XCTAssertEqual(test?.outcome, PreferenceDeputyProbe.Outcome.notApplicable,
                           "an uninterpretable control must withhold the test case")
            XCTAssertFalse(test?.isBoundaryViolation ?? true,
                           "a withheld test case must not be reported as a violation")
            XCTAssertTrue(result.violations.isEmpty,
                          "no violation may be claimed when the control did not pass")
        } else {
            XCTAssertEqual(test?.outcome, PreferenceDeputyProbe.Outcome.contained)
        }
    }

    func testViolationRequiresEscapeWithSuccess() {        // A violation is a write that reported success but did not land in this
        // container. Contained, denied, and not-applicable are never violations.
        let cases: [(PreferenceDeputyProbe.Outcome, Bool)] = [
            (.escaped, true), (.contained, false), (.denied, false), (.notApplicable, false)
        ]
        for (outcome, shouldFlag) in cases {
            let experiment = PreferenceDeputyProbe.Experiment(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errorDomain: nil, errorCode: nil, errorDescription: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(experiment.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }

        // And a violation must be one the policy predicted would be denied.
        let expected = PreferenceDeputyProbe.Experiment(
            id: "case", mechanism: "m", operation: "o", arguments: "a",
            expected: "e", expectedDenied: false, outcome: .escaped,
            errorDomain: nil, errorCode: nil, errorDescription: nil,
            observed: "obs", interpretation: "interp"
        )
        XCTAssertFalse(expected.isBoundaryViolation,
                       "an escape where containment was not expected is not a violation")
    }

    func testControlCaseIsNeverAViolation() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = PreferenceDeputyProbe.probe(containerPath: root)
        let control = result.experiments.first { $0.id == "prefs-control-own-suite" }
        XCTAssertNotNil(control)
        XCTAssertFalse(control?.isBoundaryViolation ?? true,
                       "the control must never be reported as a boundary violation")
    }

    func testViolationListMatchesPerExperimentFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = PreferenceDeputyProbe.probe(containerPath: root)
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the per-experiment flags")
    }

    func testReportRendersTheDeputySection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            preferenceDeputy: PreferenceDeputyProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("cfprefsd as a confused deputy"),
                      "the report must render the deputy section")
        XCTAssertTrue(text.contains("prefs-control-own-suite"),
                      "the control must be identifiable in the report")
    }
}
