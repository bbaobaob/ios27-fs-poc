import XCTest
@testable import FSProbeCore

/// Tests for the user-granted-scope experiments.
///
/// The probe takes a path the user granted and asks whether the grant is confined
/// to it. On the verification host there is no iOS document picker, so these tests
/// run it against a synthetic directory and assert the experiment set is complete,
/// that each experiment states its expectation, and that a success where a denial
/// was expected is flagged. Whether iOS confines a real grant is a device result.
final class SecurityScopeProbeTests: XCTestCase {

    var granted: String!

    override func setUpWithError() throws {
        granted = NSTemporaryDirectory() + "fsprobe-scope-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: granted, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let granted = granted { try? FileManager.default.removeItem(atPath: granted) }
    }

    func testProbeRunsTheFullScopeBattery() throws {
        let result = SecurityScopeProbe.probe(grantedPath: granted)
        let ids = Set(result.experiments.map { $0.id })
        for expected in ["granted-path", "granted-parent", "granted-dotdot-escape",
                         "granted-write"] {
            XCTAssertTrue(ids.contains(expected), "missing \(expected) in \(ids.sorted())")
        }
        // The symlink case is present either way: run, or reported as not run.
        XCTAssertTrue(ids.contains("granted-symlink-escape"))
    }

    func testEveryExperimentStatesItsExpectation() throws {
        let result = SecurityScopeProbe.probe(grantedPath: granted)
        for experiment in result.experiments {
            XCTAssertFalse(experiment.mechanism.isEmpty, "\(experiment.id) has no mechanism")
            XCTAssertFalse(experiment.expected.isEmpty, "\(experiment.id) has no expectation")
            XCTAssertFalse(experiment.interpretation.isEmpty, "\(experiment.id) has no interpretation")
            if experiment.outcome == .denied {
                XCTAssertFalse(experiment.errnoName?.isEmpty ?? true,
                               "\(experiment.id) denied without an errno")
            }
        }
    }

    func testTheGrantedPathControlSucceeds() throws {
        // The control must be permitted, or nothing else is interpretable.
        let result = SecurityScopeProbe.probe(grantedPath: granted)
        let control = result.experiments.first { $0.id == "granted-path" }
        XCTAssertEqual(control?.outcome, .permitted)
        XCTAssertEqual(control?.expectedDenied, false)
        XCTAssertFalse(control?.isBoundaryViolation ?? true,
                       "the control must never be flagged as a violation")
    }

    func testViolationsAreFlaggedAndOnlyWhenUnexpected() throws {
        let result = SecurityScopeProbe.probe(grantedPath: granted)
        for experiment in result.experiments {
            if experiment.isBoundaryViolation {
                XCTAssertTrue(experiment.expectedDenied,
                              "\(experiment.id) flagged but a success was expected there")
                XCTAssertEqual(experiment.outcome, .permitted)
            }
        }
        // The violation list must agree with the per-experiment flags.
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed)
    }

    func testAfterReleaseProbeAsksWhetherAccessStops() throws {
        let result = SecurityScopeProbe.probeAfterRelease(grantedPath: granted)
        XCTAssertEqual(result.scopeActive, false)
        XCTAssertEqual(result.experiments.count, 1)
        XCTAssertEqual(result.experiments[0].id, "after-release")
        XCTAssertTrue(result.experiments[0].expectedDenied)
    }

    func testProbeLeavesNothingBehind() throws {
        _ = SecurityScopeProbe.probe(grantedPath: granted)
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: granted)) ?? []
        XCTAssertTrue(leftovers.isEmpty, "probe left files behind: \(leftovers)")
    }

    func testReportRendersTheScopeResults() throws {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            securityScope: SecurityScopeProbe.probe(grantedPath: granted),
            securityScopeAfterRelease: SecurityScopeProbe.probeAfterRelease(grantedPath: granted)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("User-granted scope"))
        XCTAssertTrue(text.contains("while the scope is held"))
        XCTAssertTrue(text.contains("after the scope was released"))
        XCTAssertTrue(text.contains(granted))
    }
}
