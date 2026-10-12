import XCTest
@testable import FSProbeCore

/// Tests for the APFS-clone boundary experiment.
///
/// The experiment asks whether cloning a protected file into the container (and
/// vice versa) is authorized. On the verification host there is no iOS sandbox,
/// so these tests assert the experiment set is complete, that each experiment
/// states its expectation, that a permitted result where a denial was expected is
/// flagged, and that nothing is left behind. Whether iOS confines a clone is a
/// device result.
final class CloneProbeTests: XCTestCase {

    var container: String!

    override func setUpWithError() throws {
        container = NSTemporaryDirectory() + "fsprobe-clone-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: container + "/Documents", withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let container = container { try? FileManager.default.removeItem(atPath: container) }
    }

    func testProbeReportsItsPreconditionHonestly() throws {
        let result = CloneProbe.run(containerPath: container)
        // Either a candidate source was found and both directions ran, or the
        // probe says the precondition failed. It must not report a denial it did
        // not observe.
        XCTAssertFalse(result.candidateSources.isEmpty,
                       "the probe must record which candidates it tried")
        XCTAssertFalse(result.experiments.isEmpty, "the probe must produce at least one experiment")
        for experiment in result.experiments {
            XCTAssertFalse(experiment.mechanism.isEmpty)
            XCTAssertFalse(experiment.expected.isEmpty)
            XCTAssertFalse(experiment.interpretation.isEmpty)
            if experiment.outcome == .denied {
                XCTAssertFalse(experiment.errnoName?.isEmpty ?? true,
                               "\(experiment.id) denied without an errno")
            }
        }
    }

    func testViolationsAreFlaggedAndOnlyWhenUnexpected() throws {
        let result = CloneProbe.run(containerPath: container)
        for experiment in result.experiments {
            if experiment.isBoundaryViolation {
                XCTAssertTrue(experiment.expectedDenied,
                              "\(experiment.id) flagged but a success was expected there")
                XCTAssertEqual(experiment.outcome, .permitted)
            }
        }
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the per-experiment flags")
    }

    func testProbeLeavesNoArtefactsBehind() throws {
        _ = CloneProbe.run(containerPath: container)
        let documents = container + "/Documents"
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: documents)) ?? []
        XCTAssertTrue(leftovers.isEmpty, "the clone probe left files behind: \(leftovers)")
    }

    func testProbeIsSafeToRunTwice() throws {
        // A second run must behave identically: no state accumulates.
        let first = CloneProbe.run(containerPath: container)
        let second = CloneProbe.run(containerPath: container)
        XCTAssertEqual(first.experiments.map { $0.id }, second.experiments.map { $0.id })
        XCTAssertEqual(first.experiments.map { $0.outcome }, second.experiments.map { $0.outcome })
    }

    func testReportRendersTheCloneResults() throws {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            clone: CloneProbe.run(containerPath: container)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("APFS clone"), "the report must mention the experiment")
    }
}
