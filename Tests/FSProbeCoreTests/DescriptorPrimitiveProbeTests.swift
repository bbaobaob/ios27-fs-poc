import XCTest
@testable import FSProbeCore

/// Tests for the descriptor-primitive experiment.
///
/// The descriptor calls are Darwin-only, so the verification host short-circuits
/// every case. What these tests establish is the property the experiment rests
/// on: a step whose prerequisite failed is never reported as a denial, and a
/// step that was never attempted is never reported as a violation.
final class DescriptorPrimitiveProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-desc-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testOnlyPermittedIsAViolation() {
        // The four non-permitted outcomes all mean "nothing was measured", for
        // different reasons. None may be dressed up as a finding.
        let cases: [(DescriptorPrimitiveProbe.Outcome, Bool)] = [
            (.permitted, true), (.denied, false),
            (.prerequisiteFailed, false), (.controlFailed, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let step = DescriptorPrimitiveProbe.Step(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, errnoNumber: nil, entryCount: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(step.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeCoversTheGateAndThreeDescriptorCalls() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = DescriptorPrimitiveProbe.probe(containerPath: root)

        // The O_EVTONLY gate plus three descriptor calls, at two directories --
        // unless the gate's control failed, in which case the descriptor calls
        // report prerequisiteFailed instead. Either way the coverage is present.
        XCTAssertEqual(result.steps.count, 8, "expected 2 directories x 4 steps")
        let ids = Set(result.steps.map { $0.id })
        for directory in ["/var/mobile/Library", "/var/mobile/Media"] {
            XCTAssertTrue(ids.contains("open-evtonly-\(directory)"),
                          "the O_EVTONLY gate is missing at \(directory)")
            XCTAssertTrue(ids.contains("getdirentriesattr-fd-\(directory)"),
                          "the enumeration step is missing at \(directory)")
        }
    }

    func testNoViolationIsClaimedWhereNothingWasMeasured() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = DescriptorPrimitiveProbe.probe(containerPath: root)
        for step in result.steps {
            if step.isBoundaryViolation {
                // A violation must be a measurement, with evidence.
                XCTAssertEqual(step.outcome, .permitted)
                XCTAssertFalse(step.interpretation.isEmpty)
            }
            // A prerequisite failure is never a denial.
            if step.outcome == .prerequisiteFailed {
                XCTAssertNil(step.errnoName,
                             "\(step.id) was never attempted but carries an errno")
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testViolationListMatchesPerStepFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = DescriptorPrimitiveProbe.probe(containerPath: root)
        let flagged = Set(result.steps.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheDescriptorSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            descriptorPrimitives: DescriptorPrimitiveProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Primitives reachable through a descriptor"),
                      "the report must render the descriptor section")
        XCTAssertTrue(text.contains("getdirentriesattr"),
                      "the enumeration step must be identifiable")
    }
}
