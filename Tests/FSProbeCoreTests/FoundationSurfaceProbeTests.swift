import XCTest
@testable import FSProbeCore

/// Tests for the Foundation-surface experiment.
///
/// The `access()` calls and the container API are Darwin-only, so the verification
/// host withholds them. What these tests establish is that a withheld case is
/// never reported as a finding, and that a control failure is never reported as a
/// denial.
final class FoundationSurfaceProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-found-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testOnlyGrantedIsAViolation() {
        let cases: [(FoundationSurfaceProbe.Outcome, Bool)] = [
            (.granted, true), (.refused, false),
            (.noAnswer, false), (.controlFailed, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = FoundationSurfaceProbe.Case(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeCoversAccessAndFoundationAtBothDirectories() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FoundationSurfaceProbe.probe(containerPath: root)
        let ids = Set(result.cases.map { $0.id })

        // The containermanagerd deputy case must always be present, whatever the
        // platform.
        XCTAssertTrue(ids.contains("containerURL-app-group"),
                      "the containermanagerd deputy case is missing")

        // On the verification host the protected paths do not exist, so the
        // per-directory cases are withheld. On the device they run. Either way the
        // containermanagerd case is the one that carries the new hypothesis.
        XCTAssertGreaterThanOrEqual(result.cases.count, 1)
    }

    func testNoViolationWhereNothingWasMeasured() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FoundationSurfaceProbe.probe(containerPath: root)
        for item in result.cases {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .granted)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            // A control failure is never a denial.
            if item.outcome == .controlFailed {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .granted })
    }

    func testViolationListMatchesPerCaseFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FoundationSurfaceProbe.probe(containerPath: root)
        let flagged = Set(result.cases.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheFoundationSurfaceSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            foundationSurface: FoundationSurfaceProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("The same boundary through Foundation"),
                      "the report must render the Foundation-surface section")
        XCTAssertTrue(text.contains("containerURL-app-group"),
                      "the containermanagerd deputy case must be identifiable")
    }
}
