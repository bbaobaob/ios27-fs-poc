import XCTest
@testable import FSProbeCore

/// Tests for the remaining-primitives experiment.
///
/// The calls are Darwin-only, so the verification host withholds them. What these
/// tests establish is that a withheld case is never a violation, and that the
/// control case (`hw.model`, a public MIB) is never itself reported as a finding.
final class RemainingPrimitivesProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-remain-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testOnlyAnsweredWhereDenialWasExpectedIsAViolation() {
        let cases: [(RemainingPrimitivesProbe.Outcome, Bool)] = [
            (.answered, true), (.denied, false),
            (.controlFailed, false), (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = RemainingPrimitivesProbe.Case(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                returnValue: nil, errorName: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeCoversAllFivePrimitives() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = RemainingPrimitivesProbe.probe(containerPath: root)
        let ids = Set(result.cases.map { $0.id })
        for id in ["getfsstat-mount-count", "mach-host-port", "sysctl-hw-model",
                   "sysctl-kern-bootargs", "sysctl-sandbox-sentinel",
                   "copyfile-protected-source"] {
            XCTAssertTrue(ids.contains(id), "missing case \(id)")
        }
    }

    func testThePublicControlIsNeverReportedAsAFinding() throws {
        // hw.model is a genuinely public MIB and must succeed. It carries
        // expectedDenied: false, so even an answer is not a violation.
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = RemainingPrimitivesProbe.probe(containerPath: root)
        let control = result.cases.first { $0.id == "sysctl-hw-model" }
        XCTAssertNotNil(control)
        XCTAssertFalse(control?.isBoundaryViolation ?? true,
                       "the public control MIB must never be reported as a violation")
    }

    func testNoViolationWhereNothingWasMeasured() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = RemainingPrimitivesProbe.probe(containerPath: root)
        for item in result.cases {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .answered)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .symbolUnavailable || item.outcome == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .answered })
    }

    func testViolationListMatchesPerCaseFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = RemainingPrimitivesProbe.probe(containerPath: root)
        let flagged = Set(result.cases.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testCopyfileLeavesNothingBehind() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        _ = RemainingPrimitivesProbe.probe(containerPath: root)
        let leftovers = (try? FileManager.default.contentsOfDirectory(
            atPath: root + "/Documents"
        )) ?? []
        XCTAssertTrue(leftovers.isEmpty,
                      "the copyfile case left an artifact: \(leftovers)")
    }

    func testReportRendersTheRemainingPrimitivesSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            remainingPrimitives: RemainingPrimitivesProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Primitives never tried before"),
                      "the report must render the remaining-primitives section")
        XCTAssertTrue(text.contains("mach-host-port"),
                      "the host-port case must be identifiable")
    }
}
