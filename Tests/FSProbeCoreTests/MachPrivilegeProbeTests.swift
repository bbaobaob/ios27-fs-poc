import XCTest
@testable import FSProbeCore

/// Tests for the Mach privilege ladder.
///
/// The calls are Darwin-only, so the verification host withholds every rung. What
/// these tests establish is that a control rung (self-targeting, legitimate) is
/// never reported as a finding, and that a withheld rung is never a violation.
final class MachPrivilegeProbeTests: XCTestCase {

    func testOnlyPermittedWhereDenialWasExpectedIsAViolation() {
        let cases: [(MachPrivilegeProbe.Outcome, Bool)] = [
            (.permitted, true), (.denied, false),
            (.prerequisiteFailed, false), (.controlFailed, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let rung = MachPrivilegeProbe.Rung(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                returnValue: nil, errorName: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(rung.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeCoversTheLadderWithControlsFirst() {
        let result = MachPrivilegeProbe.probe()
        let ids = Set(result.rungs.map { $0.id })

        XCTAssertTrue(ids.contains("task_get_special_port-host"),
                      "the host-port rung is missing")
        XCTAssertTrue(ids.contains("task_threads-self"),
                      "the self-threads control rung is missing")
        XCTAssertTrue(ids.contains("task_info-self"),
                      "the self-task-info control rung is missing")
    }

    func testTheControlRungsAreNeverFindings() {
        // task_threads and task_info on SELF are legitimate for any app. They
        // carry expectedDenied: false precisely so that proving the API works is
        // never mistaken for proving a boundary was crossed.
        let result = MachPrivilegeProbe.probe()
        for rung in result.rungs where rung.id.hasSuffix("-self") {
            XCTAssertFalse(rung.isBoundaryViolation,
                           "\(rung.id) is a control and must never be a finding")
        }
    }

    func testNoViolationWhereNothingWasMeasured() {
        let result = MachPrivilegeProbe.probe()
        for rung in result.rungs {
            if rung.isBoundaryViolation {
                XCTAssertEqual(rung.outcome, .permitted)
                XCTAssertFalse(rung.interpretation.isEmpty)
            }
            if rung.outcome == .symbolUnavailable || rung.outcome == .notAttempted {
                XCTAssertFalse(rung.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testViolationListMatchesPerRungFlags() {
        let result = MachPrivilegeProbe.probe()
        let flagged = Set(result.rungs.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheMachPrivilegeSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            machPrivilege: MachPrivilegeProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("The Mach privilege ladder"),
                      "the report must render the Mach-privilege section")
        XCTAssertTrue(text.contains("task_get_special_port-host"),
                      "the host-port rung must be identifiable")
    }
}
