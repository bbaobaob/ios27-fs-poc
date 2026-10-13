import XCTest
@testable import FSProbeCore

/// Tests for the IPC surface probe.
///
/// The CoreFoundation and Darwin-notification APIs are Darwin-only, so the
/// verification host withholds every mechanism. What these tests establish is
/// that a withheld mechanism is never a violation, and that Darwin notifications
/// are explicitly not treated as a boundary.
final class IPCSurfaceProbeTests: XCTestCase {

    func testOnlyReachableWhereRefusalWasExpectedIsAViolation() {
        let cases: [(IPCSurfaceProbe.Outcome, Bool)] = [
            (.reachable, true), (.refused, false),
            (.unavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = IPCSurfaceProbe.Mechanism(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testPortNamesLeadWithANegativeControl() {
        let list = IPCSurfaceProbe.portNames
        XCTAssertFalse(list.isEmpty)
        XCTAssertTrue(list[0].name.contains("nonexistent"),
                      "the first port name must be the negative control")
        XCTAssertTrue(list[0].refused)
        // The names the XPC path REFUSED are the ones that would make a third
        // bypass visible, so at least one must be present.
        XCTAssertTrue(list.contains { $0.refused && !$0.name.contains("nonexistent") },
                      "the list must include a name the other lookup paths refused")
        for entry in list {
            XCTAssertFalse(entry.rationale.isEmpty, "\(entry.name) has no rationale")
        }
    }

    func testProbeNeverFabricatesAViolation() {
        let result = IPCSurfaceProbe.probe()
        for item in result.mechanisms {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .reachable)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .unavailable || item.outcome == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        let flagged = Set(result.mechanisms.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testDarwinNotificationsAreNotABoundary() {
        // Darwin notifications carry no payload and grant no capability. They are
        // recorded as reachable so "IPC was tested" means something specific, and
        // they must never be reported as a crossing.
        let result = IPCSurfaceProbe.probe()
        let notify = result.mechanisms.first { $0.id == "darwin-notification" }
        XCTAssertNotNil(notify)
        XCTAssertFalse(notify?.isBoundaryViolation ?? true,
                       "Darwin notifications are not a security boundary")
    }

    func testReportRendersTheIPCSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            ipcSurface: IPCSurfaceProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("IPC surface reachable from an ordinary app"),
                      "the report must render the IPC section")
        XCTAssertTrue(text.contains("darwin-notification"),
                      "the notification case must be identifiable")
    }
}
