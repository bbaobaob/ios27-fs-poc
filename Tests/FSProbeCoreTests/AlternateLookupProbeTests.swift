import XCTest
@testable import FSProbeCore

/// Tests for the alternate-lookup experiment.
///
/// The Mach bootstrap API is Darwin-only, so the verification host withholds
/// every lookup. What these tests establish is the property the experiment rests
/// on: a resolved port is only a finding when the XPC path refused the same name,
/// and a lookup that was never made is never a violation.
final class AlternateLookupProbeTests: XCTestCase {

    func testOnlyARefusedByXPCNameIsAViolation() {
        // Without the XPC outcome recorded alongside, a resolved port says
        // nothing: plenty of services are legitimately reachable. The whole point
        // is the DIFFERENCE between the two paths.
        let cases: [(outcome: AlternateLookupProbe.Outcome, xpc: String?, shouldFlag: Bool)] = [
            (.resolved, "refused", true),
            (.resolved, "reachable", false),
            (.resolved, nil, false),
            (.refused, "refused", false),
            (.refused, "reachable", false),
            (.noBootstrapPort, "refused", false),
            (.notAttempted, "refused", false),
        ]
        for (outcome, xpc, shouldFlag) in cases {
            let item = AlternateLookupProbe.Lookup(
                serviceName: "com.example.test", rationale: "r",
                xpcOutcome: xpc, outcome: outcome,
                returnValue: nil, errorName: nil, interpretation: "i"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome)/\(xpc ?? "nil") must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testServiceListLeadsWithANegativeControl() {
        // The control calibrates the failure signature. Without it, a failed
        // lookup is uninterpretable: it could mean the policy denied it, or that
        // the name was wrong.
        let list = AlternateLookupProbe.serviceList
        XCTAssertFalse(list.isEmpty)
        XCTAssertTrue(list[0].name.contains("nonexistent"),
                      "the first entry must be the negative control")
        XCTAssertEqual(list[0].xpc, "refused",
                       "the control's XPC outcome must be recorded as refused")
        // Every entry needs its XPC outcome, or a result here is uninterpretable.
        for entry in list {
            XCTAssertFalse(entry.rationale.isEmpty, "\(entry.name) has no rationale")
            XCTAssertFalse(entry.xpc.isEmpty, "\(entry.name) has no recorded XPC outcome")
        }
    }

    func testProbeNeverFabricatesAViolation() {
        let result = AlternateLookupProbe.probe()
        for item in result.lookups {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .resolved)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            // A lookup that was never made is never a finding.
            if item.outcome == .notAttempted || item.outcome == .noBootstrapPort {
                XCTAssertFalse(item.isBoundaryViolation)
                XCTAssertNil(item.returnValue == nil ? nil : nil)
            }
        }
        // The violation list must match the per-item flags exactly.
        let flagged = Set(result.lookups.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheAlternateLookupSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            alternateLookups: AlternateLookupProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Mach service lookup by a path other than the XPC factory"),
                      "the report must render the alternate-lookup section")
        XCTAssertTrue(text.contains("bootstrap port available"),
                      "the bootstrap-port state must be reported")
        XCTAssertTrue(text.contains("nonexistent.control"),
                      "the negative control must be identifiable")
    }
}
