import XCTest
@testable import FSProbeCore

/// Tests for the XPC reply probe.
///
/// XPC is Darwin-only, so the verification host withholds every probe. What these
/// tests establish is that silence is the expected outcome and never a finding,
/// and that a reply is only a finding from a service the lookup reached.
final class XPCReplyProbeTests: XCTestCase {

    func testOnlyAReplyFromAReachableServiceIsAViolation() {
        // Silence is what "reachable but unusable" looks like, and it is the
        // expected outcome. A reply from a service the lookup REFUSED is not a
        // violation of this boundary either -- it would be a different and
        // stranger result, but not this one.
        let cases: [(reply: XPCReplyProbe.Reply, lookup: String, shouldFlag: Bool)] = [
            (.replied, "reachable", true),
            (.replied, "refused", false),
            (.silent, "reachable", false),
            (.silent, "refused", false),
            (.interrupted, "reachable", false),
            (.notCreated, "reachable", false),
            (.notAttempted, "reachable", false),
        ]
        for (reply, lookup, shouldFlag) in cases {
            let item = XPCReplyProbe.Probe(
                serviceName: "com.example.test", rationale: "r",
                lookupOutcome: lookup, reply: reply,
                responseMilliseconds: nil, interruptionReason: nil, replyShape: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(reply)/\(lookup) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTargetsLeadWithANegativeControl() {
        // The control calibrates what rejection looks like as distinct from
        // silence. Without it, silence is uninterpretable.
        let list = XPCReplyProbe.targets
        XCTAssertFalse(list.isEmpty)
        XCTAssertTrue(list[0].name.contains("nonexistent"),
                      "the first target must be the negative control")
        XCTAssertEqual(list[0].lookup, "refused")
        for entry in list {
            XCTAssertFalse(entry.rationale.isEmpty, "\(entry.name) has no rationale")
            XCTAssertFalse(entry.lookup.isEmpty,
                           "\(entry.name) has no recorded lookup outcome")
        }
    }

    func testProbeNeverFabricatesAViolation() {
        let result = XPCReplyProbe.probe(timeout: 0.2)
        for item in result.probes {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.reply, .replied)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.reply == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        let flagged = Set(result.probes.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheReplySection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            xpcReplies: XPCReplyProbe.probe(timeout: 0.2)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Do the reachable services actually answer"),
                      "the report must render the reply section")
        XCTAssertTrue(text.contains("nonexistent.control"),
                      "the negative control must be identifiable")
    }
}
