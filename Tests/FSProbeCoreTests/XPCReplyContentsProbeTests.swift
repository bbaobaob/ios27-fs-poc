import XCTest
@testable import FSProbeCore

/// Tests for the reply-contents probe.
///
/// XPC is Darwin-only, so the verification host withholds every probe. What these
/// tests establish is the discipline this module depends on: only key NAMES are
/// recorded, never values, and transport bookkeeping is never a finding.
final class XPCReplyContentsProbeTests: XCTestCase {

    func testOnlyKeysOfTheServiceOwnAreAViolation() {
        // Transport bookkeeping is XPC answering, not the service. An empty reply
        // has nothing to interpret. Only the service's own keys are a finding.
        let cases: [(XPCReplyContentsProbe.Outcome, Bool)] = [
            (.repliedWithKeys, true), (.transportOnly, false),
            (.emptyReply, false), (.interrupted, false),
            (.silent, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = XPCReplyContentsProbe.Reply(
                serviceName: "com.example.test", outcome: outcome,
                keyNames: [], observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeTargetsOnlyTheServicesThatAnswered() {
        // These are the three the reply probe measured as replying to an empty
        // message. Probing a service that never answered would produce silence and
        // tell us nothing new.
        let list = XPCReplyContentsProbe.targets
        XCTAssertEqual(list.count, 3)
        XCTAssertTrue(list.contains("com.apple.cfprefsd.daemon"))
        XCTAssertTrue(list.contains("com.apple.containermanagerd"))
        XCTAssertTrue(list.contains("com.apple.containermanagerd.system"))
    }

    func testTransportKeysAreRecognised() {
        // A reply carrying only these is the transport, not the service. If this
        // ever regressed, every transport reply would be reported as a finding.
        let list = XPCReplyContentsProbe.transportKeys
        XCTAssertTrue(list.contains("XPCErrorDescription"))
        XCTAssertTrue(list.contains("XPCErrorDomain"))
        XCTAssertTrue(list.contains("XPCErrorCode"))
    }

    func testProbeNeverFabricatesAViolation() {
        let result = XPCReplyContentsProbe.probe(timeout: 0.2)
        for item in result.replies {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .repliedWithKeys)
                XCTAssertFalse(item.keyNames.isEmpty,
                               "a finding must name the keys that produced it")
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        let flagged = Set(result.replies.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheReplyContentsSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            xpcReplyContents: XPCReplyContentsProbe.probe(timeout: 0.2)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("What do the services that answer actually send back?"),
                      "the report must render the reply-contents section")
        XCTAssertTrue(text.contains("cfprefsd.daemon"),
                      "a target service must be identifiable")
    }
}
