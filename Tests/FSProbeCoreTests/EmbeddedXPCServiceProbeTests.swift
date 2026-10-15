import XCTest
@testable import FSProbeCore

/// Tests for the embedded-XPC-service probe.
///
/// The service walk is Darwin-only, so on the verification host it finds nothing.
/// What these tests establish is the discipline that matters most here: reaching
/// an embedded helper and getting an answer from it is NOT, by itself, a finding,
/// and the load control is always present so a successful load is interpretable.
final class EmbeddedXPCServiceProbeTests: XCTestCase {

    func testOnlyARealReplyIsEverFlagged() {
        // Every other outcome must stay unfinding. In particular `found` -- the
        // service bundle exists and its framework loaded -- is reconnaissance, and
        // reporting it as a violation would produce a false finding for every
        // framework on the device.
        let cases: [(EmbeddedXPCServiceProbe.Outcome, Bool)] = [
            (.replied, true), (.refused, false),
            (.found, false), (.noService, false),
            (.loadFailed, false), (.notFound, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = EmbeddedXPCServiceProbe.Service(
                id: "case", framework: "F.framework", mechanism: "m",
                operation: "o", arguments: "a", expected: "e",
                expectedDenied: true, outcome: outcome,
                observed: "obs", replyShape: nil, interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTheLoadControlIsAlwaysPresent() {
        // A successful load of a real framework means nothing until a load of a
        // path that cannot exist has been seen to fail. Without the control, a
        // load failure on a real framework would be ambiguous.
        let result = EmbeddedXPCServiceProbe.probe()
        XCTAssertTrue(result.services.contains { $0.id == "embedded-xpc-load-control" },
                      "the load control must always be attempted")
    }

    func testTheLoadControlDoesNotExpectDenial() {
        // The control is a path that does not exist, so its expected outcome is
        // that it is not found -- not that it is denied. A control that expected
        // denial could be "satisfied" by a refusal, which is not the calibration
        // the control is for.
        let result = EmbeddedXPCServiceProbe.probe()
        if let control = result.services.first(where: { $0.id == "embedded-xpc-load-control" }) {
            XCTAssertFalse(control.expectedDenied,
                           "the nonexistent-path control must not expect denial")
        }
    }

    func testViolationListMatchesFlags() {
        let result = EmbeddedXPCServiceProbe.probe()
        let flagged = Set(result.services.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testFrameworkRootWalksBackOutOfTheServiceDirectory() {
        // .../Foo.framework/XPCServices/Bar.xpc -> .../Foo.framework. Getting this
        // wrong would dlopen a path that cannot exist for every service, and every
        // result would then read as "load failed" rather than as a service outcome.
        let root = EmbeddedXPCServiceProbe.frameworkRootPathForTesting(
            "/System/Library/Frameworks/Foo.framework/XPCServices/Bar.xpc"
        )
        XCTAssertEqual(root, "/System/Library/Frameworks/Foo.framework")
    }

    func testReportRendersTheEmbeddedSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            embeddedXPCServices: EmbeddedXPCServiceProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("XPC services shipped inside system frameworks"),
                      "the report must render the embedded-service section")
        XCTAssertTrue(text.contains("service bundles found"),
                      "the counts must be reported, not implied")
    }
}
