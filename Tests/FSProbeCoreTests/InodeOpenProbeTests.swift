import XCTest
@testable import FSProbeCore

/// Tests for the open-by-inode experiment.
///
/// The experiment itself targets iOS: it resolves `openbyid_np` at runtime and
/// opens vnodes by inode, with no path traversal. On the verification host the
/// symbol is absent, so what is tested here is that the probe reports that
/// honestly rather than crashing or fabricating a result.
final class InodeOpenProbeTests: XCTestCase {

    func testProbeReportsMissingSymbolHonestly() {
        let result = InodeOpenProbe.probe(paths: InodeOpenProbe.defaultTargets())
        if !result.symbolAvailable {
            // The host has no openbyid_np: no attempts, no violations, and the
            // report must say so rather than implying a denial.
            XCTAssertTrue(result.attempts.isEmpty)
            XCTAssertTrue(result.violations.isEmpty)
        } else {
            // If the symbol is present, every default target must have been
            // attempted and must carry identifiers.
            XCTAssertEqual(result.attempts.count, InodeOpenProbe.defaultTargets().count)
            for attempt in result.attempts {
                XCTAssertTrue(attempt.identifiersAvailable,
                              "\(attempt.path) should be stat-able on this host")
            }
        }
    }

    func testDefaultTargetsAreTheVarSetTheDeviceEstablished() {
        let targets = InodeOpenProbe.defaultTargets()
        // These are the paths the device run showed as lstat-able but not
        // openable, which is what makes them valid test subjects.
        for expected in ["/var", "/private/var", "/var/mobile", "/var/mobile/Library",
                         "/var/mobile/Containers", "/var/tmp"] {
            XCTAssertTrue(targets.contains(expected), "missing \(expected)")
        }
        XCTAssertEqual(Set(targets).count, targets.count, "duplicate targets")
    }

    func testReportRendersWhenTheSymbolIsMissing() throws {
        // The report must render without a matrix containing the probe.
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            inodeOpen: InodeOpenProbe.probe(paths: ["/var/mobile"])
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Open-by-inode"), "the report must mention the experiment")
        XCTAssertTrue(text.contains("/var/mobile"))
    }
}
