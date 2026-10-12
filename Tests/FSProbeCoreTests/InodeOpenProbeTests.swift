import XCTest
@testable import FSProbeCore

/// Tests for the open-by-inode experiment.
///
/// The experiment resolves `openbyid_np` at runtime and opens vnodes by inode,
/// with no path traversal. Whether the symbol is present depends on the host:
/// it is present on Darwin (macOS runners exercise the real experiment) and
/// absent on the Android verification host. These tests cover both cases and
/// assert only what holds on either.
final class InodeOpenProbeTests: XCTestCase {

    func testProbeIsSelfConsistent() {
        let result = InodeOpenProbe.probe(paths: InodeOpenProbe.defaultTargets())

        if result.symbolAvailable {
            // Every target must have been attempted, whether or not it could be
            // stat'd: on a macOS host the iOS paths simply do not exist.
            XCTAssertEqual(result.attempts.count, InodeOpenProbe.defaultTargets().count)
            for attempt in result.attempts {
                // An attempt without identifiers must say so rather than
                // reporting a denial it did not observe.
                if !attempt.identifiersAvailable {
                    XCTAssertNil(attempt.evtonlyErrnoName)
                    XCTAssertNil(attempt.readonlyErrnoName)
                    XCTAssertNil(attempt.directoryErrnoName)
                    XCTAssertNil(attempt.pathOpenErrnoName)
                    XCTAssertNil(attempt.pathEnumerationErrnoName)
                }
            }
        } else {
            // No symbol: nothing was attempted and nothing is claimed.
            XCTAssertTrue(result.attempts.isEmpty)
            XCTAssertTrue(result.violations.isEmpty)
        }

        // Violations must always be a subset of the attempts.
        let attemptPaths = Set(result.attempts.map { $0.path })
        for violation in result.violations {
            XCTAssertTrue(attemptPaths.contains(violation.path))
        }
    }

    func testViolationDetectionRequiresBothHalves() {
        // A permitted inode open is only a violation when the path-based open was
        // refused. Constructing the two cases directly proves the logic.
        let permittedAndPathDenied = InodeOpenProbe.Attempt(
            path: "/x", deviceID: 1, inode: 2, identifiersAvailable: true,
            evtonlyErrnoName: nil, readonlyErrnoName: nil, directoryErrnoName: "EPERM",
            enumeratedEntries: nil, sampleEntryNames: nil,
            pathOpenErrnoName: "EPERM", pathEnumerationErrnoName: "EPERM"
        )
        XCTAssertTrue(permittedAndPathDenied.inodeOpenSucceededWherePathFailed)

        // Permitted by inode AND permitted by path: normal, not a violation.
        let permittedBoth = InodeOpenProbe.Attempt(
            path: "/x", deviceID: 1, inode: 2, identifiersAvailable: true,
            evtonlyErrnoName: nil, readonlyErrnoName: nil, directoryErrnoName: nil,
            enumeratedEntries: 3, sampleEntryNames: nil,
            pathOpenErrnoName: nil, pathEnumerationErrnoName: nil
        )
        XCTAssertFalse(permittedBoth.inodeOpenSucceededWherePathFailed)

        // Denied by inode: not a violation even though the path was also denied.
        let deniedBoth = InodeOpenProbe.Attempt(
            path: "/x", deviceID: 1, inode: 2, identifiersAvailable: true,
            evtonlyErrnoName: "EPERM", readonlyErrnoName: "EPERM", directoryErrnoName: "EPERM",
            enumeratedEntries: nil, sampleEntryNames: nil,
            pathOpenErrnoName: "EPERM", pathEnumerationErrnoName: "EPERM"
        )
        XCTAssertFalse(deniedBoth.inodeOpenSucceededWherePathFailed)
    }

    func testEnumerationByInodeRequiresThePathToHaveBeenRefused() {
        let enumerated = InodeOpenProbe.Attempt(
            path: "/x", deviceID: 1, inode: 2, identifiersAvailable: true,
            evtonlyErrnoName: nil, readonlyErrnoName: nil, directoryErrnoName: nil,
            enumeratedEntries: 7, sampleEntryNames: ["a", "b"],
            pathOpenErrnoName: nil, pathEnumerationErrnoName: "EPERM"
        )
        XCTAssertTrue(enumerated.enumeratedByInode)

        // Same enumeration but the path was also enumerable: not a finding.
        let notAFinding = InodeOpenProbe.Attempt(
            path: "/x", deviceID: 1, inode: 2, identifiersAvailable: true,
            evtonlyErrnoName: nil, readonlyErrnoName: nil, directoryErrnoName: nil,
            enumeratedEntries: 7, sampleEntryNames: ["a", "b"],
            pathOpenErrnoName: nil, pathEnumerationErrnoName: nil
        )
        XCTAssertFalse(notAFinding.enumeratedByInode)
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

    func testReportRendersForEitherHostCase() throws {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            inodeOpen: InodeOpenProbe.probe(paths: ["/var/mobile"])
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Open-by-inode"), "the report must mention the experiment")
        // Whatever the host, the report must state an outcome rather than
        // presenting an empty section as a result.
        XCTAssertTrue(
            text.contains("symbol available: false")
                || text.contains("by inode:")
                || text.contains("no inode-based open"),
            "the report must state an outcome"
        )
    }
}
