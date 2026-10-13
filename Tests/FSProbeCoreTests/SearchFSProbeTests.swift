import XCTest
@testable import FSProbeCore

/// Tests for the searchfs experiment.
///
/// `searchfs` is Darwin-only and `/var/mobile` does not exist on the verification
/// host, so every case is withheld here. What these tests establish is the
/// property the experiment rests on: a search that completes without being
/// refused is a violation even when it reports no matches, and a withheld case
/// is never a violation.
final class SearchFSProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-search-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testACompletedSearchWithNoMatchesIsStillAViolation() {
        // The load-bearing property. A search that runs to completion on a
        // protected volume has crossed the boundary whether or not it found
        // anything: an absence of matches is not an absence of authorization.
        let cases: [(SearchFSProbe.Outcome, Bool)] = [
            (.answered, true), (.noMatches, true),
            (.denied, false), (.controlFailed, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = SearchFSProbe.Search(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, matchCount: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProbeWithholdsWhenTheTargetDoesNotExist() throws {
        // On the verification host /var/mobile is absent, so the experiment is
        // withheld. Reporting an ENOENT as a violation would fabricate a finding
        // from a path that was never there.
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = SearchFSProbe.probe(containerPath: root)
        for item in result.searches {
            if item.outcome == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
                XCTAssertNil(item.errnoName,
                             "\(item.id) was never attempted but carries an errno")
            }
        }
        XCTAssertTrue(result.violations.isEmpty,
                      "no violation may be claimed where nothing was measured")
    }

    func testViolationListMatchesPerSearchFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = SearchFSProbe.probe(containerPath: root)
        let flagged = Set(result.searches.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheSearchFSSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            searchFS: SearchFSProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Volume-wide name search"),
                      "the report must render the searchfs section")
        XCTAssertTrue(text.contains("searchfs-var-mobile"),
                      "the protected-volume case must be identifiable")
    }
}
