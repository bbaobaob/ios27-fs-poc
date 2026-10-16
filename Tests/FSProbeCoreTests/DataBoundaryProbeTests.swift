import XCTest
@testable import FSProbeCore

/// Tests for the keychain-isolation and IOKit-census probes.
///
/// Both are Darwin-only, so on the verification host they report unattempted.
/// What these tests pin is the discipline each probe depends on: the keychain
/// probe must never call a foreign item a violation without naming the group,
/// and the IOKit census must never call visibility a finding at all.
final class DataBoundaryProbeTests: XCTestCase {

    // MARK: - KeychainIsolationProbe

    func testOnlyForeignItemsAreViolations() {
        let cases: [(KeychainIsolationProbe.Outcome, Bool)] = [
            (.foreignItems, true), (.isolated, false),
            (.denied, false), (.notFound, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = KeychainIsolationProbe.Query(
                id: "case", operation: "o", arguments: "a", expected: "e",
                expectedDenied: true, outcome: outcome,
                statusName: nil, matchCount: nil, foreignMatchCount: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTheControlLeadsAndDoesNotExpectDenial() {
        // A service that cannot exist must answer not-found. That is what
        // makes an empty broad query meaningful: the query ran and matched
        // nothing, rather than the mechanism being absent.
        let result = KeychainIsolationProbe.probe()
        XCTAssertFalse(result.queries.isEmpty)
        let control = result.queries.first
        XCTAssertEqual(control?.id, "keychain-nonexistent-control",
                       "the first query must be the nonexistent-service control")
        XCTAssertFalse(control?.expectedDenied ?? true,
                       "the control must not expect denial")
    }

    func testViolationListMatchesFlags() {
        let result = KeychainIsolationProbe.probe()
        let flagged = Set(result.queries.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    // MARK: - IOKitCensusProbe

    func testVisibilityIsNeverAFinding() {
        // Every outcome -- including a populated enumeration -- must stay a
        // non-finding. A census that reported visibility as a violation would
        // produce a false finding for every kernel service at once, which is
        // the same failure mode the Mach-service census rule exists to prevent.
        let cases: [IOKitCensusProbe.Outcome] = [
            .enumerated, .empty, .refused, .symbolUnavailable, .notAttempted
        ]
        for outcome in cases {
            let entry = IOKitCensusProbe.Entry(
                id: "case", serviceClass: "IOService", operation: "o",
                outcome: outcome, matchCount: nil, exhausted: nil,
                sampleNames: [], errorName: nil, observed: "obs",
                interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testTheControlIsAlwaysPresent() {
        // A populated root iterator means nothing until a class that cannot
        // exist has been seen to match nothing.
        let result = IOKitCensusProbe.probe()
        XCTAssertTrue(result.entries.contains { $0.id == "iokit-control" },
                      "the nonexistent-class control must always be present")
    }

    func testViolationsAreAlwaysEmpty() {
        let result = IOKitCensusProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    func testOnlyOutsideItemsAreViolations() {
        // The metadata index either keeps names inside the container or it
        // does not. Anything else -- including a control that could not run
        // -- is never a violation, because a violation here claims a leak.
        let cases: [(SpotlightEnumerationProbe.Outcome, Bool)] = [
            (.outsideItems, true), (.isolated, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = SpotlightEnumerationProbe.Query(
                id: "case", operation: "o", arguments: "a", expected: "e",
                expectedDenied: true, outcome: outcome,
                matchCount: nil, outsideCount: nil, outsidePaths: [],
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testSpotlightControlLeadsAndViolationListMatches() {
        // Tmp as the container: the sentinel round-trips through the real
        // mechanism wherever Spotlight exists, and reports unattempted where
        // it does not. Either way the control is first and the violation
        // list matches the flags.
        let dir = NSTemporaryDirectory()
        let result = SpotlightEnumerationProbe.probe(containerPath: dir)
        XCTAssertFalse(result.queries.isEmpty)
        XCTAssertEqual(result.queries.first?.id, "spotlight-control")
        let flagged = Set(result.queries.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersBothSections() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            keychainIsolation: KeychainIsolationProbe.probe(),
            ioKitCensus: IOKitCensusProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Does the keychain isolate apps by access group?"),
                      "the report must render the keychain section")
        XCTAssertTrue(text.contains("IORegistry census"),
                      "the report must render the IOKit section")
        let matrix2 = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            spotlightEnumeration: SpotlightEnumerationProbe.probe(
                containerPath: NSTemporaryDirectory()
            )
        )
        let text2 = ReportExporter.text(matrix2, targets: [])
        XCTAssertTrue(text2.contains("Does the metadata index leak names outside the container?"),
                      "the report must render the Spotlight section")
    }
}
