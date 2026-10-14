import XCTest
@testable import FSProbeCore

/// Tests for the mach-service census.
///
/// The enumeration is Darwin-only, so the verification host reports the manifest
/// as unreadable and probes nothing. What these tests establish is that
/// reachability is never reported as a finding, and that a census which could not
/// run says so rather than appearing to have found nothing.
final class MachServiceEnumerationProbeTests: XCTestCase {

    func testReachabilityIsNeverAFinding() {
        // This is the property that matters most for a census. A reachable service
        // is reconnaissance; the finding would be an effect it produces for an
        // unidentified caller. A census that reported reachability as a violation
        // would produce dozens of false findings at once.
        let cases: [(MachServiceEnumerationProbe.Outcome, Bool)] = [
            (.reachable, false), (.refused, false),
            (.manifestUnreadable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = MachServiceEnumerationProbe.Service(
                serviceName: "com.example.test", outcome: outcome,
                errorName: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTheAlreadyTestedSetCoversTheEarlierExperiment() {
        // The census is only useful if it can be compared against what was already
        // known. That comparison is what turns "N services reachable" into "M of
        // them are new", and the new ones are the interesting ones.
        let tested = MachServiceEnumerationProbe.alreadyTested
        XCTAssertTrue(tested.contains("com.apple.cfprefsd.daemon"))
        XCTAssertTrue(tested.contains("com.apple.containermanagerd"))
        XCTAssertTrue(tested.contains("com.apple.LaunchServices"))
    }

    func testACensusThatCouldNotRunSaysSo() {
        // On the verification host the manifest is unreadable, so nothing is
        // probed. The result must record that rather than appearing to have found
        // nothing -- an empty census and an impossible census are different facts.
        let result = MachServiceEnumerationProbe.probe()
        if !result.manifestReadable {
            XCTAssertTrue(result.reachableNames.isEmpty)
            XCTAssertEqual(result.manifestEntryCount, 0)
            XCTAssertFalse(result.services.isEmpty,
                           "a census that could not run must still record the control")
        }
    }

    func testTheControlIsAlwaysPresent() {
        // Whatever happens, the nonexistent-name control must be attempted. It is
        // what makes a refusal interpretable at all.
        let result = MachServiceEnumerationProbe.probe()
        XCTAssertTrue(result.services.contains { $0.serviceName == "com.bbaobaob.fsprobe.nonexistent.control" },
                      "the negative control must always be present")
    }

    func testReportRendersTheCensusSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            machServiceCensus: MachServiceEnumerationProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Mach service census"),
                      "the report must render the census section")
        XCTAssertTrue(text.contains("manifest readable"),
                      "the manifest state must be reported")
    }
}
