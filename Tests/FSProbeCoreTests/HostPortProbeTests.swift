import XCTest
@testable import FSProbeCore

/// Tests for the host-port usability probe.
///
/// The Mach calls are Darwin-only, so the verification host withholds every rung.
/// What these tests establish is the distinction this module exists to make: a
/// policy refusal and a validity refusal mean different things, and only one of
/// them means the port is real.
final class HostPortProbeTests: XCTestCase {

    func testOnlyPermittedIsAViolation() {
        let cases: [(HostPortProbe.Outcome, Bool)] = [
            (.permitted, true), (.deniedByPolicy, false),
            (.deniedByValidity, false), (.noHostPort, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let rung = HostPortProbe.Rung(
                id: "case", mechanism: "m", operation: "o",
                expected: "e", expectedDenied: true, outcome: outcome,
                returnValue: nil, errorName: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(rung.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testAPolicyRefusalAndAValidityRefusalAreDifferent() {
        // This is the distinction the module exists to make. A policy error means
        // the kernel recognized the port and applied a rule -- the port is real. A
        // validity error means the port is not what it claims to be.
        let policy = HostPortProbe.Rung(
            id: "case", mechanism: "m", operation: "o",
            expected: "e", expectedDenied: true, outcome: .deniedByPolicy,
            returnValue: nil, errorName: "KERN_PROTECTION_FAILURE",
            observed: "refused", interpretation: "The port is real."
        )
        let validity = HostPortProbe.Rung(
            id: "case", mechanism: "m", operation: "o",
            expected: "e", expectedDenied: true, outcome: .deniedByValidity,
            returnValue: nil, errorName: "KERN_INVALID_HOST",
            observed: "refused", interpretation: "The port grants nothing."
        )
        XCTAssertEqual(policy.outcome, .deniedByPolicy)
        XCTAssertEqual(validity.outcome, .deniedByValidity)
        XCTAssertNotEqual(policy.outcome, validity.outcome)
        // Neither is a violation on its own -- both are refusals.
        XCTAssertFalse(policy.isBoundaryViolation)
        XCTAssertFalse(validity.isBoundaryViolation)
    }

    func testProbeReportsWhetherTheHostPortWasObtained() {
        let result = HostPortProbe.probe()
        // Whatever the platform, the result must say whether a host port was
        // obtained, because that is what makes the earlier violation
        // interpretable.
        XCTAssertFalse(result.rungs.isEmpty)
        if !result.hostPortObtained {
            XCTAssertTrue(result.violations.isEmpty,
                          "no violation may be claimed without a host port")
            XCTAssertFalse(result.hostPortIsImpotent,
                           "impotence is only meaningful once a port was obtained")
        }
    }

    func testImpotenceRequiresEveryRungToFailByValidity() {
        // Impotence is the conclusion that closes the question. It must not be
        // reachable from a mix of policy and validity refusals, because a single
        // policy refusal means the port is real.
        let result = HostPortProbe.probe()
        if result.hostPortIsImpotent {
            XCTAssertTrue(result.hostPortObtained)
            let attempted = result.rungs.filter { $0.outcome != .notAttempted }
            XCTAssertFalse(attempted.isEmpty)
            XCTAssertTrue(attempted.allSatisfy { $0.outcome == .deniedByValidity },
                          "impotence requires every attempted rung to fail by validity")
        }
    }

    func testViolationListMatchesPerRungFlags() {
        let result = HostPortProbe.probe()
        let flagged = Set(result.rungs.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheHostPortSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            hostPort: HostPortProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Is an obtainable host port actually usable?"),
                      "the report must render the host-port section")
        XCTAssertTrue(text.contains("host port obtained"),
                      "the host-port state must be reported")
    }
}
