import XCTest
@testable import FSProbeCore

/// Tests for the processor-set probe.
///
/// The Mach calls are Darwin-only, so the verification host withholds every rung.
/// What these tests establish is the distinction that matters here: a policy
/// refusal and a validity refusal mean different things, and an empty result is
/// notable in its own right because it means the check did not refuse.
final class ProcessorSetProbeTests: XCTestCase {

    func testOnlyPermittedIsAViolation() {
        let cases: [(ProcessorSetProbe.Outcome, Bool)] = [
            (.permitted, true), (.empty, false),
            (.deniedByPolicy, false), (.deniedByValidity, false),
            (.prerequisiteFailed, false), (.controlFailed, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let rung = ProcessorSetProbe.Rung(
                id: "case", mechanism: "m", operation: "o",
                expected: "e", expectedDenied: true, outcome: outcome,
                returnValue: nil, errorName: nil, taskCount: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(rung.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testPolicyAndValidityRefusalsAreDistinguished() {
        // A policy refusal means the kernel recognized the port and applied a
        // rule. A validity refusal means the port is not what it claims to be.
        // Collapsing them would lose exactly the information that decides whether
        // a host port is real.
        let policy = ProcessorSetProbe.Rung(
            id: "case", mechanism: "m", operation: "o",
            expected: "e", expectedDenied: true, outcome: .deniedByPolicy,
            returnValue: nil, errorName: "KERN_PROTECTION_FAILURE", taskCount: nil,
            observed: "refused", interpretation: "The port is real."
        )
        let validity = ProcessorSetProbe.Rung(
            id: "case", mechanism: "m", operation: "o",
            expected: "e", expectedDenied: true, outcome: .deniedByValidity,
            returnValue: nil, errorName: "KERN_INVALID_HOST", taskCount: nil,
            observed: "refused", interpretation: "The port is not usable."
        )
        XCTAssertNotEqual(policy.outcome, validity.outcome)
    }

    func testProbeRunsTheControlFirstWhereItCanRun() {
        // On a platform with the Mach API the control leads. On the verification
        // host the API is absent, so the whole experiment is withheld with a
        // single symbolUnavailable rung. Asserting the control's position
        // unconditionally would encode one platform's shape as the rule.
        let result = ProcessorSetProbe.probe()
        XCTAssertFalse(result.rungs.isEmpty)

        if MachShim.available {
            XCTAssertEqual(result.rungs.first?.id, "task-threads-self",
                           "the first rung must be the self-enumeration control")
            XCTAssertFalse(result.rungs.first?.isBoundaryViolation ?? true,
                           "the control must never be reported as a violation")
        } else {
            XCTAssertEqual(result.rungs.first?.outcome, .symbolUnavailable)
            XCTAssertTrue(result.violations.isEmpty,
                          "a withheld experiment must not report a violation")
        }
    }

    func testNoViolationWhereNothingWasMeasured() {
        let result = ProcessorSetProbe.probe()
        for rung in result.rungs {
            if rung.isBoundaryViolation {
                XCTAssertEqual(rung.outcome, .permitted)
                XCTAssertNotNil(rung.taskCount)
                XCTAssertFalse(rung.interpretation.isEmpty)
            }
            if rung.outcome == .prerequisiteFailed || rung.outcome == .controlFailed {
                XCTAssertFalse(rung.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testViolationListMatchesPerRungFlags() {
        let result = ProcessorSetProbe.probe()
        let flagged = Set(result.rungs.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheProcessorSetSection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            processorSets: ProcessorSetProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Can an ordinary app enumerate every task"),
                      "the report must render the processor-set section")
        XCTAssertTrue(text.contains("processor-set-tasks-default"),
                      "the default-set rung must be identifiable")
    }
}
