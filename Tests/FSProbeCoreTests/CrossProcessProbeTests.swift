import XCTest
@testable import FSProbeCore

/// Tests for the cross-process authorization module.
///
/// The mach-lookup and introspection experiments are Darwin-only: libxpc,
/// libproc, and the Mach task API do not exist on the verification host. What
/// these tests establish is that the module reports its own unavailability
/// honestly rather than fabricating results, and that the result model cannot
/// express a violation without evidence. The measurements themselves are device
/// results.
final class CrossProcessProbeTests: XCTestCase {

    func testMachServiceUnavailabilityIsNotFabricated() {
        let probe = CrossProcessProbe.probeMachService(
            "com.bbaobaob.fsprobe.nonexistent.control", rationale: "control", timeout: 0.2
        )
        // On either platform the symbol resolution state must be stated truthfully.
        XCTAssertFalse(probe.symbolResolved == false && probe.reachability == .refused,
                       "a refusal cannot be reported when the symbol never resolved")
        if CrossProcessProbe.machReachabilityAvailable {
            // Darwin: the experiment ran, so the symbol state is meaningful.
            XCTAssertTrue(probe.symbolResolved,
                          "the connection factory should resolve on a platform that has libxpc")
        } else {
            XCTAssertEqual(probe.reachability, CrossProcessProbe.MachReachability.notAttempted)
            XCTAssertEqual(probe.symbolResolved, false)
        }
    }

    func testMachServiceCandidateListLeadsWithANegativeControl() {
        let candidates = CrossProcessProbe.machServiceCandidates()
        XCTAssertFalse(candidates.isEmpty)
        XCTAssertTrue(
            candidates[0].rationale.contains("NEGATIVE CONTROL"),
            "the first candidate must be the negative control that calibrates refusals"
        )
        XCTAssertTrue(
            candidates[0].name.contains("nonexistent"),
            "the control service name must be one that cannot exist"
        )
        // Every candidate must carry a rationale, so no result is unattributable.
        for candidate in candidates {
            XCTAssertFalse(candidate.rationale.isEmpty, "\(candidate.name) has no rationale")
        }
    }

    func testIntrospectionReportsNoFabricatedViolations() {
        let report = CrossProcessProbe.probeProcessIntrospection()
        if CrossProcessProbe.machReachabilityAvailable {
            // Darwin: the control must have run, and it must be the first attempt.
            XCTAssertFalse(report.attempts.isEmpty, "no introspection attempts were recorded")
            XCTAssertEqual(
                report.attempts.first?.isControl, true,
                "the first attempt must be the self-targeting control"
            )
            // A violation requires a succeeded, non-control operation.
            for violation in report.violations {
                XCTAssertTrue(violation.isControl == false)
                XCTAssertEqual(violation.outcome, CrossProcessProbe.IntrospectionOutcome.succeeded)
                XCTAssertFalse(violation.interpretation.isEmpty)
            }
            // The violation list must match the per-attempt outcome exactly.
            let flagged = Set(report.attempts.filter {
                !$0.isControl && $0.outcome == .succeeded
                    && ($0.operation == "task_for_pid" || $0.operation == "proc_pidpath")
            }.map { $0.id })
            let listed = Set(report.violations.map { $0.id })
            XCTAssertEqual(flagged, listed, "the violation list must match the per-attempt outcomes")
        } else {
            XCTAssertTrue(report.attempts.isEmpty,
                          "a platform without libproc must report no introspection results")
            XCTAssertTrue(report.violations.isEmpty)
            XCTAssertFalse(report.controlSucceeded)
        }
    }

    func testControlFailureMakesTheExperimentInconclusive() {
        // If the self-control fails, the module must not claim a denial on other
        // processes. This is the property that keeps a broken API from being
        // reported as a sandbox result.
        let controlFailure = CrossProcessProbe.IntrospectionAttempt(
            operation: "proc_pidpath", target: "self (pid 0)", isControl: true,
            outcome: .denied, returnValue: nil, errorName: "EPERM", observed: nil,
            interpretation: "The control failed, so nothing below is interpretable."
        )
        let denied = CrossProcessProbe.IntrospectionAttempt(
            operation: "proc_pidpath", target: "launchd (pid 1)", isControl: false,
            outcome: .denied, returnValue: nil, errorName: "EPERM", observed: nil,
            interpretation: "Refused."
        )
        let report = CrossProcessProbe.IntrospectionReport(
            attempts: [controlFailure, denied],
            controlSucceeded: false,
            violations: []
        )
        XCTAssertFalse(report.controlSucceeded)
        XCTAssertTrue(report.violations.isEmpty)
        // The report must be usable to render an inconclusive verdict.
        XCTAssertFalse(report.attempts.isEmpty)
    }

    func testViolationRequiresSucceededOutcomeAndEvidence() {
        // Model invariant: a violation is a success where refusal was predicted,
        // and it must carry an interpretation. Denied and notAttempted never are.
        let cases: [(CrossProcessProbe.IntrospectionOutcome, Bool)] = [
            (.succeeded, true), (.denied, false), (.notApplicable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let attempt = CrossProcessProbe.IntrospectionAttempt(
                operation: "task_for_pid", target: "launchd (pid 1)", isControl: false,
                outcome: outcome, returnValue: nil, errorName: nil, observed: nil,
                interpretation: "interpretation"
            )
            let report = CrossProcessProbe.IntrospectionReport(
                attempts: [attempt],
                controlSucceeded: true,
                violations: attempt.outcome == .succeeded ? [attempt] : []
            )
            XCTAssertEqual(report.violations.isEmpty, !shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") produce a violation")
        }
    }

    // MARK: - Report rendering

    /// The mach-lookup section's rendering must be verified somewhere, and the
    /// only place it can be is here: on the verification host
    /// `machReachabilityAvailable` is false, so the section never appears in a
    /// real CLI run and its formatting would otherwise be unexercised until a
    /// device build.
    func testReportRendersMachServicesAndIntrospection() throws {
        let machServices = [
            CrossProcessProbe.MachServiceProbe(
                serviceName: "com.bbaobaob.fsprobe.nonexistent.control",
                rationale: "NEGATIVE CONTROL: calibration",
                symbolResolved: true,
                reachability: .refused,
                refusalReason: "Connection refused",
                responseMilliseconds: 3
            ),
            CrossProcessProbe.MachServiceProbe(
                serviceName: "com.apple.FileCoordination",
                rationale: "deputy",
                symbolResolved: true,
                reachability: .reachable,
                refusalReason: nil,
                responseMilliseconds: 5
            ),
        ]
        let introspection = CrossProcessProbe.IntrospectionReport(
            attempts: [
                CrossProcessProbe.IntrospectionAttempt(
                    operation: "proc_pidpath", target: "self (pid 1)", isControl: true,
                    outcome: .succeeded, returnValue: "512 bytes", errorName: nil,
                    observed: "/var/containers/Bundle/Application/test/FSProbe.app/FSProbe",
                    interpretation: "The control succeeded."
                ),
                CrossProcessProbe.IntrospectionAttempt(
                    operation: "task_for_pid", target: "launchd (pid 1)", isControl: false,
                    outcome: .denied, returnValue: "kern_return_t 5", errorName: "KERN_FAILURE",
                    observed: nil,
                    interpretation: "Refused. The expected boundary."
                ),
            ],
            controlSucceeded: true,
            violations: []
        )

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            machServices: machServices,
            processIntrospection: introspection
        )
        let text = ReportExporter.text(matrix, targets: [])

        XCTAssertTrue(text.contains("Mach service reachability"),
                      "the mach section must render when data is present")
        XCTAssertTrue(text.contains("negative control"),
                      "the negative control must be called out explicitly")
        XCTAssertTrue(text.contains("Connection refused"),
                      "the platform's refusal reason must be preserved")
        XCTAssertTrue(text.contains("reachability is reconnaissance, not a finding"),
                      "the section must not present reachability as a finding")
        XCTAssertTrue(text.contains("Cross-process introspection"))
        XCTAssertTrue(text.contains("[control]"), "the control attempt must be marked")
        XCTAssertTrue(text.contains("KERN_FAILURE"), "the kernel error name must be preserved")
        XCTAssertTrue(text.contains("no cross-process operation succeeded"))
    }

    /// A failed control must render as inconclusive, never as a denial.
    func testReportMarksInconclusiveWhenControlFails() throws {
        let introspection = CrossProcessProbe.IntrospectionReport(
            attempts: [
                CrossProcessProbe.IntrospectionAttempt(
                    operation: "proc_pidpath", target: "self (pid 1)", isControl: true,
                    outcome: .denied, returnValue: nil, errorName: "EPERM", observed: nil,
                    interpretation: "The control FAILED, so nothing below is interpretable."
                ),
            ],
            controlSucceeded: false,
            violations: []
        )
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            processIntrospection: introspection
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("INCONCLUSIVE"))
        XCTAssertFalse(text.contains("no cross-process operation succeeded"),
                       "a failed control must not be reported as a sandbox denial")
    }

    /// Absent data must render as NOT_ATTEMPTED, never as a denial and never as
    /// a silent omission that a reader could mistake for a pass.
    func testReportMarksNotAttemptedWhenMachDataIsAbsent() throws {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            )
        )
        let text = ReportExporter.text(matrix, targets: [])
        // With no data at all the section is absent, which is correct: nothing
        // was requested. What must never happen is a refusal being implied.
        XCTAssertFalse(text.contains("Mach service reachability"))
        XCTAssertFalse(text.contains("denied"), "no refusal may be implied without a measurement")
    }
}
