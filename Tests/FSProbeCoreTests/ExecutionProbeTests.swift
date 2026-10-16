import XCTest
@testable import FSProbeCore

/// Tests for the process-execution and profile-spawn probes.
///
/// Both are Darwin-only, so the verification host withholds every case. What
/// these tests establish is that a withheld case is never a violation, and that
/// ENOENT and EPERM are never collapsed — the control depends on that distinction.
final class ExecutionProbeTests: XCTestCase {

    // MARK: - ProcessExecutionProbe

    func testOnlyPermittedIsAViolation() {
        let cases: [(ProcessExecutionProbe.Outcome, Bool)] = [
            (.permitted, true), (.denied, false),
            (.notFound, false), (.otherError, false),
            (.callerAborted, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = ProcessExecutionProbe.Spawn(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, returnValue: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTheControlLeadsAndExpectsNotFound() {
        // The control is a path that cannot exist, and its expected answer is
        // ENOENT. That is what makes a refusal on a real binary interpretable:
        // ENOENT means the lookup ran and found nothing, EPERM means the policy
        // refused it. Without this the whole experiment is unreadable.
        let result = ProcessExecutionProbe.probe()
        XCTAssertFalse(result.spawns.isEmpty)
        let control = result.spawns.first
        XCTAssertEqual(control?.id, "posix-spawn-nonexistent-control",
                       "the first case must be the nonexistent-path control")
        XCTAssertFalse(control?.expectedDenied ?? true,
                       "the control must not expect denial")
    }

    func testNoViolationWhereNothingWasMeasured() {
        let result = ProcessExecutionProbe.probe()
        for item in result.spawns {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .permitted)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .notFound || item.outcome == .otherError {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testSystemIsRecordedAsATrapAndNeverCalled() {
        // system() aborts its caller (SIGABRT via abort_report_np, measured on
        // the simulator on 2026-10-16), so the probe must record the trap
        // without calling it. If this entry ever reads as anything but a
        // non-violation trap record, the harness is one edit away from killing
        // itself again.
        let result = ProcessExecutionProbe.probe()
        let trap = result.spawns.first { $0.id == "system-true" }
        XCTAssertNotNil(trap, "the system() trap must always be recorded")
        XCTAssertEqual(trap?.outcome, .callerAborted)
        XCTAssertFalse(trap?.isBoundaryViolation ?? true,
                       "a refusal-by-death is not a violation")
        XCTAssertFalse(result.violations.contains { $0.id == "system-true" })
    }

    func testClassifyMapsReturnCodesToOutcomes() {
        // The mapping is the whole experiment, so it is pinned directly: every
        // platform only produces its own errnos at runtime, and a wrong row here
        // is a wrong answer about the boundary. In particular ENOENT and EPERM
        // must never collapse -- one calibrates the control, the other names a
        // policy refusal -- and (rc != 0, err == 0) must never read as
        // permitted, because posix_spawn-family calls return the error number
        // and leave errno at zero.
        func outcome(rc: Int, err: Int32) -> ProcessExecutionProbe.Outcome {
            ProcessExecutionProbe.classify(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                rc: rc, err: err, expectedDenied: true, expected: "e",
                permittedMeaning: "p", deniedMeaning: "d", notFoundMeaning: "n"
            ).outcome
        }
        XCTAssertEqual(outcome(rc: 0, err: 0), .permitted)
        XCTAssertEqual(outcome(rc: 2, err: 2), .notFound)   // ENOENT
        XCTAssertEqual(outcome(rc: 1, err: 1), .denied)     // EPERM
        XCTAssertEqual(outcome(rc: 13, err: 13), .denied)   // EACCES
        XCTAssertEqual(outcome(rc: -1, err: 0), .otherError)  // unanswered, never permitted
        XCTAssertEqual(outcome(rc: 2, err: 0), .otherError)  // returned errno, errno untouched
        XCTAssertEqual(outcome(rc: 1, err: 0), .otherError)
    }

    func testViolationListMatchesPerSpawnFlags() {
        let result = ProcessExecutionProbe.probe()
        let flagged = Set(result.spawns.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    // MARK: - SandboxProfileSpawnProbe

    func testProfileSpawnOnlyPermittedIsAViolation() {
        let cases: [(SandboxProfileSpawnProbe.Outcome, Bool)] = [
            (.permitted, true), (.denied, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = SandboxProfileSpawnProbe.Attempt(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, returnValue: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testProfileNamesIncludeTheOneFromTheWriteup() {
        // "no-network" is the profile the published writeup used: it permits
        // filesystem access the caller lacks. It has to be in the list or the
        // experiment does not test the published mechanism.
        let list = SandboxProfileSpawnProbe.profileNames
        XCTAssertTrue(list.contains("no-network"),
                      "the profile from the writeup must be tested")
    }

    func testProfileSpawnNeverFabricatesAViolation() {
        let result = SandboxProfileSpawnProbe.probe()
        for item in result.attempts {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .permitted)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .symbolUnavailable || item.outcome == .notAttempted {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        let flagged = Set(result.attempts.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersBothNewSections() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            processExecution: ProcessExecutionProbe.probe(),
            profileSpawn: SandboxProfileSpawnProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Can an ordinary app execute a system binary?"),
                      "the report must render the execution section")
        XCTAssertTrue(text.contains("CVE-2026-20628"),
                      "the report must render the profile-spawn section")
    }
}
