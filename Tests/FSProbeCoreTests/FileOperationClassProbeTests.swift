import XCTest
@testable import FSProbeCore

/// Tests for the untested-operation-class experiment.
///
/// The operations are Darwin libc calls, so the verification host runs them for
/// real. What these tests establish is that the module cannot express a violation
/// without the discriminating evidence, that the control gates each case, and
/// that it cleans up everything it creates.
final class FileOperationClassProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-opclass-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testProbeRunsAllFourClassesAtBothDirectories() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FileOperationClassProbe.probe(containerPath: root)

        // Two protected directories x four operation classes.
        XCTAssertEqual(result.experiments.count, 8,
                       "expected 2 directories x 4 operation classes")
        let ids = Set(result.experiments.map { $0.id })
        for directory in ["/var/mobile/Library", "/var/mobile/Media"] {
            for op in ["mkdir", "symlink", "mkfifo", "link-reverse-destination"] {
                XCTAssertTrue(ids.contains("\(op)-\(directory)"),
                              "missing experiment \(op) at \(directory)")
            }
        }
    }

    func testProbeLeavesNothingBehind() throws {
        let root = NSTemporaryDirectory() + "fsprobe-opclass-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: root) }

        _ = FileOperationClassProbe.probe(containerPath: root)

        let leftovers = (try? FileManager.default.contentsOfDirectory(
            atPath: root + "/Documents"
        )) ?? []
        XCTAssertTrue(leftovers.isEmpty,
                      "the probe left artifacts in the container: \(leftovers)")
    }

    func testControlFailureWithholdsTheVerdict() {
        // A control that fails means the operation is broken here, so a refusal
        // outside says nothing about policy. This is the property that stops a
        // non-functional platform from being reported as a sandbox denial.
        let cases: [(FileOperationClassProbe.Outcome, Bool)] = [
            (.permitted, true), (.denied, false),
            (.controlFailed, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let experiment = FileOperationClassProbe.Experiment(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, errnoNumber: nil, cleanedUp: true,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(experiment.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testDenialCarriesErrnoAndControlEvidence() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FileOperationClassProbe.probe(containerPath: root)
        for experiment in result.experiments {
            // Whatever the platform does, every experiment must state its
            // control's outcome, because that is what makes the result readable.
            XCTAssertTrue(experiment.observed?.contains("control") == true
                            || experiment.outcome == .notAttempted,
                          "\(experiment.id) does not report its control's outcome")
            // A denial must carry the errno that produced it.
            if experiment.outcome == .denied {
                XCTAssertNotNil(experiment.errnoName,
                                "\(experiment.id) is denied without an errno")
            }
            // A permitted result must have cleaned up after itself.
            if experiment.outcome == .permitted {
                XCTAssertTrue(experiment.cleanedUp,
                              "\(experiment.id) created an artifact and did not remove it")
            }
        }
    }

    func testAFailedControlIsNeverReportedAsADenial() throws {
        // The invariant that matters, stated so it holds on every platform: a
        // result may only be called `denied` when its control succeeded. A refusal
        // measured against a broken control says nothing about policy.
        //
        // The platforms disagree about the control, and that is the point. On the
        // verification host link() in a temporary directory is refused, so the
        // control fails and the case must read controlFailed. On macOS it succeeds,
        // so the case legitimately reads denied. Asserting either outcome outright
        // would encode one platform's behaviour as the rule.
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FileOperationClassProbe.probe(containerPath: root)
        XCTAssertFalse(result.experiments.isEmpty)
        for experiment in result.experiments {
            if experiment.outcome == .denied {
                XCTAssertTrue(
                    experiment.observed?.contains("control") == true
                        && experiment.observed?.contains("succeeded") == true,
                    "\(experiment.id) is reported as a denial, but its control did not succeed"
                )
                XCTAssertNotNil(experiment.errnoName,
                                "\(experiment.id) is denied without an errno")
            }
            // Whatever the platform, a control failure must never become a
            // violation, and a violation must never be claimed without evidence.
            if experiment.outcome == .controlFailed {
                XCTAssertFalse(experiment.isBoundaryViolation)
            }
            if experiment.isBoundaryViolation {
                XCTAssertTrue(experiment.cleanedUp,
                              "\(experiment.id) created an artifact and did not remove it")
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testViolationListMatchesPerExperimentFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = FileOperationClassProbe.probe(containerPath: root)
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheOperationClassSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            operationClasses: FileOperationClassProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Untested sandbox operation classes"),
                      "the report must render the operation-class section")
        XCTAssertTrue(text.contains("link-reverse-destination"),
                      "the reverse-direction link case must be identifiable")
    }
}
