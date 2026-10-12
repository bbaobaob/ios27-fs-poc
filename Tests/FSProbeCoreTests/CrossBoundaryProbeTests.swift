import XCTest
@testable import FSProbeCore

/// Tests for the boundary-mechanism experiments.
///
/// These run against a synthetic container on the verification host. They assert
/// that the experiments execute, that they report denials with real errnos, that
/// they are self-consistent, and that they leave no artefacts behind. What the
/// boundary *means* on iOS is a device result; these tests only prove the
/// experiments are sound.
///
/// Note on host limitations: `link()` is refused with EACCES on the Android
/// verification host, so the hard-link control legitimately fails there. The
/// experiments are written to detect that and skip the dependent test rather
/// than report a meaningless result — which is the behaviour asserted here.
final class CrossBoundaryProbeTests: XCTestCase {

    var root: String!
    var container: String!

    override func setUpWithError() throws {
        root = NSTemporaryDirectory() + "fsprobe-boundary-\(UUID().uuidString)"
        container = root + "/container"
        try FileManager.default.createDirectory(
            atPath: container + "/Documents",
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let root = root { try? FileManager.default.removeItem(atPath: root) }
    }

    /// A path outside the synthetic container that this host refuses.
    private var outsidePath: String { NSTemporaryDirectory() }

    private func battery() -> [CrossBoundaryProbe.Experiment] {
        CrossBoundaryProbe.runAll(containerPath: container, outsidePath: outsidePath)
    }

    private func byID(_ experiments: [CrossBoundaryProbe.Experiment])
        -> [String: CrossBoundaryProbe.Experiment]
    {
        Dictionary(uniqueKeysWithValues: experiments.map { ($0.id, $0) })
    }

    func testBatteryRunsEveryExperiment() throws {
        let ids = Set(battery().map { $0.id })
        let required = [
            "dotdot-traversal", "hardlink-control", "rename-control",
            "rename-cross-boundary", "enumerate-posix", "enumerate-foundation"
        ]
        for id in required {
            XCTAssertTrue(ids.contains(id), "missing experiment: \(id) (got \(ids.sorted()))")
        }
    }

    func testEveryExperimentRecordsItsMechanismAndExpectation() throws {
        for experiment in battery() {
            XCTAssertFalse(experiment.mechanism.isEmpty, "\(experiment.id) has no mechanism")
            XCTAssertFalse(experiment.expected.isEmpty, "\(experiment.id) has no expectation")
            XCTAssertFalse(experiment.arguments.isEmpty, "\(experiment.id) has no arguments")
            XCTAssertFalse(experiment.interpretation.isEmpty, "\(experiment.id) has no interpretation")
            if experiment.outcome == .denied {
                XCTAssertFalse(experiment.errnoName?.isEmpty ?? true,
                               "\(experiment.id) denied without an errno name")
            }
        }
    }

    func testBatteryIsSelfConsistentAboutSkippedExperiments() throws {
        let experiments = byID(battery())

        // If the link control failed, the cross-boundary link test must have been
        // skipped rather than reported with a meaningless outcome.
        if let control = experiments["hardlink-control"], control.outcome != .permitted {
            XCTAssertNil(experiments["hardlink-cross-boundary"],
                         "the dependent test ran even though its control failed")
            XCTAssertFalse(control.interpretation.isEmpty)
        } else {
            XCTAssertNotNil(experiments["hardlink-cross-boundary"],
                            "the control succeeded, so the dependent test must run")
        }

        // Rename has no such host limitation, so both must always be present.
        XCTAssertNotNil(experiments["rename-cross-boundary"])
    }

    func testPermittedResultsAreFlaggedAsBoundaryViolations() throws {
        // On the verification host there is no iOS sandbox, so a cross-boundary
        // link or rename may legitimately succeed. What must hold is that a
        // permitted result is flagged, never reported as a plain success.
        for experiment in battery() {
            if experiment.outcome == .permitted, experiment.id != "hardlink-control",
               experiment.id != "rename-control" {
                XCTAssertTrue(experiment.isBoundaryViolation,
                              "\(experiment.id) permitted but not flagged as a violation")
            }
        }
    }

    func testControlsAreNotFlaggedAsBoundaryViolations() throws {
        // A control succeeding inside the container is the expected outcome and
        // must not be reported as a violation.
        for experiment in battery() {
            if experiment.id == "hardlink-control" || experiment.id == "rename-control" {
                XCTAssertTrue(experiment.expectedPermitted,
                              "\(experiment.id) should be marked expected-permitted")
                if experiment.outcome == .permitted {
                    XCTAssertFalse(experiment.isBoundaryViolation,
                                   "\(experiment.id) succeeded inside the container but was flagged")
                }
            }
        }
    }

    func testBatteryLeavesNoArtefactsBehind() throws {
        _ = battery()
        let documents = container + "/Documents"
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: documents)) ?? []
        XCTAssertTrue(leftovers.isEmpty, "experiments left files behind: \(leftovers)")
    }

    func testSymlinkExperimentReportsItsPreconditionHonestly() throws {
        // Point the "container" at a path whose Documents cannot be created,
        // because its parent is a regular file.
        let blocker = root + "/blocker"
        try Data("not a directory".utf8).write(to: URL(fileURLWithPath: blocker))
        let experiments = CrossBoundaryProbe.pathResolutionBattery(
            containerPath: blocker + "/container",
            outsidePath: outsidePath
        )

        // The traversal experiment is independent of the symlink, so it still runs.
        XCTAssertTrue(experiments.contains { $0.id == "dotdot-traversal" })

        // The symlink experiments must report notApplicable, not a fake result.
        for experiment in experiments where experiment.id.hasPrefix("symlink-escape") {
            XCTAssertEqual(experiment.outcome, .notApplicable,
                           "\(experiment.id) should report its failed precondition")
        }
    }

    func testEnumerationDifferentialComparesBothPaths() throws {
        let experiments = CrossBoundaryProbe.enumerationDifferential(outsidePath: outsidePath)
        let ids = Set(experiments.map { $0.id })
        XCTAssertTrue(ids.contains("enumerate-posix"))
        XCTAssertTrue(ids.contains("enumerate-foundation"))
        for experiment in experiments {
            XCTAssertFalse(experiment.interpretation.isEmpty)
        }
    }
}
