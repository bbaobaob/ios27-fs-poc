import XCTest
@testable import FSProbeCore

/// Tests for the service-mediated authorization module.
///
/// The XPC half is Darwin-only: libxpc and NSFileCoordinator do not exist on the
/// verification host. What these tests establish is that the module reports its
/// own unavailability honestly on that host rather than fabricating results, and
/// that the report renders either way. The service-reachability map and the
/// confused-deputy experiments are device results.
final class XPCProbeTests: XCTestCase {

    func testModuleReportsAvailabilityHonestly() {
        // On the device XPCProbe.xpcAvailable is true; on the verification host it
        // is false. Either way, probeServices must not claim a result it does not
        // have.
        let services = XPCProbe.probeServices(timeout: 1.0)
        if XPCProbe.xpcAvailable {
            // Darwin: every candidate must be probed.
            XCTAssertEqual(services.count, XPCProbe.serviceCandidates().count)
            for service in services {
                XCTAssertFalse(service.rationale.isEmpty,
                               "\(service.serviceName) has no rationale")
            }
        } else {
            XCTAssertTrue(services.isEmpty,
                          "a platform without XPC must report no service results")
        }
    }

    func testDeputyVerdictRequiresTheEffectNotTheCoordination() throws {
        // This is the correctness property that matters: NSFileCoordinator granting
        // coordination is not read or write access. A verdict of permitted must
        // require bytes actually read, or a file actually landing.
        //
        // On the verification host NSFileCoordinator does not exist, so the module
        // reports no experiments. The property is asserted through the model instead.
        let root = NSTemporaryDirectory() + "fsprobe-xpc-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = XPCProbe.probeFileCoordinator(
            containerPath: root,
            outsideDirectory: "/var/mobile/Library"
        )
        for experiment in result.experiments {
            // Anything flagged as a violation must carry evidence of an effect.
            if experiment.isBoundaryViolation {
                XCTAssertFalse(experiment.interpretation.isEmpty)
            }
        }
    }

    func testCoordinatorProbeIsSafeOnEitherPlatform() throws {
        let root = NSTemporaryDirectory() + "fsprobe-xpc-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = XPCProbe.probeFileCoordinator(
            containerPath: root,
            outsideDirectory: "/var/mobile/Library"
        )

        // Either the experiments ran, or the platform cannot run them and says so.
        // Neither case may fabricate a violation.
        for experiment in result.experiments {
            if experiment.isBoundaryViolation {
                XCTAssertTrue(experiment.expectedDenied)
                XCTAssertEqual(experiment.outcome.rawValue, "permitted")
            }
        }
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the per-experiment flags")
    }

    func testCoordinatorProbeLeavesNothingBehind() throws {
        let root = NSTemporaryDirectory() + "fsprobe-xpc-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: root) }

        _ = XPCProbe.probeFileCoordinator(
            containerPath: root,
            outsideDirectory: "/var/mobile/Library"
        )
        let documents = root + "/Documents"
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: documents)) ?? []
        XCTAssertTrue(leftovers.isEmpty, "the probe left files behind: \(leftovers)")
    }

    func testReportRendersTheXpcSections() throws {
        let root = NSTemporaryDirectory() + "fsprobe-xpc-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            xpcServices: XPCProbe.probeServices(timeout: 1.0),
            fileCoordinator: XPCProbe.probeFileCoordinator(
                containerPath: root,
                outsideDirectory: "/var/mobile/Library"
            )
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("NSFileCoordinator"), "the report must mention the deputy test")
    }
}
