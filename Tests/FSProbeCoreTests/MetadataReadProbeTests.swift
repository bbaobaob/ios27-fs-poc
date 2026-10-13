import XCTest
@testable import FSProbeCore

/// Tests for the metadata-read experiment.
///
/// The calls are resolved at runtime, so on the verification host the symbols
/// are absent and every case reports symbolUnavailable. What these tests
/// establish is the distinction the whole experiment rests on: an "absent"
/// answer is NOT a denial, and the model must never collapse the two.
final class MetadataReadProbeTests: XCTestCase {

    private func scratchContainer() throws -> String {
        let root = NSTemporaryDirectory() + "fsprobe-meta-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root + "/Documents", withIntermediateDirectories: true
        )
        return root
    }

    func testAnAbsentAnswerIsNotADenial() {
        // This is the property the experiment exists to protect. ENOENT, ENOATTR
        // and ENOTSUP mean the path was resolved and authorized; EPERM means the
        // policy refused. Collapsing them would either discard the finding or
        // fabricate one, depending on which way the collapse went.
        let cases: [(MetadataReadProbe.Outcome, Bool)] = [
            (.answered, true), (.absent, true),
            (.denied, false), (.controlFailed, false),
            (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let experiment = MetadataReadProbe.Experiment(
                id: "case", mechanism: "m", operation: "o", arguments: "a",
                expected: "e", expectedDenied: true, outcome: outcome,
                errnoName: nil, errnoNumber: nil, reportedBytes: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(experiment.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }

        // And a violation must be one the policy predicted would be denied.
        let expected = MetadataReadProbe.Experiment(
            id: "case", mechanism: "m", operation: "o", arguments: "a",
            expected: "e", expectedDenied: false, outcome: .absent,
            errnoName: nil, errnoNumber: nil, reportedBytes: nil,
            observed: "obs", interpretation: "interp"
        )
        XCTAssertFalse(expected.isBoundaryViolation,
                       "an absence answer where denial was not expected is not a violation")
    }

    func testProbeCoversFourPrimitivesAtBothDirectories() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = MetadataReadProbe.probe(containerPath: root)

        XCTAssertEqual(result.experiments.count, 8,
                       "expected 2 directories x 4 read primitives")
        let ids = Set(result.experiments.map { $0.id })
        for directory in ["/var/mobile/Library", "/var/mobile/Media"] {
            for op in ["getxattr", "listxattr", "getattrlist", "statfs"] {
                XCTAssertTrue(ids.contains("\(op)-\(directory)"),
                              "missing experiment \(op) at \(directory)")
            }
        }
    }

    func testSymbolUnavailableIsNeverAViolation() throws {
        // On the verification host none of these symbols resolve. That must
        // produce symbolUnavailable, never a denial and never a violation.
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = MetadataReadProbe.probe(containerPath: root)
        for experiment in result.experiments {
            if experiment.outcome == .symbolUnavailable {
                XCTAssertFalse(experiment.isBoundaryViolation)
                XCTAssertNil(experiment.errnoName,
                             "an unattempted experiment must not carry an errno")
            }
        }
        XCTAssertTrue(result.violations.isEmpty,
                      "no violation may be claimed where no measurement was made")
    }

    func testViolationListMatchesPerExperimentFlags() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let result = MetadataReadProbe.probe(containerPath: root)
        let flagged = Set(result.experiments.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheMetadataReadSection() throws {
        let root = try scratchContainer()
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            metadataReads: MetadataReadProbe.probe(containerPath: root)
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Read primitives that do not open the file"),
                      "the report must render the metadata-read section")
        XCTAssertTrue(text.contains("getxattr"),
                      "the getxattr case must be identifiable")
    }
}
