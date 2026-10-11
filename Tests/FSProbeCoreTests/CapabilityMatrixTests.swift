import XCTest
@testable import FSProbeCore

final class CapabilityMatrixTests: XCTestCase {

    private func makeEnvironment() -> CapabilityMatrix.EnvironmentRecord {
        CapabilityMatrix.EnvironmentRecord(
            osVersion: "UnitTest",
            osBuild: "test",
            deviceModel: "test"
        )
    }

    private func result(
        _ path: String,
        _ op: FSOperation,
        _ outcome: ProbeOutcome,
        errnoNumber: Int = 0,
        errnoName: String? = nil,
        evidence: ProbeEvidence = ProbeEvidence()
    ) -> ProbeResult {
        ProbeResult(
            path: path,
            operation: op,
            outcome: outcome,
            errnoNumber: errnoNumber,
            errnoName: errnoName,
            errnoDescription: nil,
            evidence: evidence
        )
    }

    func testRowsRecordIndependentResultsPerOperation() {
        let matrix = CapabilityMatrix(
            results: [
                result("/x", .enumerate, .deniedEPERM, errnoNumber: Int(EPERM), errnoName: "EPERM"),
                result("/x", .readFile, .succeeded, evidence: ProbeEvidence(bytesRead: 10))
            ],
            environment: makeEnvironment()
        )
        let rows = matrix.rows(targets: [FSTarget(path: "/x", label: "x", rationale: "", isBaseline: false)])
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].cells[.enumerate], .deniedEPERM)
        XCTAssertEqual(rows[0].cells[.readFile], .succeeded)
        // Operations are independent: no cell may be inferred from another.
        XCTAssertNil(rows[0].cells[.writeFile])
    }

    func testWriteResultsAttributeToTargetDirectory() throws {
        let root = NSTemporaryDirectory() + "fsprobe-attribution-\\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: root) }

        let matrix = MatrixRunner().run(
            targets: [FSTarget(path: root, label: "root", rationale: "test", isBaseline: false)]
        )
        // Write probes touch a synthetic file inside the directory; the result
        // must still appear in the row for the directory itself.
        let row = matrix.rows(targets: [FSTarget(path: root, label: "root", rationale: "test", isBaseline: false)])[0]
        XCTAssertEqual(row.cells[.writeFile], .succeeded)
        XCTAssertEqual(row.cells[.createFile], .succeeded)
        XCTAssertEqual(row.cells[.deleteFile], .succeeded)
        for result in matrix.results where result.targetPath == root {
            XCTAssertEqual(result.targetPath, root)
        }
    }

    func testDirectoryTargetDoesNotProduceFalseAsymmetry() {
        // Reading a directory with open+read legitimately fails with EISDIR.
        // The analysis layer must not report that as an access asymmetry.
        let matrix = CapabilityMatrix(
            results: [
                result("/dir", .stat, .succeeded, evidence: ProbeEvidence(statIsDirectory: true)),
                result("/dir", .writeFile, .succeeded),
                result("/dir", .readFile, .failedOther, errnoNumber: Int(EISDIR), errnoName: "EISDIR")
            ],
            environment: makeEnvironment()
        )
        XCTAssertTrue(matrix.discrepancies().isEmpty)
    }

    func testRegularFileAsymmetryIsStillFlagged() {
        let matrix = CapabilityMatrix(
            results: [
                result("/file", .stat, .succeeded, evidence: ProbeEvidence(statIsDirectory: false)),
                result("/file", .writeFile, .succeeded),
                result("/file", .readFile, .deniedEPERM, errnoNumber: Int(EPERM), errnoName: "EPERM")
            ],
            environment: makeEnvironment()
        )
        XCTAssertEqual(matrix.discrepancies().count, 1)
        XCTAssertTrue(matrix.discrepancies()[0].description.contains("Asymmetric access"))
    }

    func testReadWithoutEnumerationIsFlagged() {
        let matrix = CapabilityMatrix(
            results: [
                result("/x", .enumerate, .deniedEPERM, errnoNumber: Int(EPERM), errnoName: "EPERM"),
                result("/x", .readFile, .succeeded)
            ],
            environment: makeEnvironment()
        )
        let discrepancies = matrix.discrepancies()
        XCTAssertEqual(discrepancies.count, 1)
        XCTAssertTrue(discrepancies[0].description.contains("Read-without-enumeration"))
    }

    func testConsistentAccessProducesNoDiscrepancy() {
        let matrix = CapabilityMatrix(
            results: [
                result("/x", .enumerate, .succeeded),
                result("/x", .readFile, .succeeded),
                result("/x", .writeFile, .succeeded)
            ],
            environment: makeEnvironment()
        )
        XCTAssertTrue(matrix.discrepancies().isEmpty)
    }

    func testSymlinkTargetDiscrepancyIsFlagged() {
        let matrix = CapabilityMatrix(
            results: [
                result("/x", .stat, .succeeded),
                result("/x", .statFollow, .deniedEPERM, errnoNumber: Int(EPERM), errnoName: "EPERM")
            ],
            environment: makeEnvironment()
        )
        let discrepancies = matrix.discrepancies()
        XCTAssertEqual(discrepancies.count, 1)
        XCTAssertTrue(discrepancies[0].description.contains("Symlink target"))
    }

    func testJSONExportRoundTrips() throws {
        let matrix = CapabilityMatrix(
            results: [result("/x", .readFile, .succeeded, evidence: ProbeEvidence(bytesRead: 4))],
            environment: makeEnvironment()
        )
        let data = try ReportExporter.json(matrix)
        let decoded = try JSONDecoder().decode(ReportExporterProbe.self, from: data)
        XCTAssertEqual(decoded.results.count, 1)
        XCTAssertEqual(decoded.results[0].path, "/x")
        XCTAssertEqual(decoded.results[0].operation, .readFile)
        XCTAssertEqual(decoded.results[0].evidence.bytesRead, 4)
    }

    func testTextExportIncludesPlatformAndDiscrepancies() {
        let matrix = CapabilityMatrix(
            results: [
                result("/x", .enumerate, .deniedEPERM, errnoNumber: Int(EPERM), errnoName: "EPERM"),
                result("/x", .readFile, .succeeded)
            ],
            environment: makeEnvironment()
        )
        let text = ReportExporter.text(matrix, targets: [FSTarget(path: "/x", label: "x", rationale: "", isBaseline: false)])
        XCTAssertTrue(text.contains("UnitTest"))
        XCTAssertTrue(text.contains("/x"))
        XCTAssertTrue(text.contains("Read-without-enumeration"))
    }
}

/// Decoding shim: the exporter wraps results with a schema field.
private struct ReportExporterProbe: Decodable {
    let schema: String
    let results: [ProbeResult]
}
