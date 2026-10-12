import XCTest
@testable import FSProbeCore

/// Engine tests run against a synthetic directory tree the test creates itself.
/// These validate probe mechanics and evidence recording — not iOS sandbox
/// behaviour, which requires the physical device.
final class POSIXProbeEngineTests: XCTestCase {

    var root: String!

    override func setUpWithError() throws {
        root = NSTemporaryDirectory() + "fsprobe-tests-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: root,
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let root = root {
            try? FileManager.default.removeItem(atPath: root)
        }
    }

    // MARK: - Baseline (positive control)

    func testSyntheticDirectoryIsFullyAccessible() throws {
        let dir = root + "/baseline"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data("hello".utf8).write(to: URL(fileURLWithPath: dir + "/file.txt"))

        XCTAssertEqual(POSIXProbeEngine.run(.stat, on: dir).outcome, .succeeded)
        XCTAssertEqual(POSIXProbeEngine.run(.openDirectory, on: dir).outcome, .succeeded)

        let stat = POSIXProbeEngine.run(.stat, on: dir)
        XCTAssertEqual(stat.evidence.statIsDirectory, true)

        let fileStat = POSIXProbeEngine.run(.stat, on: dir + "/file.txt")
        XCTAssertEqual(fileStat.evidence.statIsDirectory, false)

        let enumerate = POSIXProbeEngine.run(.enumerate, on: dir, recordEntryNames: true)
        XCTAssertEqual(enumerate.outcome, .succeeded)
        // "." and ".." plus one real file
        XCTAssertEqual(enumerate.evidence.entryCount, 3)
        XCTAssertEqual(enumerate.evidence.sampleEntryNames, ["file.txt"])

        let read = POSIXProbeEngine.run(.readFile, on: dir + "/file.txt")
        XCTAssertEqual(read.outcome, .succeeded)
        XCTAssertEqual(read.evidence.bytesRead, 5)
    }

    func testWriteProbeVerifiesByReadBackAndCleansUp() throws {
        let dir = root + "/writable"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let write = POSIXProbeEngine.run(.writeFile, on: dir)
        XCTAssertEqual(write.outcome, .succeeded)
        XCTAssertEqual(write.evidence.readBackMatched, true)
        XCTAssertGreaterThan(write.evidence.bytesWritten ?? 0, 0)

        // The synthetic file must not survive the probe.
        let leftover = dir + "/" + POSIXProbeEngine.syntheticFileName
        XCTAssertFalse(FileManager.default.fileExists(atPath: leftover))
    }

    func testDeleteProbeRemovesSelfCreatedFile() throws {
        let dir = root + "/deletable"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let del = POSIXProbeEngine.run(.deleteFile, on: dir)
        XCTAssertEqual(del.outcome, .succeeded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir + "/" + POSIXProbeEngine.syntheticFileName))
    }

    func testWriteProbeNeverOverwritesPreExistingFile() throws {
        let dir = root + "/preexisting"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let sentinel = dir + "/sentinel.txt"
        try Data("original".utf8).write(to: URL(fileURLWithPath: sentinel))

        _ = POSIXProbeEngine.run(.writeFile, on: dir)

        let content = try Data(contentsOf: URL(fileURLWithPath: sentinel))
        XCTAssertEqual(content, Data("original".utf8), "Pre-existing file must be untouched")
    }

    // MARK: - Negative controls

    func testMissingPathReportsENOENTNotDenial() throws {
        let result = POSIXProbeEngine.run(.stat, on: root + "/does-not-exist")
        XCTAssertEqual(result.outcome, .notFound)
        XCTAssertEqual(result.errnoName, "ENOENT")
        XCTAssertEqual(result.cause, .pathAbsent)
    }

    func testFileProbedAsDirectoryReportsENOTDIR() throws {
        let file = root + "/plain.txt"
        try Data("x".utf8).write(to: URL(fileURLWithPath: file))
        let result = POSIXProbeEngine.run(.enumerate, on: file)
        XCTAssertEqual(result.outcome, .notDirectory)
        XCTAssertEqual(result.errnoName, "ENOTDIR")
    }

    func testSymlinkResolutionIsRecorded() throws {
        let dir = root + "/links"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data("target".utf8).write(to: URL(fileURLWithPath: dir + "/real.txt"))
        try FileManager.default.createSymbolicLink(
            atPath: dir + "/link.txt",
            withDestinationPath: dir + "/real.txt"
        )

        let lstat = POSIXProbeEngine.run(.stat, on: dir + "/link.txt")
        XCTAssertEqual(lstat.outcome, .succeeded)

        let link = POSIXProbeEngine.run(.readLink, on: dir + "/link.txt")
        XCTAssertEqual(link.outcome, .succeeded)
        XCTAssertEqual(link.evidence.linkTarget, dir + "/real.txt")
    }

    func testReadIsBounded() throws {
        let dir = root + "/big"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let big = Data(repeating: 0x41, count: 100_000)
        try big.write(to: URL(fileURLWithPath: dir + "/big.bin"))

        let read = POSIXProbeEngine.run(.readFile, on: dir + "/big.bin")
        XCTAssertEqual(read.outcome, .succeeded)
        XCTAssertEqual(read.evidence.bytesRead, POSIXProbeEngine.maxReadBytes)
    }
}

// The macOS-host CI run reported readBackMatched=false on every successful write
// while the direct probe tests above passed. These tests drive the same code
// through MatrixRunner so the discrepancy is reproducible in CI rather than only
// through the CLI.
final class MatrixRunnerWriteTests: XCTestCase {

    var root: String!

    override func setUpWithError() throws {
        root = NSTemporaryDirectory() + "fsprobe-runner-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let root = root { try? FileManager.default.removeItem(atPath: root) }
    }

    func testMatrixRunnerWriteProbeReadsBack() throws {
        let matrix = MatrixRunner().run(
            targets: [FSTarget(path: root, label: "root", rationale: "test", isBaseline: true)]
        )
        let writes = matrix.results.filter {
            $0.operation == .writeFile || $0.operation == .createFile
        }
        XCTAssertEqual(writes.count, 2)
        for result in writes {
            let operation = result.operation.rawValue
            XCTAssertEqual(result.outcome, .succeeded, "\(operation) should succeed in \(root)")
            XCTAssertEqual(result.evidence.bytesWritten, 29, "\(operation) should write the payload")
            XCTAssertEqual(result.evidence.bytesReadBack, 29,
                           "\(operation) read-back returned \(result.evidence.bytesReadBack ?? -1) bytes")
            XCTAssertEqual(result.evidence.readBackMatched, true,
                           "\(operation) read-back mismatch: \(result.note ?? "no note")")
        }
    }

    func testMatrixRunnerLeavesNoSyntheticFileBehind() throws {
        _ = MatrixRunner().run(
            targets: [FSTarget(path: root, label: "root", rationale: "test", isBaseline: true)]
        )
        let leftover = root + "/" + POSIXProbeEngine.syntheticFileName
        XCTAssertFalse(FileManager.default.fileExists(atPath: leftover))
    }
}

// Reproduces the read-back failure in CI: a file created through
// POSIXShim.openFile with mode 0o644 was not readable afterwards (EACCES on the
// read-back open). If open()'s variadic mode argument is not surviving the
// @_silgen_name binding, the file is created with a mode that denies read.
final class OpenFileModeTests: XCTestCase {

    var root: String!

    override func setUpWithError() throws {
        root = NSTemporaryDirectory() + "fsprobe-mode-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let root = root { try? FileManager.default.removeItem(atPath: root) }
    }

    func testCreatedFileIsReadableAndHasTheRequestedMode() throws {
        let path = root + "/modecheck.bin"
        let fd = POSIXShim.openFile(path, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        XCTAssertGreaterThanOrEqual(fd, 0, "create should succeed")
        if fd >= 0 {
            let written = "hello".withCString { ptr in
                POSIXShim.writeFD(fd, ptr, 5)
            }
            XCTAssertEqual(written, 5)
            POSIXShim.closeFile(fd)
        }

        // The mode must permit reading, or the read-back cannot work.
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(mode, 0o644, "created file has mode \(String(mode ?? -1, radix: 8))")

        // And it must actually be openable for reading.
        let readFD = POSIXShim.openFile(path, O_RDONLY, 0)
        XCTAssertGreaterThanOrEqual(readFD, 0, "read-back open failed")
        if readFD >= 0 { POSIXShim.closeFile(readFD) }
    }
}
