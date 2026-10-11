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
