import XCTest
@testable import FSProbeCore

/// Tests for the container write-boundary map.
///
/// These verify the probe enumerates the container, classifies each directory
/// correctly, and leaves nothing behind. Which directories iOS actually permits
/// is a device result; these tests only prove the probe is sound.
final class ContainerWriteProbeTests: XCTestCase {

    var container: String!

    override func setUpWithError() throws {
        container = NSTemporaryDirectory() + "fsprobe-cwp-\(UUID().uuidString)"
        // Build a container-shaped tree: the root plus the standard
        // subdirectories, and a system-managed one that should be refused on a
        // device.
        for name in ["Documents", "Library", "tmp", "SystemData"] {
            try FileManager.default.createDirectory(
                atPath: container + "/" + name,
                withIntermediateDirectories: true
            )
        }
        // Second level under Library, where Preferences and Caches live.
        for name in ["Preferences", "Caches"] {
            try FileManager.default.createDirectory(
                atPath: container + "/Library/" + name,
                withIntermediateDirectories: true
            )
        }
    }

    override func tearDownWithError() throws {
        if let container = container { try? FileManager.default.removeItem(atPath: container) }
    }

    func testProbeCoversTheContainerRootAndItsChildren() throws {
        let result = ContainerWriteProbe.probe(containerPath: container)
        let paths = Set(result.entries.map { $0.path })

        XCTAssertTrue(paths.contains(container), "the container root must be probed")
        for name in ["Documents", "Library", "tmp", "SystemData"] {
            XCTAssertTrue(paths.contains(container + "/" + name),
                          "missing \(name) in \(paths.sorted())")
        }
        // Second level under Library.
        XCTAssertTrue(paths.contains(container + "/Library/Preferences"))
        XCTAssertTrue(paths.contains(container + "/Library/Caches"))
    }

    func testEveryEntryRecordsItsClassification() throws {
        let result = ContainerWriteProbe.probe(containerPath: container)
        for entry in result.entries {
            XCTAssertTrue(entry.exists, "\(entry.path) should exist")
            XCTAssertNotNil(entry.modeOctal, "\(entry.path) has no mode")
            if entry.isDirectory {
                XCTAssertTrue(entry.enumerable, "\(entry.path) should be enumerable")
                XCTAssertNotNil(entry.entryCount)
            }
            // A refusal must carry the errno that produced it.
            if !entry.writable {
                XCTAssertNotNil(entry.createErrnoName,
                                "\(entry.path) refused without an errno")
            } else {
                // A successful write must be verified and cleaned up.
                XCTAssertEqual(entry.readBackMatched, true,
                               "\(entry.path) read-back mismatch")
                XCTAssertTrue(entry.removable, "\(entry.path) could not be cleaned up")
            }
        }
    }

    func testClassificationsAreConsistentWithTheSummary() throws {
        let result = ContainerWriteProbe.probe(containerPath: container)
        let writable = Set(result.writablePaths)
        let readableNotWritable = Set(result.readableButNotWritablePaths)

        for entry in result.entries {
            if writable.contains(entry.path) {
                XCTAssertTrue(entry.writable)
            }
            if readableNotWritable.contains(entry.path) {
                XCTAssertTrue(entry.enumerable && !entry.writable)
            }
        }
        // On the verification host there is no iOS sandbox, so every directory is
        // writable; what must hold is that the two summary lists never overlap.
        XCTAssertTrue(writable.intersection(readableNotWritable).isEmpty)
    }

    func testProbeLeavesNothingBehind() throws {
        _ = ContainerWriteProbe.probe(containerPath: container)
        for entry in ContainerWriteProbe.probe(containerPath: container).entries {
            let synthetic = entry.path + "/" + POSIXProbeEngine.syntheticFileName
            XCTAssertFalse(FileManager.default.fileExists(atPath: synthetic),
                           "\(synthetic) was left behind")
        }
        // And no stray files anywhere in the tree.
        let all = (try? FileManager.default.subpathsOfDirectory(atPath: container)) ?? []
        XCTAssertTrue(all.allSatisfy { !$0.contains("fsprobe-") },
                      "probe left artefacts: \(all.filter { $0.contains("fsprobe-") })")
    }

    func testProbeHandlesAMissingContainer() throws {
        let missing = container + "/does-not-exist"
        let result = ContainerWriteProbe.probe(containerPath: missing)
        XCTAssertEqual(result.entries.count, 1)
        XCTAssertFalse(result.entries[0].exists)
        XCTAssertTrue(result.writablePaths.isEmpty)
        XCTAssertTrue(result.readableButNotWritablePaths.isEmpty)
    }
}
