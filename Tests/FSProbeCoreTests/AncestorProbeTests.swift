import XCTest
@testable import FSProbeCore

/// Tests for the directory-ascent experiment.
///
/// These verify the mechanics (walking, termination, boundary reporting) against
/// a synthetic tree the test creates. What the boundary *means* on iOS is a
/// device result and is recorded separately.
final class AncestorProbeTests: XCTestCase {

    var root: String!

    override func setUpWithError() throws {
        root = NSTemporaryDirectory() + "fsprobe-ancestor-\(UUID().uuidString)"
        // Build a/b/c/d so the walk has several levels to climb.
        try FileManager.default.createDirectory(
            atPath: root + "/a/b/c/d",
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let root = root {
            try? FileManager.default.removeItem(atPath: root)
        }
    }

    func testAscentWalksUpOneLevelAtATime() throws {
        let steps = AncestorProbe.ascend(from: root + "/a/b/c/d", maxDepth: 4)
        XCTAssertEqual(steps.count, 4)
        XCTAssertEqual(steps[0].path, root + "/a/b/c/d")
        XCTAssertEqual(steps[0].depth, 0)
        XCTAssertEqual(steps[1].path, root + "/a/b/c")
        XCTAssertEqual(steps[1].depth, 1)
        XCTAssertEqual(steps[2].path, root + "/a/b")
        XCTAssertEqual(steps[3].path, root + "/a")
    }

    func testAscentStopsAtTheFilesystemRoot() throws {
        // maxDepth well beyond the real depth; the walk must still terminate.
        let steps = AncestorProbe.ascend(from: root + "/a", maxDepth: 200)
        XCTAssertFalse(steps.isEmpty)
        let last = steps.last!
        XCTAssertEqual(last.path, "/", "the walk must terminate at the filesystem root")
    }

    func testTrailingSlashDoesNotProduceDuplicateParents() throws {
        let withSlash = AncestorProbe.ascend(from: root + "/a/b/", maxDepth: 3)
        let withoutSlash = AncestorProbe.ascend(from: root + "/a/b", maxDepth: 3)
        XCTAssertEqual(withSlash.map { $0.path }, withoutSlash.map { $0.path })
    }

    func testExistingDirectoriesAreFullyVisible() throws {
        let steps = AncestorProbe.ascend(from: root + "/a/b/c/d", maxDepth: 3)
        for step in steps {
            XCTAssertTrue(step.fullyVisible, "\(step.path) should be fully visible")
            XCTAssertNil(step.errnoName)
        }
    }

    func testMissingDirectoryReportsNotFoundNotDenial() throws {
        let steps = AncestorProbe.ascend(
            from: root + "/does/not/exist",
            maxDepth: 1
        )
        XCTAssertEqual(steps.count, 1)
        XCTAssertEqual(steps[0].lstat, .notFound)
        XCTAssertEqual(steps[0].errnoName, "ENOENT")
    }

    func testBoundaryIsTheFirstNotFullyVisibleAncestor() throws {
        let steps = AncestorProbe.ascend(from: root + "/a/b/c/d", maxDepth: 3)
        // Everything here is visible, so there is no boundary within range.
        XCTAssertNil(AncestorProbe.boundary(in: steps))

        // A missing leaf makes the first step the boundary.
        let missing = AncestorProbe.ascend(from: root + "/nope", maxDepth: 1)
        XCTAssertEqual(AncestorProbe.boundary(in: missing)?.depth, 0)
    }

    func testAscentStopsAfterConsecutiveFailures() throws {
        let steps = AncestorProbe.ascend(
            from: root + "/does/not/exist",
            maxDepth: 10,
            stopAfterConsecutiveFailures: 2
        )
        // The first two ancestors are absent; the walk should stop there rather
        // than climbing all the way to the root.
        XCTAssertEqual(steps.count, 2)
        XCTAssertNotNil(steps.last?.stopReason)
        XCTAssertTrue(steps.last!.stopReason!.contains("Boundary established"))
    }

    func testAscentIsReadOnly() throws {
        // The ascent must not create anything. Snapshot the tree before and after.
        func snapshot(_ path: String) -> [String] {
            (try? FileManager.default.subpathsOfDirectory(atPath: path)) ?? []
        }
        let before = snapshot(root)
        _ = AncestorProbe.ascend(from: root + "/a/b/c/d", maxDepth: 6)
        let after = snapshot(root)
        XCTAssertEqual(before, after, "the ascent probe must not modify the tree")
    }
}
