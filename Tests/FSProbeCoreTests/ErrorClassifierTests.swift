import XCTest
@testable import FSProbeCore

final class ErrorClassifierTests: XCTestCase {

    func testErrnoNames() {
        XCTAssertEqual(ErrorClassifier.errnoName(Int32(EPERM)), "EPERM")
        XCTAssertEqual(ErrorClassifier.errnoName(Int32(ENOENT)), "ENOENT")
        XCTAssertEqual(ErrorClassifier.errnoName(Int32(EACCES)), "EACCES")
        XCTAssertEqual(ErrorClassifier.errnoName(Int32(ENOTDIR)), "ENOTDIR")
        XCTAssertEqual(ErrorClassifier.errnoName(12345), "errno(12345)")
    }

    func testOutcomeMapping() {
        XCTAssertEqual(ErrorClassifier.outcome(for: 0), .succeeded)
        XCTAssertEqual(ErrorClassifier.outcome(for: Int32(ENOENT)), .notFound)
        XCTAssertEqual(ErrorClassifier.outcome(for: Int32(ENOTDIR)), .notDirectory)
        XCTAssertEqual(ErrorClassifier.outcome(for: Int32(EPERM)), .deniedEPERM)
        XCTAssertEqual(ErrorClassifier.outcome(for: Int32(EACCES)), .deniedEACCES)
        XCTAssertEqual(ErrorClassifier.outcome(for: Int32(EIO)), .failedOther)
    }

    /// EPERM must be attributed to the sandbox, EACCES to POSIX permissions.
    /// Conflating them would hide the authorization boundary.
    func testCauseAttributionDistinguishesEPERMFromEACCES() {
        XCTAssertEqual(
            ErrorClassifier.cause(outcome: .deniedEPERM, pathExisted: true),
            .sandboxEnforcement
        )
        XCTAssertEqual(
            ErrorClassifier.cause(outcome: .deniedEACCES, pathExisted: true),
            .posixPermissions
        )
    }

    func testMissingPathIsNotASecurityObservation() {
        XCTAssertEqual(
            ErrorClassifier.cause(outcome: .notFound, pathExisted: false),
            .pathAbsent
        )
    }

    func testDescriptionIsExactNotGeneric() {
        let text = ErrorClassifier.description(for: Int32(EPERM))
        XCTAssertFalse(text.isEmpty)
        XCTAssertNotEqual(text.lowercased(), "error")
    }
}
