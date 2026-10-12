import XCTest
@testable import FSProbeCore

final class SHA256Tests: XCTestCase {

    func testKnownVectors() {
        // FIPS 180-4 / standard published vectors.
        XCTAssertEqual(SHA256.hexDigest(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(SHA256.hexDigest(Data("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(
            SHA256.hexDigest(Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    }

    func testDigestIsStableAndLengthIndependent() {
        let data = Data((0..<1000).map { UInt8($0 % 256) })
        XCTAssertEqual(SHA256.hexDigest(data), SHA256.hexDigest(data))
        XCTAssertEqual(SHA256.hexDigest(data).count, 64)
    }

    func testDigestChangesWithContent() {
        XCTAssertNotEqual(
            SHA256.hexDigest(Data("a".utf8)),
            SHA256.hexDigest(Data("b".utf8))
        )
    }
}
