import XCTest
@testable import VaultCrypto

final class Blake2bTests: XCTestCase {
    /// RFC 7693 Appendix A.
    func testAbc512() {
        let digest = Blake2b.hash(Array("abc".utf8), digestLength: 64)
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    }

    func testEmpty512() {
        let digest = Blake2b.hash([UInt8](), digestLength: 64)
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
    }

    func testShortDigestLengths() {
        // Digest length is bound into the parameter block, so different lengths
        // are different hashes rather than truncations of one another.
        let long = Blake2b.hash(Array("abc".utf8), digestLength: 64)
        let short = Blake2b.hash(Array("abc".utf8), digestLength: 32)
        XCTAssertEqual(short.count, 32)
        XCTAssertNotEqual(Array(long.prefix(32)), short)
    }

    func testLongInputSpansBlocks() {
        let input = [UInt8](repeating: 0x61, count: 1000)
        XCTAssertEqual(Blake2b.hash(input, digestLength: 64).count, 64)
    }
}
