import XCTest
@testable import VaultCrypto

/// RFC 9106 section 5 test vectors.
final class Argon2idTests: XCTestCase {
    private let password = [UInt8](repeating: 0x01, count: 32)
    private let salt = [UInt8](repeating: 0x02, count: 16)
    private let secret = [UInt8](repeating: 0x03, count: 8)
    private let associatedData = [UInt8](repeating: 0x04, count: 12)

    private func derive(_ variant: Argon2id.Variant) throws -> String {
        try Argon2id.derive(
            password: password, salt: salt,
            memoryKiB: 32, iterations: 3, parallelism: 4,
            tagLength: 32, secret: secret, associatedData: associatedData,
            variant: variant
        ).map { String(format: "%02x", $0) }.joined()
    }

    func testArgon2d() throws {
        XCTAssertEqual(try derive(.d),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
    }

    func testArgon2i() throws {
        XCTAssertEqual(try derive(.i),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
    }

    func testArgon2id() throws {
        XCTAssertEqual(try derive(.id),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    /// The RFC vectors all use m=32, which gives a segment length of 2. The
    /// first segment of the first pass then runs zero times, so an entire code
    /// path goes unexercised — and that is exactly where a defect lived: the
    /// first address block was never generated, and every derivation at a
    /// realistic size was wrong while the three vectors above passed.
    ///
    /// Generated with the reference implementation:
    ///   printf 'password' | argon2 saltsaltsaltsalt -id -k M -t T -p P -l 32 -r
    func testMatchesTheReferenceImplementationAtRealisticSizes() throws {
        let vectors: [(m: Int, t: Int, p: Int, expected: String)] = [
            (8, 1, 1, "94c3e0558c1de1901090e8a964635193"),
            (64, 1, 1, "59bf4338b29483094be5f8da77db5f08"),
            (256, 4, 2, "602cef299d3307ab20e7d8cf14531e02"),
            (512, 1, 1, "c6c8932e8f7b0374cde76fcf68df034e"),
            (1024, 1, 1, "4c9a847bca2cfc41d97cbdd56a9739f4"),
            (4096, 3, 4, "7f77af0c247ce317b69574fc9ccf5008"),
        ]

        for vector in vectors {
            let tag = try Argon2id.derive(
                password: Array("password".utf8),
                salt: Array("saltsaltsaltsalt".utf8),
                memoryKiB: vector.m, iterations: vector.t,
                parallelism: vector.p, tagLength: 32, variant: .id)

            XCTAssertEqual(
                String(tag.map { String(format: "%02x", $0) }.joined().prefix(32)),
                vector.expected,
                "m=\(vector.m) t=\(vector.t) p=\(vector.p)")
        }
    }

    func testMatchesTheReferenceAtShippingParameters() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["SEALSTONE_SLOW_TESTS"] == "1",
            "set SEALSTONE_SLOW_TESTS=1 to run at shipping parameters")

        let tag = try Argon2id.derive(
            password: Array("password".utf8),
            salt: Array("saltsaltsaltsalt".utf8),
            memoryKiB: 65536, iterations: 3, parallelism: 4,
            tagLength: 32, variant: .id)

        XCTAssertEqual(
            String(tag.map { String(format: "%02x", $0) }.joined().prefix(32)),
            "ac15942c3e63386a50cb7dab2ef19c9a")
    }

    func testRejectsParametersOutOfRange() {
        func expectFailure(memory: Int = 64, iterations: Int = 1, parallelism: Int = 1) {
            XCTAssertThrowsError(try Argon2id.derive(
                password: password, salt: salt, memoryKiB: memory,
                iterations: iterations, parallelism: parallelism))
        }
        expectFailure(iterations: 0)
        expectFailure(parallelism: 0)
        expectFailure(memory: 4, parallelism: 1)   // below 8 * parallelism
    }

    func testDifferentSaltsGiveDifferentKeys() throws {
        let a = try Argon2id.derive(password: password, salt: [UInt8](repeating: 1, count: 16),
                                    memoryKiB: 64, iterations: 1, parallelism: 1)
        let b = try Argon2id.derive(password: password, salt: [UInt8](repeating: 2, count: 16),
                                    memoryKiB: 64, iterations: 1, parallelism: 1)
        XCTAssertNotEqual(a, b)
    }
}
