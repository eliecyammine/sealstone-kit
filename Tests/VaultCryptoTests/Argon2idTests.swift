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
