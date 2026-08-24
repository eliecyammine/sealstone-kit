import XCTest
@testable import VaultCrypto

final class ImpressionRegressionTests: XCTestCase {
    private let passphrase = "correct horse battery staple"

    private func fastSeal(_ plaintext: [UInt8]) throws -> [UInt8] {
        try Impression.seal(plaintext, using: .passphrase(passphrase),
                            memoryKiB: 64, iterations: 1, parallelism: 1)
    }

    /// A truncated file must produce a message, at every length, rather than a
    /// crash or an index error.
    func testTruncationAtEveryLengthIsRejectedCleanly() throws {
        let blob = try fastSeal(Array("{}".utf8))

        for length in 0..<blob.count {
            let truncated = Array(blob[..<length])
            XCTAssertThrowsError(
                try Impression.open(truncated, using: .passphrase(passphrase)),
                "a file truncated to \(length) bytes was accepted"
            ) { error in
                XCTAssertTrue(error is ImpressionError,
                              "length \(length) failed with \(error)")
            }
        }
    }

    /// The format requires zero KDF parameters when no derivation is used.
    /// The tag catches a file altered after sealing, but not one written this
    /// way by a non-conforming implementation.
    func testKeyBasedFileMustCarryZeroKDFParameters() throws {
        let key = [UInt8](repeating: 0x2A, count: 32)
        let blob = try Impression.seal(Array("{}".utf8), using: .key(key))

        XCTAssertNoThrow(try Impression.open(blob, using: .key(key)))

        for offset in [11, 15, 19] {   // memory, iterations, parallelism
            var corrupted = blob
            corrupted[offset] = 0x01
            XCTAssertThrowsError(try Impression.open(corrupted, using: .key(key)),
                                 "non-zero KDF field at \(offset) was accepted")
        }
    }

    /// Argon2id is public, so a caller reaching it directly must face the same
    /// ceiling the envelope applies.
    func testDirectDerivationIsBounded() {
        XCTAssertThrowsError(
            try Argon2id.derive(password: [1], salt: [UInt8](repeating: 2, count: 16),
                                memoryKiB: Argon2id.maxMemoryKiB + 1,
                                iterations: 1, parallelism: 1)
        ) { error in
            guard case Argon2id.Failure.allocationRefused = error else {
                return XCTFail("wrong error: \(error)")
            }
        }
    }
}
