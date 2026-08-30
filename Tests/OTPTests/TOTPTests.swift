import XCTest
@testable import OTP
import VaultCore

/// RFC 6238 Appendix B. Each algorithm uses a different seed length.
final class TOTPTests: XCTestCase {
    private let seeds: [Authenticator.Algorithm: [UInt8]] = [
        .sha1: Array("12345678901234567890".utf8),
        .sha256: Array("12345678901234567890123456789012".utf8),
        .sha512: Array("1234567890123456789012345678901234567890123456789012345678901234".utf8),
    ]

    private let vectors: [(TimeInterval, [Authenticator.Algorithm: String])] = [
        (59, [.sha1: "94287082", .sha256: "46119246", .sha512: "90693936"]),
        (1111111109, [.sha1: "07081804", .sha256: "68084774", .sha512: "25091201"]),
        (1111111111, [.sha1: "14050471", .sha256: "67062674", .sha512: "99943326"]),
        (1234567890, [.sha1: "89005924", .sha256: "91819424", .sha512: "93441116"]),
        (2000000000, [.sha1: "69279037", .sha256: "90698825", .sha512: "38618901"]),
        (20000000000, [.sha1: "65353130", .sha256: "77737706", .sha512: "47863826"]),
    ]

    func testRFC6238Vectors() throws {
        for (timestamp, expected) in vectors {
            for (algorithm, code) in expected {
                XCTAssertEqual(
                    try OneTimePassword.totp(
                        secret: seeds[algorithm]!,
                        at: Date(timeIntervalSince1970: timestamp),
                        digits: 8, algorithm: algorithm),
                    code, "t=\(timestamp) \(algorithm)")
            }
        }
    }

    func testCodeIsStableWithinItsPeriod() throws {
        let secret = seeds[.sha1]!
        let aligned: Int = 1234567890 - (1234567890 % 30)
        let base = Date(timeIntervalSince1970: TimeInterval(aligned))

        let first = try OneTimePassword.totp(secret: secret, at: base)
        XCTAssertEqual(try OneTimePassword.totp(secret: secret, at: base.addingTimeInterval(29)),
                       first)
        XCTAssertNotEqual(try OneTimePassword.totp(secret: secret, at: base.addingTimeInterval(30)),
                          first)
    }

    func testRejectsPeriodOutOfRange() {
        XCTAssertThrowsError(try OneTimePassword.totp(secret: seeds[.sha1]!, period: 0))
    }

    func testSecondsRemaining() {
        XCTAssertEqual(OneTimePassword.secondsRemaining(at: Date(timeIntervalSince1970: 1000)),
                       20.0, accuracy: 0.001)
        XCTAssertEqual(OneTimePassword.secondsRemaining(at: Date(timeIntervalSince1970: 1020)),
                       30.0, accuracy: 0.001)
    }
}
