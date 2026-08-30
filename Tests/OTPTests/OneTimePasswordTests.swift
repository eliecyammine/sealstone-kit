import XCTest
@testable import OTP
import VaultCore

/// RFC 4226 Appendix D.
final class HOTPTests: XCTestCase {
    private let secret = Array("12345678901234567890".utf8)
    private let expected = ["755224", "287082", "359152", "969429", "338314",
                            "254676", "287922", "162583", "399871", "520489"]

    func testRFC4226Vectors() throws {
        for (counter, code) in expected.enumerated() {
            XCTAssertEqual(
                try OneTimePassword.hotp(secret: secret, counter: UInt64(counter)),
                code, "counter \(counter)")
        }
    }

    func testRejectsDigitsOutOfRange() {
        XCTAssertThrowsError(try OneTimePassword.hotp(secret: secret, counter: 0, digits: 5))
        XCTAssertThrowsError(try OneTimePassword.hotp(secret: secret, counter: 0, digits: 11))
    }

    func testShortCodesArePaddedNotTruncated() throws {
        // A truncated value with leading zeros must still be the full width.
        for counter in 0..<200 {
            let code = try OneTimePassword.hotp(secret: secret, counter: UInt64(counter))
            XCTAssertEqual(code.count, 6, "counter \(counter) produced \(code)")
        }
    }
}
