import XCTest
@testable import OTP
import VaultCore

/// One test per reported defect. Each fails against the code as it was.
final class OTPRegressionTests: XCTestCase {
    private let secret = Array("12345678901234567890".utf8)

    /// The modulus was derived through Double and narrowed to UInt32. 10^10
    /// exceeds UInt32.max, so the longest permitted code length trapped.
    func testEveryPermittedDigitCountProducesACode() throws {
        for digits in 6...10 {
            let code = try OneTimePassword.hotp(secret: secret, counter: 0, digits: digits)
            XCTAssertEqual(code.count, digits, "digits = \(digits)")
            XCTAssertTrue(code.allSatisfy(\.isNumber), code)
        }
    }

    func testTenDigitCodesAcrossManyCounters() throws {
        for counter in 0..<50 {
            let code = try OneTimePassword.hotp(
                secret: secret, counter: UInt64(counter), digits: 10)
            XCTAssertEqual(code.count, 10, "counter \(counter)")
        }
    }

    /// The six-digit vectors must still hold after the modulus change.
    func testRFC4226StillPasses() throws {
        XCTAssertEqual(try OneTimePassword.hotp(secret: secret, counter: 0), "755224")
        XCTAssertEqual(try OneTimePassword.hotp(secret: secret, counter: 9), "520489")
    }
}
