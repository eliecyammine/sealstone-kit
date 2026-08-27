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

/// Clocks that are wrong in the one direction `UInt64` cannot hold.
final class PreEpochClockTests: XCTestCase {
    private let secret = try! Base32.decode("JBSWY3DPEHPK3PXP")

    /// A device whose clock is before 1970 used to crash on every code drawn.
    func testADateBeforeTheEpochProducesACodeRatherThanACrash() throws {
        let code = try OneTimePassword.totp(
            secret: secret, at: Date(timeIntervalSince1970: -86_400))
        XCTAssertEqual(code.count, 6)
    }

    /// Reachable without a strange clock: the previous-window code subtracts a
    /// period, so a clock near the epoch arrives negative on its own.
    func testTheWindowBeforeTheEpochIsStillAnswerable() throws {
        let atEpoch = Date(timeIntervalSince1970: 0)
        let before = atEpoch.addingTimeInterval(-30)

        XCTAssertNoThrow(try OneTimePassword.totp(secret: secret, at: before))
        XCTAssertEqual(try OneTimePassword.totp(secret: secret, at: before),
                       try OneTimePassword.totp(secret: secret, at: atEpoch),
                       "before time started, there is one window and it is the first")
    }

    func testSteamSurvivesItToo() {
        XCTAssertEqual(
            OneTimePassword.steam(secret: secret,
                                  at: Date(timeIntervalSince1970: -1_000)).count, 5)
    }
}
