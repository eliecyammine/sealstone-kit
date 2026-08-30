import XCTest
@testable import OTP
import VaultCore

/// A recovered vault must yield codes, not just secrets.
final class GenerateFromItemTests: XCTestCase {
    private let base = Authenticator(secret: "GEZDGNBVGY3TQOJQ")

    func testTOTPItemMatchesDirectCall() throws {
        let secret = try Base32.decode(base.secret)
        let at = Date(timeIntervalSince1970: 1234567890)
        XCTAssertEqual(try OneTimePassword.generate(base, at: at),
                       try OneTimePassword.totp(secret: secret, at: at))
    }

    func testHOTPItemUsesItsCounter() throws {
        var item = base
        item.kind = .hotp(counter: 5)
        let secret = try Base32.decode(item.secret)
        XCTAssertEqual(try OneTimePassword.generate(item),
                       try OneTimePassword.hotp(secret: secret, counter: 5))
    }

    func testSteamItem() throws {
        var item = base
        item.kind = .steam
        XCTAssertEqual(try OneTimePassword.generate(
            item, at: Date(timeIntervalSince1970: 1234567890)).count, 5)
    }

    func testEightDigitSHA256Item() throws {
        var item = Authenticator(secret: "GEZDGNBVGY3TQOJQ", algorithm: .sha256,
                                 digits: 8, period: 60)
        item.kind = .totp
        let code = try OneTimePassword.generate(item, at: Date(timeIntervalSince1970: 1234567890))
        XCTAssertEqual(code.count, 8)
    }

    func testRejectsInvalidSecret() {
        let item = Authenticator(secret: "not base32!")
        XCTAssertThrowsError(try OneTimePassword.generate(item))
    }
}
