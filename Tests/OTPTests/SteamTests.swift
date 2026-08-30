import XCTest
@testable import OTP
import VaultCore

final class SteamTests: XCTestCase {
    func testShape() {
        let code = OneTimePassword.steam(secret: Array("12345678901234567890".utf8),
                                         at: Date(timeIntervalSince1970: 1234567890))
        XCTAssertEqual(code.count, 5)
        for character in code {
            XCTAssertTrue(OneTimePassword.steamAlphabet.contains(character))
        }
    }

    func testAlphabetOmitsConfusableCharacters() {
        for character in "01IOL" {
            XCTAssertFalse(OneTimePassword.steamAlphabet.contains(character))
        }
    }
}
