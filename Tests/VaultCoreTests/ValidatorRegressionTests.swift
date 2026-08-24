import XCTest
@testable import VaultCore

final class ValidatorRegressionTests: XCTestCase {
    private func document(_ authenticator: Authenticator) -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "S", identifier: "me")],
            items: [Item(id: "i1", accountId: "a1", payload: .authenticator(authenticator))])
    }

    /// A Steam code is five characters from a 26-symbol alphabet, so the
    /// 6-to-10 digit rule never described it. Enforcing it rejected every
    /// Steam credential at the point of import.
    func testSteamCredentialValidates() throws {
        var steam = Authenticator(secret: "JBSWY3DPEHPK3PXP", digits: 5)
        steam.kind = .steam
        XCTAssertNoThrow(try VaultValidator.validate(document(steam)))
    }

    func testSteamRejectsAnythingOtherThanFive() {
        var steam = Authenticator(secret: "JBSWY3DPEHPK3PXP", digits: 6)
        steam.kind = .steam
        XCTAssertThrowsError(try VaultValidator.validate(document(steam)))
    }

    func testTOTPStillBoundedSixToTen() throws {
        for digits in 6...10 {
            let item = Authenticator(secret: "JBSWY3DPEHPK3PXP", digits: digits)
            XCTAssertNoThrow(try VaultValidator.validate(document(item)), "digits \(digits)")
        }
        for digits in [5, 11] {
            let item = Authenticator(secret: "JBSWY3DPEHPK3PXP", digits: digits)
            XCTAssertThrowsError(try VaultValidator.validate(document(item)), "digits \(digits)")
        }
    }
}
