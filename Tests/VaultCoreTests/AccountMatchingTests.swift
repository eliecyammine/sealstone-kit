import XCTest
@testable import VaultCore

/// Deciding when two names are the same account.
final class AccountMatchingTests: XCTestCase {
    private func document() -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "GitHub", identifier: "elie")])
    }

    func testAnExistingAccountIsReused() {
        var document = document()
        let id = document.accountId(forService: "GitHub", identifier: "elie")

        XCTAssertEqual(id, "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }

    func testMatchingIgnoresCase() {
        var document = document()
        XCTAssertEqual(document.accountId(forService: "github", identifier: "ELIE"), "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }

    /// Locale-aware, not `lowercased()`. In Turkish, uppercase "I" lowercases
    /// to a dotless "ı", so a byte comparison decides these are two accounts.
    func testMatchingHandlesLanguagesWhereCaseIsNotASCII() {
        var document = VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "İşbank", identifier: "elie")])

        XCTAssertEqual(document.accountId(forService: "İŞBANK", identifier: "elie"), "a1")
        XCTAssertEqual(document.accounts.count, 1, "one account, not two spellings of it")
    }

    func testADifferentIdentifierIsADifferentAccount() {
        var document = document()
        let id = document.accountId(forService: "GitHub", identifier: "someone-else")

        XCTAssertNotEqual(id, "a1")
        XCTAssertEqual(document.accounts.count, 2)
    }

    func testANewAccountIsCreatedWithWhatWasAskedFor() {
        var document = document()
        let id = document.accountId(forService: "Fastmail", identifier: "me@example.com")

        let created = document.account(id)
        XCTAssertEqual(created?.service, "Fastmail")
        XCTAssertEqual(created?.identifier, "me@example.com")
    }
}
