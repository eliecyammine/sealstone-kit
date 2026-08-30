import XCTest
@testable import VaultCore

/// The one rule for whether two names mean the same account.
final class AccountMatchKeyTests: XCTestCase {
    func testCaseDoesNotMakeADifferentAccount() {
        XCTAssertEqual(Account.matchKey(service: "GitHub", identifier: "Elie"),
                       Account.matchKey(service: "github", identifier: "elie"))
    }

    func testSurroundingSpaceDoesNotMakeADifferentAccount() {
        XCTAssertEqual(Account.matchKey(service: "  GitHub ", identifier: "elie\n"),
                       Account.matchKey(service: "GitHub", identifier: "elie"))
    }

    func testDifferentAccountsStayDifferent() {
        XCTAssertNotEqual(Account.matchKey(service: "GitHub", identifier: "elie"),
                          Account.matchKey(service: "GitHub", identifier: "someone"))
        XCTAssertNotEqual(Account.matchKey(service: "GitHub", identifier: "elie"),
                          Account.matchKey(service: "GitLab", identifier: "elie"))
    }

    /// The separator stops two different splits colliding: "ab" + "c" must not
    /// key the same as "a" + "bc".
    func testFieldsCannotRunTogether() {
        XCTAssertNotEqual(Account.matchKey(service: "ab", identifier: "c"),
                          Account.matchKey(service: "a", identifier: "bc"))
    }

    /// The document's own lookup and the key agree, which is the whole point
    /// of there being one function.
    func testLookupAgreesWithTheKey() {
        var document = VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "İşbank", identifier: "elie")])

        let found = document.accountId(forService: "İŞBANK", identifier: "ELIE")
        XCTAssertEqual(found, "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }
}
