import XCTest
@testable import ImportExport
import VaultCore

/// Spotting what is already in the vault.
final class DuplicateSymmetryTests: XCTestCase {
    private func vault() -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "me@example.com",
                               identifier: "me@example.com")],
            items: [Item(id: "existing", accountId: "a1",
                         payload: .authenticator(
                            Authenticator(secret: "JBSWY3DPEHPK3PXP")))])
    }

    /// A candidate with no issuer is filed under its account name, so that is
    /// what it has to be matched on. Keying it on "" meant this duplicate was
    /// never found, which is the one hardest to notice by eye.
    func testACandidateWithNoIssuerStillMatches() {
        var staging = ImportStaging(candidates: [
            .init(issuer: nil, account: "me@example.com",
                  authenticator: Authenticator(secret: "JBSWY3DPEHPK3PXP")),
        ])
        staging.markDuplicates(against: vault())

        XCTAssertEqual(staging.duplicates.count, 1)
        if case .replace(let itemId) = staging.duplicates.first?.resolution {
            XCTAssertEqual(itemId, "existing")
        } else {
            XCTFail("should have resolved to replacing the existing item")
        }
    }

    func testADifferentSecretOnTheSameAccountIsNotADuplicate() {
        var staging = ImportStaging(candidates: [
            .init(issuer: nil, account: "me@example.com",
                  authenticator: Authenticator(secret: "GEZDGNBVGY3TQOJQ")),
        ])
        staging.markDuplicates(against: vault())
        XCTAssertTrue(staging.duplicates.isEmpty)
    }
}
