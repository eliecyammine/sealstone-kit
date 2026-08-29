import XCTest
@testable import ImportExport
import VaultCore

final class ImportStagingTests: XCTestCase {
    private func document() -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "Example", identifier: "me")],
            items: [Item(id: "i1", accountId: "a1",
                         payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP")))])
    }

    func testApplyAddsAccountsAndItems() throws {
        var staging = try Importer.stage(Data("""
        otpauth://totp/NewService:someone?secret=GEZDGNBVGY3TQOJQ
        """.utf8))
        staging.markDuplicates(against: document())

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.accounts.count, 2)
        XCTAssertEqual(updated.items.count, 2)
    }

    func testDuplicateDetectionMatchesOnAccountAndSecret() throws {
        var staging = try Importer.stage(Data("""
        otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP
        otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ
        """.utf8))
        staging.markDuplicates(against: document())

        // Same account, same secret is a duplicate. Same account, different
        // secret is a genuinely new credential.
        XCTAssertEqual(staging.duplicates.count, 1)
        XCTAssertEqual(staging.willAdd.count, 1)
    }

    func testReplaceUpdatesInPlace() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&digits=8".utf8))
        staging.markDuplicates(against: document())
        XCTAssertEqual(staging.duplicates.count, 1)

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.items.count, 1, "replace created a second item")
        guard case .authenticator(let authenticator) = updated.items[0].payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(authenticator.digits, 8)
    }

    func testSkipLeavesTheVaultUntouched() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/New:someone?secret=GEZDGNBVGY3TQOJQ".utf8))
        for candidate in staging.candidates {
            staging.setResolution(.skip, for: candidate.id)
        }

        let original = document()
        let updated = try staging.apply(to: original)
        XCTAssertEqual(updated.items.count, original.items.count)
        XCTAssertEqual(updated.accounts.count, original.accounts.count)
    }

    func testApplyValidatesTheResult() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/New:someone?secret=GEZDGNBVGY3TQOJQ".utf8))
        staging.setResolution(.replace(existingItemId: "does-not-exist"),
                              for: staging.candidates[0].id)

        XCTAssertThrowsError(try staging.apply(to: document()))
    }

    func testExistingAccountIsReusedRatherThanDuplicated() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ".utf8))
        staging.markDuplicates(against: document())

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.accounts.count, 1, "a duplicate account was created")
        XCTAssertEqual(updated.items.count, 2)
    }
}
