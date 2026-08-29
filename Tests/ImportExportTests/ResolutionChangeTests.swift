import XCTest
@testable import ImportExport
import VaultCore

/// Changing your mind about a duplicate, twice.
final class ResolutionChangeTests: XCTestCase {
    private func staged() -> ImportStaging {
        let vault = VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "GitHub", identifier: "elie")],
            items: [Item(id: "existing", accountId: "a1",
                         payload: .authenticator(
                            Authenticator(secret: "JBSWY3DPEHPK3PXP")))])

        var staging = ImportStaging(candidates: [
            .init(issuer: "GitHub", account: "elie",
                  authenticator: Authenticator(secret: "JBSWY3DPEHPK3PXP")),
        ])
        staging.markDuplicates(against: vault)
        return staging
    }

    /// Skip used to destroy the only record of what would have been replaced,
    /// so choosing Replace afterwards did nothing at all and the control
    /// snapped back with no explanation.
    func testReplaceIsStillReachableAfterChoosingSkip() throws {
        var staging = staged()
        let id = try XCTUnwrap(staging.candidates.first?.id)
        let target = try XCTUnwrap(staging.candidates.first?.duplicateOf)

        staging.setResolution(.skip, for: id)
        XCTAssertEqual(staging.candidates.first?.duplicateOf, target,
                       "what it duplicates does not change because of what was chosen")

        staging.setResolution(.replace(existingItemId: target), for: id)
        if case .replace(let chosen) = staging.candidates.first?.resolution {
            XCTAssertEqual(chosen, target)
        } else {
            XCTFail("replace should be reachable again")
        }
    }

    /// And it stays in the duplicates list whatever is chosen, so it does not
    /// vanish out of the review while being looked at.
    func testADuplicateStaysListedWhicheverChoiceIsMade() throws {
        var staging = staged()
        let id = try XCTUnwrap(staging.candidates.first?.id)

        for resolution in [ImportStaging.Resolution.skip, .add] {
            staging.setResolution(resolution, for: id)
            XCTAssertEqual(staging.duplicates.count, 1, "still a duplicate")
        }
    }

    func testSomethingNewIsNeverADuplicate() {
        var staging = ImportStaging(candidates: [
            .init(issuer: "Fastmail", account: "me",
                  authenticator: Authenticator(secret: "GEZDGNBVGY3TQOJQ")),
        ])
        staging.markDuplicates(against: VaultDocument(vaultId: "v1"))

        XCTAssertNil(staging.candidates.first?.duplicateOf)
        XCTAssertTrue(staging.duplicates.isEmpty)
    }
}
