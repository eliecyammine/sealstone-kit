import Testing
import Foundation
@testable import VaultCore

/// Cutting a subset out of a vault and handing it to people.
///
/// The rules that matter here are not about correctness, they are about what a
/// keeper learns. A bundle that carried the keeper list would tell each of them
/// who the others are. A link pointing at an account that did not travel names
/// an account they were not given. Both are enforced when the bundle is cut,
/// so producing one that leaks either is not something this offers.
struct HandoverBundleTests {
    private let sealedAt = Timestamp(parsing: "2026-08-24T10:00:00Z")!

    private func handover(threshold: Int = 3, total: Int = 5) -> Handover {
        Handover(bundleId: "bnd_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
                 setId: "4F3A9C21000000000000000000000000",
                 threshold: threshold, total: total, sealedAt: sealedAt,
                 note: "For the family. The bank and the email.")
    }

    private func vault() -> VaultDocument {
        VaultDocument(
            vaultId: "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
            accounts: [
                Account(id: "acc_bank", service: "Bank", identifier: "a@example.com"),
                Account(id: "acc_mail", service: "Mail", identifier: "b@example.com"),
                Account(id: "acc_other", service: "Kept back", identifier: "c@example.com"),
            ],
            items: [
                Item(id: "itm_bank", accountId: "acc_bank",
                     payload: .note(Note(title: "Bank", body: "codes"))),
                Item(id: "itm_mail", accountId: "acc_mail",
                     payload: .note(Note(title: "Mail", body: "codes"))),
                Item(id: "itm_other", accountId: "acc_other",
                     payload: .note(Note(title: "Private", body: "not for them"))),
            ],
            links: [
                Link(id: "lnk_in", sourceAccountId: "acc_mail",
                     targetAccountId: "acc_bank", method: .email),
                Link(id: "lnk_out", sourceAccountId: "acc_other",
                     targetAccountId: "acc_bank", method: .email),
            ],
            keepers: [
                Keeper(id: "kpr_1", displayName: "Someone", contact: "s@example.com",
                       bundleId: "bnd_old", fragmentIndex: 1, issuedAt: sealedAt),
            ])
    }

    private func cut() -> VaultDocument {
        HandoverBundle.cut(from: vault(),
                           itemIds: ["itm_bank", "itm_mail"],
                           handover: handover(),
                           at: sealedAt.date)
    }

    // MARK: - What travels

    @Test func onlyTheChosenItemsAndTheirAccountsTravel() {
        let bundle = cut()
        #expect(bundle.items.map(\.id).sorted() == ["itm_bank", "itm_mail"])
        #expect(bundle.accounts.map(\.id).sorted() == ["acc_bank", "acc_mail"])
    }

    /// A subset is a subset. The account that was kept back stays kept back,
    /// and so does everything hanging off it.
    @Test func whatWasKeptBackIsNotInThere() throws {
        let encoded = try JSONEncoder().encode(cut())
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(!text.contains("not for them"))
        #expect(!text.contains("acc_other"))
    }

    /// **Copying the keeper list would tell every keeper who the others are.**
    @Test func theKeeperListIsEmptied() {
        #expect(cut().keepers.isEmpty)
        #expect(HandoverBundle.problems(with: cut()).isEmpty)
    }

    /// **A link pointing outward names an account they were not given.**
    @Test func aLinkWithOneEndOutsideDoesNotTravel() {
        let links = cut().links.map(\.id)
        #expect(links == ["lnk_in"])
    }

    @Test func itCarriesTheVaultItWasCutFrom() {
        #expect(cut().vaultId == vault().vaultId)
    }

    @Test func theNoteIsCarriedAsItWasWritten() {
        #expect(cut().handover?.note == "For the family. The bank and the email.")
    }

    // MARK: - Reading one that arrived from elsewhere

    @Test func aVaultIsNotABundle() {
        #expect(HandoverBundle.problems(with: vault()) == [.notABundle])
    }

    @Test func aBundleCarryingKeepersIsRefused() {
        var bundle = cut()
        bundle.keepers = vault().keepers
        #expect(HandoverBundle.problems(with: bundle)
            .contains(.keepersAreNotEmpty(count: 1)))
    }

    @Test func aDanglingLinkIsNamed() {
        var bundle = cut()
        bundle.links.append(Link(id: "lnk_dangling", sourceAccountId: "acc_bank",
                                 targetAccountId: "acc_gone", method: .email))
        #expect(HandoverBundle.problems(with: bundle)
            .contains(.linkPointsOutside(linkId: "lnk_dangling", accountId: "acc_gone")))
    }

    @Test func aSplitNobodyCouldMeetIsNamed() {
        var bundle = cut()
        bundle.handover = handover(threshold: 6, total: 5)
        #expect(HandoverBundle.problems(with: bundle)
            .contains(.thresholdMakesNoSense(threshold: 6, total: 5)))
    }

    /// Every fault at once. Somebody looking at a file that will not open wants
    /// to know what is wrong with it, not one fault per attempt.
    @Test func itReportsEveryFaultRatherThanTheFirst() {
        var bundle = cut()
        bundle.keepers = vault().keepers
        bundle.handover = Handover(bundleId: "not-an-identifier", setId: "nope",
                                   threshold: 9, total: 2, sealedAt: sealedAt)
        #expect(HandoverBundle.problems(with: bundle).count >= 4)
    }

    // MARK: - Against the fragments

    /// Caught here rather than as a reconstruction that produces a key opening
    /// nothing, which is a far worse thing to hand somebody.
    @Test func aFragmentFromAnotherSetIsCaughtBeforeReconstruction() throws {
        let wrongSet = try Fragment(setId: Array(repeating: 0xAB, count: 16),
                                    index: 1, threshold: 3, total: 5,
                                    share: Array(repeating: 0x01, count: 32))
        #expect(HandoverBundle.problems(with: cut(), given: [wrongSet])
            .contains(.fragmentBelongsToAnotherSet))
    }

    @Test func aFragmentThatDisagreesAboutTheSplitIsCaught() throws {
        let bundle = cut()
        let setId = try #require(bundle.handover?.setIdBytes)
        let disagreeing = try Fragment(setId: setId, index: 1, threshold: 2, total: 4,
                                       share: Array(repeating: 0x01, count: 32))
        #expect(HandoverBundle.problems(with: bundle, given: [disagreeing])
            .contains(.fragmentDisagreesAboutTheSplit(
                bundleThreshold: 3, bundleTotal: 5,
                fragmentThreshold: 2, fragmentTotal: 4)))
    }

    @Test func theRightFragmentRaisesNothing() throws {
        let bundle = cut()
        let setId = try #require(bundle.handover?.setIdBytes)
        let right = try Fragment(setId: setId, index: 2, threshold: 3, total: 5,
                                 share: Array(repeating: 0x01, count: 32))
        #expect(HandoverBundle.problems(with: bundle, given: [right]).isEmpty)
    }

    // MARK: - Round trip

    /// A bundle is a vault document, so everything §3 says about one applies,
    /// including that a key this version does not know survives being read and
    /// written again.
    @Test func aBundleSurvivesBeingWrittenAndReadBack() throws {
        let bundle = cut()
        let back = try JSONDecoder().decode(
            VaultDocument.self, from: try JSONEncoder().encode(bundle))
        #expect(back.handover == bundle.handover)
        #expect(back.items.count == 2)
    }

    /// Absent is what says a document is a vault, so it must not be written as
    /// null: the one bit a reader checks first cannot be ambiguous.
    @Test func aVaultWritesNoHandoverKeyAtAll() throws {
        let text = String(decoding: try JSONEncoder().encode(vault()), as: UTF8.self)
        #expect(!text.contains("handover"))
    }
}
