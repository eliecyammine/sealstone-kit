import Testing
import Foundation
import VaultCore
import VaultCrypto
@testable import VaultStore

/// Sealing a handover and opening it again.
///
/// These are the tests that decide whether somebody gets back in. Everything
/// else in this package fails in front of a person who can ask for help; a
/// handover fails in front of a person who cannot.
struct HandoverSealingTests {
    private let at = Date(timeIntervalSince1970: 1_780_000_000)

    private func vault() -> VaultDocument {
        VaultDocument(
            vaultId: SealstoneID.make(.vault, at: at),
            accounts: [
                Account(id: "acc_bank", service: "Bank", identifier: "a@example.com"),
                Account(id: "acc_mail", service: "Mail", identifier: "b@example.com"),
                Account(id: "acc_private", service: "Kept back", identifier: "c@example.com"),
            ],
            items: [
                Item(id: "itm_bank", accountId: "acc_bank",
                     payload: .note(Note(title: "Bank", body: "the bank codes"))),
                Item(id: "itm_mail", accountId: "acc_mail",
                     payload: .note(Note(title: "Mail", body: "the mail codes"))),
                Item(id: "itm_private", accountId: "acc_private",
                     payload: .note(Note(title: "Private", body: "never handed over"))),
            ])
    }

    private let recipients = [
        HandoverSealing.Recipient(displayName: "Sister", contact: "s@example.com"),
        HandoverSealing.Recipient(displayName: "Solicitor", contact: "l@example.com"),
        HandoverSealing.Recipient(displayName: "Friend", contact: "f@example.com"),
    ]

    private func sealed(threshold: Int = 2) throws -> HandoverSealing.Sealed {
        try HandoverSealing.seal(itemIds: ["itm_bank", "itm_mail"],
                                 from: vault(), to: recipients,
                                 threshold: threshold,
                                 note: "The bank and the email.", at: at)
    }

    // MARK: - The whole point

    /// Enough fragments open it. This is the property the product sells.
    @Test func enoughFragmentsOpenTheBundle() throws {
        let handover = try sealed()
        let opened = try HandoverSealing.open(
            bundle: handover.bundle,
            with: Array(handover.fragments.prefix(2)))

        #expect(opened.items.map(\.id).sorted() == ["itm_bank", "itm_mail"])
    }

    /// Any two of the three, not just the first two. A keeper is whoever turns
    /// up, and which two of them it is cannot matter.
    @Test func anyTwoOfThemWillDo() throws {
        let handover = try sealed()
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let opened = try HandoverSealing.open(
                bundle: handover.bundle,
                with: pair.map { handover.fragments[$0] })
            #expect(opened.items.count == 2, "fragments \(pair) failed to open it")
        }
    }

    /// **One fragment is nothing.** Not a partial vault, not a hint.
    @Test func oneFragmentOpensNothing() throws {
        let handover = try sealed(threshold: 3)
        #expect(throws: (any Error).self) {
            try HandoverSealing.open(bundle: handover.bundle,
                                     with: [handover.fragments[0]])
        }
    }

    @Test func tooFewFragmentsOpenNothing() throws {
        let handover = try sealed(threshold: 3)
        #expect(throws: (any Error).self) {
            try HandoverSealing.open(bundle: handover.bundle,
                                     with: Array(handover.fragments.prefix(2)))
        }
    }

    // MARK: - What the keepers get

    /// **A handover is a subset.** What was kept back must not be anywhere in
    /// the bytes, not merely absent from the parsed result.
    @Test func whatWasKeptBackIsNotInTheCiphertextEither() throws {
        let handover = try sealed()
        let opened = try HandoverSealing.open(
            bundle: handover.bundle, with: Array(handover.fragments.prefix(2)))

        #expect(!opened.accounts.contains { $0.id == "acc_private" })
        let text = String(decoding: try VaultCoding.encode(opened), as: UTF8.self)
        #expect(!text.contains("never handed over"))
    }

    /// One file, copied. It is ciphertext and opens for nobody without enough
    /// fragments, so there is no reason for each keeper to hold a different one
    /// and every reason not to produce three things where one will do.
    @Test func everyKeeperGetsTheSameBundle() throws {
        let handover = try sealed()
        #expect(handover.fragments.count == 3)
        #expect(Set(handover.fragments.map(\.index)).count == 3)
        #expect(handover.keepers.map(\.fragmentIndex).sorted() == [1, 2, 3])
    }

    /// Two handovers cut from one vault share nothing. A keeper on one cannot
    /// combine with a keeper on the other.
    @Test func twoHandoversAreIndependent() throws {
        let first = try sealed()
        let second = try sealed()

        #expect(first.handover.setId != second.handover.setId)
        #expect(first.handover.bundleId != second.handover.bundleId)
        #expect(throws: (any Error).self) {
            try HandoverSealing.open(bundle: first.bundle,
                                     with: Array(second.fragments.prefix(2)))
        }
    }

    /// The keeper list is not carried into what the keepers hold, so none of
    /// them learns who the others are.
    @Test func theBundleNamesNoKeepers() throws {
        let handover = try sealed()
        let opened = try HandoverSealing.open(
            bundle: handover.bundle, with: Array(handover.fragments.prefix(2)))

        #expect(opened.keepers.isEmpty)
        let text = String(decoding: try VaultCoding.encode(opened), as: UTF8.self)
        #expect(!text.contains("Solicitor"))
    }

    // MARK: - The envelope

    /// Sealed under a key, not a passphrase, so the header says there is no key
    /// derivation to run. A keeper is not asked for a password they were never
    /// given.
    @Test func theBundleCarriesNoKeyDerivation() throws {
        let header = try Impression.inspect(try sealed().bundle)
        #expect(header.kdf == .none)
    }

    @Test func itIsAnOrdinaryImpressionAnythingCanRead() throws {
        let handover = try sealed()
        let header = try Impression.inspect(handover.bundle)
        #expect(header.formatMajor == 1)
    }

    // MARK: - What cannot be sealed

    @Test func handingOverNothingIsRefused() {
        #expect(throws: HandoverSealing.Failure.nothingChosen) {
            try HandoverSealing.seal(itemIds: [], from: vault(),
                                     to: recipients, threshold: 2, at: at)
        }
    }

    /// A threshold of one is not a split. It is the key, copied, handed to
    /// three people.
    @Test func aThresholdOfOneIsRefused() {
        #expect(throws: HandoverSealing.Failure.self) {
            try HandoverSealing.seal(itemIds: ["itm_bank"], from: vault(),
                                     to: recipients, threshold: 1, at: at)
        }
    }

    /// And one nobody could ever meet leaves the data unreachable forever.
    @Test func aThresholdAboveTheKeeperCountIsRefused() {
        #expect(throws: HandoverSealing.Failure.self) {
            try HandoverSealing.seal(itemIds: ["itm_bank"], from: vault(),
                                     to: recipients, threshold: 4, at: at)
        }
    }
}
