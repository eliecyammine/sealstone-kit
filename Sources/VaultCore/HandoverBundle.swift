public import Foundation

/// Cutting a bundle out of a vault, and checking one that arrives from
/// somewhere else.
///
/// A bundle is an ordinary vault document carrying only what is being handed
/// over, plus the `handover` object saying what it is. Ordinary on purpose: a
/// keeper reconstructing one in ten years is the least supported reader this
/// format has, and giving them a second document type to find a reader for is
/// a way of making a bad day worse.
///
/// **Two of the rules are privacy rules and are enforced by construction rather
/// than checked afterwards.** The keeper list is emptied, because copying it in
/// would tell every keeper who the others are. Links are kept only where both
/// ends are in the bundle, because a link pointing outward names an account the
/// keeper was not given and so leaks that it exists. Building a bundle that
/// breaks either is not something this offers.
public enum HandoverBundle {
    public enum Problem: Error, Sendable, Hashable {
        /// No `handover` object, so this is a vault and not a bundle.
        case notABundle
        /// Tells each keeper who the others are.
        case keepersAreNotEmpty(count: Int)
        /// Names an account the keeper was not given, which leaks that it
        /// exists.
        case linkPointsOutside(linkId: String, accountId: String)
        /// An item with no account in the bundle cannot be acted on.
        case itemHasNoAccount(itemId: String, accountId: String)
        case setIdIsNotSixteenBytes(String)
        case thresholdMakesNoSense(threshold: Int, total: Int)
        case bundleIdIsMalformed(String)
        case vaultIdIsMalformed(String)
        /// A fragment from another split. Caught here rather than as an
        /// obscure failure to reconstruct.
        case fragmentBelongsToAnotherSet
        case fragmentDisagreesAboutTheSplit(bundleThreshold: Int, bundleTotal: Int,
                                            fragmentThreshold: Int, fragmentTotal: Int)
    }

    /// The chosen items, the accounts they hang off, and nothing else.
    ///
    /// `vaultId` is carried across rather than made fresh: a keeper handing
    /// this back has to be matchable to the vault it came from.
    public static func cut(from vault: VaultDocument,
                           itemIds: Set<String>,
                           handover: Handover,
                           at date: Date = Date()) -> VaultDocument {
        let items = vault.items.filter { itemIds.contains($0.id) }
        let accountIds = Set(items.map(\.accountId))
        let accounts = vault.accounts.filter { accountIds.contains($0.id) }

        // Both ends, or it does not travel.
        let links = vault.links.filter {
            accountIds.contains($0.sourceAccountId)
                && accountIds.contains($0.targetAccountId)
        }

        return VaultDocument(
            vaultId: vault.vaultId,
            createdAt: vault.createdAt,
            updatedAt: Timestamp(date),
            accounts: accounts,
            items: items,
            links: links,
            // Emptied, not copied.
            keepers: [],
            handover: handover)
    }

    /// Everything wrong with a bundle that can be told from the bundle alone.
    ///
    /// Returns all of them rather than the first. Somebody looking at a file
    /// that will not open wants to know what is wrong with it, not to discover
    /// one fault per attempt.
    public static func problems(with document: VaultDocument) -> [Problem] {
        guard let handover = document.handover else { return [.notABundle] }

        var problems: [Problem] = []

        if !document.keepers.isEmpty {
            problems.append(.keepersAreNotEmpty(count: document.keepers.count))
        }
        if handover.setIdBytes == nil {
            problems.append(.setIdIsNotSixteenBytes(handover.setId))
        }
        if handover.threshold < 2 || handover.threshold > handover.total
            || handover.total > 255 {
            problems.append(.thresholdMakesNoSense(threshold: handover.threshold,
                                                   total: handover.total))
        }
        if SealstoneID.parse(handover.bundleId)?.kind != .bundle {
            problems.append(.bundleIdIsMalformed(handover.bundleId))
        }
        if SealstoneID.parse(document.vaultId)?.kind != .vault {
            problems.append(.vaultIdIsMalformed(document.vaultId))
        }

        let accountIds = Set(document.accounts.map(\.id))
        for link in document.links {
            for end in [link.sourceAccountId, link.targetAccountId]
            where !accountIds.contains(end) {
                problems.append(.linkPointsOutside(linkId: link.id, accountId: end))
            }
        }
        for item in document.items where !accountIds.contains(item.accountId) {
            problems.append(.itemHasNoAccount(itemId: item.id,
                                              accountId: item.accountId))
        }

        return problems
    }

    /// And what can only be told by holding the fragments beside it.
    ///
    /// Checked before reconstruction is attempted, so a fragment from the wrong
    /// set is named rather than producing a key that opens nothing.
    public static func problems(with document: VaultDocument,
                                given fragments: [Fragment]) -> [Problem] {
        var problems = problems(with: document)
        guard let handover = document.handover else { return problems }

        for fragment in fragments {
            if let expected = handover.setIdBytes, fragment.setId != expected {
                problems.append(.fragmentBelongsToAnotherSet)
            }
            if Int(fragment.threshold) != handover.threshold
                || Int(fragment.total) != handover.total {
                problems.append(.fragmentDisagreesAboutTheSplit(
                    bundleThreshold: handover.threshold,
                    bundleTotal: handover.total,
                    fragmentThreshold: Int(fragment.threshold),
                    fragmentTotal: Int(fragment.total)))
            }
        }

        return problems
    }
}
