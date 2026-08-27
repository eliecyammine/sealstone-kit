/// Counts of what a vault holds, item type by item type.
///
/// The counts are a fact about the vault, so they are computed here in the
/// core rather than in any app that reports them. The order is fixed by this
/// type: a presentation that re-ordered or re-sorted itself as counts changed
/// would make the same facts look different on every visit.
public struct VaultSummary: Sendable, Hashable {
    public var itemCounts: [ItemTypeCount]
    public var totalItems: Int
    public var accounts: Int
    /// The number of distinct, non-empty service names among the accounts.
    /// "Google" used by three accounts is one service. An empty name (which
    /// can be imported) counts as nothing.
    public var services: Int
    public var links: Int
    public var keepers: Int
}

/// The count of one item type, in the order `VaultSummary` presents it.
public struct ItemTypeCount: Sendable, Hashable, Identifiable {
    public init(typeName: String, count: Int, isKnown: Bool) {
        self.typeName = typeName
        self.count = count
        self.isKnown = isKnown
    }

    /// The `Item.Payload.typeName` this row counts.
    public let typeName: String
    public let count: Int
    /// False when this version does not recognise the type. It is still
    /// counted and still carried, because unknown data must survive.
    public let isKnown: Bool
    public var id: String { typeName }
}

extension VaultDocument {
    /// Counts the material and relationships stored in the vault.
    ///
    /// Known types appear in the order this version understands them; anything
    /// written by a newer build follows, sorted by name. Rows for types with
    /// nothing stored are omitted, so `itemCounts` holds exactly what is here.
    /// Use `totalItems` when the question is "how much is in this vault".
    public var summary: VaultSummary {
        let knownOrder = [
            "authenticator",
            "recoveryCodes",
            "recoveryContact",
            "securityQuestions",
            "seedPhrase",
            "hardwareKey",
            "note",
        ]

        var tally: [String: Tally] = [:]
        for item in items {
            let typeName = item.payload.typeName
            var entry = tally[typeName] ?? Tally(count: 0, known: item.payload.isUnderstood)
            entry.count += 1
            // A payload this build cannot open must remain visibly unknown,
            // even if its type name collides with one this build normally
            // understands. That case is unusual, but hiding it would turn a
            // forward-compatibility fact into a misleading settings row.
            entry.known = entry.known && item.payload.isUnderstood
            tally[typeName] = entry
        }

        let knownRows: [ItemTypeCount] = knownOrder.compactMap { typeName in
            guard let entry = tally[typeName], entry.known else { return nil }
            return ItemTypeCount(typeName: typeName, count: entry.count, isKnown: entry.known)
        }

        let unknownRows: [ItemTypeCount] = tally
            .filter { !$0.value.known }
            .map { ItemTypeCount(typeName: $0.key, count: $0.value.count, isKnown: false) }
            .sorted { $0.typeName < $1.typeName }

        var distinctServices: Set<String> = []
        distinctServices.reserveCapacity(accounts.count)
        for account in accounts {
            let service = account.service.trimmingCharacters(in: .whitespacesAndNewlines)
            if !service.isEmpty {
                // Account matching is case-insensitive too: "Google" and
                // "google" are one service to the person reading Settings.
                distinctServices.insert(service.folding(options: .caseInsensitive,
                                                        locale: .current))
            }
        }

        return VaultSummary(
            itemCounts: knownRows + unknownRows,
            totalItems: items.count,
            accounts: accounts.count,
            services: distinctServices.count,
            links: links.count,
            keepers: keepers.count)
    }

    private struct Tally {
        var count: Int
        var known: Bool
    }
}
