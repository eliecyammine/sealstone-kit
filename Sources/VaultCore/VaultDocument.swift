public import Foundation


extension Account {
    /// The form two names are compared in to decide whether they mean the same
    /// account.
    ///
    /// A single function rather than a comparison in one place and a
    /// dictionary key in another. Those two existed and disagreed: one folded
    /// case the way the user's language does, the other lowercased bytes, so
    /// importing and adding by hand could reach different answers in languages
    /// where those differ.
    ///
    /// Locale-aware, because these are names people typed or a service
    /// exported, not identifiers.
    public static func matchKey(service: String, identifier: String) -> String {
        let fold = { (text: String) in
            text.trimmingCharacters(in: .whitespacesAndNewlines)
                .folding(options: .caseInsensitive, locale: .current)
        }
        return "\(fold(service))\u{0}\(fold(identifier))"
    }
}



/// The whole vault: what gets encrypted into an Impression.
public struct VaultDocument: Sendable, Hashable {
    public static let currentFormatVersion = 1

    public var formatVersion: Int
    public let vaultId: String
    public var createdAt: Timestamp
    public var updatedAt: Timestamp
    public var accounts: [Account]
    public var items: [Item]
    public var links: [Link]
    public var keepers: [Keeper]

    /// Top-level keys written by a newer version, carried through untouched.
    ///
    /// Opening a vault in an older build and saving it must not destroy what
    /// the newer build put there. Synthesised `Codable` cannot do this: it
    /// writes back only the keys it has properties for, so the coding is
    /// written out by hand in `VaultDocument+Coding.swift`.
    public var unrecognised: [String: JSONValue]

    public init(
        vaultId: String = SealstoneID.make(.vault),
        createdAt: Timestamp = .now(),
        updatedAt: Timestamp = .now(),
        accounts: [Account] = [],
        items: [Item] = [],
        links: [Link] = [],
        keepers: [Keeper] = [],
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.formatVersion = Self.currentFormatVersion
        self.vaultId = vaultId
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.accounts = accounts
        self.items = items
        self.links = links
        self.keepers = keepers
        self.unrecognised = unrecognised
    }
}

// MARK: - Accounts

extension VaultDocument {
    /// The account for a service and identifier, creating one if there is none.
    ///
    /// Two credentials for the same service and the same login belong to one
    /// account, which is what lets a TOTP secret and that account's recovery
    /// codes sit together. Deciding when two names are the same account is the
    /// whole of it, and it has to be decided in one place: every caller that
    /// writes its own version is a way for two of them to disagree about
    /// whether "GitHub" and "github" are one account or two.
    ///
    /// Matching is case-insensitive and locale-aware. These are names people
    /// typed or a service exported, not identifiers, and `lowercased()` gets
    /// languages such as Turkish wrong.
    public mutating func accountId(forService service: String,
                                   identifier: String) -> String {
        let wanted = Account.matchKey(service: service, identifier: identifier)
        if let existing = accounts.first(where: {
            Account.matchKey(service: $0.service, identifier: $0.identifier) == wanted
        }) {
            return existing.id
        }

        let account = Account(id: SealstoneID.make(.account),
                              service: service,
                              identifier: identifier)
        accounts.append(account)
        return account.id
    }
}

// MARK: - Lookups

extension VaultDocument {
    public func account(_ id: String) -> Account? {
        accounts.first { $0.id == id }
    }

    public func items(for accountId: String) -> [Item] {
        items.filter { $0.accountId == accountId }
    }

    public var authenticators: [(item: Item, authenticator: Authenticator)] {
        items.compactMap { item in
            guard case .authenticator(let value) = item.payload else { return nil }
            return (item, value)
        }
    }

    /// Accounts that can be used to recover the given account.
    public func recoveryPaths(into accountId: String) -> [Link] {
        links.filter { $0.targetAccountId == accountId }
    }

    /// Accounts that depend on the given one to get back in.
    public func dependents(of accountId: String) -> [Link] {
        links.filter { $0.sourceAccountId == accountId }
    }
}
