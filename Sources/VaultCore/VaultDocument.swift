public import Foundation

/// A service account, and the anchor everything else hangs from.
public struct Account: Sendable, Hashable, Identifiable, Codable {
    public let id: String
    public var service: String
    public var identifier: String
    public var domain: String?
    public var tags: [String]
    public var notes: String?
    public var createdAt: Timestamp

    public init(
        id: String,
        service: String,
        identifier: String,
        domain: String? = nil,
        tags: [String] = [],
        notes: String? = nil,
        createdAt: Timestamp = .now()
    ) {
        self.id = id
        self.service = service
        self.identifier = identifier
        self.domain = domain
        self.tags = tags
        self.notes = notes
        self.createdAt = createdAt
    }
}

/// "This account can be used to recover that one." The edges of the recovery
/// graph, and the reason accounts and items are modelled separately.
public struct Link: Sendable, Hashable, Identifiable, Codable {
    public let id: String
    public var sourceAccountId: String
    public var targetAccountId: String
    public var method: Method
    public var verifiedAt: Timestamp?
    public var note: String?

    public enum Method: String, Sendable, Codable, CaseIterable {
        case email, sms, voice
        case backupCodes, securityQuestions, trustedContact, hardwareKey
        case other
    }

    public init(
        id: String,
        sourceAccountId: String,
        targetAccountId: String,
        method: Method,
        verifiedAt: Timestamp? = nil,
        note: String? = nil
    ) {
        self.id = id
        self.sourceAccountId = sourceAccountId
        self.targetAccountId = targetAccountId
        self.method = method
        self.verifiedAt = verifiedAt
        self.note = note
    }
}

/// Someone holding one fragment of a handover bundle key.
///
/// The fragment itself is never stored — the point is that it left. Only the
/// index is kept, so the app can say which fragment a given keeper holds.
public struct Keeper: Sendable, Hashable, Identifiable, Codable {
    public let id: String
    public var displayName: String
    public var contact: String
    public var bundleId: String
    public var fragmentIndex: Int
    public var issuedAt: Timestamp
    public var lastConfirmedAt: Timestamp?
    public var status: Status

    public enum Status: String, Sendable, Codable, CaseIterable {
        case active, unreachable, revoked
    }

    public init(
        id: String,
        displayName: String,
        contact: String,
        bundleId: String,
        fragmentIndex: Int,
        issuedAt: Timestamp = .now(),
        lastConfirmedAt: Timestamp? = nil,
        status: Status = .active
    ) {
        self.id = id
        self.displayName = displayName
        self.contact = contact
        self.bundleId = bundleId
        self.fragmentIndex = fragmentIndex
        self.issuedAt = issuedAt
        self.lastConfirmedAt = lastConfirmedAt
        self.status = status
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
