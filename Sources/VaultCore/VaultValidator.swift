public import Foundation

/// Checks a decoded document before anything acts on it.
///
/// Decoding proves the shape is right. This proves the contents are coherent:
/// identifiers unique, references resolvable, sizes within bounds.
public enum VaultValidator {
    public static let maxAccounts = 100_000
    public static let maxItems = 500_000
    public static let maxLinks = 1_000_000
    /// The ceiling on any single string, in bytes. A megabyte is far past any
    /// real value and well short of what makes a document a weapon.
    public static let maxStringBytes = 1024 * 1024

    public static func validate(_ document: VaultDocument) throws {
        guard document.formatVersion == VaultDocument.currentFormatVersion else {
            throw VaultError.unsupportedFormatVersion(
                found: document.formatVersion,
                supported: VaultDocument.currentFormatVersion)
        }

        try checkSize(document.accounts.count, "accounts", limit: maxAccounts)
        try checkSize(document.items.count, "items", limit: maxItems)
        try checkSize(document.links.count, "links", limit: maxLinks)

        let accountIds = try uniqueIdentifiers(document.accounts.map(\.id), in: "accounts")
        _ = try uniqueIdentifiers(document.items.map(\.id), in: "items")
        _ = try uniqueIdentifiers(document.links.map(\.id), in: "links")
        _ = try uniqueIdentifiers(document.keepers.map(\.id), in: "keepers")

        for item in document.items where !accountIds.contains(item.accountId) {
            throw VaultError.danglingReference(
                field: "accountId", value: item.accountId, in: "item \(item.id)")
        }

        for link in document.links {
            guard accountIds.contains(link.sourceAccountId) else {
                throw VaultError.danglingReference(
                    field: "sourceAccountId", value: link.sourceAccountId,
                    in: "link \(link.id)")
            }
            guard accountIds.contains(link.targetAccountId) else {
                throw VaultError.danglingReference(
                    field: "targetAccountId", value: link.targetAccountId,
                    in: "link \(link.id)")
            }
        }

        for item in document.items {
            switch item.payload {
            case .authenticator(let authenticator):
                try validate(authenticator, itemId: item.id)
            case .password(let password):
                try validate(password, itemId: item.id)
            default:
                break
            }
        }
    }

    /// A password item with no password.
    ///
    /// The specification says only `password` is required of this type, and
    /// nothing checked it, so an item could be stored, listed and counted
    /// while carrying nothing at all. A recovery vault holding an empty
    /// password is worse than one holding none: it says the credential is
    /// here, and it is not.
    private static func validate(_ password: Password, itemId: String) throws {
        guard !password.password.isEmpty else {
            throw VaultError.invalidField("password", in: "item \(itemId)",
                                          reason: "must not be empty")
        }
        guard password.password.utf8.count <= maxStringBytes else {
            throw VaultError.invalidField(
                "password", in: "item \(itemId)",
                reason: "must be at most \(maxStringBytes / 1024) KiB")
        }
    }

    private static func validate(_ authenticator: Authenticator, itemId: String) throws {
        // A Steam code is five characters drawn from a 26-symbol alphabet, so
        // the digit-count rule does not apply to it.
        let otpType: String
        switch authenticator.kind {
        case .steam: otpType = "steam"
        case .totp: otpType = "totp"
        case .hotp: otpType = "hotp"
        }

        let permitted = Authenticator.permittedDigits(forOTPType: otpType)
        guard permitted.contains(authenticator.digits) else {
            throw VaultError.invalidField(
                "digits", in: "item \(itemId)",
                reason: permitted.count == 1
                    ? "a Steam code is always 5 characters"
                    : "must be between 6 and 10")
        }
        guard (1...300).contains(authenticator.period) else {
            throw VaultError.invalidField("period", in: "item \(itemId)",
                                          reason: "must be between 1 and 300 seconds")
        }
        guard !authenticator.secret.isEmpty else {
            throw VaultError.invalidField("secret", in: "item \(itemId)",
                                          reason: "must not be empty")
        }
        do {
            _ = try Base32.decode(authenticator.secret)
        } catch {
            throw VaultError.invalidField("secret", in: "item \(itemId)",
                                          reason: "is not valid Base32")
        }
    }

    private static func checkSize(_ count: Int, _ collection: String, limit: Int) throws {
        guard count <= limit else {
            throw VaultError.limitExceeded(collection, count: count, limit: limit)
        }
    }

    private static func uniqueIdentifiers(
        _ identifiers: [String], in collection: String
    ) throws -> Set<String> {
        var seen = Set<String>()
        for identifier in identifiers {
            guard seen.insert(identifier).inserted else {
                throw VaultError.duplicateIdentifier(identifier, in: collection)
            }
        }
        return seen
    }
}
