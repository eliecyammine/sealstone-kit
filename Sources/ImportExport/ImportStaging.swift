public import Foundation
public import VaultCore

/// Import proceeds through a staging area and is never applied piecemeal.
///
/// Everything is parsed and validated first, the user sees what will happen,
/// and the change is applied in one step or not at all. A partially applied
/// import leaves someone unable to tell what they now have, which in a
/// recovery product is worse than importing nothing.
public struct ImportStaging: Sendable {
    /// One credential that parsed successfully.
    public struct Candidate: Sendable, Hashable, Identifiable {
        public let id: String
        public let issuer: String?
        public let account: String
        public let authenticator: Authenticator
        public var resolution: Resolution

        /// The item in the vault this one duplicates, if any.
        ///
        /// Separate from `resolution` because it is a fact rather than a
        /// choice. It used to live inside `.replace`, which meant choosing
        /// Skip destroyed the only record of what would have been replaced,
        /// and choosing Replace afterwards silently did nothing.
        public internal(set) var duplicateOf: String?

        public init(issuer: String?, account: String,
                    authenticator: Authenticator,
                    resolution: Resolution = .add) {
            self.id = SealstoneID.make(.item)
            self.issuer = issuer
            self.account = account
            self.authenticator = authenticator
            self.resolution = resolution
        }

        public var label: String {
            issuer.map { "\($0) (\(account))" } ?? account
        }
    }

    /// What to do with a candidate that already looks present.
    public enum Resolution: Sendable, Hashable {
        case add
        case skip
        case replace(existingItemId: String)
    }

    /// One entry that did not parse, kept so the user can be told which and why
    /// rather than being given a count.
    public struct Rejection: Sendable, Hashable {
        public let source: String
        public let reason: String

        public init(source: String, reason: String) {
            self.source = source
            self.reason = reason
        }
    }

    public private(set) var candidates: [Candidate]
    public private(set) var rejections: [Rejection]

    public init(candidates: [Candidate] = [], rejections: [Rejection] = []) {
        self.candidates = candidates
        self.rejections = rejections
    }

    public var isEmpty: Bool { candidates.isEmpty }

    public var willAdd: [Candidate] {
        candidates.filter { if case .add = $0.resolution { true } else { false } }
    }

    /// Candidates that already exist in the vault.
    ///
    /// Decided by what they are, not by what the user has chosen to do with
    /// them, so a duplicate stays in this list after being set to Skip.
    public var duplicates: [Candidate] {
        candidates.filter { $0.duplicateOf != nil }
    }

    /// Marks candidates that already exist in `document`.
    ///
    /// A duplicate is the same secret on the same account. Matching on label
    /// alone would call two different credentials the same thing; matching on
    /// secret alone would miss the same secret legitimately enrolled twice.
    public mutating func markDuplicates(against document: VaultDocument) {
        var existing: [String: String] = [:]
        for (item, authenticator) in document.authenticators {
            guard let account = document.account(item.accountId) else { continue }
            let key = duplicateKey(service: account.service,
                                   identifier: account.identifier,
                                   secret: authenticator.secret)
            existing[key] = item.id
        }

        for index in candidates.indices {
            let candidate = candidates[index]
            // The same service name this candidate would be filed under if it
            // were added. Keying an issuer-less candidate on "" meant it never
            // matched the account it was about to land on, so the one kind of
            // duplicate hardest to spot by eye was the one never reported.
            let key = duplicateKey(service: candidate.issuer ?? candidate.account,
                                   identifier: candidate.account,
                                   secret: candidate.authenticator.secret)
            if let itemId = existing[key] {
                candidates[index].duplicateOf = itemId
                candidates[index].resolution = .replace(existingItemId: itemId)
            }
        }
    }

    public mutating func setResolution(_ resolution: Resolution, for candidateId: String) {
        guard let index = candidates.firstIndex(where: { $0.id == candidateId }) else { return }
        candidates[index].resolution = resolution
    }

    /// Built from the document's own rule for what counts as the same account,
    /// plus the secret. Writing the name comparison a second time here is how
    /// it drifted from the first one.
    private func duplicateKey(service: String, identifier: String, secret: String) -> String {
        "\(Account.matchKey(service: service, identifier: identifier))\u{0}\(secret.uppercased())"
    }

    /// Applies the staged changes to a copy of `document`.
    ///
    /// Returns the new document rather than mutating in place, so a caller that
    /// throws part-way through has changed nothing.
    public func apply(to document: VaultDocument) throws -> VaultDocument {
        var updated = document

        for candidate in candidates {
            switch candidate.resolution {
            case .skip:
                continue

            case .replace(let existingItemId):
                guard let index = updated.items.firstIndex(where: { $0.id == existingItemId })
                else {
                    throw VaultError.danglingReference(
                        field: "existingItemId", value: existingItemId,
                        in: "import of \(candidate.label)")
                }
                updated.items[index].payload = .authenticator(candidate.authenticator)
                updated.items[index].modifiedAt = .now()

            case .add:
                let account = accountFor(candidate, in: &updated)
                updated.items.append(Item(
                    id: SealstoneID.make(.item),
                    accountId: account,
                    payload: .authenticator(candidate.authenticator),
                    ordering: updated.items.count))
            }
        }

        updated.updatedAt = .now()
        try VaultValidator.validate(updated)
        return updated
    }

    /// Finds or creates the account a candidate belongs to.
    ///
    /// The rule lives on the document so importing and adding by hand cannot
    /// disagree about when two names are the same account.
    private func accountFor(_ candidate: Candidate, in document: inout VaultDocument) -> String {
        document.accountId(forService: candidate.issuer ?? candidate.account,
                           identifier: candidate.account)
    }
}
