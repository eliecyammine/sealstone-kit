public import Foundation

/// A credential belonging to an account.
///
/// The JSON form is flat — `type` sits alongside the fields that type implies —
/// so encoding and decoding are written by hand rather than synthesised.
public struct Item: Sendable, Hashable, Identifiable {
    public let id: String
    public var accountId: String
    public var favorite: Bool
    public var ordering: Int
    public var createdAt: Timestamp
    public var modifiedAt: Timestamp?

    /// When this credential was last used, which for an authenticator means
    /// the last time its code was copied.
    ///
    /// Answers a question the user otherwise cannot: re-enrolling with a
    /// service leaves two codes for one account, only one of which still
    /// works, and the one being used every week is not the one to delete.
    ///
    /// Absent on an item that has never been used. Optional to write, but a
    /// decoder that does not write it must still preserve one it reads.
    public var lastUsedAt: Timestamp?
    public var payload: Payload

    /// Fields present in the file that this version does not know about.
    /// Carried through unchanged so an older build cannot destroy a newer
    /// build's data by opening and saving.
    public var unrecognised: [String: JSONValue]

    public init(
        id: String,
        accountId: String,
        payload: Payload,
        favorite: Bool = false,
        ordering: Int = 0,
        createdAt: Timestamp = .now(),
        modifiedAt: Timestamp? = nil,
        lastUsedAt: Timestamp? = nil,
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.accountId = accountId
        self.payload = payload
        self.favorite = favorite
        self.ordering = ordering
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.lastUsedAt = lastUsedAt
        self.unrecognised = unrecognised
    }
}

// MARK: - Payload

extension Item {
    public enum Payload: Sendable, Hashable {
        case authenticator(Authenticator)
        case recoveryCodes([RecoveryCode])
        case recoveryContact(RecoveryContact)
        case securityQuestions([SecurityQuestion])
        case seedPhrase(SeedPhrase)
        case hardwareKey(HardwareKey)
        case password(Password)
        case note(Note)

        /// A type introduced after this version was built.
        case unknown(type: String, fields: [String: JSONValue])

        public var typeName: String {
            switch self {
            case .authenticator: "authenticator"
            case .recoveryCodes: "recoveryCodes"
            case .recoveryContact: "recoveryContact"
            case .securityQuestions: "securityQuestions"
            case .seedPhrase: "seedPhrase"
            case .hardwareKey: "hardwareKey"
            case .password: "password"
            case .note: "note"
            case .unknown(let type, _): type
            }
        }

        /// Whether this version can act on the payload rather than just carry it.
        public var isUnderstood: Bool {
            if case .unknown = self { return false }
            return true
        }

        /// Every type name this version understands, in the order the cases
        /// are declared above.
        ///
        /// Here rather than wherever a list of types is needed, because a
        /// second copy is a copy that goes stale. One did: the summary carried
        /// its own list, `password` was added to the enum and not to the list,
        /// and password items stopped being counted while still contributing
        /// to the total. Anything that needs the set of known types reads it
        /// from here.
        public static let knownTypeNames = [
            "authenticator",
            "recoveryCodes",
            "recoveryContact",
            "securityQuestions",
            "seedPhrase",
            "hardwareKey",
            "password",
            "note",
        ]
    }
}

// MARK: - Payload types
