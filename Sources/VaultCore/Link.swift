

/// "This account can be used to recover that one." The edges of the recovery
/// graph, and the reason accounts and items are modelled separately.
public struct Link: Sendable, Hashable, Identifiable {
    public let id: String
    public var sourceAccountId: String
    public var targetAccountId: String
    public var method: Method
    public var verifiedAt: Timestamp?
    public var note: String?

    /// Keys written by a newer version, carried through untouched.
    ///
    /// New optional fields land on this kind of object far more often than at
    /// the document root, so dropping them here is the more likely way to lose
    /// somebody's data.
    public var unrecognised: [String: JSONValue]

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
        note: String? = nil,
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.sourceAccountId = sourceAccountId
        self.targetAccountId = targetAccountId
        self.method = method
        self.verifiedAt = verifiedAt
        self.note = note
        self.unrecognised = unrecognised
    }
}
