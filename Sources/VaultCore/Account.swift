

/// A service account, and the anchor everything else hangs from.
public struct Account: Sendable, Hashable, Identifiable {
    public let id: String
    public var service: String
    public var identifier: String
    public var domain: String?
    public var tags: [String]
    public var notes: String?
    public var createdAt: Timestamp

    /// Keys written by a newer version, carried through untouched.
    ///
    /// New optional fields land on this kind of object far more often than at
    /// the document root, so dropping them here is the more likely way to lose
    /// somebody's data.
    public var unrecognised: [String: JSONValue]

    public init(
        id: String,
        service: String,
        identifier: String,
        domain: String? = nil,
        tags: [String] = [],
        notes: String? = nil,
        createdAt: Timestamp = .now(),
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.service = service
        self.identifier = identifier
        self.domain = domain
        self.tags = tags
        self.notes = notes
        self.createdAt = createdAt
        self.unrecognised = unrecognised
    }
}
