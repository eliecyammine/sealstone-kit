

/// Someone holding one fragment of a handover bundle key.
///
/// The fragment itself is never stored — the point is that it left. Only the
/// index is kept, so the app can say which fragment a given keeper holds.
public struct Keeper: Sendable, Hashable, Identifiable {
    public let id: String
    public var displayName: String
    public var contact: String
    public var bundleId: String
    public var fragmentIndex: Int
    public var issuedAt: Timestamp
    public var lastConfirmedAt: Timestamp?
    public var status: Status

    /// Keys written by a newer version, carried through untouched.
    ///
    /// New optional fields land on this kind of object far more often than at
    /// the document root, so dropping them here is the more likely way to lose
    /// somebody's data.
    public var unrecognised: [String: JSONValue]

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
        status: Status = .active,
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.displayName = displayName
        self.contact = contact
        self.bundleId = bundleId
        self.fragmentIndex = fragmentIndex
        self.issuedAt = issuedAt
        self.lastConfirmedAt = lastConfirmedAt
        self.status = status
        self.unrecognised = unrecognised
    }
}
