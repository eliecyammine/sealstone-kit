

/// One of the single-use codes a service issues when two-factor is enabled.
public struct RecoveryCode: Sendable, Hashable, Codable {
    public var code: String
    public var used: Bool
    public var usedAt: Timestamp?

    public init(code: String, used: Bool = false, usedAt: Timestamp? = nil) {
        self.code = code
        self.used = used
        self.usedAt = usedAt
    }
}
