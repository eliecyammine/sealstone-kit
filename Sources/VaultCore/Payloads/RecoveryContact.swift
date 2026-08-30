

/// An address or number a service can use to reach the account owner.
public struct RecoveryContact: Sendable, Hashable, Codable {
    public var channel: Channel
    public var value: String

    public enum Channel: String, Sendable, Codable, CaseIterable {
        case email, sms, voice
    }

    public init(channel: Channel, value: String) {
        self.channel = channel
        self.value = value
    }
}
