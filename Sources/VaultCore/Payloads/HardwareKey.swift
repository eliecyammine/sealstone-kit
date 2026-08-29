

public struct HardwareKey: Sendable, Hashable, Codable {
    public var label: String
    public var serial: String?
    public var keyType: String?

    public init(label: String, serial: String? = nil, keyType: String? = nil) {
        self.label = label
        self.serial = serial
        self.keyType = keyType
    }
}
