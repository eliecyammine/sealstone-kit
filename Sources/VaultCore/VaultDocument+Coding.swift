/// Coding for `VaultDocument`.
///
/// Written by hand for one reason: a key this version does not recognise has
/// to survive being read and written again. Synthesised `Codable` reads the
/// keys it has properties for and writes the keys it has properties for, so a
/// field added by a later version would be silently dropped the first time an
/// older build saved the vault.
extension VaultDocument: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion, vaultId, createdAt, updatedAt
        case accounts, items, links, keepers
    }

    /// Lets the decoder enumerate the keys actually present, rather than only
    /// the ones this version knows to ask for.
    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            vaultId: try container.decode(String.self, forKey: .vaultId),
            createdAt: try container.decode(Timestamp.self, forKey: .createdAt),
            updatedAt: try container.decode(Timestamp.self, forKey: .updatedAt),
            accounts: try container.decode([Account].self, forKey: .accounts),
            items: try container.decode([Item].self, forKey: .items),
            links: try container.decode([Link].self, forKey: .links),
            keepers: try container.decode([Keeper].self, forKey: .keepers),
            unrecognised: try Self.leftoverKeys(from: decoder)
        )

        // Read rather than assumed. A file claiming a version this build does
        // not produce still round-trips with the version it arrived with.
        formatVersion = try container.decode(Int.self, forKey: .formatVersion)
    }

    private static func leftoverKeys(from decoder: any Decoder) throws -> [String: JSONValue] {
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        let container = try decoder.container(keyedBy: AnyKey.self)

        var leftover: [String: JSONValue] = [:]
        for key in container.allKeys where !known.contains(key.stringValue) {
            leftover[key.stringValue] = try container.decode(JSONValue.self, forKey: key)
        }
        return leftover
    }

    public func encode(to encoder: any Encoder) throws {
        // Unrecognised keys go down first so a known key can never be
        // overwritten by stale content carried from an older read.
        var passthrough = encoder.container(keyedBy: AnyKey.self)
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        for (key, value) in unrecognised where !known.contains(key) {
            try passthrough.encode(value, forKey: AnyKey(stringValue: key))
        }

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(formatVersion, forKey: .formatVersion)
        try container.encode(vaultId, forKey: .vaultId)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encode(accounts, forKey: .accounts)
        try container.encode(items, forKey: .items)
        try container.encode(links, forKey: .links)
        try container.encode(keepers, forKey: .keepers)
    }
}
