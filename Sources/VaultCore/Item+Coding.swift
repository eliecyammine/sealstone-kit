public import Foundation

/// Coding for `Item`.
///
/// The JSON is flat: the discriminator and the fields it implies sit at the
/// same level. Decoding therefore reads the whole object, lifts the keys it
/// understands, and keeps whatever is left. Encoding reverses that, so a file
/// written by a newer version survives being opened and saved by this one.
extension Item: Codable {
    private enum Key {
        static let id = "id"
        static let accountId = "accountId"
        static let type = "type"
        static let favorite = "favorite"
        static let ordering = "ordering"
        static let createdAt = "createdAt"
        static let modifiedAt = "modifiedAt"
        static let lastUsedAt = "lastUsedAt"

        static let common: Set<String> = [
            id, accountId, type, favorite, ordering, createdAt, modifiedAt,
            lastUsedAt,
        ]

        /// Keys owned by each payload type, so they are not mistaken for
        /// unrecognised content.
        static func owned(by type: String) -> Set<String> {
            switch type {
            case "authenticator":
                ["secret", "algorithm", "digits", "period", "counter", "otpType"]
            case "recoveryCodes": ["codes"]
            case "recoveryContact": ["channel", "value"]
            case "securityQuestions": ["questions"]
            case "seedPhrase": ["words", "wordlist", "passphrase"]
            case "hardwareKey": ["label", "serial", "keyType"]
            case "password": ["password", "username", "site", "note"]
            case "note": ["title", "body"]
            default: []
            }
        }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode([String: JSONValue].self)

        func require(_ key: String) throws -> JSONValue {
            guard let value = raw[key] else {
                throw VaultError.missingField(key, in: "item")
            }
            return value
        }

        guard let id = try require(Key.id).stringValue else {
            throw VaultError.invalidField(Key.id, in: "item", reason: "must be a string")
        }
        guard let accountId = try require(Key.accountId).stringValue else {
            throw VaultError.invalidField(Key.accountId, in: "item", reason: "must be a string")
        }
        guard let type = try require(Key.type).stringValue else {
            throw VaultError.invalidField(Key.type, in: "item", reason: "must be a string")
        }

        guard let createdText = try require(Key.createdAt).stringValue,
              let createdAt = Timestamp(parsing: createdText) else {
            throw VaultError.invalidField(Key.createdAt, in: "item \(id)",
                                          reason: "must be an ISO 8601 timestamp")
        }

        var modifiedAt: Timestamp?
        if let text = raw[Key.modifiedAt]?.stringValue {
            guard let parsed = Timestamp(parsing: text) else {
                throw VaultError.invalidField(Key.modifiedAt, in: "item \(id)",
                                              reason: "must be an ISO 8601 timestamp")
            }
            modifiedAt = parsed
        }

        var lastUsedAt: Timestamp?
        if let text = raw[Key.lastUsedAt]?.stringValue {
            guard let parsed = Timestamp(parsing: text) else {
                throw VaultError.invalidField(Key.lastUsedAt, in: "item \(id)",
                                              reason: "must be an ISO 8601 timestamp")
            }
            lastUsedAt = parsed
        }

        let payload = try Item.decodePayload(type: type, from: raw, itemId: id)

        var leftover = raw
        for key in Key.common.union(Key.owned(by: type)) {
            leftover.removeValue(forKey: key)
        }

        // A known key holding an unexpected type is kept rather than dropped.
        //
        // `favorite` and `ordering` fall back to a default when they are not
        // the type this version expects, and removing them above would throw
        // the original away. If a later version widens either of these, an
        // older build would silently destroy the new value on the first save.
        // Preserving it costs nothing and is what the format promises.
        if raw[Key.favorite] != nil, raw[Key.favorite]?.boolValue == nil {
            leftover[Key.favorite] = raw[Key.favorite]
        }
        if raw[Key.ordering] != nil, raw[Key.ordering]?.intValue == nil {
            leftover[Key.ordering] = raw[Key.ordering]
        }
        // An unknown type owns every field it brought with it.
        if case .unknown = payload {
            leftover = [:]
        }

        self.init(
            id: id,
            accountId: accountId,
            payload: payload,
            favorite: raw[Key.favorite]?.boolValue ?? false,
            ordering: raw[Key.ordering]?.intValue ?? 0,
            createdAt: createdAt,
            modifiedAt: modifiedAt,
            lastUsedAt: lastUsedAt,
            unrecognised: leftover
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var fields: [String: JSONValue] = unrecognised

        fields[Key.id] = .string(id)
        fields[Key.accountId] = .string(accountId)
        fields[Key.type] = .string(payload.typeName)
        fields[Key.createdAt] = .string(createdAt.description)

        if favorite { fields[Key.favorite] = .bool(true) }
        if ordering != 0 { fields[Key.ordering] = .number(Double(ordering)) }
        if let modifiedAt { fields[Key.modifiedAt] = .string(modifiedAt.description) }
        if let lastUsedAt { fields[Key.lastUsedAt] = .string(lastUsedAt.description) }

        for (key, value) in try Item.encodePayload(payload) {
            fields[key] = value
        }

        var container = encoder.singleValueContainer()
        try container.encode(fields)
    }
}
