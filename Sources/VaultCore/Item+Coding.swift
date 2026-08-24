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

// MARK: - Payload coding

extension Item {
    private static func decodePayload(
        type: String,
        from raw: [String: JSONValue],
        itemId: String
    ) throws -> Payload {
        func decode<T: Decodable>(_ key: String, as _: T.Type) throws -> T {
            guard let value = raw[key] else {
                throw VaultError.missingField(key, in: "item \(itemId)")
            }
            return try JSONValueCoder.decode(T.self, from: value)
        }

        switch type {
        case "authenticator":
            guard let secret = raw["secret"]?.stringValue else {
                throw VaultError.invalidField("secret", in: "item \(itemId)",
                                              reason: "must be a Base32 string")
            }
            let algorithmName = raw["algorithm"]?.stringValue ?? "SHA1"
            guard let algorithm = Authenticator.Algorithm(rawValue: algorithmName) else {
                throw VaultError.invalidField(
                    "algorithm", in: "item \(itemId)",
                    reason: "must be one of \(Authenticator.Algorithm.allCases.map(\.rawValue))"
                )
            }

            let otpType = raw["otpType"]?.stringValue ?? "totp"
            let counter = raw["counter"]?.intValue

            let kind: Authenticator.Kind
            switch otpType {
            case "totp":
                guard counter == nil else {
                    throw VaultError.invalidField(
                        "counter", in: "item \(itemId)",
                        reason: "only HOTP items carry a counter"
                    )
                }
                kind = .totp
            case "hotp":
                guard let counter, counter >= 0 else {
                    throw VaultError.invalidField(
                        "counter", in: "item \(itemId)",
                        reason: "an HOTP item needs a counter of zero or more"
                    )
                }
                kind = .hotp(counter: UInt64(counter))
            case "steam":
                kind = .steam
            default:
                throw VaultError.invalidField("otpType", in: "item \(itemId)",
                                              reason: "must be totp, hotp or steam")
            }

            return .authenticator(Authenticator(
                secret: secret,
                algorithm: algorithm,
                digits: raw["digits"]?.intValue ?? (otpType == "steam" ? 5 : 6),
                period: raw["period"]?.intValue ?? 30,
                kind: kind
            ))

        case "recoveryCodes":
            return .recoveryCodes(try decode("codes", as: [RecoveryCode].self))

        case "recoveryContact":
            guard let channelName = raw["channel"]?.stringValue,
                  let channel = RecoveryContact.Channel(rawValue: channelName),
                  let value = raw["value"]?.stringValue else {
                throw VaultError.invalidField("channel", in: "item \(itemId)",
                                              reason: "must be email, sms or voice")
            }
            return .recoveryContact(RecoveryContact(channel: channel, value: value))

        case "securityQuestions":
            return .securityQuestions(try decode("questions", as: [SecurityQuestion].self))

        case "seedPhrase":
            guard let words = raw["words"]?.arrayValue?.compactMap(\.stringValue) else {
                throw VaultError.invalidField("words", in: "item \(itemId)",
                                              reason: "must be a list of strings")
            }
            return .seedPhrase(SeedPhrase(
                words: words,
                wordlist: raw["wordlist"]?.stringValue,
                passphrase: raw["passphrase"]?.stringValue
            ))

        case "hardwareKey":
            guard let label = raw["label"]?.stringValue else {
                throw VaultError.invalidField("label", in: "item \(itemId)",
                                              reason: "must be a string")
            }
            return .hardwareKey(HardwareKey(
                label: label,
                serial: raw["serial"]?.stringValue,
                keyType: raw["keyType"]?.stringValue
            ))

        case "note":
            return .note(Note(
                title: raw["title"]?.stringValue ?? "",
                body: raw["body"]?.stringValue ?? ""
            ))

        default:
            // Keep everything. This is what stops an older build destroying a
            // newer build's data.
            var fields = raw
            fields.removeValue(forKey: "id")
            fields.removeValue(forKey: "accountId")
            fields.removeValue(forKey: "type")
            return .unknown(type: type, fields: fields)
        }
    }

    private static func encodePayload(_ payload: Payload) throws -> [String: JSONValue] {
        switch payload {
        case .authenticator(let value):
            var fields: [String: JSONValue] = [
                "secret": .string(value.secret),
                "algorithm": .string(value.algorithm.rawValue),
                "digits": .number(Double(value.digits)),
                "period": .number(Double(value.period)),
                "otpType": .string(value.kind.name),
            ]
            if case .hotp(let counter) = value.kind {
                fields["counter"] = .number(Double(counter))
            } else {
                fields["counter"] = .null
            }
            return fields

        case .recoveryCodes(let value):
            return ["codes": try JSONValueCoder.encode(value)]

        case .recoveryContact(let value):
            return ["channel": .string(value.channel.rawValue),
                    "value": .string(value.value)]

        case .securityQuestions(let value):
            return ["questions": try JSONValueCoder.encode(value)]

        case .seedPhrase(let value):
            var fields: [String: JSONValue] = [
                "words": .array(value.words.map { .string($0) }),
            ]
            fields["wordlist"] = value.wordlist.map { .string($0) } ?? .null
            fields["passphrase"] = value.passphrase.map { .string($0) } ?? .null
            return fields

        case .hardwareKey(let value):
            var fields: [String: JSONValue] = ["label": .string(value.label)]
            fields["serial"] = value.serial.map { .string($0) } ?? .null
            fields["keyType"] = value.keyType.map { .string($0) } ?? .null
            return fields

        case .note(let value):
            return ["title": .string(value.title), "body": .string(value.body)]

        case .unknown(_, let fields):
            return fields
        }
    }
}

// MARK: - Bridging Codable types through JSONValue

enum JSONValueCoder {
    static func decode<T: Decodable>(_ type: T.Type, from value: JSONValue) throws -> T {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(type, from: data)
    }

    static func encode(_ value: some Encodable) throws -> JSONValue {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }
}
