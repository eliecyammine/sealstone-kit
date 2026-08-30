public import Foundation

/// Reading and writing the eight shapes an item's payload can take.
///
/// Kept apart from the item's own coding because the questions are different.
/// The item knows its id, its account and when it changed; this knows what a
/// recovery code looks like on disk, and it is the part that grows every time
/// the format learns a new kind of thing.

extension Item {
    static func decodePayload(
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

        case "password":
            return .password(Password(
                password: raw["password"]?.stringValue ?? "",
                username: raw["username"]?.stringValue,
                site: raw["site"]?.stringValue,
                note: raw["note"]?.stringValue
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

    static func encodePayload(_ payload: Payload) throws -> [String: JSONValue] {
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

        case .password(let value):
            // Absent stays absent rather than becoming an empty string, which
            // is what every other optional on an item does.
            var fields: [String: JSONValue] = ["password": .string(value.password)]
            if let username = value.username { fields["username"] = .string(username) }
            if let site = value.site { fields["site"] = .string(site) }
            if let note = value.note { fields["note"] = .string(note) }
            return fields

        case .note(let value):
            return ["title": .string(value.title), "body": .string(value.body)]

        case .unknown(_, let fields):
            return fields
        }
    }
}
