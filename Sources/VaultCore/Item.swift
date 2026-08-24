public import Foundation

/// A credential belonging to an account.
///
/// The JSON form is flat — `type` sits alongside the fields that type implies —
/// so encoding and decoding are written by hand rather than synthesised.
public struct Item: Sendable, Hashable, Identifiable {
    public let id: String
    public var accountId: String
    public var favorite: Bool
    public var ordering: Int
    public var createdAt: Timestamp
    public var modifiedAt: Timestamp?
    public var payload: Payload

    /// Fields present in the file that this version does not know about.
    /// Carried through unchanged so an older build cannot destroy a newer
    /// build's data by opening and saving.
    public var unrecognised: [String: JSONValue]

    public init(
        id: String,
        accountId: String,
        payload: Payload,
        favorite: Bool = false,
        ordering: Int = 0,
        createdAt: Timestamp = .now(),
        modifiedAt: Timestamp? = nil,
        unrecognised: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.accountId = accountId
        self.payload = payload
        self.favorite = favorite
        self.ordering = ordering
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.unrecognised = unrecognised
    }
}

// MARK: - Payload

extension Item {
    public enum Payload: Sendable, Hashable {
        case authenticator(Authenticator)
        case recoveryCodes([RecoveryCode])
        case recoveryContact(RecoveryContact)
        case securityQuestions([SecurityQuestion])
        case seedPhrase(SeedPhrase)
        case hardwareKey(HardwareKey)
        case note(Note)

        /// A type introduced after this version was built.
        case unknown(type: String, fields: [String: JSONValue])

        public var typeName: String {
            switch self {
            case .authenticator: "authenticator"
            case .recoveryCodes: "recoveryCodes"
            case .recoveryContact: "recoveryContact"
            case .securityQuestions: "securityQuestions"
            case .seedPhrase: "seedPhrase"
            case .hardwareKey: "hardwareKey"
            case .note: "note"
            case .unknown(let type, _): type
            }
        }

        /// Whether this version can act on the payload rather than just carry it.
        public var isUnderstood: Bool {
            if case .unknown = self { return false }
            return true
        }
    }
}

// MARK: - Payload types

/// A one-time password credential.
public struct Authenticator: Sendable, Hashable {
    public var secret: String          // Base32, RFC 4648
    public var algorithm: Algorithm
    public var digits: Int
    public var period: Int
    public var kind: Kind

    public enum Algorithm: String, Sendable, Codable, CaseIterable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
    }

    /// The counter lives inside the `hotp` case, which makes a counter-less
    /// HOTP and a counter-bearing TOTP both unrepresentable. The compiler
    /// rejects what would otherwise need a runtime validator.
    public enum Kind: Sendable, Hashable {
        case totp
        case hotp(counter: UInt64)
        case steam

        public var name: String {
            switch self {
            case .totp: "totp"
            case .hotp: "hotp"
            case .steam: "steam"
            }
        }
    }

    public init(
        secret: String,
        algorithm: Algorithm = .sha1,
        digits: Int = 6,
        period: Int = 30,
        kind: Kind = .totp
    ) {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.kind = kind
    }
}

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

public struct SecurityQuestion: Sendable, Hashable, Codable {
    public var question: String
    public var answer: String

    public init(question: String, answer: String) {
        self.question = question
        self.answer = answer
    }
}

public struct SeedPhrase: Sendable, Hashable, Codable {
    public var words: [String]
    public var wordlist: String?
    public var passphrase: String?

    public init(words: [String], wordlist: String? = nil, passphrase: String? = nil) {
        self.words = words
        self.wordlist = wordlist
        self.passphrase = passphrase
    }
}

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

public struct Note: Sendable, Hashable, Codable {
    public var title: String
    public var body: String

    public init(title: String, body: String) {
        self.title = title
        self.body = body
    }
}
