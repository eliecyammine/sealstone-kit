

/// A one-time password credential.
public struct Authenticator: Sendable, Hashable {
    /// How many characters a code of a given kind has.
    ///
    /// Steam is always five, and everything else is six to ten. This existed
    /// three times over, written slightly differently each time, and the three
    /// disagreed: a Steam credential written out as a URI could not be read
    /// back, because the writer emitted five digits and the reader allowed
    /// only six upwards. One copy means that cannot happen again.
    public static func permittedDigits(forOTPType type: String) -> ClosedRange<Int> {
        type.lowercased() == "steam" ? 5...5 : 6...10
    }

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
