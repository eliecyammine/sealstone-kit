import CryptoKit
public import Foundation
public import VaultCore

/// One-time password generation: HOTP (RFC 4226), TOTP (RFC 6238), Steam.
public enum OneTimePassword {
    static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")

    /// A counter-based code, zero-padded to `digits`.
    public static func hotp(
        secret: [UInt8],
        counter: UInt64,
        digits: Int = 6,
        algorithm: Authenticator.Algorithm = .sha1
    ) throws -> String {
        guard (6...10).contains(digits) else {
            throw OTPError.digitsOutOfRange(digits)
        }

        let value = truncate(mac(secret: secret, counter: counter, algorithm: algorithm))

        // Computed as an integer in 64 bits. 10^10 exceeds UInt32.max, so
        // deriving the modulus through Double and narrowing to UInt32 traps on
        // the largest permitted code length.
        var modulus: UInt64 = 1
        for _ in 0..<digits { modulus *= 10 }

        return String(UInt64(value) % modulus).leftPadded(to: digits, with: "0")
    }

    /// A time-based code. Pass `at` to reproduce a code for a known instant.
    public static func totp(
        secret: [UInt8],
        at date: Date = Date(),
        period: Int = 30,
        digits: Int = 6,
        algorithm: Authenticator.Algorithm = .sha1
    ) throws -> String {
        guard period >= 1 else { throw OTPError.periodOutOfRange(period) }

        let counter = UInt64(floor(date.timeIntervalSince1970 / Double(period)))
        return try hotp(secret: secret, counter: counter,
                        digits: digits, algorithm: algorithm)
    }

    /// A Steam Guard code: five characters from a 26-symbol alphabet.
    ///
    /// Same MAC and truncation as HOTP, then repeated division by the alphabet
    /// size instead of by ten.
    public static func steam(
        secret: [UInt8],
        at date: Date = Date(),
        period: Int = 30
    ) -> String {
        let counter = UInt64(floor(date.timeIntervalSince1970 / Double(period)))
        var value = truncate(mac(secret: secret, counter: counter, algorithm: .sha1))

        var code = ""
        for _ in 0..<5 {
            code.append(steamAlphabet[Int(value % UInt32(steamAlphabet.count))])
            value /= UInt32(steamAlphabet.count)
        }
        return code
    }

    /// How long the current code stays valid.
    public static func secondsRemaining(at date: Date = Date(), period: Int = 30) -> Double {
        Double(period) - date.timeIntervalSince1970.truncatingRemainder(dividingBy: Double(period))
    }

    /// The current code for an authenticator from a vault.
    ///
    /// The item carries every parameter needed, so recovery does not depend on
    /// remembering how a service was configured.
    public static func generate(
        _ authenticator: Authenticator,
        at date: Date = Date()
    ) throws -> String {
        let secret = try Base32.decode(authenticator.secret)

        switch authenticator.kind {
        case .totp:
            return try totp(secret: secret, at: date,
                            period: authenticator.period,
                            digits: authenticator.digits,
                            algorithm: authenticator.algorithm)
        case .hotp(let counter):
            return try hotp(secret: secret, counter: counter,
                            digits: authenticator.digits,
                            algorithm: authenticator.algorithm)
        case .steam:
            return steam(secret: secret, at: date, period: authenticator.period)
        }
    }

    // MARK: - Internals

    private static func mac(
        secret: [UInt8],
        counter: UInt64,
        algorithm: Authenticator.Algorithm
    ) -> [UInt8] {
        let key = SymmetricKey(data: secret)
        let message = withUnsafeBytes(of: counter.bigEndian) { Array($0) }

        switch algorithm {
        case .sha1:
            return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256:
            return Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512:
            return Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
    }

    /// RFC 4226 dynamic truncation: the low nibble of the last byte picks the
    /// offset, and the top bit of the extracted word is cleared.
    private static func truncate(_ digest: [UInt8]) -> UInt32 {
        let offset = Int(digest[digest.count - 1] & 0x0F)
        let value = (UInt32(digest[offset]) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        return value & 0x7FFF_FFFF
    }
}

public enum OTPError: Error, Sendable, Equatable {
    case digitsOutOfRange(Int)
    case periodOutOfRange(Int)
}

extension OTPError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .digitsOutOfRange(let digits):
            "A code length of \(digits) is not supported. Codes are between 6 and 10 digits."
        case .periodOutOfRange(let period):
            "A period of \(period) seconds is not valid. It must be at least 1."
        }
    }
}

private extension String {
    func leftPadded(to length: Int, with character: Character) -> String {
        count >= length ? self : String(repeating: character, count: length - count) + self
    }
}
