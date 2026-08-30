public import Foundation
public import VaultCore

/// Turning what was parsed into something the vault can hold.
///
/// Shared by every format above, which is the whole reason they can disagree
/// about field names and still produce the same thing.

extension Importer {
    /// Names a URI that would not parse, without repeating what it carried.
    ///
    /// The first sixty characters used to go on the review screen verbatim.
    /// `otpauth://totp/x?secret=...` puts the secret inside them, so a line
    /// that failed for an unrelated reason printed a working credential onto a
    /// screen, into a screenshot, and into whatever the person sent to ask
    /// what went wrong. The label identifies the row; the query never does.
    static func describeURI(_ text: String) -> String {
        // The scheme is required, not assumed. A line with no scheme is a
        // valid relative reference whose path is the entire line, so without
        // this check a stray line is quoted back in full and the quoting is
        // the thing being fixed.
        guard let components = URLComponents(string: text),
              components.scheme?.lowercased() == "otpauth" else {
            return "an entry that is not a link"
        }
        let path = components.path.hasPrefix("/")
            ? String(components.path.dropFirst()) : components.path
        let label = (path.removingPercentEncoding ?? path)
            .trimmingCharacters(in: .whitespaces)
        return label.isEmpty ? "an unnamed entry" : String(label.prefix(60))
    }

    /// Counters below zero are not representable and must not be converted.
    /// A hand-edited export with `"counter": -1` is a rejection row, not a trap.
    static func nonNegative(_ value: Int?) -> UInt64? {
        guard let value, value >= 0 else { return nil }
        return UInt64(value)
    }

    static func makeAuthenticator(
        secret: String, algorithm: String, digits: Int, period: Int,
        kindName: String, counter: UInt64?
    ) throws -> Authenticator {
        let normalised = secret.uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "=", with: "")

        guard let decoded = try? Base32.decode(normalised), !decoded.isEmpty else {
            throw OTPAuthURI.Failure.invalidSecret
        }
        guard let parsedAlgorithm = Authenticator.Algorithm(rawValue: algorithm) else {
            throw OTPAuthURI.Failure.invalidParameter("algorithm", algorithm)
        }
        guard Authenticator.permittedDigits(forOTPType: kindName).contains(digits) else {
            throw OTPAuthURI.Failure.invalidParameter("digits", String(digits))
        }
        guard (1...300).contains(period) else {
            throw OTPAuthURI.Failure.invalidParameter("period", String(period))
        }

        let kind: Authenticator.Kind
        switch kindName {
        case "totp": kind = .totp
        case "steam": kind = .steam
        case "hotp":
            guard let counter else { throw OTPAuthURI.Failure.missingCounter }
            kind = .hotp(counter: counter)
        default:
            throw OTPAuthURI.Failure.unsupportedType(kindName)
        }

        return Authenticator(secret: normalised, algorithm: parsedAlgorithm,
                             digits: digits, period: period, kind: kind)
    }

    /// What to call an entry in a message about it when the export named it
    /// nothing. Better than a blank, and better than inventing a name that
    /// would read like one the file supplied.
    static func named(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "an unnamed entry" : name
    }

    static func describe(_ error: any Error) -> String {
        guard let failure = error as? OTPAuthURI.Failure else {
            return error.localizedDescription
        }
        return switch failure {
        case .notAnOTPAuthURI: "not an otpauth:// URI"
        case .unsupportedType(let name): "unsupported type '\(name)'"
        case .missingSecret: "no secret"
        case .invalidSecret: "the secret is not valid Base32"
        case .invalidParameter(let name, let value): "invalid \(name) '\(value)'"
        case .missingCounter: "an HOTP credential without a counter"
        }
    }
}
