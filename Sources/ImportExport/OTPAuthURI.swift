public import Foundation
public import VaultCore

/// Parses `otpauth://` URIs, the near-universal interchange form for a single
/// authenticator credential.
///
/// Deliberately lenient about what it accepts and strict about what it
/// believes: unknown query parameters are ignored, but a malformed secret,
/// digit count or period is a rejection rather than a silent default. A
/// credential imported with the wrong period produces codes that never work,
/// and the user finds out during a lockout.
public enum OTPAuthURI {
    public struct Parsed: Sendable, Hashable {
        public let issuer: String?
        public let account: String
        public let authenticator: Authenticator
    }

    public enum Failure: Error, Sendable, Equatable {
        case notAnOTPAuthURI
        case unsupportedType(String)
        case missingSecret
        case invalidSecret
        case invalidParameter(String, String)
        case missingCounter
    }

    public static func parse(_ text: String) throws -> Parsed {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "otpauth" else {
            throw Failure.notAnOTPAuthURI
        }

        let kindName = (components.host ?? "").lowercased()
        guard ["totp", "hotp", "steam"].contains(kindName) else {
            throw Failure.unsupportedType(kindName)
        }

        // The label is "Issuer:account" or just "account".
        let label = components.path.hasPrefix("/")
            ? String(components.path.dropFirst())
            : components.path
        var issuer: String?
        var account = label

        if let separator = label.firstIndex(of: ":") {
            issuer = String(label[..<separator]).trimmingCharacters(in: .whitespaces)
            account = String(label[label.index(after: separator)...])
                .trimmingCharacters(in: .whitespaces)
        }

        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            query[item.name.lowercased()] = item.value
        }

        // The issuer parameter wins over the label prefix when both are present.
        if let parameter = query["issuer"], !parameter.isEmpty {
            issuer = parameter
        }

        guard let secret = query["secret"], !secret.isEmpty else {
            throw Failure.missingSecret
        }
        // Reject an unusable secret now rather than at the moment a code is needed.
        let normalisedSecret = secret.uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "-", with: "")
        guard let decoded = try? Base32.decode(normalisedSecret), !decoded.isEmpty else {
            throw Failure.invalidSecret
        }

        let algorithm: Authenticator.Algorithm
        if let name = query["algorithm"] {
            guard let parsed = Authenticator.Algorithm(rawValue: name.uppercased()) else {
                throw Failure.invalidParameter("algorithm", name)
            }
            algorithm = parsed
        } else {
            algorithm = .sha1
        }

        let digits: Int
        if let text = query["digits"] {
            guard let value = Int(text), (6...10).contains(value) else {
                throw Failure.invalidParameter("digits", text)
            }
            digits = value
        } else {
            digits = kindName == "steam" ? 5 : 6
        }

        let period: Int
        if let text = query["period"] {
            guard let value = Int(text), (1...300).contains(value) else {
                throw Failure.invalidParameter("period", text)
            }
            period = value
        } else {
            period = 30
        }

        let kind: Authenticator.Kind
        switch kindName {
        case "totp":
            kind = .totp
        case "steam":
            kind = .steam
        case "hotp":
            guard let text = query["counter"] else { throw Failure.missingCounter }
            guard let value = UInt64(text) else {
                throw Failure.invalidParameter("counter", text)
            }
            kind = .hotp(counter: value)
        default:
            throw Failure.unsupportedType(kindName)
        }

        return Parsed(
            issuer: issuer?.isEmpty == true ? nil : issuer,
            account: account,
            authenticator: Authenticator(secret: normalisedSecret,
                                         algorithm: algorithm,
                                         digits: digits,
                                         period: period,
                                         kind: kind)
        )
    }

    /// Renders a credential back to a URI, for sharing a single item.
    public static func render(_ parsed: Parsed) -> String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = parsed.authenticator.kind.name

        let label = parsed.issuer.map { "\($0):\(parsed.account)" } ?? parsed.account
        components.path = "/\(label)"

        var items = [URLQueryItem(name: "secret", value: parsed.authenticator.secret)]
        if let issuer = parsed.issuer {
            items.append(URLQueryItem(name: "issuer", value: issuer))
        }
        items.append(URLQueryItem(name: "algorithm",
                                  value: parsed.authenticator.algorithm.rawValue))
        items.append(URLQueryItem(name: "digits",
                                  value: String(parsed.authenticator.digits)))
        items.append(URLQueryItem(name: "period",
                                  value: String(parsed.authenticator.period)))
        if case .hotp(let counter) = parsed.authenticator.kind {
            items.append(URLQueryItem(name: "counter", value: String(counter)))
        }
        components.queryItems = items

        return components.string ?? ""
    }
}
