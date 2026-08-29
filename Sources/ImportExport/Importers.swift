public import Foundation
public import VaultCore

/// Reads the export formats other authenticators produce.
///
/// Every importer parses into a staging area and validates before anything is
/// applied. The source file is never modified.
public enum Importer {
    public enum Format: String, Sendable, CaseIterable {
        case otpauthURIs
        case googleAuthenticator
        case aegis
        case twoFAS
        case enteAuth
        case raivo
        case lastPass
        case genericJSON

        public var displayName: String {
            switch self {
            case .otpauthURIs: "otpauth:// URIs"
            case .googleAuthenticator: "Google Authenticator"
            case .aegis: "Aegis"
            case .twoFAS: "2FAS"
            case .enteAuth: "Ente Auth"
            case .raivo: "Raivo"
            case .lastPass: "LastPass Authenticator"
            case .genericJSON: "JSON"
            }
        }
    }

    public enum Failure: Error, Sendable, Equatable {
        case unrecognisedFormat
        case malformed(String)
    }

    /// Guesses the format from the content.
    ///
    /// Extensions lie and users rename files, so this looks at what is actually
    /// there.
    public static func detect(_ data: Data) -> Format? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)

        if GoogleAuthenticatorMigration.isMigrationURI(trimmed) { return .googleAuthenticator }
        if trimmed.lowercased().hasPrefix("otpauth://") { return .otpauthURIs }

        guard trimmed.hasPrefix("{") || trimmed.hasPrefix("["),
              let object = try? JSONSerialization.jsonObject(with: Data(trimmed.utf8))
        else {
            if trimmed.contains("otpauth-migration://") { return .googleAuthenticator }
            return trimmed.contains("otpauth://") ? .otpauthURIs : nil
        }

        if let root = object as? [String: Any] {
            if root["db"] != nil, root["header"] != nil { return .aegis }
            if root["services"] != nil { return .twoFAS }

            // LastPass also keys its list "accounts", so the list itself is
            // what tells them apart: LastPass names the fields inside each
            // entry differently from everyone else.
            if let accounts = root["accounts"] as? [[String: Any]],
               accounts.first?["issuerName"] != nil
                || accounts.first?["originalIssuerName"] != nil {
                return .lastPass
            }
            if root["items"] != nil || root["entries"] != nil { return .genericJSON }
        }
        if let array = object as? [[String: Any]] {
            if array.first?["secret"] != nil { return .raivo }
            return .genericJSON
        }
        return .genericJSON
    }

    /// Parses `data` into a staging area. Nothing is applied.
    public static func stage(_ data: Data, as format: Format? = nil) throws -> ImportStaging {
        guard let resolved = format ?? detect(data) else {
            throw Failure.unrecognisedFormat
        }

        switch resolved {
        case .googleAuthenticator:
            return try GoogleAuthenticatorMigration.parse(
                String(decoding: data, as: UTF8.self))
        case .otpauthURIs:
            return stageURIs(data)
        case .aegis:
            return try stageAegis(data)
        case .twoFAS:
            return try stageTwoFAS(data)
        case .enteAuth, .raivo, .lastPass, .genericJSON:
            return try stageGeneric(data)
        }
    }

    // MARK: - Formats

    private static func stageURIs(_ data: Data) -> ImportStaging {
        let text = String(decoding: data, as: UTF8.self)
        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            do {
                let parsed = try OTPAuthURI.parse(trimmed)
                candidates.append(.init(issuer: parsed.issuer,
                                        account: parsed.account,
                                        authenticator: parsed.authenticator))
            } catch {
                rejections.append(.init(source: describeURI(trimmed),
                                        reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    private static func stageAegis(_ data: Data) throws -> ImportStaging {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let db = root["db"] as? [String: Any] else {
            throw Failure.malformed(
                "This looks like an Aegis export but the database section is missing. "
                + "If it is encrypted, decrypt it in Aegis before importing.")
        }
        guard let entries = db["entries"] as? [[String: Any]] else {
            throw Failure.malformed("This Aegis export contains no entries.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for entry in entries {
            let name = entry["name"] as? String ?? ""
            guard let info = entry["info"] as? [String: Any],
                  let secret = info["secret"] as? String else {
                rejections.append(.init(source: named(name), reason: "no secret"))
                continue
            }

            let kindName = (entry["type"] as? String ?? "totp").lowercased()
            let algorithmName = (info["algo"] as? String ?? "SHA1").uppercased()
            let digits = info["digits"] as? Int ?? (kindName == "steam" ? 5 : 6)
            let period = info["period"] as? Int ?? 30
            let counter = nonNegative(info["counter"] as? Int)

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret, algorithm: algorithmName, digits: digits,
                    period: period, kindName: kindName, counter: counter)
                candidates.append(.init(issuer: entry["issuer"] as? String,
                                        account: name,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(name), reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    private static func stageTwoFAS(_ data: Data) throws -> ImportStaging {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let services = root["services"] as? [[String: Any]] else {
            throw Failure.malformed("This 2FAS export contains no services.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for service in services {
            let name = service["name"] as? String ?? ""
            guard let secret = service["secret"] as? String else {
                rejections.append(.init(source: named(name), reason: "no secret"))
                continue
            }

            let otp = service["otp"] as? [String: Any] ?? [:]
            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (otp["algorithm"] as? String ?? "SHA1").uppercased(),
                    digits: otp["digits"] as? Int
                        ?? ((otp["tokenType"] as? String ?? "").lowercased() == "steam" ? 5 : 6),
                    period: otp["period"] as? Int ?? 30,
                    kindName: (otp["tokenType"] as? String ?? "totp").lowercased(),
                    counter: nonNegative(otp["counter"] as? Int))
                // 2FAS puts the service in `name` and, when it has one, the
                // login in `otp.account`. Falling back to `name` for the
                // account put the service on both halves, so every row read
                // "GitHub (GitHub)". An entry with no login has no login;
                // repeating the service does not supply one.
                candidates.append(.init(issuer: otp["issuer"] as? String
                                            ?? (name.isEmpty ? nil : name),
                                        account: otp["account"] as? String ?? "",
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(name), reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    /// Handles Ente, Raivo and hand-rolled JSON, which all reduce to a list of
    /// objects carrying a secret and some labels under varying key names.
    private static func stageGeneric(_ data: Data) throws -> ImportStaging {
        let object = try? JSONSerialization.jsonObject(with: data)

        let rows: [[String: Any]]
        if let array = object as? [[String: Any]] {
            rows = array
        } else if let root = object as? [String: Any] {
            rows = (root["items"] as? [[String: Any]])
                ?? (root["entries"] as? [[String: Any]])
                ?? (root["accounts"] as? [[String: Any]])
                ?? []
        } else {
            throw Failure.malformed("This file is not a list of credentials.")
        }

        guard !rows.isEmpty else {
            throw Failure.malformed("This file contains no credentials.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for row in rows {
            // Matched without regard to case, and one level into nested
            // objects. Exports disagree about capitalisation as much as about
            // wording, and several bury the interesting fields one object
            // deep. Only the keys named below are followed inwards: taking
            // any string found nested would happily label an account with the
            // name of the folder it was filed in.
            func value(_ keys: [String]) -> Any? {
                for key in keys {
                    if let found = row.first(where: {
                        $0.key.caseInsensitiveCompare(key) == .orderedSame
                    })?.value, !(found is NSNull) {
                        return found
                    }
                }
                for nested in row.values.compactMap({ $0 as? [String: Any] }) {
                    for key in keys {
                        if let found = nested.first(where: {
                            $0.key.caseInsensitiveCompare(key) == .orderedSame
                        })?.value, !(found is NSNull) {
                            return found
                        }
                    }
                }
                return nil
            }
            func string(_ keys: [String]) -> String? {
                guard let text = value(keys) as? String, !text.isEmpty else { return nil }
                return text
            }
            func integer(_ keys: [String]) -> Int? {
                if let number = value(keys) as? Int { return number }
                if let text = value(keys) as? String, let number = Int(text) { return number }
                return nil
            }

            // An unnamed row is left unnamed rather than called "unknown".
            // A placeholder that looks like a name survives the review screen
            // unchallenged and lands in the vault as though the export had
            // said it, and every such row reads the same, so a vault of them
            // cannot be told apart afterwards.
            let label = string(["account", "accountName", "name", "label",
                                "username", "userName", "originalUserName",
                                "user", "login", "email", "displayName"]) ?? ""

            // A whole otpauth URI in a field is common in hand-rolled exports.
            if let uri = string(["uri", "url", "otpauth"]),
               uri.lowercased().hasPrefix("otpauth://") {
                do {
                    let parsed = try OTPAuthURI.parse(uri)
                    candidates.append(.init(issuer: parsed.issuer,
                                            account: parsed.account,
                                            authenticator: parsed.authenticator))
                } catch {
                    rejections.append(.init(source: named(label),
                                            reason: describe(error)))
                }
                continue
            }

            guard let secret = string(["secret", "seed", "key", "secretKey"]) else {
                rejections.append(.init(source: named(label),
                                        reason: "no secret"))
                continue
            }

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (string(["algorithm", "algo"]) ?? "SHA1").uppercased(),
                    digits: integer(["digits"])
                        ?? ((string(["type", "tokenType", "kind"]) ?? "").lowercased() == "steam" ? 5 : 6),
                    period: integer(["period", "timer", "timeStep"]) ?? 30,
                    kindName: (string(["type", "tokenType", "kind"]) ?? "totp").lowercased(),
                    counter: nonNegative(integer(["counter"])))
                candidates.append(.init(issuer: string(["issuer", "issuerName",
                                                        "originalIssuerName", "service",
                                                        "serviceName", "provider", "site",
                                                        "title"]),
                                        account: label,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(label),
                                        reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    // MARK: - Shared

    /// Names a URI that would not parse, without repeating what it carried.
    ///
    /// The first sixty characters used to go on the review screen verbatim.
    /// `otpauth://totp/x?secret=...` puts the secret inside them, so a line
    /// that failed for an unrelated reason printed a working credential onto a
    /// screen, into a screenshot, and into whatever the person sent to ask
    /// what went wrong. The label identifies the row; the query never does.
    private static func describeURI(_ text: String) -> String {
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
    private static func nonNegative(_ value: Int?) -> UInt64? {
        guard let value, value >= 0 else { return nil }
        return UInt64(value)
    }

    private static func makeAuthenticator(
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
    private static func named(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "an unnamed entry" : name
    }

    private static func describe(_ error: any Error) -> String {
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
