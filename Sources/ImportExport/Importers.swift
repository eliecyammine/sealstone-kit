public import Foundation
public import VaultCore

/// Reads the export formats other authenticators produce.
///
/// Every importer parses into a staging area and validates before anything is
/// applied. The source file is never modified.
public enum Importer {
    public enum Format: String, Sendable, CaseIterable {
        case otpauthURIs
        case aegis
        case twoFAS
        case enteAuth
        case raivo
        case genericJSON

        public var displayName: String {
            switch self {
            case .otpauthURIs: "otpauth:// URIs"
            case .aegis: "Aegis"
            case .twoFAS: "2FAS"
            case .enteAuth: "Ente Auth"
            case .raivo: "Raivo"
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

        if trimmed.lowercased().hasPrefix("otpauth://") { return .otpauthURIs }

        guard trimmed.hasPrefix("{") || trimmed.hasPrefix("["),
              let object = try? JSONSerialization.jsonObject(with: Data(trimmed.utf8))
        else {
            return trimmed.contains("otpauth://") ? .otpauthURIs : nil
        }

        if let root = object as? [String: Any] {
            if root["db"] != nil, root["header"] != nil { return .aegis }
            if root["services"] != nil { return .twoFAS }
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
        case .otpauthURIs:
            return stageURIs(data)
        case .aegis:
            return try stageAegis(data)
        case .twoFAS:
            return try stageTwoFAS(data)
        case .enteAuth, .raivo, .genericJSON:
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
                rejections.append(.init(source: String(trimmed.prefix(60)),
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
            let name = entry["name"] as? String ?? "unknown"
            guard let info = entry["info"] as? [String: Any],
                  let secret = info["secret"] as? String else {
                rejections.append(.init(source: name, reason: "no secret"))
                continue
            }

            let kindName = (entry["type"] as? String ?? "totp").lowercased()
            let algorithmName = (info["algo"] as? String ?? "SHA1").uppercased()
            let digits = info["digits"] as? Int ?? 6
            let period = info["period"] as? Int ?? 30
            let counter = (info["counter"] as? Int).map { UInt64($0) }

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret, algorithm: algorithmName, digits: digits,
                    period: period, kindName: kindName, counter: counter)
                candidates.append(.init(issuer: entry["issuer"] as? String,
                                        account: name,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: name, reason: describe(error)))
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
            let name = service["name"] as? String ?? "unknown"
            guard let secret = service["secret"] as? String else {
                rejections.append(.init(source: name, reason: "no secret"))
                continue
            }

            let otp = service["otp"] as? [String: Any] ?? [:]
            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (otp["algorithm"] as? String ?? "SHA1").uppercased(),
                    digits: otp["digits"] as? Int ?? 6,
                    period: otp["period"] as? Int ?? 30,
                    kindName: (otp["tokenType"] as? String ?? "totp").lowercased(),
                    counter: (otp["counter"] as? Int).map { UInt64($0) })
                candidates.append(.init(issuer: otp["issuer"] as? String ?? name,
                                        account: otp["account"] as? String ?? name,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: name, reason: describe(error)))
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
            func string(_ keys: [String]) -> String? {
                for key in keys {
                    if let value = row[key] as? String, !value.isEmpty { return value }
                }
                return nil
            }
            func integer(_ keys: [String]) -> Int? {
                for key in keys {
                    if let value = row[key] as? Int { return value }
                    if let text = row[key] as? String, let value = Int(text) { return value }
                }
                return nil
            }

            let label = string(["account", "name", "label", "username"]) ?? "unknown"

            // A whole otpauth URI in a field is common in hand-rolled exports.
            if let uri = string(["uri", "url", "otpauth"]),
               uri.lowercased().hasPrefix("otpauth://") {
                do {
                    let parsed = try OTPAuthURI.parse(uri)
                    candidates.append(.init(issuer: parsed.issuer,
                                            account: parsed.account,
                                            authenticator: parsed.authenticator))
                } catch {
                    rejections.append(.init(source: label, reason: describe(error)))
                }
                continue
            }

            guard let secret = string(["secret", "seed", "key"]) else {
                rejections.append(.init(source: label, reason: "no secret"))
                continue
            }

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (string(["algorithm", "algo"]) ?? "SHA1").uppercased(),
                    digits: integer(["digits"]) ?? 6,
                    period: integer(["period", "timer"]) ?? 30,
                    kindName: (string(["type", "tokenType", "kind"]) ?? "totp").lowercased(),
                    counter: integer(["counter"]).map { UInt64($0) })
                candidates.append(.init(issuer: string(["issuer", "service"]),
                                        account: label,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: label, reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    // MARK: - Shared

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
        guard (6...10).contains(digits) else {
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
