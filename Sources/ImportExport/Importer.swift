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





    // MARK: - Shared





}
