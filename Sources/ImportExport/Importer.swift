public import Foundation
import VaultCore

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
        /// Recognised, and not something this can open.
        case unreadable(Unreadable)
    }

    /// A file we can name without being able to read it.
    ///
    /// A value, not a sentence. This package has no writing rules and the
    /// application's do not reach across into it, so an English sentence
    /// written here would escape both: no check for an em-dash, none for the
    /// vocabulary the product does not use. The application says the words,
    /// under the rules that govern words. This says which case it is.
    public enum Unreadable: Sendable, Hashable {
        /// A zip, whatever produced it. Raivo exports one, and so does anybody
        /// who zipped a folder before mailing it to themselves.
        case archive
        /// An export the other application encrypted on the way out.
        case encrypted(Format)
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

    /// A file we can name but cannot read, and what to do about it.
    ///
    /// Every app on the list offers an encrypted or archived export as well as
    /// a plain one, and those are the shapes somebody reaches for first,
    /// because they are the ones the other app recommends. Falling through to
    /// "unrecognised format" tells them their file is wrong when it is fine and
    /// simply not yet openable here. Aegis already said the useful thing; this
    /// says it for the rest.
    public static func unreadable(_ data: Data) -> Unreadable? {
        // The local file header every zip starts with.
        if data.starts(with: [0x50, 0x4B, 0x03, 0x04]) { return .archive }

        guard let text = String(data: data, encoding: .utf8),
              let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)),
              let root = object as? [String: Any]
        else { return nil }

        // Ente writes the ciphertext under one key and the parameters for
        // deriving its key under another. Neither is anything we can open.
        if root["encryptedData"] != nil || root["kdfParams"] != nil {
            return .encrypted(.enteAuth)
        }

        if root["servicesEncrypted"] != nil { return .encrypted(.twoFAS) }

        return nil
    }

    /// Parses `data` into a staging area. Nothing is applied.
    public static func stage(_ data: Data, as format: Format? = nil) throws -> ImportStaging {
        // Only when nobody has said what this is. A caller naming a format
        // has a parser with its own better message: Aegis already tells you to
        // decrypt in Aegis, and preempting that with something more general
        // would be a worse answer arriving sooner.
        if format == nil, let reason = unreadable(data) {
            throw Failure.unreadable(reason)
        }

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
}
