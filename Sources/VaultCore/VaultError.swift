public import Foundation

/// Errors from reading, validating or changing a vault.
///
/// Messages state what happened, what it means, and what to do. User-facing
/// copy is derived from them, so a vague message here becomes a vague message
/// on screen.
public enum VaultError: Error, Sendable, Hashable {
    case missingField(String, in: String)
    case invalidField(String, in: String, reason: String)
    case duplicateIdentifier(String, in: String)
    case danglingReference(field: String, value: String, in: String)
    case limitExceeded(String, count: Int, limit: Int)
    case unsupportedFormatVersion(found: Int, supported: Int)
}

extension VaultError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingField(let field, let context):
            "\(context) is missing the field '\(field)'. The file may be truncated "
            + "or written by a tool that does not follow the format."

        case .invalidField(let field, let context, let reason):
            "\(context) has an invalid '\(field)': \(reason)."

        case .duplicateIdentifier(let id, let collection):
            "Two entries in \(collection) share the identifier '\(id)'. "
            + "Identifiers must be unique, so one of them would be lost."

        case .danglingReference(let field, let value, let context):
            "\(context) refers to '\(value)' in '\(field)', which does not exist "
            + "in this vault. Nothing was imported."

        case .limitExceeded(let collection, let count, let limit):
            "This vault declares \(count) \(collection), above the limit of "
            + "\(limit). Refusing to open it."

        case .unsupportedFormatVersion(let found, let supported):
            "This vault is format version \(found); this version reads \(supported). "
            + "Update the app to open it."
        }
    }
}
