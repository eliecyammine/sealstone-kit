public import Foundation

/// Errors from reading or writing an Impression.
///
/// Messages state what happened, what it means, and what to do. User-facing
/// copy is derived from them.
public enum ImpressionError: Error, Sendable, Equatable {
    case notAnImpression(String)
    case unsupportedVersion(String)
    case parametersOutOfRange(String)
    case keyMaterialMismatch(String)
    case brokenSeal
}

extension ImpressionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notAnImpression(let detail):
            "This is not a Sealstone backup. \(detail)"

        case .unsupportedVersion(let detail):
            "\(detail) Update the app to open this file."

        case .parametersOutOfRange(let detail):
            "\(detail) Refusing to open it."

        case .keyMaterialMismatch(let detail):
            detail

        case .brokenSeal:
            "This seal is broken. Either the passphrase does not match, or the "
            + "file was changed after it was sealed. Nothing has been read from it."
        }
    }
}
