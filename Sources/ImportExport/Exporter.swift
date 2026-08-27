public import Foundation
public import VaultCore

/// Writes credentials out in a form other apps read.
///
/// The point of this is that leaving must be possible. A vault nobody can
/// leave is a vault nobody should adopt, and an export that only this app can
/// read is not an export.
///
/// The file it writes is **not encrypted**. That is not an oversight, it is
/// what makes it readable by another authenticator, and it is why the caller
/// has to say so in those words before writing anything.
public enum Exporter {
    /// What comes out, and what could not.
    ///
    /// The two halves are returned together on purpose. `otpauth://` carries a
    /// one-time code and nothing else: it has no way to express a set of
    /// recovery codes, a seed phrase, a password or a note. Reporting only the
    /// URIs would let a user believe their vault had been carried across when
    /// most of it had been left behind, and they would find out at the moment
    /// they needed the part that did not travel.
    public struct Export: Sendable, Equatable {
        /// One `otpauth://` URI per line, newline-terminated.
        public let text: String

        /// How many items were written.
        public let written: Int

        /// The items no URI can express, described so the user can see what
        /// stayed behind rather than being handed a number.
        public let untranslatable: [Untranslatable]

        public struct Untranslatable: Sendable, Equatable {
            public let label: String
            public let kind: String
        }

        public var isEmpty: Bool { written == 0 }
    }

    /// Renders every authenticator in the document.
    ///
    /// Ordering follows the document, so a file exported twice from an
    /// unchanged vault is the same file both times. A diff that is only
    /// reordering is a diff nobody can read.
    public static func otpauthURIs(from document: VaultDocument) -> Export {
        var lines: [String] = []
        var untranslatable: [Export.Untranslatable] = []

        for item in document.items {
            let account = document.account(item.accountId)
            let service = account?.service.trimmingCharacters(in: .whitespacesAndNewlines)
            let identifier = account?.identifier ?? ""

            guard case .authenticator(let authenticator) = item.payload else {
                untranslatable.append(.init(
                    label: describe(service: service, identifier: identifier),
                    kind: item.payload.typeName))
                continue
            }

            lines.append(OTPAuthURI.render(OTPAuthURI.Parsed(
                issuer: (service?.isEmpty == false) ? service : nil,
                account: identifier,
                authenticator: authenticator)))
        }

        return Export(
            text: lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n",
            written: lines.count,
            untranslatable: untranslatable)
    }

    private static func describe(service: String?, identifier: String) -> String {
        let service = service ?? ""
        switch (service.isEmpty, identifier.isEmpty) {
        case (false, false): return "\(service) (\(identifier))"
        case (false, true): return service
        case (true, false): return identifier
        case (true, true): return "Unnamed"
        }
    }
}
