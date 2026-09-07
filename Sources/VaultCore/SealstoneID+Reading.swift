import Foundation

/// Reading an identifier back, including one somebody has retyped.
///
/// Generating them is the easy half. The half that matters is a keeper sitting
/// with a printed sheet and a keyboard, copying an identifier across without
/// the vault, the app, or anything to check their work against. What they type
/// will not be what was printed: a letter O for a zero, a capital I for a one,
/// the case their keyboard happened to be in.
///
/// So the body is read leniently and the kind is not. Two spellings of one body
/// name one thing, which is what lets a person succeed at retyping. Two
/// spellings of one *kind* would let `acc_…` and `ACC_…` name one thing in two
/// ways, and the vault refuses two things with one name.
extension SealstoneID {
    /// An identifier taken apart.
    public struct Parsed: Sendable, Hashable {
        public let kind: Kind

        /// The body in its one canonical spelling, whatever spelling arrived.
        public let body: String

        /// How it is written down.
        public var canonical: String { "\(kind.rawValue)_\(body)" }
    }

    /// Characters in a body: a hundred and twenty-eight bits at five bits each,
    /// rounded up. Checked as a count rather than as a decoded length, because
    /// twenty-six and twenty-seven characters both decode to sixteen bytes and
    /// one of them is a typing mistake.
    static let bodyLength = 26

    /// Reads an identifier, or does not.
    public static func parse(_ text: String) -> Parsed? {
        guard let separator = text.firstIndex(of: "_") else { return nil }

        // Matched exactly. `Kind` spells its cases in lower case and this does
        // not fold, so `ACC_` is not an account.
        guard let kind = Kind(rawValue: String(text[text.startIndex..<separator]))
        else { return nil }

        let written = String(text[text.index(after: separator)...])
        guard let body = CrockfordBase32.canonical(written),
              body.count == bodyLength
        else { return nil }

        return Parsed(kind: kind, body: body)
    }

    /// Whether two identifiers name the same thing.
    ///
    /// Anything unreadable names nothing, and nothing is the same as nothing,
    /// so two unreadable identifiers are not equal to each other.
    public static func areTheSame(_ one: String, _ other: String) -> Bool {
        guard let one = parse(one), let other = parse(other) else { return false }
        return one == other
    }
}
