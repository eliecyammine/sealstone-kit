/// Carrying the keys a version does not recognise.
///
/// A vault written by a newer version contains fields this one has no property
/// for. Dropping them means that opening a vault in an older build and saving
/// it destroys whatever the newer build wrote, so every object that can gain a
/// field keeps what it did not understand and writes it back out.
///
/// Synthesised `Codable` cannot do this. It reads the keys it has properties
/// for and writes the keys it has properties for, which is why the types that
/// need this code themselves.
enum UnknownKeys {
    /// Every key actually present that `known` does not cover.
    static func read(from decoder: any Decoder,
                     known: Set<String>) throws -> [String: JSONValue] {
        let container = try decoder.container(keyedBy: AnyKey.self)

        var leftover: [String: JSONValue] = [:]
        for key in container.allKeys where !known.contains(key.stringValue) {
            leftover[key.stringValue] = try container.decode(JSONValue.self, forKey: key)
        }
        return leftover
    }

    /// Writes the carried keys.
    ///
    /// Call this before writing the known ones. Encoding the same key twice
    /// keeps the last value, so writing these first means a stale carried entry
    /// can never shadow a real field.
    static func write(_ leftover: [String: JSONValue],
                      known: Set<String>,
                      to encoder: any Encoder) throws {
        guard !leftover.isEmpty else { return }

        var container = encoder.container(keyedBy: AnyKey.self)
        for (key, value) in leftover where !known.contains(key) {
            try container.encode(value, forKey: AnyKey(stringValue: key))
        }
    }

    /// Lets a decoder enumerate the keys that are there, rather than only the
    /// ones this version knows to ask for.
    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }
}
