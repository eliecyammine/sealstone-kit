public import Foundation

/// Moving a Codable type through `JSONValue` and back.
///
/// The format stores unrecognised keys as `JSONValue` so a file written by a
/// newer version survives a round trip through an older one. Anything that
/// needs to become a real type on the way in or out goes through here.

enum JSONValueCoder {
    static func decode<T: Decodable>(_ type: T.Type, from value: JSONValue) throws -> T {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(type, from: data)
    }

    static func encode(_ value: some Encodable) throws -> JSONValue {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }
}
