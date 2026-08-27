public import Foundation

/// Arbitrary JSON, used to carry fields this version does not recognise.
///
/// A vault written by a newer version may contain item types and keys that do
/// not exist yet. Decoding must not drop them, or opening a vault in an older
/// build and saving it would silently destroy data. Unrecognised content is
/// parked here and written back out byte-for-byte equivalent.
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "value is not valid JSON"
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()

        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .number(let value):
            // Whole numbers round-trip as integers so a counter of 7 does not
            // become 7.0 and change the bytes of a re-encoded vault.
            if value == value.rounded(), abs(value) < 9_007_199_254_740_992 {
                try container.encode(Int64(value))
            } else {
                try container.encode(value)
            }
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

extension JSONValue {
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var intValue: Int? {
        guard case .number(let value) = self else { return nil }

        // `Int(exactly:)` rather than a rounded check and a conversion. JSON
        // numbers are Doubles, and a hostile file can carry 1e300: that is a
        // whole number, so a rounded check waves it through, and converting it
        // then traps. This module refuses bad input rather than dying on it,
        // and a number too large to be an Int is simply not an Int.
        return Int(exactly: value)
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }
}
