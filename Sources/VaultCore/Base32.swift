public import Foundation

/// RFC 4648 Base32, the encoding `otpauth://` uses for OTP secrets.
public enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static let decodeTable: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (index, character) in alphabet.enumerated() {
            table[Int(character.asciiValue!)] = Int8(index)
            table[Int(Character(character.lowercased()).asciiValue!)] = Int8(index)
        }
        return table
    }()

    public static func encode(_ data: some Sequence<UInt8>) -> String {
        var output = ""
        var buffer = 0
        var bits = 0

        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[(buffer >> bits) & 0x1F])
            }
        }
        if bits > 0 {
            output.append(alphabet[(buffer << (5 - bits)) & 0x1F])
        }
        return output
    }

    /// Decodes leniently: lowercase, padding, spaces and hyphens are accepted,
    /// because secrets are routinely copied out of emails and printed pages.
    public static func decode(_ text: String) throws -> [UInt8] {
        var output: [UInt8] = []
        var buffer = 0
        var bits = 0

        for character in text.unicodeScalars {
            if character == "=" || character == " " || character == "-"
                || character == "\n" || character == "\r" || character == "\t" {
                continue
            }
            guard character.isASCII,
                  case let index = Int(character.value),
                  index < 128,
                  decodeTable[index] >= 0 else {
                throw Base32Error.invalidCharacter(Character(character))
            }

            buffer = (buffer << 5) | Int(decodeTable[index])
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> bits) & 0xFF))
            }
        }
        return output
    }
}

public enum Base32Error: Error, Sendable, Equatable {
    case invalidCharacter(Character)
}

extension Base32Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidCharacter(let character):
            "'\(character)' is not part of the Base32 alphabet. Check the secret "
            + "for a mistyped character."
        }
    }
}
