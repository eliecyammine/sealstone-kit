public import Foundation
public import VaultCore

/// Google Authenticator's batch export.
///
/// Its export QR codes carry an `otpauth-migration://offline?data=<base64>`
/// URI whose payload is a protocol buffer. Rather than take a protobuf
/// dependency for one message, the three field types actually present are
/// decoded directly — varints, length-delimited bytes, and nested messages.
/// The wire format is stable and simple enough that reading it is smaller than
/// depending on a library to read it.
public enum GoogleAuthenticatorMigration {
    public enum Failure: Error, Sendable, Equatable {
        case notAMigrationURI
        case malformedPayload(String)
    }

    public static func isMigrationURI(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .hasPrefix("otpauth-migration://")
    }

    public static func parse(_ text: String) throws -> ImportStaging {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isMigrationURI(trimmed),
              let components = URLComponents(string: trimmed),
              let encoded = components.queryItems?.first(where: { $0.name == "data" })?.value
        else {
            throw Failure.notAMigrationURI
        }

        // The payload arrives percent-decoded by URLComponents but may still
        // use the URL-safe alphabet and omit padding.
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }

        guard let payload = Data(base64Encoded: base64) else {
            throw Failure.malformedPayload("the data parameter is not valid base64")
        }

        return try decode([UInt8](payload))
    }

    // MARK: - Protocol buffer

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        var isAtEnd: Bool { offset >= bytes.count }

        mutating func varint() throws -> UInt64 {
            var value: UInt64 = 0
            var shift: UInt64 = 0

            while true {
                guard offset < bytes.count else {
                    throw Failure.malformedPayload("a number runs past the end of the payload")
                }
                guard shift < 64 else {
                    throw Failure.malformedPayload("a number is too large to be valid")
                }
                let byte = bytes[offset]
                offset += 1
                value |= UInt64(byte & 0x7F) << shift
                if byte & 0x80 == 0 { break }
                shift += 7
            }
            return value
        }

        mutating func lengthDelimited() throws -> [UInt8] {
            let length = Int(try varint())
            guard length >= 0, offset + length <= bytes.count else {
                throw Failure.malformedPayload("a field claims more bytes than the payload holds")
            }
            let slice = Array(bytes[offset..<(offset + length)])
            offset += length
            return slice
        }

        /// Steps over a field this decoder does not need.
        mutating func skip(wireType: UInt64) throws {
            switch wireType {
            case 0: _ = try varint()
            case 1: offset += 8
            case 2: _ = try lengthDelimited()
            case 5: offset += 4
            default:
                throw Failure.malformedPayload("unsupported field encoding \(wireType)")
            }
            guard offset <= bytes.count else {
                throw Failure.malformedPayload("a field runs past the end of the payload")
            }
        }
    }

    private static func decode(_ payload: [UInt8]) throws -> ImportStaging {
        var reader = Reader(bytes: payload)
        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        while !reader.isAtEnd {
            let key = try reader.varint()
            let field = key >> 3
            let wireType = key & 0x7

            // Field 1 is the repeated OtpParameters message. Everything else —
            // version, batch size, batch index, batch id — is metadata.
            guard field == 1, wireType == 2 else {
                try reader.skip(wireType: wireType)
                continue
            }

            let message = try reader.lengthDelimited()
            do {
                candidates.append(try decodeParameters(message))
            } catch {
                rejections.append(.init(source: "a Google Authenticator entry",
                                        reason: describe(error)))
            }
        }

        guard !candidates.isEmpty || !rejections.isEmpty else {
            throw Failure.malformedPayload("this export contains no credentials")
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }

    private static func decodeParameters(_ message: [UInt8]) throws -> ImportStaging.Candidate {
        var reader = Reader(bytes: message)

        var secret: [UInt8] = []
        var name = ""
        var issuer: String?
        var algorithmCode: UInt64 = 1
        var digitsCode: UInt64 = 1
        var typeCode: UInt64 = 2
        var counter: UInt64 = 0

        while !reader.isAtEnd {
            let key = try reader.varint()
            let field = key >> 3
            let wireType = key & 0x7

            switch (field, wireType) {
            case (1, 2): secret = try reader.lengthDelimited()
            case (2, 2): name = String(decoding: try reader.lengthDelimited(), as: UTF8.self)
            case (3, 2): issuer = String(decoding: try reader.lengthDelimited(), as: UTF8.self)
            case (4, 0): algorithmCode = try reader.varint()
            case (5, 0): digitsCode = try reader.varint()
            case (6, 0): typeCode = try reader.varint()
            case (7, 0): counter = try reader.varint()
            default: try reader.skip(wireType: wireType)
            }
        }

        guard !secret.isEmpty else {
            throw Failure.malformedPayload("an entry carries no secret")
        }

        // The enums are small and closed. An unknown value is a newer export
        // than this build understands, and guessing would produce a credential
        // that generates wrong codes.
        let algorithm: Authenticator.Algorithm = switch algorithmCode {
        case 0, 1: .sha1
        case 2: .sha256
        case 3: .sha512
        default: throw Failure.malformedPayload("unknown algorithm code \(algorithmCode)")
        }

        let digits: Int = switch digitsCode {
        case 0, 1: 6
        case 2: 8
        default: throw Failure.malformedPayload("unknown digit-count code \(digitsCode)")
        }

        let kind: Authenticator.Kind = switch typeCode {
        case 1: .hotp(counter: counter)
        case 0, 2: .totp
        default: throw Failure.malformedPayload("unknown credential type \(typeCode)")
        }

        // The label is "Issuer:account" when the issuer field is absent.
        var account = name
        if issuer == nil, let separator = name.firstIndex(of: ":") {
            issuer = String(name[..<separator]).trimmingCharacters(in: .whitespaces)
            account = String(name[name.index(after: separator)...])
                .trimmingCharacters(in: .whitespaces)
        }

        return ImportStaging.Candidate(
            issuer: issuer?.isEmpty == true ? nil : issuer,
            account: account,
            authenticator: Authenticator(
                secret: Base32.encode(secret),
                algorithm: algorithm,
                digits: digits,
                period: 30,          // Google's export carries no period; 30 is its only value
                kind: kind)
        )
    }

    private static func describe(_ error: any Error) -> String {
        if case Failure.malformedPayload(let detail) = error { return detail }
        return error.localizedDescription
    }
}
