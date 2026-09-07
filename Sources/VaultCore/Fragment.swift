import Foundation

/// The file or printed sheet a keeper holds.
///
/// One Shamir share, plus enough context to be useful on its own: which split
/// it belongs to, which point it is, and how many are needed. Without that
/// context a share is an anonymous blob nobody can act on.
///
/// **Two forms of one thing.** The binary form is what an application writes.
/// The paper form is the same bytes in Crockford Base32, grouped for
/// transcription, because the person holding this may be reading it off a sheet
/// years from now with no software at all.
///
/// **No English here.** A fragment that will not read reports which case it is
/// and the application says the sentence, under the writing rules that only
/// reach the application. That also means a sheet can be reworded without
/// touching this, which matters: reading a fragment back finds the payload by
/// its shape rather than by matching the prose around it.
public struct Fragment: Sendable, Hashable {
    public static let magic = Array("SEALFRG".utf8)
    public static let version: UInt8 = 1
    public static let setIdLength = 16
    static let headerLength = 29
    static let checksumLength = 4

    public let setId: [UInt8]
    public let index: UInt8
    public let threshold: UInt8
    public let total: UInt8
    public let share: [UInt8]

    public enum Failure: Error, Sendable, Equatable {
        case setIdIsWrongLength(Int)
        /// Index zero is the secret itself, so it is never a share.
        case indexIsZero
        case thresholdMakesNoSense(threshold: Int, total: Int)
        case shareLengthOutOfRange(Int)
        case tooShortToBeAFragment
        case notAFragment
        case unsupportedVersion(UInt8)
        /// The header says one length and the data is another: truncated, or
        /// mistyped, or both.
        case lengthDisagrees(claimed: Int, actual: Int)
        /// Almost always a character read wrong off a sheet.
        case checksumDoesNotMatch
        case noFragmentFound
        case notCrockford
    }

    public init(setId: [UInt8], index: UInt8, threshold: UInt8,
                total: UInt8, share: [UInt8]) throws {
        guard setId.count == Self.setIdLength else {
            throw Failure.setIdIsWrongLength(setId.count)
        }
        guard index != 0 else { throw Failure.indexIsZero }
        guard threshold >= 2, threshold <= total else {
            throw Failure.thresholdMakesNoSense(threshold: Int(threshold),
                                                total: Int(total))
        }
        guard !share.isEmpty, share.count <= 0xFFFF else {
            throw Failure.shareLengthOutOfRange(share.count)
        }

        self.setId = setId
        self.index = index
        self.threshold = threshold
        self.total = total
        self.share = share
    }

    // MARK: - Binary

    /// The bytes an application writes. Big-endian throughout, as everywhere
    /// else in this format.
    public var encoded: [UInt8] {
        var body = Self.magic
        body.append(Self.version)
        body += setId
        body += [index, threshold, total]
        body += [UInt8(share.count >> 8), UInt8(share.count & 0xFF)]
        body += share

        let checksum = CRC32.checksum(body)
        body += [UInt8(truncatingIfNeeded: checksum >> 24),
                 UInt8(truncatingIfNeeded: checksum >> 16),
                 UInt8(truncatingIfNeeded: checksum >> 8),
                 UInt8(truncatingIfNeeded: checksum)]
        return body
    }

    public static func decode(_ data: [UInt8]) throws -> Fragment {
        guard data.count >= headerLength + checksumLength else {
            throw Failure.tooShortToBeAFragment
        }
        guard Array(data[0..<magic.count]) == magic else { throw Failure.notAFragment }

        let version = data[7]
        guard version == Self.version else { throw Failure.unsupportedVersion(version) }

        let shareLength = Int(data[27]) << 8 | Int(data[28])
        let expected = headerLength + shareLength + checksumLength
        guard data.count == expected else {
            throw Failure.lengthDisagrees(
                claimed: shareLength,
                actual: data.count - headerLength - checksumLength)
        }

        // Checked before anything is believed, because everything after this
        // is read out of bytes somebody may have mistyped.
        let body = Array(data[0..<(data.count - checksumLength)])
        let carried = data.suffix(checksumLength).reduce(UInt32(0)) {
            $0 << 8 | UInt32($1)
        }
        guard CRC32.checksum(body) == carried else {
            throw Failure.checksumDoesNotMatch
        }

        return try Fragment(setId: Array(data[8..<24]),
                            index: data[24],
                            threshold: data[25],
                            total: data[26],
                            share: Array(data[headerLength..<(headerLength + shareLength)]))
    }

    // MARK: - Paper

    /// The payload as it is printed: Crockford Base32 in groups of five.
    ///
    /// Crockford because it leaves out I, L, O and U, which are the characters
    /// people mistranscribe, and reads back leniently for the same reason.
    public var paperGroups: [String] {
        CrockfordBase32.encode(encoded, group: 5).split(separator: " ").map(String.init)
    }

    /// The set, short enough to be printed beside the groups and compared by
    /// eye against another keeper's sheet.
    public var setLabel: String {
        let head = setId.prefix(4).map { String(format: "%02X", $0) }.joined()
        return "\(head.prefix(4))-\(head.suffix(4))"
    }

    /// Reads a fragment back out of whatever was typed or pasted.
    ///
    /// A whole sheet can be handed to this without trimming the instructions
    /// off it. Payload is recognised by its shape, groups of five Crockford
    /// characters, rather than by matching the words around it, so the sheet
    /// can be reworded or translated without breaking the way it is read back.
    public static func fromPaper(_ text: String) throws -> Fragment {
        var payload: [String] = []
        var inPayload = false

        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard !tokens.isEmpty else { continue }

            let looksLikePayload = tokens.allSatisfy(isPayloadToken)
                && (tokens.contains { $0.count == 5 } || inPayload)

            if looksLikePayload {
                payload += tokens
                inPayload = true
            } else {
                inPayload = false
            }
        }

        guard !payload.isEmpty else { throw Failure.noFragmentFound }
        guard let bytes = try? CrockfordBase32.decode(payload.joined()) else {
            throw Failure.notCrockford
        }
        return try decode(bytes)
    }

    /// Five characters of Crockford. Prose fails on length, on punctuation, or
    /// on both.
    private static func isPayloadToken(_ token: String) -> Bool {
        guard !token.isEmpty, token.count <= 5 else { return false }
        return (try? CrockfordBase32.decode(token)) != nil
    }
}
