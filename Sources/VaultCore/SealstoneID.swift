public import Foundation

/// Identifier generation.
///
/// Two schemes, and which one an identifier gets is decided by its kind rather
/// than by the caller — the choice is a security decision and does not belong
/// at a call site.
///
/// **Time-ordered** identifiers carry a millisecond timestamp in their leading
/// bits (the UUID version 7 layout). They sort by creation, which makes a vault
/// dump readable and a diff meaningful. Used for everything that stays inside
/// the encrypted vault.
///
/// **Random** identifiers carry no timestamp. Used for anything that can appear
/// outside the vault — a keeper's handover URL is seen by whoever holds the
/// link, and a time-ordered identifier there would tell them when the handover
/// was set up. That is a small leak, and it is free to avoid.
public enum SealstoneID {
    public enum Kind: String, Sendable, CaseIterable {
        case vault = "vlt"
        case account = "acc"
        case item = "itm"
        case link = "lnk"
        case keeper = "kpr"
        case bundle = "bnd"

        /// Whether an identifier of this kind can be seen outside the vault.
        var escapesTheVault: Bool {
            switch self {
            case .keeper, .bundle: true
            case .vault, .account, .item, .link: false
            }
        }
    }

    /// Generates an identifier for `kind`.
    public static func make(_ kind: Kind, at date: Date = Date()) -> String {
        let bytes = kind.escapesTheVault ? randomBytes(16) : timeOrderedBytes(at: date)
        return "\(kind.rawValue)_\(CrockfordBase32.encode(bytes, group: 0))"
    }

    /// The UUID version 7 layout: a 48-bit millisecond timestamp, then random
    /// bits, with the version and variant markers in their fixed positions.
    static func timeOrderedBytes(at date: Date = Date()) -> [UInt8] {
        var bytes = randomBytes(16)

        let milliseconds = UInt64((date.timeIntervalSince1970 * 1000).rounded(.down))
        for offset in 0..<6 {
            bytes[offset] = UInt8((milliseconds >> (8 * UInt64(5 - offset))) & 0xFF)
        }

        bytes[6] = (bytes[6] & 0x0F) | 0x70   // version 7
        bytes[8] = (bytes[8] & 0x3F) | 0x80   // variant 10

        return bytes
    }

    /// The timestamp embedded in a time-ordered identifier, for diagnostics.
    /// Returns nil for random identifiers and for anything malformed.
    public static func creationDate(of identifier: String) -> Date? {
        let parts = identifier.split(separator: "_", maxSplits: 1)
        guard parts.count == 2,
              let kind = Kind(rawValue: String(parts[0])),
              !kind.escapesTheVault,
              let bytes = try? CrockfordBase32.decode(String(parts[1])),
              bytes.count >= 8,
              (bytes[6] & 0xF0) == 0x70 else { return nil }

        var milliseconds: UInt64 = 0
        for offset in 0..<6 {
            milliseconds = (milliseconds << 8) | UInt64(bytes[offset])
        }
        return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
    }

    private static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for index in 0..<count { bytes[index] = UInt8.random(in: 0...255, using: &generator) }
        return bytes
    }
}
