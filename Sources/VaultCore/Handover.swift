import Foundation

/// What a handover bundle says about itself.
///
/// Its presence is the one bit that tells a reader what they are holding: a
/// document with this is a bundle cut from a vault, a document without it is
/// the vault. That is checkable before anything else in the file is trusted,
/// which is why it is a single key at the root rather than something inferred
/// from what is inside.
public struct Handover: Sendable, Hashable {
    /// Stable across reissues of the same set. Rotation replaces the fragments,
    /// not the identity of what they open.
    public let bundleId: String

    /// The split these fragments belong to, as thirty-two hex characters.
    /// Held as written so it round-trips exactly, whatever produced it.
    public let setId: String

    public let threshold: Int
    public let total: Int
    public let sealedAt: Timestamp

    /// What the owner wrote for the keepers, shown to them as they wrote it.
    /// The only free text here, and a reader must not interpret it.
    public var note: String?

    /// Set when a later bundle replaces this one, so a keeper holding both can
    /// tell which is current.
    public var supersededBy: String?

    public var unrecognised: [String: JSONValue]

    public init(bundleId: String, setId: String, threshold: Int, total: Int,
                sealedAt: Timestamp, note: String? = nil,
                supersededBy: String? = nil,
                unrecognised: [String: JSONValue] = [:]) {
        self.bundleId = bundleId
        self.setId = setId
        self.threshold = threshold
        self.total = total
        self.sealedAt = sealedAt
        self.note = note
        self.supersededBy = supersededBy
        self.unrecognised = unrecognised
    }

    /// The set identifier as bytes, when it is written the way it should be.
    public var setIdBytes: [UInt8]? {
        guard setId.count == Fragment.setIdLength * 2 else { return nil }
        var bytes = [UInt8]()
        var index = setId.startIndex
        while index < setId.endIndex {
            let next = setId.index(index, offsetBy: 2)
            guard let byte = UInt8(setId[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}
