import Foundation
public import VaultCore

/// Between a document and the bytes that get sealed.
///
/// One place, because a vault and a handover bundle are the same kind of
/// document and must be written the same way. Keys are sorted so that sealing
/// the same document twice produces the same plaintext, which is what lets the
/// test corpus be compared byte for byte.
public enum VaultCoding {
    public static func encode(_ document: VaultDocument) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return [UInt8](try encoder.encode(document))
    }

    public static func decode(_ plaintext: [UInt8]) throws -> VaultDocument {
        let document = try JSONDecoder().decode(VaultDocument.self,
                                                from: Data(plaintext))
        try VaultValidator.validate(document)
        return document
    }
}
