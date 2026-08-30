public import Foundation
public import VaultCore
public import VaultCrypto

/// Between a document and the bytes that get sealed.
///
/// `nonisolated`, because encoding is pure work on a value and holding the
/// actor while it happens would serialise every caller behind whichever one
/// is currently formatting JSON.

extension VaultStore {
    nonisolated func encode(_ document: VaultDocument) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return [UInt8](try encoder.encode(document))
    }

    nonisolated func decode(_ plaintext: [UInt8]) throws -> VaultDocument {
        try VaultStore.decodeDocument(plaintext)
    }

    static func decodeDocument(_ plaintext: [UInt8]) throws -> VaultDocument {
        let document = try JSONDecoder().decode(VaultDocument.self,
                                                from: Data(plaintext))
        try VaultValidator.validate(document)
        return document
    }
}
