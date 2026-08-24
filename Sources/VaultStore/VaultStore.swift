public import Foundation
public import VaultCore
public import VaultCrypto

/// Reads and writes the vault on disk.
///
/// Writes are atomic: the new file is written beside the old one and swapped
/// into place, so a crash mid-write leaves the previous vault intact rather
/// than a truncated one. A vault that can be corrupted by a battery dying is
/// not a vault.
///
/// The store holds no key. Callers supply key material per operation, which
/// keeps the decision about how long a key stays in memory with the layer that
/// knows about app lifecycle.
public actor VaultStore {
    public enum Failure: Error, Sendable, Equatable {
        case noVaultAtLocation(URL)
        case vaultAlreadyExists(URL)
        case writeFailed(String)
        case backupUnreadable(String)
    }

    private let location: URL
    private let fileManager: FileManager

    public init(location: URL, fileManager: FileManager = .default) {
        self.location = location
        self.fileManager = fileManager
    }

    public var url: URL { location }

    public var exists: Bool {
        fileManager.fileExists(atPath: location.path)
    }

    // MARK: - Reading

    /// Loads and decodes the vault.
    public func load(key: [UInt8]) throws -> VaultDocument {
        guard exists else { throw Failure.noVaultAtLocation(location) }

        let data = try Data(contentsOf: location)
        let (plaintext, _) = try Impression.open([UInt8](data), using: .key(key))
        return try decode(plaintext)
    }

    // MARK: - Writing

    /// Creates a vault. Refuses to overwrite an existing one.
    public func create(_ document: VaultDocument, key: [UInt8]) throws {
        guard !exists else { throw Failure.vaultAlreadyExists(location) }
        try write(document, key: key)
    }

    /// Replaces the vault contents.
    public func save(_ document: VaultDocument, key: [UInt8]) throws {
        var updated = document
        updated.updatedAt = .now()
        try write(updated, key: key)
    }

    /// Loads, applies a change, and saves — as one operation, so two callers
    /// cannot interleave a read and a write and lose one of the changes.
    @discardableResult
    public func update<T>(
        key: [UInt8],
        _ change: (inout VaultDocument) throws -> T
    ) throws -> T {
        var document = try load(key: key)
        let result = try change(&document)
        try save(document, key: key)
        return result
    }

    private func write(_ document: VaultDocument, key: [UInt8]) throws {
        let plaintext = try encode(document)
        let sealed = try Impression.seal(plaintext, using: .key(key))

        // Write beside the target, then swap. The swap is the only step that
        // can be observed as a change, and it either happened or it did not.
        let temporary = location.deletingLastPathComponent()
            .appendingPathComponent(".\(location.lastPathComponent).writing")

        do {
            try fileManager.createDirectory(
                at: location.deletingLastPathComponent(),
                withIntermediateDirectories: true)

            try Data(sealed).write(to: temporary, options: .atomic)
            try excludeFromBackup(temporary)

            if fileManager.fileExists(atPath: location.path) {
                _ = try fileManager.replaceItemAt(location, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: location)
            }
            try excludeFromBackup(location)
        } catch {
            try? fileManager.removeItem(at: temporary)
            throw Failure.writeFailed(error.localizedDescription)
        }
    }

    /// The vault is deliberately not swept into iCloud Backup. Restoring a
    /// device restores the app, not the vault; the sealed backup is the only
    /// restore path, which is what keeps the vault out of anyone else's
    /// infrastructure.
    private func excludeFromBackup(_ url: URL) throws {
        var mutable = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutable.setResourceValues(values)
    }

    // MARK: - Backups

    /// Writes a passphrase-protected backup to `destination`.
    ///
    /// The key derivation parameters default to the shipping values and are
    /// exposed so tests can use cheap ones. Lowering them for a real backup
    /// makes it correspondingly cheaper to attack.
    public func sealBackup(
        _ document: VaultDocument,
        passphrase: String,
        to destination: URL,
        memoryKiB: Int = Impression.defaultMemoryKiB,
        iterations: Int = Impression.defaultIterations,
        parallelism: Int = Impression.defaultParallelism
    ) throws {
        let sealed = try Impression.seal(
            try encode(document),
            using: .passphrase(passphrase),
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism)
        try Data(sealed).write(to: destination, options: .atomic)
    }

    /// Opens a backup and confirms it parses.
    ///
    /// Verification decrypts and decodes rather than checking a hash this app
    /// wrote itself. A backup nobody has opened is a guess.
    public nonisolated func verifyBackup(
        at source: URL,
        passphrase: String
    ) throws -> VaultDocument {
        let data: Data
        do {
            data = try Data(contentsOf: source)
        } catch {
            throw Failure.backupUnreadable(error.localizedDescription)
        }

        let (plaintext, _) = try Impression.open([UInt8](data),
                                                 using: .passphrase(passphrase))
        return try VaultStore.decodeDocument(plaintext)
    }

    /// Replaces the vault with the contents of a backup.
    public func restore(from source: URL, passphrase: String, key: [UInt8]) throws {
        let document = try verifyBackup(at: source, passphrase: passphrase)
        try write(document, key: key)
    }

    // MARK: - Deletion

    /// Removes the vault file. The caller is responsible for the key.
    public func destroy() throws {
        guard exists else { return }
        try fileManager.removeItem(at: location)
    }

    // MARK: - Coding

    private nonisolated func encode(_ document: VaultDocument) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return [UInt8](try encoder.encode(document))
    }

    private nonisolated func decode(_ plaintext: [UInt8]) throws -> VaultDocument {
        try VaultStore.decodeDocument(plaintext)
    }

    private static func decodeDocument(_ plaintext: [UInt8]) throws -> VaultDocument {
        let document = try JSONDecoder().decode(VaultDocument.self,
                                                from: Data(plaintext))
        try VaultValidator.validate(document)
        return document
    }
}
