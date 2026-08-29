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
        case backupExclusionFailed(String)
        /// The document would not survive being read back.
        case wouldNotLoad(String)
    }

    private let location: URL
    /// Read-only after init and safe to consult from any executor, which is
    /// what lets `exists` answer synchronously. FileManager documents its
    /// queries as thread-safe.
    nonisolated(unsafe) private let fileManager: FileManager

    public init(location: URL, fileManager: FileManager = .default) {
        self.location = location
        self.fileManager = fileManager
    }

    public var url: URL { location }

    /// Whether the vault file is present, answerable without entering the
    /// actor and without a key.
    ///
    /// Nonisolated deliberately: the session's state resolver runs before the
    /// first frame is composed, and whether anything exists to open is exactly
    /// the question it must settle first. Reading a directory entry touches
    /// no mutable state.
    public nonisolated var exists: Bool {
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

    /// Checked on the way out as well as on the way in.
    ///
    /// Loading has always validated. Writing did not, which meant a document
    /// could be sealed and stored and then refuse to open: the vault would be
    /// intact, encrypted, and unreadable by its own decoder. Nothing in the
    /// interface can produce one today, but "no caller does this yet" is not
    /// something a store should rely on, and the failure it guards against is
    /// silent until the next launch.
    ///
    /// The check happens before anything is written, so a document that would
    /// not load is refused rather than replacing one that does.
    func validate(_ document: VaultDocument) throws {
        do {
            try VaultValidator.validate(document)
        } catch {
            throw Failure.wouldNotLoad(error.localizedDescription)
        }
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

    /// The vault is deliberately not swept into iCloud Backup. Restoring a
    /// device restores the app, not the vault; the sealed backup is the only
    /// restore path, which is what keeps the vault out of anyone else's
    /// infrastructure. `SealedFile` is what guarantees that, and it throws
    /// rather than swallowing a failure to exclude.
    func write(_ document: VaultDocument, key: [UInt8]) throws {
        try validate(document)
        let plaintext = try encode(document)
        let sealed = try Impression.seal(plaintext, using: .key(key))

        do {
            try SealedFile(url: location, fileManager: fileManager).write(sealed)
        } catch let failure as SealedFile.Failure {
            throw translate(failure)
        }
    }

    /// `SealedFile` has its own error surface. Callers of `VaultStore` have
    /// only ever seen this one, so the mapping stays here rather than leaking
    /// a second vocabulary into the app.
    private func translate(_ failure: SealedFile.Failure) -> Failure {
        switch failure {
        case .notFound: .noVaultAtLocation(location)
        case .writeFailed(let detail): .writeFailed(detail)
        case .backupExclusionFailed(let detail): .backupExclusionFailed(detail)
        }
    }





    // MARK: - Deletion

    /// Removes the vault file. The caller is responsible for the key.
    public func destroy() throws {
        guard exists else { return }
        try fileManager.removeItem(at: location)
    }




}

extension VaultStore.Failure: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noVaultAtLocation:
            "There's no vault file on this device. If you have a backup, you can "
            + "open it and start again from there."

        case .vaultAlreadyExists:
            "There's already a vault on this device. Opening it is the way in; "
            + "creating another would leave the first one unreachable."

        case .writeFailed(let detail):
            "The vault couldn't be saved: \(detail). Your previous version is "
            + "still intact, so nothing was lost. Check you have free space and "
            + "try again."

        case .backupUnreadable(let detail):
            "That backup file couldn't be read: \(detail). Check the file is "
            + "still where you left it and hasn't been renamed to something else."

        case .backupExclusionFailed(let detail):
            "The vault was saved, but couldn't be marked as excluded from iCloud "
            + "Backup: \(detail). Turn off iCloud Backup for Sealstone in "
            + "Settings, or restart and try again."

        case .wouldNotLoad(let detail):
            "That change wasn't saved, because the result wouldn't open again: "
            + "\(detail). Your previous version is still intact."
        }
    }
}
