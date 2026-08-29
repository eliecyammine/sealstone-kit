public import Foundation
public import VaultCore
public import VaultCrypto

/// Making a backup, checking one, and putting it back.
///
/// A backup is sealed with a passphrase rather than with the vault's key, so
/// it can be opened on a machine that has never seen this vault. That is the
/// whole point of one: a copy that only the original device can read is not a
/// backup, it is a second copy of the same single point of failure.

extension VaultStore {
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
        // Checked before sealing, for the same reason writing is. A backup
        // that cannot be restored is worse than no backup: it is a promise
        // that only fails on the day it is needed.
        try validate(document)

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
    /// Isolated to the store, deliberately.
    ///
    /// This was `nonisolated`, which reads as harmless and is not: a
    /// `nonisolated` method called from the main actor runs synchronously on
    /// the main thread rather than hopping anywhere. `await` in front of it
    /// made that invisible. So opening a backup ran Argon2id at shipping
    /// parameters on the UI thread, and the app locked solid for as long as it
    /// took: no progress indicator could draw, because the frame that would
    /// have drawn it never ran.
    ///
    /// Restoring goes through here too, and so does the check that follows
    /// sealing, which is why all three flows froze.
    public func verifyBackup(
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
}
