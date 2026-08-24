import XCTest
@testable import VaultStore
import VaultCore
import VaultCrypto

final class VaultStoreTests: XCTestCase {
    private var directory: URL!
    private var store: VaultStore!
    private let key = [UInt8](repeating: 0x2A, count: 32)

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("sealstone-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        store = VaultStore(location: directory.appendingPathComponent("vault.seal"))
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func sampleDocument() -> VaultDocument {
        VaultDocument(
            vaultId: "test-vault",
            accounts: [Account(id: "a1", service: "Mail", identifier: "me@example.com")],
            items: [Item(id: "i1", accountId: "a1",
                         payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP")))],
            links: []
        )
    }

    func testCreateThenLoad() async throws {
        let document = sampleDocument()
        try await store.create(document, key: key)

        let loaded = try await store.load(key: key)
        XCTAssertEqual(loaded.vaultId, document.vaultId)
        XCTAssertEqual(loaded.items.count, 1)
    }

    func testCreateRefusesToOverwrite() async throws {
        try await store.create(sampleDocument(), key: key)
        do {
            try await store.create(sampleDocument(), key: key)
            XCTFail("overwrote an existing vault")
        } catch VaultStore.Failure.vaultAlreadyExists {
            // expected
        }
    }

    func testLoadWithoutAVault() async throws {
        do {
            _ = try await store.load(key: key)
            XCTFail("loaded a vault that does not exist")
        } catch VaultStore.Failure.noVaultAtLocation {
            // expected
        }
    }

    func testWrongKeyIsRejected() async throws {
        try await store.create(sampleDocument(), key: key)
        let wrong = [UInt8](repeating: 0x99, count: 32)
        do {
            _ = try await store.load(key: wrong)
            XCTFail("a wrong key opened the vault")
        } catch {
            // expected
        }
    }

    func testUpdateIsReadModifyWriteInOneStep() async throws {
        try await store.create(sampleDocument(), key: key)

        try await store.update(key: key) { document in
            document.accounts.append(
                Account(id: "a2", service: "Bank", identifier: "me"))
        }

        let loaded = try await store.load(key: key)
        XCTAssertEqual(loaded.accounts.count, 2)
    }

    func testSaveStampsUpdatedAt() async throws {
        let document = sampleDocument()
        try await store.create(document, key: key)
        try await Task.sleep(nanoseconds: 1_100_000_000)
        try await store.save(document, key: key)

        let loaded = try await store.load(key: key)
        XCTAssertGreaterThan(loaded.updatedAt, document.updatedAt)
    }

    /// A crash mid-write must leave the previous vault intact rather than a
    /// truncated one.
    func testInterruptedWriteLeavesThePreviousVaultIntact() async throws {
        try await store.create(sampleDocument(), key: key)
        let original = try await store.load(key: key)

        // Simulate a write that died after creating the temporary file.
        let temporary = directory.appendingPathComponent(".vault.seal.writing")
        try Data([0xDE, 0xAD, 0xBE, 0xEF]).write(to: temporary)

        let loaded = try await store.load(key: key)
        XCTAssertEqual(loaded.vaultId, original.vaultId,
                       "a stray temporary file affected the vault")
    }

    func testVaultFileIsExcludedFromBackup() async throws {
        try await store.create(sampleDocument(), key: key)

        let values = try await store.url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true,
                       "the vault would be swept into iCloud Backup")
    }

    func testDestroy() async throws {
        try await store.create(sampleDocument(), key: key)
        let exists = await store.exists
        XCTAssertTrue(exists)

        try await store.destroy()
        let gone = await store.exists
        XCTAssertFalse(gone)
    }

    func testDestroyOnNothingIsNotAnError() async throws {
        try await store.destroy()
    }

    /// Writing refuses a document that could not be read back.
    ///
    /// The guard exists so a vault cannot be sealed, stored, and then refuse to
    /// open: intact, encrypted, and unreadable by its own decoder.
    func testWritingRefusesADocumentThatWouldNotLoad() async throws {
        do {
            try await store.create(brokenDocument(), key: key)
            XCTFail("a vault with a dangling reference was written")
        } catch let failure as VaultStore.Failure {
            guard case .wouldNotLoad = failure else {
                return XCTFail("wrong error: \(failure)")
            }
        }
    }

    /// And a refused write leaves what was already there alone.
    func testARefusedWriteLeavesTheVaultIntact() async throws {
        try await store.create(sampleDocument(), key: key)
        try? await store.save(brokenDocument(), key: key)

        let loaded = try await store.load(key: key)
        XCTAssertEqual(loaded.vaultId, sampleDocument().vaultId)
    }

    /// Loading still validates too. A file planted by anything other than this
    /// store, or corrupted in place, must not open just because it decodes.
    func testValidationRunsOnLoad() async throws {
        // Written past the store, since the store now refuses to write it.
        let plaintext = try JSONEncoder().encode(brokenDocument())
        let sealed = try Impression.seal([UInt8](plaintext), using: .key(key))
        try SealedFile(url: await store.url).write(sealed)

        do {
            _ = try await store.load(key: key)
            XCTFail("a vault with a dangling reference loaded")
        } catch let error as VaultError {
            guard case .danglingReference = error else {
                return XCTFail("wrong error: \(error)")
            }
        }
    }

    private func brokenDocument() -> VaultDocument {
        var broken = sampleDocument()
        broken.items = [Item(id: "i1", accountId: "does-not-exist",
                             payload: .note(Note(title: "t", body: "b")))]
        return broken
    }
}

final class BackupTests: XCTestCase {
    private var directory: URL!
    private var store: VaultStore!
    private let key = [UInt8](repeating: 0x2A, count: 32)
    private let passphrase = "correct horse battery staple"

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("sealstone-backup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        store = VaultStore(location: directory.appendingPathComponent("vault.seal"))
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func sample() -> VaultDocument {
        VaultDocument(vaultId: "backup-vault",
                      accounts: [Account(id: "a1", service: "Mail", identifier: "me")])
    }

    func testSealVerifyRestore() async throws {
        try await store.create(sample(), key: key)
        let backup = directory.appendingPathComponent("backup.seal")

        try await store.sealBackup(sample(), passphrase: passphrase, to: backup,
                                  memoryKiB: 64, iterations: 1, parallelism: 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: backup.path))

        // Verification decrypts and parses rather than checking a hash we wrote.
        let verified = try await store.verifyBackup(at: backup, passphrase: passphrase)
        XCTAssertEqual(verified.vaultId, "backup-vault")

        try await store.destroy()
        try await store.restore(from: backup, passphrase: passphrase, key: key)
        let restored = try await store.load(key: key)
        XCTAssertEqual(restored.vaultId, "backup-vault")
    }

    func testVerifyRejectsWrongPassphrase() async throws {
        let backup = directory.appendingPathComponent("backup.seal")
        try await store.sealBackup(sample(), passphrase: passphrase, to: backup,
                                  memoryKiB: 64, iterations: 1, parallelism: 1)

        do {
            _ = try await store.verifyBackup(at: backup, passphrase: "wrong")
            XCTFail("a wrong passphrase verified")
        } catch {
            // expected
        }
    }

    func testVerifyRejectsATamperedBackup() async throws {
        let backup = directory.appendingPathComponent("backup.seal")
        try await store.sealBackup(sample(), passphrase: passphrase, to: backup,
                                  memoryKiB: 64, iterations: 1, parallelism: 1)

        var bytes = [UInt8](try Data(contentsOf: backup))
        bytes[bytes.count - 1] ^= 0x01
        try Data(bytes).write(to: backup)

        do {
            _ = try await store.verifyBackup(at: backup, passphrase: passphrase)
            XCTFail("a tampered backup verified")
        } catch {
            // expected
        }
    }

    func testVerifyReportsAMissingFileClearly() async throws {
        do {
            _ = try await store.verifyBackup(
                at: directory.appendingPathComponent("nope.seal"),
                passphrase: passphrase)
            XCTFail("verified a file that does not exist")
        } catch VaultStore.Failure.backupUnreadable {
            // expected
        }
    }
}
