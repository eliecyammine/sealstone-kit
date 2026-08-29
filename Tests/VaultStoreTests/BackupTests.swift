import XCTest
@testable import VaultStore
import VaultCore
import VaultCrypto

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
