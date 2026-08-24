import XCTest
@testable import VaultStore

final class SealedFileTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sealedfile-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func file(_ name: String = "test.seal") -> SealedFile {
        SealedFile(url: directory.appendingPathComponent(name))
    }

    func testWriteThenReadRoundTrips() throws {
        let sealed = file()
        try sealed.write([1, 2, 3, 250, 251])
        XCTAssertEqual(try sealed.read(), [1, 2, 3, 250, 251])
    }

    func testWritingCreatesMissingDirectories() throws {
        let nested = SealedFile(url: directory
            .appendingPathComponent("a/b/c")
            .appendingPathComponent("test.seal"))
        try nested.write([9])
        XCTAssertEqual(try nested.read(), [9])
    }

    func testOverwritingReplacesTheContents() throws {
        let sealed = file()
        try sealed.write([1, 2, 3])
        try sealed.write([4])
        XCTAssertEqual(try sealed.read(), [4])
    }

    /// The write goes to a neighbour and swaps. If the neighbour is left
    /// behind, a directory listing shows a file nobody asked for and a crash
    /// mid-write would leave ciphertext lying around outside the real file.
    func testNoTemporaryFileIsLeftBehind() throws {
        let sealed = file()
        try sealed.write([1])
        try sealed.write([2])

        let contents = try FileManager.default
            .contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(contents, ["test.seal"])
    }

    /// Keeping this out of iCloud Backup is a stated guarantee, so it is
    /// asserted rather than assumed.
    func testTheFileIsExcludedFromBackup() throws {
        let sealed = file()
        try sealed.write([1])

        let values = try sealed.url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }

    func testReadingSomethingThatIsNotThereSaysSo() throws {
        XCTAssertThrowsError(try file().read()) { error in
            XCTAssertEqual(error as? SealedFile.Failure, .notFound)
        }
    }

    func testExistsReflectsReality() throws {
        let sealed = file()
        XCTAssertFalse(sealed.exists)
        try sealed.write([1])
        XCTAssertTrue(sealed.exists)
        try sealed.destroy()
        XCTAssertFalse(sealed.exists)
    }

    /// The caller wanted it gone. It is gone.
    func testDestroyingSomethingThatIsNotThereIsNotAnError() throws {
        XCTAssertNoThrow(try file().destroy())
    }
}
