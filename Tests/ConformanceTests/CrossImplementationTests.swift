import XCTest
@testable import VaultCrypto

/// Writes files for the Python reference decoder to open.
///
/// The corpus proves this implementation can read what Python wrote. This
/// produces the evidence for the other direction, which is the half that
/// matters when a user's backup has to be openable by something that is not
/// this app.
final class CrossImplementationTests: XCTestCase {
    func testWritesAFileForTheReferenceDecoder() throws {
        let document = """
        {"formatVersion":1,"vaultId":"00000000-0000-4000-8000-00000000ffff",\
        "createdAt":"2026-08-24T00:00:00Z","updatedAt":"2026-08-24T00:00:00Z",\
        "accounts":[],"items":[],"links":[],"keepers":[]}
        """
        let plaintext = Array(document.utf8)

        let blob = try Impression.seal(
            plaintext,
            using: .passphrase("correct horse battery staple"),
            memoryKiB: 64, iterations: 1, parallelism: 1
        )

        // Reading our own output back is necessary but not sufficient.
        let (reopened, _) = try Impression.open(
            blob, using: .passphrase("correct horse battery staple"))
        XCTAssertEqual(reopened, plaintext)

        guard let directory = ProcessInfo.processInfo.environment["SEALSTONE_CROSS_OUTPUT"] else {
            return
        }
        try Data(blob).write(to: URL(fileURLWithPath: directory)
            .appendingPathComponent("swift-written.seal"))
    }
}
