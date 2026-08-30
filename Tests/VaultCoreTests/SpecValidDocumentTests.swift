import XCTest
@testable import VaultCore

/// Documents written by another implementation following the specification.
///
/// The specification says an absent array and an empty array mean the same
/// thing, and that an account's identifier is optional. The decoder required
/// both, so a file that the specification calls valid, and that the reference
/// Python decoder accepts, would not open here. A format nobody else can write
/// for is not a format.
final class SpecValidDocumentTests: XCTestCase {
    private func decode(_ json: String) throws -> VaultDocument {
        try JSONDecoder().decode(VaultDocument.self, from: Data(json.utf8))
    }

    func testACollectionMayBeAbsent() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
        """)

        XCTAssertTrue(document.accounts.isEmpty)
        XCTAssertTrue(document.items.isEmpty)
        XCTAssertTrue(document.links.isEmpty)
        XCTAssertTrue(document.keepers.isEmpty)
    }

    func testAnAccountIdentifierMayBeAbsent() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
         "accounts":[{"id":"acc_1","service":"Google",
                      "createdAt":"2026-01-01T00:00:00Z"}],
         "items":[],"links":[],"keepers":[]}
        """)

        XCTAssertEqual(document.accounts.first?.identifier, "")
    }

    /// Absent goes in, empty comes out. The specification says a writer should
    /// emit the empty array, so a document read from a sparse file and written
    /// back is a document the next reader does not have to guess about.
    func testAbsentCollectionsAreWrittenBackAsEmpty() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
        """)

        let written = try JSONEncoder().encode(document)
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: written) as? [String: Any])

        for key in ["accounts", "items", "links", "keepers"] {
            XCTAssertNotNil(root[key] as? [Any], "\(key) should be written as an array")
        }
    }
}
