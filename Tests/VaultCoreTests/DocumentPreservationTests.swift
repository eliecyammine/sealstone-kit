import XCTest
@testable import VaultCore

/// The format requires a decoder to preserve top-level keys it does not
/// recognise. Without that, opening a vault in an older build and saving it
/// destroys whatever a newer build wrote.
///
/// This was broken: `VaultDocument` used synthesised `Codable`, which writes
/// back only the keys it has properties for.
final class DocumentPreservationTests: XCTestCase {
    private static let base = """
    "formatVersion":1,"vaultId":"vlt_1",\
    "createdAt":"2026-08-24T10:00:00Z","updatedAt":"2026-08-24T11:00:00Z",\
    "accounts":[],"items":[],"links":[],"keepers":[]
    """

    private func roundTrip(_ json: String) throws -> [String: Any] {
        let document = try JSONDecoder().decode(VaultDocument.self, from: Data(json.utf8))
        let data = try JSONEncoder().encode(document)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testUnknownTopLevelKeysSurvive() throws {
        let output = try roundTrip("""
        {\(Self.base),\
        "settings":{"autoLockSeconds":60},\
        "somethingFromTheFuture":["a","b"],\
        "aNumber":7,"aNull":null}
        """)

        XCTAssertEqual((output["settings"] as? [String: Any])?["autoLockSeconds"] as? Int, 60)
        XCTAssertEqual(output["somethingFromTheFuture"] as? [String], ["a", "b"])
        XCTAssertEqual(output["aNumber"] as? Int, 7, "a whole number must not become 7.0")
        XCTAssertTrue(output["aNull"] is NSNull)
    }

    func testKnownKeysAreUnaffected() throws {
        let output = try roundTrip("{\(Self.base)}")

        XCTAssertEqual(output.count, 8, "a document with nothing extra gains nothing")
        XCTAssertEqual(output["formatVersion"] as? Int, 1)
        XCTAssertEqual(output["vaultId"] as? String, "vlt_1")
    }

    /// A stale unrecognised entry must never shadow a real field. The only way
    /// to get one is to construct it directly, so that is what this does.
    func testUnrecognisedCannotOverwriteAKnownKey() throws {
        var document = VaultDocument(vaultId: "vlt_real")
        document.unrecognised = ["vaultId": .string("vlt_stale"), "keepers": .string("nonsense")]

        let data = try JSONEncoder().encode(document)
        let output = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(output["vaultId"] as? String, "vlt_real")
        XCTAssertNotNil(output["keepers"] as? [Any])
    }

    func testVersionIsCarriedThroughAsRead() throws {
        let output = try roundTrip("{\(Self.base.replacingOccurrences(of: "\"formatVersion\":1", with: "\"formatVersion\":2"))}")
        XCTAssertEqual(output["formatVersion"] as? Int, 2,
                       "the version a file arrived with must not be rewritten on save")
    }
}
