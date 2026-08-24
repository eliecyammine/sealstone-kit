import XCTest
@testable import VaultCore

/// The format requires a decoder to preserve keys it does not recognise, at
/// the document root and inside the objects the document holds. Without that,
/// opening a vault in an older build and saving it destroys whatever a newer
/// build wrote, and a new optional field lands on an account or a keeper far
/// more often than at the root.
///
/// This was broken: all four types used synthesised `Codable`, which writes
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

    // MARK: - Nested objects

    func testAnAccountKeepsWhatItDidNotUnderstand() throws {
        let output = try roundTrip("""
        {"formatVersion":1,"vaultId":"vlt_1",\
        "createdAt":"2026-08-24T10:00:00Z","updatedAt":"2026-08-24T11:00:00Z",\
        "accounts":[{"id":"a1","service":"Google","identifier":"me@example.com",\
        "tags":["email"],"createdAt":"2026-08-24T10:00:00Z",\
        "colour":"#8A4B1F","lastVerifiedAt":"2026-08-24T09:00:00Z"}],\
        "items":[],"links":[],"keepers":[]}
        """)

        let account = (output["accounts"] as! [[String: Any]])[0]
        XCTAssertEqual(account["colour"] as? String, "#8A4B1F")
        XCTAssertEqual(account["lastVerifiedAt"] as? String, "2026-08-24T09:00:00Z")
        XCTAssertEqual(account["service"] as? String, "Google")
    }

    func testALinkKeepsWhatItDidNotUnderstand() throws {
        let output = try roundTrip("""
        {"formatVersion":1,"vaultId":"vlt_1",\
        "createdAt":"2026-08-24T10:00:00Z","updatedAt":"2026-08-24T11:00:00Z",\
        "accounts":[{"id":"a1","service":"S","identifier":"i","tags":[],\
        "createdAt":"2026-08-24T10:00:00Z"},\
        {"id":"a2","service":"T","identifier":"j","tags":[],\
        "createdAt":"2026-08-24T10:00:00Z"}],\
        "items":[],\
        "links":[{"id":"l1","sourceAccountId":"a1","targetAccountId":"a2",\
        "method":"email","strength":"weak"}],\
        "keepers":[]}
        """)

        let link = (output["links"] as! [[String: Any]])[0]
        XCTAssertEqual(link["strength"] as? String, "weak")
        XCTAssertEqual(link["method"] as? String, "email")
    }

    func testAKeeperKeepsWhatItDidNotUnderstand() throws {
        let output = try roundTrip("""
        {"formatVersion":1,"vaultId":"vlt_1",\
        "createdAt":"2026-08-24T10:00:00Z","updatedAt":"2026-08-24T11:00:00Z",\
        "accounts":[],"items":[],"links":[],\
        "keepers":[{"id":"kpr_1","displayName":"Sam","contact":"sam@example.com",\
        "bundleId":"bdl_1","fragmentIndex":2,"issuedAt":"2026-08-24T10:00:00Z",\
        "status":"active","relayEndpoint":"https://example.invalid/r"}]}
        """)

        let keeper = (output["keepers"] as! [[String: Any]])[0]
        XCTAssertEqual(keeper["relayEndpoint"] as? String, "https://example.invalid/r")
        XCTAssertEqual(keeper["fragmentIndex"] as? Int, 2)
    }

    /// Absent optionals were omitted by the synthesised versions rather than
    /// written as null. The hand-written ones have to match, or every file this
    /// build writes differs from every file the last one wrote.
    func testAbsentOptionalsStayAbsent() throws {
        let output = try roundTrip("""
        {"formatVersion":1,"vaultId":"vlt_1",\
        "createdAt":"2026-08-24T10:00:00Z","updatedAt":"2026-08-24T11:00:00Z",\
        "accounts":[{"id":"a1","service":"S","identifier":"i","tags":[],\
        "createdAt":"2026-08-24T10:00:00Z"}],\
        "items":[],"links":[],"keepers":[]}
        """)

        let account = (output["accounts"] as! [[String: Any]])[0]
        XCTAssertFalse(account.keys.contains("domain"), "an absent optional became a key")
        XCTAssertFalse(account.keys.contains("notes"), "an absent optional became a key")
    }
}
