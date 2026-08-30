import XCTest
@testable import VaultCore

/// The password item type.
final class PasswordItemTests: XCTestCase {
    private func roundTrip(_ json: String) throws -> (Item, [String: Any]) {
        let item = try JSONDecoder().decode(Item.self, from: Data(json.utf8))
        let encoded = try JSONEncoder().encode(item)
        return (item, try JSONSerialization.jsonObject(with: encoded) as! [String: Any])
    }

    func testAPasswordSurvivesARoundTrip() throws {
        let (item, output) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2","username":"elie","site":"github.com","note":"work"}
        """)

        guard case .password(let password) = item.payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(password.password, "hunter2")
        XCTAssertEqual(password.username, "elie")
        XCTAssertEqual(password.site, "github.com")
        XCTAssertEqual(output["type"] as? String, "password")
        XCTAssertEqual(output["password"] as? String, "hunter2")
    }

    /// Absent stays absent rather than becoming an empty string, like every
    /// other optional on an item.
    func testOnlyThePasswordIsRequired() throws {
        let (item, output) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2"}
        """)

        guard case .password(let password) = item.payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertNil(password.username)
        XCTAssertFalse(output.keys.contains("username"))
    }

    /// It is a type this version understands, not something carried through
    /// as unknown.
    func testItIsNotTreatedAsSomethingFromTheFuture() throws {
        let (item, _) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2"}
        """)
        XCTAssertTrue(item.payload.isUnderstood)
        XCTAssertTrue(item.unrecognised.isEmpty)
    }
}
