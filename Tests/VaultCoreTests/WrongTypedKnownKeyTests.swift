import XCTest
@testable import VaultCore

/// Keys this version knows the name of but not the shape of.
final class WrongTypedKnownKeyTests: XCTestCase {
    private func roundTrip(_ json: String) throws -> [String: Any] {
        let item = try JSONDecoder().decode(Item.self, from: Data(json.utf8))
        let data = try JSONEncoder().encode(item)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    /// A later version could widen `ordering`. An older build that read it,
    /// failed to understand it, and dropped it would destroy that value on the
    /// first save, which is exactly what the format promises will not happen.
    func testAKnownKeyWithAnUnexpectedTypeSurvives() throws {
        let output = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"note","createdAt":"2026-08-24T00:00:00Z",
         "ordering":"first","favorite":"yes","title":"t","body":"b"}
        """)

        XCTAssertEqual(output["ordering"] as? String, "first")
        XCTAssertEqual(output["favorite"] as? String, "yes")
    }

    func testTheExpectedTypesAreStillReadNormally() throws {
        let item = try JSONDecoder().decode(Item.self, from: Data("""
        {"id":"i1","accountId":"a1","type":"note","createdAt":"2026-08-24T00:00:00Z",
         "ordering":3,"favorite":true,"title":"t","body":"b"}
        """.utf8))

        XCTAssertEqual(item.ordering, 3)
        XCTAssertTrue(item.favorite)
        XCTAssertNil(item.unrecognised["ordering"], "a value it understood is not carried twice")
    }
}
