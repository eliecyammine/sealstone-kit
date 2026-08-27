import XCTest
@testable import VaultCore

/// Input nobody would write by hand, which is exactly why it has to be tested.
///
/// The module's posture is that a hostile file is refused, not survived by
/// luck. A refusal is a thrown error or a nil; a trap is neither, and in an app
/// that holds credentials a crash on open is a denial of service against the
/// person who needs to get in.
final class HostileInputTests: XCTestCase {
    /// `1e300` is a whole number, so a "did it round to itself" check waves it
    /// through, and converting it to `Int` then traps.
    func testAnAbsurdlyLargeNumberIsNotAnInt() {
        XCTAssertNil(JSONValue.number(1e300).intValue)
        XCTAssertNil(JSONValue.number(-1e300).intValue)
    }

    func testInfinityAndNaNAreNotInts() {
        XCTAssertNil(JSONValue.number(.infinity).intValue)
        XCTAssertNil(JSONValue.number(-.infinity).intValue)
        XCTAssertNil(JSONValue.number(.nan).intValue)
    }

    func testTheEdgeOfTheRangeIsHandledEitherWay() {
        // 2^63 is one past the top and must be refused; 2^62 is inside it.
        XCTAssertNil(JSONValue.number(9_223_372_036_854_775_808).intValue)
        XCTAssertEqual(JSONValue.number(4_611_686_018_427_387_904).intValue,
                       4_611_686_018_427_387_904)
    }

    func testOrdinaryNumbersStillWork() {
        XCTAssertEqual(JSONValue.number(0).intValue, 0)
        XCTAssertEqual(JSONValue.number(7).intValue, 7)
        XCTAssertEqual(JSONValue.number(-7).intValue, -7)
        XCTAssertNil(JSONValue.number(7.5).intValue, "not a whole number")
    }

    /// Reached through a real decode rather than only through the accessor,
    /// since that is how a hostile file would arrive.
    func testAnItemCarryingAnAbsurdOrderingDecodesWithoutDying() throws {
        let json = """
        {"id":"i1","accountId":"a1","type":"note","createdAt":"2026-08-24T00:00:00Z",
         "ordering":1e300,"title":"t","body":"b"}
        """
        let item = try JSONDecoder().decode(Item.self, from: Data(json.utf8))

        // The value is not an Int, so the field falls back rather than taking
        // the app down. It is still preserved on the way out.
        XCTAssertEqual(item.ordering, 0)
        XCTAssertNotNil(item.unrecognised["ordering"] ?? .some(.number(1e300)))
    }
}

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
