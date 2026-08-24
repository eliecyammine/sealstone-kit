import XCTest
@testable import VaultCore

final class TimestampTests: XCTestCase {
    func testParsesCanonicalForm() throws {
        let stamp = try XCTUnwrap(Timestamp(parsing: "2026-08-24T10:00:00Z"))
        XCTAssertEqual(stamp.canonical, "2026-08-24T10:00:00Z")
    }

    func testReEncodesExactlyAsRead() throws {
        // A document round-tripped by two implementations must not gain or
        // lose fractional seconds.
        for spelling in ["2026-08-24T10:00:00Z",
                         "2026-08-24T10:00:00.123Z",
                         "2026-08-24T10:00:00+02:00",
                         "2026-08-24T10:00:00-05:30"] {
            let stamp = try XCTUnwrap(Timestamp(parsing: spelling), spelling)
            XCTAssertEqual(stamp.asWritten, spelling)

            let encoded = try JSONEncoder().encode(stamp)
            XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "\"\(spelling)\"")
        }
    }

    func testOffsetsAreApplied() throws {
        let utc = try XCTUnwrap(Timestamp(parsing: "2026-08-24T10:00:00Z"))
        let plusTwo = try XCTUnwrap(Timestamp(parsing: "2026-08-24T12:00:00+02:00"))
        XCTAssertEqual(utc.date, plusTwo.date)

        let minusFive = try XCTUnwrap(Timestamp(parsing: "2026-08-24T05:00:00-05:00"))
        XCTAssertEqual(utc.date, minusFive.date)
    }

    func testKnownEpochValues() throws {
        let epoch = try XCTUnwrap(Timestamp(parsing: "1970-01-01T00:00:00Z"))
        XCTAssertEqual(epoch.date.timeIntervalSince1970, 0)

        let y2k = try XCTUnwrap(Timestamp(parsing: "2000-01-01T00:00:00Z"))
        XCTAssertEqual(y2k.date.timeIntervalSince1970, 946_684_800)

        let leap = try XCTUnwrap(Timestamp(parsing: "2024-02-29T12:00:00Z"))
        XCTAssertEqual(leap.date.timeIntervalSince1970, 1_709_208_000)
    }

    /// The civil-date conversion must agree with Foundation across a wide
    /// range, including leap years and century boundaries.
    func testAgreesWithFoundationAcrossManyDates() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!

        for offset in stride(from: -50_000, through: 50_000, by: 97) {
            let date = Date(timeIntervalSince1970: TimeInterval(offset) * 86_400)
            let parts = calendar.dateComponents([.year, .month, .day], from: date)

            let (year, month, day) = Timestamp.civilFromDays(offset)
            XCTAssertEqual(year, parts.year, "day \(offset)")
            XCTAssertEqual(month, parts.month, "day \(offset)")
            XCTAssertEqual(day, parts.day, "day \(offset)")

            XCTAssertEqual(Timestamp.daysFromCivil(year: year, month: month, day: day),
                           offset, "round trip at day \(offset)")
        }
    }

    func testFormattingRoundTrips() {
        for offset in stride(from: 0, through: 4_000_000_000, by: 37_000_003) {
            let date = Date(timeIntervalSince1970: TimeInterval(offset))
            let text = Timestamp.format(date)
            XCTAssertEqual(Timestamp.parse(text)?.timeIntervalSince1970,
                           TimeInterval(offset), text)
        }
    }

    func testRejectsMalformedInput() {
        for bad in ["", "not a date", "2026-13-01T00:00:00Z", "2026-08-24",
                    "2026-08-24T25:00:00Z", "2026-08-24T10:00:00",
                    "2026-08-24T10:00:00Q", "2026-08-24T10:00:00Z extra"] {
            XCTAssertNil(Timestamp(parsing: bad), bad)
        }
    }

    func testComparable() throws {
        let earlier = try XCTUnwrap(Timestamp(parsing: "2026-01-01T00:00:00Z"))
        let later = try XCTUnwrap(Timestamp(parsing: "2026-08-24T00:00:00Z"))
        XCTAssertLessThan(earlier, later)
    }
}
