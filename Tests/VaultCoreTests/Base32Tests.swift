import XCTest
@testable import VaultCore

final class Base32Tests: XCTestCase {
    func testKnownValue() throws {
        XCTAssertEqual(try Base32.decode("JBSWY3DPEHPK3PXP"),
                       Array("Hello!".utf8) + [0xde, 0xad, 0xbe, 0xef])
    }

    func testRoundTrip() throws {
        for length in 0...40 {
            let data = [UInt8](repeating: 0, count: length).enumerated().map { UInt8($0.offset % 251) }
            let decoded = try Base32.decode(Base32.encode(data))
            XCTAssertEqual(Array(decoded.prefix(length)), data, "length \(length)")
        }
    }

    func testDecodesLeniently() throws {
        let canonical = try Base32.decode("JBSWY3DPEHPK3PXP")
        for spelling in ["jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP",
                         "JBSW-Y3DP-EHPK-3PXP", "JBSWY3DPEHPK3PXP===="] {
            XCTAssertEqual(try Base32.decode(spelling), canonical, spelling)
        }
    }

    func testRejectsInvalidCharacters() {
        XCTAssertThrowsError(try Base32.decode("ABC!DEF"))
        XCTAssertThrowsError(try Base32.decode("ABC1DEF"))   // 1 is not in RFC 4648
    }
}

final class CrockfordBase32Tests: XCTestCase {
    func testRoundTrip() throws {
        for length in 1...40 {
            let data = (0..<length).map { UInt8($0 % 251) }
            let decoded = try CrockfordBase32.decode(CrockfordBase32.encode(data))
            XCTAssertEqual(Array(decoded.prefix(length)), data, "length \(length)")
        }
    }

    func testOmitsConfusableCharacters() {
        for character in "ILOU" {
            XCTAssertFalse(CrockfordBase32.alphabet.contains(character))
        }
    }

    func testMapsConfusableCharactersOnInput() throws {
        XCTAssertEqual(try CrockfordBase32.decode("HIJK"),
                       try CrockfordBase32.decode("H1JK"))
        XCTAssertEqual(try CrockfordBase32.decode("HLJK"),
                       try CrockfordBase32.decode("H1JK"))
        XCTAssertEqual(try CrockfordBase32.decode("0AB"),
                       try CrockfordBase32.decode("OAB"))
        XCTAssertEqual(try CrockfordBase32.decode("hijk"),
                       try CrockfordBase32.decode("HIJK"))
    }

    func testIgnoresSeparators() throws {
        XCTAssertEqual(try CrockfordBase32.decode("ABCDE FGHJK"),
                       try CrockfordBase32.decode("ABCDE-FGHJK"))
    }

    func testGrouping() {
        let text = CrockfordBase32.encode([UInt8](repeating: 0xFF, count: 10), group: 5)
        for group in text.split(separator: " ").dropLast() {
            XCTAssertEqual(group.count, 5)
        }
        XCTAssertFalse(CrockfordBase32.encode([1, 2, 3], group: 0).contains(" "))
    }

    func testRejectsU() {
        // U is excluded to avoid reading as V, and is not silently mapped.
        XCTAssertThrowsError(try CrockfordBase32.decode("ABCDU"))
    }
}
