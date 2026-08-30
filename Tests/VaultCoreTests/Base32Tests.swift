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
