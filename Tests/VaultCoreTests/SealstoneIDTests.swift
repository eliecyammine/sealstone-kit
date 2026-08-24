import XCTest
@testable import VaultCore

final class SealstoneIDTests: XCTestCase {
    func testEveryKindProducesAPrefixedIdentifier() {
        for kind in SealstoneID.Kind.allCases {
            let identifier = SealstoneID.make(kind)
            XCTAssertTrue(identifier.hasPrefix("\(kind.rawValue)_"), identifier)
            XCTAssertGreaterThan(identifier.count, 20, identifier)
        }
    }

    func testIdentifiersAreUnique() {
        var seen = Set<String>()
        for _ in 0..<10_000 {
            XCTAssertTrue(seen.insert(SealstoneID.make(.item)).inserted)
        }
    }

    func testInternalIdentifiersSortByCreationTime() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let identifiers = (0..<50).map {
            SealstoneID.make(.item, at: base.addingTimeInterval(Double($0)))
        }
        XCTAssertEqual(identifiers, identifiers.sorted(),
                       "time-ordered identifiers did not sort by creation")
    }

    func testInternalIdentifiersCarryTheirTimestamp() throws {
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        let identifier = SealstoneID.make(.account, at: when)

        let recovered = try XCTUnwrap(SealstoneID.creationDate(of: identifier))
        XCTAssertEqual(recovered.timeIntervalSince1970,
                       when.timeIntervalSince1970, accuracy: 0.001)
    }

    /// Keeper and bundle identifiers appear in handover URLs. A timestamp
    /// there would tell whoever holds the link when the handover was set up.
    func testEscapingIdentifiersCarryNoTimestamp() {
        for kind in SealstoneID.Kind.allCases where kind.escapesTheVault {
            let identifier = SealstoneID.make(kind, at: Date(timeIntervalSince1970: 1_700_000_000))
            XCTAssertNil(SealstoneID.creationDate(of: identifier),
                         "\(kind) leaked a creation time")
        }
    }

    func testEscapingIdentifiersDoNotSortByTime() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let identifiers = (0..<50).map {
            SealstoneID.make(.keeper, at: base.addingTimeInterval(Double($0)))
        }
        XCTAssertNotEqual(identifiers, identifiers.sorted(),
                          "keeper identifiers appear to be time-ordered")
    }

    func testVersionAndVariantMarkers() {
        let bytes = SealstoneID.timeOrderedBytes()
        XCTAssertEqual(bytes[6] & 0xF0, 0x70, "version marker is not 7")
        XCTAssertEqual(bytes[8] & 0xC0, 0x80, "variant marker is not 10")
    }

    func testCreationDateRejectsMalformedInput() {
        XCTAssertNil(SealstoneID.creationDate(of: "nonsense"))
        XCTAssertNil(SealstoneID.creationDate(of: "xxx_ABCDEF"))
        XCTAssertNil(SealstoneID.creationDate(of: "itm_"))
    }
}
