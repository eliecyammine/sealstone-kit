import XCTest
@testable import VaultCrypto

final class ShamirTests: XCTestCase {
    private let secret = [UInt8](0..<32)

    func testEveryThreeOfFiveSubsetReconstructs() throws {
        let shares = try Shamir.split(secret: secret, threshold: 3, total: 5)
        var subsets = 0
        for a in 0..<5 {
            for b in (a + 1)..<5 {
                for c in (b + 1)..<5 {
                    subsets += 1
                    let combined = try Shamir.combine([shares[a], shares[b], shares[c]])
                    XCTAssertEqual(combined, secret)
                }
            }
        }
        XCTAssertEqual(subsets, 10)
    }

    func testBelowThresholdRevealsNothing() throws {
        let shares = try Shamir.split(secret: secret, threshold: 3, total: 5)
        for a in 0..<5 {
            for b in (a + 1)..<5 {
                let combined = try Shamir.combine([shares[a], shares[b]])
                XCTAssertNotEqual(combined, secret)
            }
        }
    }

    func testMoreThanThresholdAlsoWorks() throws {
        let shares = try Shamir.split(secret: secret, threshold: 3, total: 5)
        XCTAssertEqual(try Shamir.combine(Array(shares.prefix(4))), secret)
        XCTAssertEqual(try Shamir.combine(shares), secret)
    }

    /// The field has 256 elements, so the whole multiplication table fits in a test.
    func testExhaustiveFieldArithmetic() {
        for a in 0...255 {
            for b in 1...255 {
                let product = Shamir.multiply(UInt8(a), UInt8(b))
                XCTAssertEqual(Shamir.divide(product, UInt8(b)), UInt8(a))
            }
        }
    }

    func testInverseIsCorrectForEveryNonZeroElement() {
        for a in 1...255 {
            XCTAssertEqual(Shamir.multiply(UInt8(a), Shamir.inverse(UInt8(a))), 1)
        }
    }

    func testMultiplicationIsCommutativeAndDistributive() {
        for a in stride(from: 0, through: 255, by: 17) {
            for b in stride(from: 0, through: 255, by: 13) {
                for c in stride(from: 0, through: 255, by: 29) {
                    let x = UInt8(a), y = UInt8(b), z = UInt8(c)
                    XCTAssertEqual(Shamir.multiply(x, y), Shamir.multiply(y, x))
                    XCTAssertEqual(Shamir.multiply(x, y ^ z),
                                   Shamir.multiply(x, y) ^ Shamir.multiply(x, z))
                }
            }
        }
    }

    func testRejectsBadInput() {
        XCTAssertThrowsError(try Shamir.split(secret: secret, threshold: 1, total: 5))
        XCTAssertThrowsError(try Shamir.split(secret: secret, threshold: 6, total: 5))
        XCTAssertThrowsError(try Shamir.split(secret: [], threshold: 3, total: 5))
        XCTAssertThrowsError(try Shamir.combine([.init(index: 0, bytes: [1]),
                                                 .init(index: 2, bytes: [2])]))
        XCTAssertThrowsError(try Shamir.combine([.init(index: 1, bytes: [1]),
                                                 .init(index: 1, bytes: [2])]))
        XCTAssertThrowsError(try Shamir.combine([.init(index: 1, bytes: [1, 2]),
                                                 .init(index: 2, bytes: [3])]))
    }
}
