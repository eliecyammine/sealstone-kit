import XCTest
@testable import OTP
import VaultCore

/// Clocks that are wrong in the one direction `UInt64` cannot hold.
final class PreEpochClockTests: XCTestCase {
    private let secret = try! Base32.decode("JBSWY3DPEHPK3PXP")

    /// A device whose clock is before 1970 used to crash on every code drawn.
    func testADateBeforeTheEpochProducesACodeRatherThanACrash() throws {
        let code = try OneTimePassword.totp(
            secret: secret, at: Date(timeIntervalSince1970: -86_400))
        XCTAssertEqual(code.count, 6)
    }

    /// Reachable without a strange clock: the previous-window code subtracts a
    /// period, so a clock near the epoch arrives negative on its own.
    func testTheWindowBeforeTheEpochIsStillAnswerable() throws {
        let atEpoch = Date(timeIntervalSince1970: 0)
        let before = atEpoch.addingTimeInterval(-30)

        XCTAssertNoThrow(try OneTimePassword.totp(secret: secret, at: before))
        XCTAssertEqual(try OneTimePassword.totp(secret: secret, at: before),
                       try OneTimePassword.totp(secret: secret, at: atEpoch),
                       "before time started, there is one window and it is the first")
    }

    func testSteamSurvivesItToo() {
        XCTAssertEqual(
            OneTimePassword.steam(secret: secret,
                                  at: Date(timeIntervalSince1970: -1_000)).count, 5)
    }
}
