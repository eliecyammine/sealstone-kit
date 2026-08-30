import XCTest
@testable import ImportExport
import VaultCore

/// A Steam credential written out and read back again.
///
/// The writer emitted five digits and the reader allowed only six upwards, so
/// this app could produce a URI it could not itself parse. Three call sites
/// held the rule and the three disagreed.
final class SteamRoundTripTests: XCTestCase {
    private func steam() -> OTPAuthURI.Parsed {
        var authenticator = Authenticator(secret: "GEZDGNBVGY3TQOJQ", digits: 5)
        authenticator.kind = .steam
        return OTPAuthURI.Parsed(issuer: "Valve", account: "player",
                                 authenticator: authenticator)
    }

    func testASteamURISurvivesBeingWrittenAndReadBack() throws {
        let uri = OTPAuthURI.render(steam())
        let parsed = try OTPAuthURI.parse(uri)

        XCTAssertEqual(parsed.authenticator.digits, 5)
        XCTAssertEqual(parsed.authenticator.kind, .steam)
        XCTAssertEqual(parsed.authenticator.secret, "GEZDGNBVGY3TQOJQ")
    }

    /// The rule is per kind, so the ordinary range still holds for the rest.
    func testFiveDigitsIsStillRefusedForATimeBasedCode() {
        let uri = "otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ&digits=5"
        XCTAssertThrowsError(try OTPAuthURI.parse(uri))
    }

    func testSixDigitsIsRefusedForSteam() {
        let uri = "otpauth://steam/Valve:player?secret=GEZDGNBVGY3TQOJQ&digits=6"
        XCTAssertThrowsError(try OTPAuthURI.parse(uri))
    }

    func testTheRuleHasOneAnswerPerKind() {
        XCTAssertEqual(Authenticator.permittedDigits(forOTPType: "steam"), 5...5)
        XCTAssertEqual(Authenticator.permittedDigits(forOTPType: "STEAM"), 5...5)
        XCTAssertEqual(Authenticator.permittedDigits(forOTPType: "totp"), 6...10)
        XCTAssertEqual(Authenticator.permittedDigits(forOTPType: "hotp"), 6...10)
    }
}
