import XCTest
@testable import ImportExport
import VaultCore

final class OTPAuthURITests: XCTestCase {
    func testParsesACompleteURI() throws {
        let parsed = try OTPAuthURI.parse(
            "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP"
            + "&issuer=Example&algorithm=SHA256&digits=8&period=60")

        XCTAssertEqual(parsed.issuer, "Example")
        XCTAssertEqual(parsed.account, "me@example.com")
        XCTAssertEqual(parsed.authenticator.algorithm, .sha256)
        XCTAssertEqual(parsed.authenticator.digits, 8)
        XCTAssertEqual(parsed.authenticator.period, 60)
        XCTAssertEqual(parsed.authenticator.kind, .totp)
    }

    func testAppliesDefaults() throws {
        let parsed = try OTPAuthURI.parse("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(parsed.authenticator.algorithm, .sha1)
        XCTAssertEqual(parsed.authenticator.digits, 6)
        XCTAssertEqual(parsed.authenticator.period, 30)
        XCTAssertNil(parsed.issuer)
    }

    func testIssuerParameterWinsOverLabelPrefix() throws {
        let parsed = try OTPAuthURI.parse(
            "otpauth://totp/Wrong:me?secret=JBSWY3DPEHPK3PXP&issuer=Right")
        XCTAssertEqual(parsed.issuer, "Right")
        XCTAssertEqual(parsed.account, "me")
    }

    func testHOTPRequiresACounter() throws {
        XCTAssertEqual(
            try OTPAuthURI.parse("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=7")
                .authenticator.kind,
            .hotp(counter: 7))

        XCTAssertThrowsError(
            try OTPAuthURI.parse("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP"))
    }

    /// A bad parameter is a rejection, not a silent default. A credential
    /// imported with the wrong period produces codes that never work, and the
    /// user finds out during a lockout.
    func testRejectsRatherThanDefaulting() {
        let cases = [
            "otpauth://totp/me",                                          // no secret
            "otpauth://totp/me?secret=!!!!",                              // not Base32
            "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=99",
            "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://unknown/me?secret=JBSWY3DPEHPK3PXP",
            "https://example.com",
        ]
        for uri in cases {
            XCTAssertThrowsError(try OTPAuthURI.parse(uri), uri)
        }
    }

    func testRoundTrip() throws {
        let original = "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP"
            + "&issuer=Example&algorithm=SHA256&digits=8&period=60"
        let parsed = try OTPAuthURI.parse(original)
        let reparsed = try OTPAuthURI.parse(OTPAuthURI.render(parsed))

        XCTAssertEqual(reparsed.issuer, parsed.issuer)
        XCTAssertEqual(reparsed.account, parsed.account)
        XCTAssertEqual(reparsed.authenticator, parsed.authenticator)
    }

    func testNormalisesSpacedSecrets() throws {
        let parsed = try OTPAuthURI.parse(
            "otpauth://totp/me?secret=jbsw%20y3dp%20ehpk%203pxp")
        XCTAssertEqual(parsed.authenticator.secret, "JBSWY3DPEHPK3PXP")
    }
}
