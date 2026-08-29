import Testing
import Foundation
import VaultCore
@testable import ImportExport

/// A name with a colon in it.
///
/// The label separator is a colon, so an account whose name contains one is
/// the case where writing and reading have to agree about which colon divides
/// the halves. They did not: exporting `user:admin` and importing it back
/// produced the issuer "user" with the account "admin", which is a rename
/// carried out by a round trip that was supposed to preserve.
struct ColonInALabelTests {
    private func roundTrip(issuer: String?, account: String) throws -> OTPAuthURI.Parsed {
        let original = OTPAuthURI.Parsed(
            issuer: issuer,
            account: account,
            authenticator: Authenticator(secret: "JBSWY3DPEHPK3PXP"))
        return try OTPAuthURI.parse(OTPAuthURI.render(original))
    }

    @Test func anAccountKeepsItsColonThroughARoundTrip() throws {
        let parsed = try roundTrip(issuer: nil, account: "user:admin")

        #expect(parsed.account == "user:admin")
        #expect(parsed.issuer == nil)
    }

    @Test func anIssuerAndAnAccountBothKeepTheirColons() throws {
        let parsed = try roundTrip(issuer: "host:8080", account: "user:admin")

        #expect(parsed.issuer == "host:8080")
        #expect(parsed.account == "user:admin")
    }

    /// The ordinary shape still splits, which is the whole point of the
    /// separator. A fix that stopped reading `Issuer:account` would break
    /// every export every other authenticator writes.
    @Test func aPlainLabelStillSplitsOnItsSeparator() throws {
        let parsed = try OTPAuthURI.parse(
            "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP")

        #expect(parsed.issuer == "GitHub")
        #expect(parsed.account == "me@example.com")
    }

    /// An escaped colon in an incoming URI is part of a name, not a separator.
    @Test func anEscapedColonIsPartOfTheName() throws {
        let parsed = try OTPAuthURI.parse(
            "otpauth://totp/user%3Aadmin?secret=JBSWY3DPEHPK3PXP")

        #expect(parsed.issuer == nil)
        #expect(parsed.account == "user:admin")
    }

    /// Spaces are the other character a label routinely carries.
    @Test func aSpaceSurvivesBothWays() throws {
        let parsed = try roundTrip(issuer: "My Bank", account: "Elie Y")

        #expect(parsed.issuer == "My Bank")
        #expect(parsed.account == "Elie Y")
    }
}
