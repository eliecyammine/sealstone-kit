import XCTest
@testable import ImportExport
import VaultCore

final class ImportRegressionTests: XCTestCase {
    /// A standard Steam URI carries no digits parameter. Defaulting it to 5 and
    /// then validating against 6...10 made the whole staged import throw, so a
    /// single Steam credential could fail an otherwise good file.
    func testSteamURIImportsAndApplies() throws {
        var staging = try Importer.stage(
            Data("otpauth://steam/Valve:me?secret=JBSWY3DPEHPK3PXP".utf8))
        XCTAssertEqual(staging.candidates.count, 1)
        XCTAssertEqual(staging.candidates[0].authenticator.kind, .steam)

        let updated = try staging.apply(to: VaultDocument(vaultId: "v1"))
        XCTAssertEqual(updated.items.count, 1)
    }

    func testSteamAlongsideOtherCredentials() throws {
        var staging = try Importer.stage(Data("""
        otpauth://totp/A:one?secret=JBSWY3DPEHPK3PXP
        otpauth://steam/Valve:two?secret=GEZDGNBVGY3TQOJQ
        otpauth://hotp/B:three?secret=JBSWY3DPEHPK3PXP&counter=1
        """.utf8))
        XCTAssertEqual(staging.candidates.count, 3)
        XCTAssertEqual(try staging.apply(to: VaultDocument(vaultId: "v1")).items.count, 3)
    }

    /// A hand-edited export with a negative counter trapped on conversion to
    /// UInt64 instead of becoming a rejection the user could act on.
    func testNegativeCounterIsRejectedNotFatal() throws {
        let staging = try Importer.stage(
            Data(#"[{"account":"a","secret":"JBSWY3DPEHPK3PXP","type":"hotp","counter":-1}]"#.utf8))
        XCTAssertEqual(staging.candidates.count, 0)
        XCTAssertEqual(staging.rejections.count, 1)
    }

    func testNegativeCounterInEveryFormat() throws {
        let files = [
            #"{"header":{},"db":{"entries":[{"type":"hotp","name":"n","info":{"secret":"JBSWY3DPEHPK3PXP","counter":-5}}]}}"#,
            #"{"services":[{"name":"n","secret":"JBSWY3DPEHPK3PXP","otp":{"tokenType":"HOTP","counter":-5}}]}"#,
            #"[{"account":"n","secret":"JBSWY3DPEHPK3PXP","type":"hotp","counter":-5}]"#,
        ]
        for file in files {
            let staging = try Importer.stage(Data(file.utf8))
            XCTAssertEqual(staging.rejections.count, 1, file)
        }
    }

    func testTenDigitCredentialImportsAndGeneratesACode() throws {
        var staging = try Importer.stage(
            Data("otpauth://totp/A:one?secret=JBSWY3DPEHPK3PXP&digits=10".utf8))
        XCTAssertEqual(staging.candidates[0].authenticator.digits, 10)
        XCTAssertNoThrow(try staging.apply(to: VaultDocument(vaultId: "v1")))
    }
}

/// LastPass Authenticator, which imported with every account called "unknown".
///
/// It names its fields differently from everyone else, and the generic reader
/// matched keys exactly. `secret`, `algorithm` and `digits` lined up; issuer,
/// user and period did not. The period silently defaulting to 30 was the worse
/// half: a wrong period produces codes that look right and never work.
final class LastPassImportTests: XCTestCase {
    private let export = """
    {"version":3,"deviceName":"iPhone","localDeviceId":"abc",
     "accounts":[
      {"accountID":"1","issuerName":"GitHub","originalIssuerName":"GitHub",
       "userName":"elie","originalUserName":"elie","pushNotification":false,
       "secret":"JBSWY3DPEHPK3PXP","timeStep":30,"digits":6,
       "creationTimestamp":1700000000,"isFavorite":false,"algorithm":"SHA1"},
      {"accountID":"2","issuerName":"Bank","originalIssuerName":"Bank",
       "userName":"me@example.com","originalUserName":"me@example.com",
       "secret":"GEZDGNBVGY3TQOJQ","timeStep":60,"digits":8,
       "creationTimestamp":1700000000,"isFavorite":false,"algorithm":"SHA256"}
     ]}
    """

    func testItIsRecognisedAsLastPassRatherThanPlainJSON() {
        XCTAssertEqual(Importer.detect(Data(export.utf8)), .lastPass)
    }

    func testAccountsAreNamedRatherThanUnknown() throws {
        let staged = try Importer.stage(Data(export.utf8))
        XCTAssertEqual(staged.candidates.count, 2)
        XCTAssertEqual(staged.rejections.count, 0)

        let github = staged.candidates[0]
        XCTAssertEqual(github.issuer, "GitHub")
        XCTAssertEqual(github.account, "elie")

        let bank = staged.candidates[1]
        XCTAssertEqual(bank.issuer, "Bank")
        XCTAssertEqual(bank.account, "me@example.com")
    }

    /// The one that would have been silent. A period read as 30 when the
    /// service uses 60 produces a code that looks entirely normal and is
    /// always rejected.
    func testThePeriodComesFromTheFileRatherThanADefault() throws {
        let staged = try Importer.stage(Data(export.utf8))
        XCTAssertEqual(staged.candidates[0].authenticator.period, 30)
        XCTAssertEqual(staged.candidates[1].authenticator.period, 60)
    }

    func testDigitsAndAlgorithmSurvive() throws {
        let staged = try Importer.stage(Data(export.utf8))
        XCTAssertEqual(staged.candidates[1].authenticator.digits, 8)
        XCTAssertEqual(staged.candidates[1].authenticator.algorithm, .sha256)
    }

    /// The fix was to stop matching keys by exact case, so an export that
    /// spells them the other way must work too.
    func testKeysAreMatchedWhateverTheirCase() throws {
        let lower = """
        {"accounts":[{"issuername":"Fastmail","username":"me","secret":"JBSWY3DPEHPK3PXP",
                      "timestep":45,"digits":6,"algorithm":"SHA1"}]}
        """
        let staged = try Importer.stage(Data(lower.utf8))
        XCTAssertEqual(staged.candidates.first?.issuer, "Fastmail")
        XCTAssertEqual(staged.candidates.first?.account, "me")
        XCTAssertEqual(staged.candidates.first?.authenticator.period, 45)
    }
}

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
