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

final class ImporterTests: XCTestCase {
    private func data(_ text: String) -> Data { Data(text.utf8) }

    func testDetectsFormats() {
        XCTAssertEqual(Importer.detect(data("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP")),
                       .otpauthURIs)
        XCTAssertEqual(Importer.detect(data(#"{"header":{},"db":{"entries":[]}}"#)), .aegis)
        XCTAssertEqual(Importer.detect(data(#"{"services":[]}"#)), .twoFAS)
        XCTAssertNil(Importer.detect(data("not a credential file")))
    }

    func testStagesURIsAndReportsEachRejection() throws {
        let staging = try Importer.stage(data("""
        otpauth://totp/A:one?secret=JBSWY3DPEHPK3PXP
        otpauth://totp/B:two?secret=GEZDGNBVGY3TQOJQ
        otpauth://totp/C:three?secret=!!!!invalid
        not a uri at all
        """))

        XCTAssertEqual(staging.candidates.count, 2)
        XCTAssertEqual(staging.rejections.count, 2)
        // Each rejection names its source and reason rather than being a count.
        XCTAssertTrue(staging.rejections.allSatisfy { !$0.reason.isEmpty })
    }

    func testStagesAegis() throws {
        let staging = try Importer.stage(data("""
        {"header":{},"db":{"entries":[
          {"type":"totp","name":"me","issuer":"Example",
           "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60}},
          {"type":"hotp","name":"counterbased","issuer":"Other",
           "info":{"secret":"GEZDGNBVGY3TQOJQ","algo":"SHA1","digits":6,"counter":7}}
        ]}}
        """))

        XCTAssertEqual(staging.candidates.count, 2)
        XCTAssertEqual(staging.candidates[0].authenticator.algorithm, .sha256)
        XCTAssertEqual(staging.candidates[1].authenticator.kind, .hotp(counter: 7))
    }

    func testStagesTwoFAS() throws {
        let staging = try Importer.stage(data("""
        {"services":[{"name":"Example","secret":"JBSWY3DPEHPK3PXP",
          "otp":{"issuer":"Example","account":"me","digits":6,"period":30,
                 "algorithm":"SHA1","tokenType":"TOTP"}}]}
        """))
        XCTAssertEqual(staging.candidates.count, 1)
        XCTAssertEqual(staging.candidates[0].account, "me")
    }

    func testStagesGenericJSONIncludingEmbeddedURIs() throws {
        let staging = try Importer.stage(data("""
        [{"account":"one","secret":"JBSWY3DPEHPK3PXP","issuer":"A"},
         {"name":"two","uri":"otpauth://totp/B:two?secret=GEZDGNBVGY3TQOJQ"}]
        """))
        XCTAssertEqual(staging.candidates.count, 2)
    }

    func testAegisEncryptedExportGivesAnActionableMessage() {
        XCTAssertThrowsError(try Importer.stage(data(#"{"header":{"slots":[]},"db":"encrypted"}"#),
                                                as: .aegis)) { error in
            guard case Importer.Failure.malformed(let message) = error else {
                return XCTFail("wrong error")
            }
            XCTAssertTrue(message.contains("decrypt"), message)
        }
    }
}

final class ImportStagingTests: XCTestCase {
    private func document() -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "Example", identifier: "me")],
            items: [Item(id: "i1", accountId: "a1",
                         payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP")))])
    }

    func testApplyAddsAccountsAndItems() throws {
        var staging = try Importer.stage(Data("""
        otpauth://totp/NewService:someone?secret=GEZDGNBVGY3TQOJQ
        """.utf8))
        staging.markDuplicates(against: document())

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.accounts.count, 2)
        XCTAssertEqual(updated.items.count, 2)
    }

    func testDuplicateDetectionMatchesOnAccountAndSecret() throws {
        var staging = try Importer.stage(Data("""
        otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP
        otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ
        """.utf8))
        staging.markDuplicates(against: document())

        // Same account, same secret is a duplicate. Same account, different
        // secret is a genuinely new credential.
        XCTAssertEqual(staging.duplicates.count, 1)
        XCTAssertEqual(staging.willAdd.count, 1)
    }

    func testReplaceUpdatesInPlace() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&digits=8".utf8))
        staging.markDuplicates(against: document())
        XCTAssertEqual(staging.duplicates.count, 1)

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.items.count, 1, "replace created a second item")
        guard case .authenticator(let authenticator) = updated.items[0].payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(authenticator.digits, 8)
    }

    func testSkipLeavesTheVaultUntouched() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/New:someone?secret=GEZDGNBVGY3TQOJQ".utf8))
        for candidate in staging.candidates {
            staging.setResolution(.skip, for: candidate.id)
        }

        let original = document()
        let updated = try staging.apply(to: original)
        XCTAssertEqual(updated.items.count, original.items.count)
        XCTAssertEqual(updated.accounts.count, original.accounts.count)
    }

    func testApplyValidatesTheResult() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/New:someone?secret=GEZDGNBVGY3TQOJQ".utf8))
        staging.setResolution(.replace(existingItemId: "does-not-exist"),
                              for: staging.candidates[0].id)

        XCTAssertThrowsError(try staging.apply(to: document()))
    }

    func testExistingAccountIsReusedRatherThanDuplicated() throws {
        var staging = try Importer.stage(Data(
            "otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ".utf8))
        staging.markDuplicates(against: document())

        let updated = try staging.apply(to: document())
        XCTAssertEqual(updated.accounts.count, 1, "a duplicate account was created")
        XCTAssertEqual(updated.items.count, 2)
    }
}
