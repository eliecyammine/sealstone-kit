import XCTest
@testable import ImportExport
import VaultCore

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
