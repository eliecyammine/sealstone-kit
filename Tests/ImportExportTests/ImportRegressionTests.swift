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
