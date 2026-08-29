import Testing
import Foundation
@testable import ImportExport

/// What happens when an export does not say what an entry is called.
///
/// The importers used to write the word "unknown" into the account. It reads
/// like a name the file supplied, so it survives the review screen without
/// being questioned, and a file with several of them lands as a set of items
/// that cannot be told apart afterwards.
struct UnnamedEntryTests {
    private func stage(_ json: String) throws -> ImportStaging {
        try Importer.stage(Data(json.utf8))
    }

    @Test func lastPassEntriesKeepTheirIssuerWhenTheUsernameIsBlank() throws {
        let staging = try stage("""
        {"version":3,"accounts":[
          {"accountID":"1","algorithm":"SHA1","digits":6,"issuerName":"Amazon",
           "originalIssuerName":"","originalUserName":"","userName":"",
           "secret":"JBSWY3DPEHPK3PXP","timeStep":30}]}
        """)

        #expect(staging.candidates.count == 1)
        #expect(staging.candidates[0].issuer == "Amazon")
        #expect(staging.candidates[0].account.isEmpty)
        #expect(staging.candidates[0].label == "Amazon")
        #expect(!staging.candidates[0].isUnnamed)
    }

    @Test func lastPassEntriesAreLabelledFromIssuerAndUser() throws {
        let staging = try stage("""
        {"version":3,"deviceName":"iPhone","accounts":[
          {"accountID":"1","algorithm":"SHA1","digits":6,"issuerName":"Amazon",
           "originalIssuerName":"Amazon","originalUserName":"me@example.com",
           "userName":"me@example.com","secret":"JBSWY3DPEHPK3PXP","timeStep":30}]}
        """)

        #expect(staging.candidates[0].label == "Amazon (me@example.com)")
    }

    /// Several exports bury the labels one object deep.
    @Test func namesAreFoundOneLevelDown() throws {
        let staging = try stage("""
        {"items":[{"details":{"issuer":"GitHub","username":"elie"},
                   "secret":"JBSWY3DPEHPK3PXP","digits":6}]}
        """)

        #expect(staging.candidates[0].issuer == "GitHub")
        #expect(staging.candidates[0].account == "elie")
    }

    /// A folder name is a string sitting in a nested object, and taking any
    /// nested string would file the account under it.
    @Test func onlyNamedKeysAreFollowedInwards() throws {
        let staging = try stage("""
        {"accounts":[{"folderData":{"folderId":0,"folderName":"Work"},
                      "issuerName":"GitHub","userName":"elie",
                      "secret":"JBSWY3DPEHPK3PXP","digits":6}]}
        """)

        #expect(staging.candidates[0].account == "elie")
    }

    @Test func anEntryWithNoNameAtAllSaysSo() throws {
        let staging = try stage("""
        [{"secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30}]
        """)

        #expect(staging.candidates.count == 1)
        #expect(staging.candidates[0].isUnnamed)
        #expect(staging.candidates[0].label == "Unnamed")
    }

    /// A null in a field is the export saying it has nothing, not a value.
    @Test func nullsAreTreatedAsAbsent() throws {
        let staging = try stage("""
        {"accounts":[{"issuerName":null,"userName":"elie",
                      "secret":"JBSWY3DPEHPK3PXP","digits":6}]}
        """)

        #expect(staging.candidates[0].issuer == nil)
        #expect(staging.candidates[0].account == "elie")
    }

    @Test func aRejectedEntryWithNoNameIsStillDescribed() throws {
        let staging = try stage("""
        [{"digits":6,"period":30},{"secret":"JBSWY3DPEHPK3PXP","digits":6}]
        """)

        #expect(staging.rejections.count == 1)
        #expect(staging.rejections[0].source == "an unnamed entry")
    }

    /// 2FAS copied the service name onto both halves, so every row read
    /// "GitHub (GitHub)".
    ///
    /// The test that was here asserted exactly that, under this name. A test
    /// that describes a fix and requires the bug passes for as long as the bug
    /// survives, which is longer than a test that describes nothing.
    @Test func twoFASDoesNotRepeatTheServiceOnBothHalves() throws {
        let staging = try stage("""
        {"services":[{"name":"GitHub","secret":"JBSWY3DPEHPK3PXP",
                      "otp":{"digits":6,"period":30}}]}
        """)

        #expect(staging.candidates[0].issuer == "GitHub")
        #expect(staging.candidates[0].account.isEmpty)
        #expect(staging.candidates[0].label == "GitHub")
        #expect(!staging.candidates[0].isUnnamed)
    }

    /// When the export does carry a login, both halves are real and both show.
    @Test func twoFASKeepsAnAccountWhenTheExportHasOne() throws {
        let staging = try stage("""
        {"services":[{"name":"GitHub","secret":"JBSWY3DPEHPK3PXP",
                      "otp":{"account":"me@example.com","digits":6,"period":30}}]}
        """)

        #expect(staging.candidates[0].label == "GitHub (me@example.com)")
    }
}

/// What a rejection is allowed to say about the line that failed.
///
/// A rejected URI used to be quoted back at sixty characters, which is long
/// enough to include the secret. The review screen is the one place a person
/// is looking at their whole import, and it was printing working credentials
/// onto it for every line that failed for any reason at all.
struct RejectionDisclosureTests {
    private func stage(_ text: String) throws -> ImportStaging {
        try Importer.stage(Data(text.utf8))
    }

    @Test func aRejectedURIDoesNotRepeatItsSecret() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        let staging = try stage(
            "otpauth://totp/GitHub:me@example.com?secret=\(secret)&digits=99")

        #expect(staging.candidates.isEmpty)
        #expect(staging.rejections.count == 1)
        #expect(!staging.rejections[0].source.contains(secret))
        #expect(!staging.rejections[0].reason.contains(secret))
    }

    /// It still has to say which row, or the screen lists failures nobody can
    /// match to anything.
    @Test func aRejectedURIIsStillIdentifiable() throws {
        let staging = try stage(
            "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&digits=99")

        #expect(staging.rejections[0].source.contains("GitHub"))
    }

    /// A stray line inside a file that is otherwise a list of links. The file
    /// is staged, so this line becomes a rejection rather than an error, and a
    /// rejection must not quote it either.
    @Test func aStrayLineIsDescribedWithoutBeingQuoted() throws {
        let staging = try stage("""
        otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP
        secret=GEZDGNBVGY3TQOJQ and some other text
        """)

        #expect(staging.candidates.count == 1)
        #expect(staging.rejections.count == 1)
        #expect(!staging.rejections[0].source.contains("GEZDGNBVGY3TQOJQ"))
    }
}
