import Testing
import Foundation
@testable import ImportExport

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
