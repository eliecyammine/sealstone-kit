import Testing
import Foundation
@testable import ImportExport

/// Files we can name and cannot open.
///
/// Every app on the import list offers an encrypted or archived export beside
/// its plain one, and those are the ones somebody reaches for first because
/// they are the ones the other app recommends. Being told "unrecognised
/// format" says their file is wrong when it is fine, so each of these is
/// reported as the case it is and the application says what to do about it.
struct UnreadableExportTests {
    @Test func aZipIsAnArchive() {
        // The local file header every zip starts with, whatever wrote it.
        let zip = Data([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00])
        #expect(Importer.unreadable(zip) == .archive)
        #expect(throws: Importer.Failure.unreadable(.archive)) {
            try Importer.stage(zip)
        }
    }

    @Test func anEncryptedEnteExportNamesEnte() {
        let data = Data(#"{"version":1,"kdfParams":{"memLimit":64},"encryptedData":"AAAA"}"#.utf8)
        #expect(Importer.unreadable(data) == .encrypted(.enteAuth))
    }

    @Test func anEncryptedTwoFASBackupNamesTwoFAS() {
        let data = Data(#"{"servicesEncrypted":"AAAA","schemaVersion":4}"#.utf8)
        #expect(Importer.unreadable(data) == .encrypted(.twoFAS))
    }

    /// Naming a format skips the check, because that parser has a better
    /// message of its own. Aegis says to decrypt in Aegis, and a more general
    /// answer arriving sooner would be a worse one.
    @Test func namingAFormatLeavesItsOwnMessageIntact() {
        let encryptedAegis = #"{"version":1,"header":{"slots":[{"type":1}],"params":{}},"db":"AAAA"}"#
        var reason: String?
        do {
            _ = try Importer.stage(Data(encryptedAegis.utf8), as: .aegis)
        } catch let failure as Importer.Failure {
            if case .malformed(let text) = failure { reason = text }
        } catch {}
        #expect(reason?.contains("Aegis") == true)
    }

    /// The check runs before detection, so it must not swallow a file that
    /// does parse. A plain 2FAS backup names its list `services`.
    @Test func aPlainBackupIsStillRead() throws {
        let plain = #"{"services":[{"otp":{"account":"a@b.com"},"secret":"JBSWY3DPEHPK3PXP","name":"Example"}]}"#
        #expect(Importer.unreadable(Data(plain.utf8)) == nil)
        let staged = try Importer.stage(Data(plain.utf8))
        #expect(!staged.candidates.isEmpty)
    }
}
