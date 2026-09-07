import Testing
import Foundation
@testable import ImportExport

/// Files we can name and cannot open.
///
/// Every app on the import list offers an encrypted or archived export beside
/// its plain one, and those are the ones somebody reaches for first because
/// they are the ones the other app recommends. Being told "unrecognised
/// format" says their file is wrong when it is fine, so each of these says what
/// the file is and what to do with it instead.
struct UnreadableExportTests {
    private func stage(_ text: String) -> String? {
        do {
            _ = try Importer.stage(Data(text.utf8))
            return nil
        } catch let failure as Importer.Failure {
            if case .malformed(let reason) = failure { return reason }
            return nil
        } catch {
            return nil
        }
    }

    @Test func aZipArchiveSaysToUnzipIt() {
        // The local file header every zip starts with, whatever wrote it.
        let zip = Data([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00])
        #expect(throws: Importer.Failure.self) { try Importer.stage(zip) }
        #expect(Importer.unreadable(zip)?.contains("Unzip") == true)
    }

    @Test func anEncryptedEnteExportSaysSo() {
        let reason = stage(#"{"version":1,"kdfParams":{"memLimit":64},"encryptedData":"AAAA"}"#)
        #expect(reason?.contains("Ente Auth") == true)
        #expect(reason?.contains("encrypted") == true)
    }

    @Test func anEncryptedTwoFASBackupSaysSo() {
        let reason = stage(#"{"servicesEncrypted":"AAAA","schemaVersion":4}"#)
        #expect(reason?.contains("2FAS") == true)
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
