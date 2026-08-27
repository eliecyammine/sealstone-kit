import Testing
import Foundation
import VaultCore
@testable import ImportExport

/// Leaving has to be possible, and has to be honest about what it carried.
struct ExporterTests {
    private func document() -> VaultDocument {
        var document = VaultDocument(vaultId: "test")
        document.accounts = [
            Account(id: "a1", service: "Bank", identifier: "elie"),
            Account(id: "a2", service: "Mail", identifier: "me@example.com"),
        ]
        document.items = [
            Item(id: "i1", accountId: "a1",
                 payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP"))),
            Item(id: "i2", accountId: "a1",
                 payload: .recoveryCodes([RecoveryCode(code: "aaa-bbb")])),
            Item(id: "i3", accountId: "a2",
                 payload: .authenticator(Authenticator(secret: "GEZDGNBVGY3TQOJQ",
                                                       algorithm: .sha256, digits: 8))),
            Item(id: "i4", accountId: "a2",
                 payload: .password(Password(password: "hunter2"))),
        ]
        return document
    }

    @Test func everyAuthenticatorBecomesAURI() throws {
        let export = Exporter.otpauthURIs(from: document())

        #expect(export.written == 2)
        let lines = export.text.split(separator: "\n").map(String.init)
        #expect(lines.count == 2)
        #expect(lines.allSatisfy { $0.hasPrefix("otpauth://") })
    }

    /// The round trip is the whole claim. A file another app cannot read back
    /// into the same credential is not an export, it is a text file.
    @Test func whatIsWrittenParsesBackToWhatWentIn() throws {
        let export = Exporter.otpauthURIs(from: document())

        for line in export.text.split(separator: "\n") {
            let parsed = try OTPAuthURI.parse(String(line))
            #expect(parsed.issuer != nil)
            #expect(!parsed.authenticator.secret.isEmpty)
        }

        let first = try OTPAuthURI.parse(String(export.text.split(separator: "\n")[0]))
        #expect(first.issuer == "Bank")
        #expect(first.account == "elie")
        #expect(first.authenticator.secret == "JBSWY3DPEHPK3PXP")

        let second = try OTPAuthURI.parse(String(export.text.split(separator: "\n")[1]))
        #expect(second.authenticator.algorithm == .sha256)
        #expect(second.authenticator.digits == 8)
    }

    /// Reporting only the URIs would let somebody believe their whole vault
    /// crossed over, and find out otherwise at the moment they needed the part
    /// that did not.
    @Test func whatCannotCrossIsNamedRatherThanCounted() {
        let export = Exporter.otpauthURIs(from: document())

        #expect(export.untranslatable.count == 2)
        #expect(export.untranslatable.map(\.kind).sorted() == ["password", "recoveryCodes"])
        #expect(export.untranslatable.allSatisfy { !$0.label.isEmpty })
        #expect(export.untranslatable.contains { $0.label == "Bank (elie)" })
    }

    @Test func hotpCarriesItsCounter() throws {
        var document = VaultDocument(vaultId: "test")
        document.accounts = [Account(id: "a1", service: "S", identifier: "i")]
        var authenticator = Authenticator(secret: "JBSWY3DPEHPK3PXP")
        authenticator.kind = .hotp(counter: 7)
        document.items = [Item(id: "i1", accountId: "a1", payload: .authenticator(authenticator))]

        let line = Exporter.otpauthURIs(from: document).text.trimmingCharacters(in: .newlines)
        let parsed = try OTPAuthURI.parse(line)

        #expect(parsed.authenticator.kind == .hotp(counter: 7))
    }

    /// A vault with nothing exportable produces an empty file, not a file with
    /// a blank line in it that another app reads as a malformed entry.
    @Test func nothingExportableWritesNothing() {
        var document = VaultDocument(vaultId: "test")
        document.accounts = [Account(id: "a1", service: "S", identifier: "i")]
        document.items = [Item(id: "i1", accountId: "a1",
                               payload: .note(Note(title: "t", body: "b")))]

        let export = Exporter.otpauthURIs(from: document)

        #expect(export.isEmpty)
        #expect(export.text.isEmpty)
        #expect(export.untranslatable.count == 1)
    }

    /// Exported twice from an unchanged vault, byte for byte the same. A diff
    /// that is only reordering is a diff nobody can read.
    @Test func exportingTwiceProducesTheSameFile() {
        let document = self.document()
        #expect(Exporter.otpauthURIs(from: document).text
                == Exporter.otpauthURIs(from: document).text)
    }
}
