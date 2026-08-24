import XCTest
@testable import ImportExport
import VaultCore

final class GoogleAuthenticatorTests: XCTestCase {
    /// Builds a migration payload the way Google's exporter does, so the test
    /// exercises the decoder rather than a fixture nobody can check.
    private func migrationURI(entries: [(secret: [UInt8], name: String, issuer: String,
                                        algorithm: UInt8, digits: UInt8,
                                        type: UInt8, counter: UInt64)]) -> String {
        func varint(_ value: UInt64) -> [UInt8] {
            var value = value, out: [UInt8] = []
            repeat {
                var byte = UInt8(value & 0x7F)
                value >>= 7
                if value != 0 { byte |= 0x80 }
                out.append(byte)
            } while value != 0
            return out
        }
        func field(_ number: UInt64, _ wire: UInt64) -> [UInt8] { varint(number << 3 | wire) }
        func delimited(_ number: UInt64, _ bytes: [UInt8]) -> [UInt8] {
            field(number, 2) + varint(UInt64(bytes.count)) + bytes
        }

        var payload: [UInt8] = []
        for entry in entries {
            var message = delimited(1, entry.secret)
            message += delimited(2, Array(entry.name.utf8))
            message += delimited(3, Array(entry.issuer.utf8))
            message += field(4, 0) + varint(UInt64(entry.algorithm))
            message += field(5, 0) + varint(UInt64(entry.digits))
            message += field(6, 0) + varint(UInt64(entry.type))
            if entry.type == 1 { message += field(7, 0) + varint(entry.counter) }
            payload += delimited(1, message)
        }
        payload += field(2, 0) + varint(1)   // version
        payload += field(3, 0) + varint(1)   // batch size

        let base64 = Data(payload).base64EncodedString()
        let escaped = base64.addingPercentEncoding(
            withAllowedCharacters: .alphanumerics) ?? base64
        return "otpauth-migration://offline?data=\(escaped)"
    }

    func testDetectsMigrationURIs() {
        let uri = migrationURI(entries: [(Array("secret!!".utf8), "me", "Example", 1, 1, 2, 0)])
        XCTAssertEqual(Importer.detect(Data(uri.utf8)), .googleAuthenticator)
    }

    func testDecodesATOTPEntry() throws {
        let secret = Array("12345678901234567890".utf8)
        let uri = migrationURI(entries: [(secret, "me@example.com", "Example", 1, 1, 2, 0)])

        let staging = try Importer.stage(Data(uri.utf8))
        XCTAssertEqual(staging.candidates.count, 1)

        let candidate = staging.candidates[0]
        XCTAssertEqual(candidate.issuer, "Example")
        XCTAssertEqual(candidate.account, "me@example.com")
        XCTAssertEqual(candidate.authenticator.kind, .totp)
        XCTAssertEqual(candidate.authenticator.algorithm, .sha1)
        XCTAssertEqual(candidate.authenticator.digits, 6)
        XCTAssertEqual(try Base32.decode(candidate.authenticator.secret), secret)
    }

    func testDecodesAlgorithmAndDigitCodes() throws {
        let secret = Array("12345678901234567890".utf8)
        for (code, expected) in [(1, Authenticator.Algorithm.sha1),
                                 (2, .sha256), (3, .sha512)] {
            let uri = migrationURI(entries: [(secret, "n", "I", UInt8(code), 1, 2, 0)])
            let staging = try Importer.stage(Data(uri.utf8))
            XCTAssertEqual(staging.candidates[0].authenticator.algorithm, expected)
        }
        for (code, expected) in [(1, 6), (2, 8)] {
            let uri = migrationURI(entries: [(secret, "n", "I", 1, UInt8(code), 2, 0)])
            let staging = try Importer.stage(Data(uri.utf8))
            XCTAssertEqual(staging.candidates[0].authenticator.digits, expected)
        }
    }

    func testDecodesHOTPWithItsCounter() throws {
        let uri = migrationURI(entries: [
            (Array("12345678901234567890".utf8), "n", "I", 1, 1, 1, 42)])
        let staging = try Importer.stage(Data(uri.utf8))
        XCTAssertEqual(staging.candidates[0].authenticator.kind, .hotp(counter: 42))
    }

    func testDecodesABatch() throws {
        let secret = Array("12345678901234567890".utf8)
        let uri = migrationURI(entries: [
            (secret, "one", "A", 1, 1, 2, 0),
            (secret, "two", "B", 2, 2, 2, 0),
            (secret, "three", "C", 1, 1, 1, 7),
        ])
        let staging = try Importer.stage(Data(uri.utf8))
        XCTAssertEqual(staging.candidates.count, 3)
        XCTAssertEqual(staging.candidates.map(\.account), ["one", "two", "three"])
    }

    /// An unknown enum value means a newer export than this build understands.
    /// Guessing would produce a credential that generates wrong codes.
    func testUnknownEnumValuesBecomeRejectionsNotGuesses() throws {
        let secret = Array("12345678901234567890".utf8)
        for (algorithm, digits, type) in [(UInt8(9), UInt8(1), UInt8(2)),
                                          (1, 9, 2), (1, 1, 9)] {
            let uri = migrationURI(entries: [(secret, "n", "I", algorithm, digits, type, 0)])
            let staging = try Importer.stage(Data(uri.utf8))
            XCTAssertEqual(staging.candidates.count, 0)
            XCTAssertEqual(staging.rejections.count, 1)
        }
    }

    func testRejectsMalformedPayloads() {
        for uri in ["otpauth-migration://offline?data=not-base64!!!",
                    "otpauth-migration://offline",
                    "otpauth-migration://offline?data="] {
            XCTAssertThrowsError(try Importer.stage(Data(uri.utf8)), uri)
        }
    }

    func testTruncatedPayloadDoesNotCrash() {
        let uri = migrationURI(entries: [
            (Array("12345678901234567890".utf8), "me", "Example", 1, 1, 2, 0)])
        guard let components = URLComponents(string: uri),
              let data = components.queryItems?.first?.value,
              let payload = Data(base64Encoded: data) else { return XCTFail("setup") }

        for length in 1..<payload.count {
            let truncated = Data(payload.prefix(length)).base64EncodedString()
            let escaped = truncated.addingPercentEncoding(
                withAllowedCharacters: .alphanumerics) ?? truncated
            // Either a rejection or a throw. Never a trap.
            _ = try? Importer.stage(
                Data("otpauth-migration://offline?data=\(escaped)".utf8))
        }
    }

    func testStagedEntriesApplyToAVault() throws {
        let uri = migrationURI(entries: [
            (Array("12345678901234567890".utf8), "me", "Example", 1, 1, 2, 0)])
        var staging = try Importer.stage(Data(uri.utf8))
        staging.markDuplicates(against: VaultDocument(vaultId: "v1"))

        let updated = try staging.apply(to: VaultDocument(vaultId: "v1"))
        XCTAssertEqual(updated.items.count, 1)
        XCTAssertEqual(updated.accounts.count, 1)
    }
}
