import XCTest
@testable import ImportExport

/// A migration QR is scanned from whatever is put in front of the camera, so
/// it is untrusted input by definition.
final class HostileMigrationTests: XCTestCase {
    private func migrationURI(payload: [UInt8]) -> String {
        let base64 = Data(payload).base64EncodedString()
        let escaped = base64
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? base64
        return "otpauth-migration://offline?data=\(escaped)"
    }

    /// Field 1, wire type 2, then a varint length of 2^63. A valid varint and
    /// not a valid `Int`: converting it before checking bounds traps, which
    /// would let a printed QR code kill the scanner.
    func testALengthTooLargeForAnIntIsRefusedRatherThanFatal() {
        let enormous: [UInt8] = [0x0A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]

        XCTAssertThrowsError(
            try GoogleAuthenticatorMigration.parse(migrationURI(payload: enormous)))
    }

    func testALengthPastTheEndIsRefused() {
        // Field 1, length 200, two bytes of payload.
        let overrun: [UInt8] = [0x0A, 0xC8, 0x01, 0x00, 0x00]

        XCTAssertThrowsError(
            try GoogleAuthenticatorMigration.parse(migrationURI(payload: overrun)))
    }

    func testTruncatedPayloadsAreRefused() {
        for length in 1...6 {
            let truncated = [UInt8](repeating: 0x0A, count: length)
            XCTAssertThrowsError(
                try GoogleAuthenticatorMigration.parse(migrationURI(payload: truncated)),
                "a \(length) byte payload should not parse")
        }
    }

    func testGarbageThatIsNotAMigrationURIIsRefused() {
        XCTAssertThrowsError(try GoogleAuthenticatorMigration.parse("not a uri"))
        XCTAssertThrowsError(
            try GoogleAuthenticatorMigration.parse("otpauth-migration://offline?data=!!!!"))
    }
}
