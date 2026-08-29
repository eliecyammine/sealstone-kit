import XCTest
@testable import VaultCore

final class VaultDocumentTests: XCTestCase {
    private func sample() throws -> VaultDocument {
        let json = """
        {"formatVersion":1,"vaultId":"v1","createdAt":"2026-08-24T00:00:00Z",
         "updatedAt":"2026-08-24T00:00:00Z",
         "accounts":[
           {"id":"mail","service":"Mail","identifier":"a@b.c","tags":[],"createdAt":"2026-08-24T00:00:00Z"},
           {"id":"bank","service":"Bank","identifier":"me","tags":[],"createdAt":"2026-08-24T00:00:00Z"}],
         "items":[
           {"id":"i1","accountId":"mail","type":"authenticator","createdAt":"2026-08-24T00:00:00Z",
            "secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30,
            "counter":null,"otpType":"totp"}],
         "links":[
           {"id":"l1","sourceAccountId":"mail","targetAccountId":"bank","method":"email"}],
         "keepers":[]}
        """
        return try JSONDecoder().decode(VaultDocument.self, from: Data(json.utf8))
    }

    func testLookups() throws {
        let document = try sample()
        XCTAssertEqual(document.account("mail")?.service, "Mail")
        XCTAssertNil(document.account("nope"))
        XCTAssertEqual(document.items(for: "mail").count, 1)
        XCTAssertEqual(document.authenticators.count, 1)
    }

    func testRecoveryGraphDirections() throws {
        let document = try sample()
        // Mail can recover Bank: Bank has a path in, Mail has a dependent.
        XCTAssertEqual(document.recoveryPaths(into: "bank").count, 1)
        XCTAssertEqual(document.dependents(of: "mail").count, 1)
        XCTAssertEqual(document.recoveryPaths(into: "mail").count, 0)
        XCTAssertEqual(document.dependents(of: "bank").count, 0)
    }

    func testRoundTrip() throws {
        let document = try sample()
        let encoded = try JSONEncoder().encode(document)
        let again = try JSONDecoder().decode(VaultDocument.self, from: encoded)
        XCTAssertEqual(again, document)
    }
}
