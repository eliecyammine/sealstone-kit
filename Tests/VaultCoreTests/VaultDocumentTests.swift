import XCTest
@testable import VaultCore

final class ItemCodingTests: XCTestCase {
    private func decode(_ json: String) throws -> Item {
        try JSONDecoder().decode(Item.self, from: Data(json.utf8))
    }

    private func encode(_ item: Item) throws -> [String: Any] {
        let data = try JSONEncoder().encode(item)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testAuthenticatorRoundTrip() throws {
        let item = try decode("""
        {"id":"i1","accountId":"a1","type":"authenticator","createdAt":"2026-08-24T00:00:00Z",
         "secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA256","digits":8,"period":60,
         "counter":null,"otpType":"totp"}
        """)

        guard case .authenticator(let authenticator) = item.payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(authenticator.algorithm, .sha256)
        XCTAssertEqual(authenticator.digits, 8)
        XCTAssertEqual(authenticator.kind, .totp)

        let encoded = try encode(item)
        XCTAssertEqual(encoded["otpType"] as? String, "totp")
        XCTAssertEqual(encoded["digits"] as? Int, 8)
    }

    func testHOTPCarriesItsCounter() throws {
        let item = try decode("""
        {"id":"i1","accountId":"a1","type":"authenticator","createdAt":"2026-08-24T00:00:00Z",
         "secret":"GEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":30,
         "counter":7,"otpType":"hotp"}
        """)
        guard case .authenticator(let authenticator) = item.payload,
              case .hotp(let counter) = authenticator.kind else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(counter, 7)
        XCTAssertEqual(try encode(item)["counter"] as? Int, 7)
    }

    /// The counter lives inside the hotp case, so these two shapes cannot be
    /// represented at all — the decoder rejects them rather than a validator
    /// catching them later.
    func testCounterAndTypeMustAgree() {
        XCTAssertThrowsError(try decode("""
        {"id":"i1","accountId":"a1","type":"authenticator","createdAt":"2026-08-24T00:00:00Z",
         "secret":"GEZDGNBVGY3TQOJQ","otpType":"hotp","counter":null}
        """), "an HOTP item without a counter was accepted")

        XCTAssertThrowsError(try decode("""
        {"id":"i1","accountId":"a1","type":"authenticator","createdAt":"2026-08-24T00:00:00Z",
         "secret":"GEZDGNBVGY3TQOJQ","otpType":"totp","counter":3}
        """), "a TOTP item with a counter was accepted")
    }

    func testUnknownTypeIsPreservedThroughRoundTrip() throws {
        let item = try decode("""
        {"id":"i9","accountId":"a1","type":"typeFromTheFuture",
         "createdAt":"2026-08-24T00:00:00Z","unknownField":{"nested":[1,2,3]},
         "another":"value"}
        """)
        XCTAssertFalse(item.payload.isUnderstood)
        XCTAssertEqual(item.payload.typeName, "typeFromTheFuture")

        let encoded = try encode(item)
        XCTAssertEqual(encoded["type"] as? String, "typeFromTheFuture")
        XCTAssertEqual(encoded["another"] as? String, "value")
        XCTAssertNotNil(encoded["unknownField"])
    }

    func testUnknownFieldsOnAKnownTypeArePreserved() throws {
        let item = try decode("""
        {"id":"i1","accountId":"a1","type":"note","createdAt":"2026-08-24T00:00:00Z",
         "title":"t","body":"b","fieldFromTheFuture":42}
        """)
        XCTAssertEqual(try encode(item)["fieldFromTheFuture"] as? Int, 42)
    }

    func testRejectsMissingRequiredFields() {
        XCTAssertThrowsError(try decode(#"{"accountId":"a1","type":"note","createdAt":"2026-08-24T00:00:00Z"}"#))
        XCTAssertThrowsError(try decode(#"{"id":"i1","type":"note","createdAt":"2026-08-24T00:00:00Z"}"#))
        XCTAssertThrowsError(try decode(#"{"id":"i1","accountId":"a1","createdAt":"2026-08-24T00:00:00Z"}"#))
    }

    func testEveryKnownPayloadTypeRoundTrips() throws {
        let samples = [
            #"{"type":"recoveryCodes","codes":[{"code":"a","used":false,"usedAt":null}]}"#,
            #"{"type":"recoveryContact","channel":"email","value":"x@example.com"}"#,
            #"{"type":"securityQuestions","questions":[{"question":"q","answer":"a"}]}"#,
            #"{"type":"seedPhrase","words":["a","b"],"wordlist":"BIP39-english","passphrase":null}"#,
            #"{"type":"hardwareKey","label":"Blue","serial":"1","keyType":"fido2"}"#,
            #"{"type":"note","title":"t","body":"b"}"#,
        ]
        for sample in samples {
            let json = #"{"id":"i1","accountId":"a1","createdAt":"2026-08-24T00:00:00Z","# 
                + sample.dropFirst()
            let item = try decode(json)
            XCTAssertTrue(item.payload.isUnderstood, sample)

            let reencoded = try JSONEncoder().encode(item)
            let again = try JSONDecoder().decode(Item.self, from: reencoded)
            XCTAssertEqual(again.payload, item.payload, sample)
        }
    }
}

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

/// Deciding when two names are the same account.
final class AccountMatchingTests: XCTestCase {
    private func document() -> VaultDocument {
        VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "GitHub", identifier: "elie")])
    }

    func testAnExistingAccountIsReused() {
        var document = document()
        let id = document.accountId(forService: "GitHub", identifier: "elie")

        XCTAssertEqual(id, "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }

    func testMatchingIgnoresCase() {
        var document = document()
        XCTAssertEqual(document.accountId(forService: "github", identifier: "ELIE"), "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }

    /// Locale-aware, not `lowercased()`. In Turkish, uppercase "I" lowercases
    /// to a dotless "ı", so a byte comparison decides these are two accounts.
    func testMatchingHandlesLanguagesWhereCaseIsNotASCII() {
        var document = VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "İşbank", identifier: "elie")])

        XCTAssertEqual(document.accountId(forService: "İŞBANK", identifier: "elie"), "a1")
        XCTAssertEqual(document.accounts.count, 1, "one account, not two spellings of it")
    }

    func testADifferentIdentifierIsADifferentAccount() {
        var document = document()
        let id = document.accountId(forService: "GitHub", identifier: "someone-else")

        XCTAssertNotEqual(id, "a1")
        XCTAssertEqual(document.accounts.count, 2)
    }

    func testANewAccountIsCreatedWithWhatWasAskedFor() {
        var document = document()
        let id = document.accountId(forService: "Fastmail", identifier: "me@example.com")

        let created = document.account(id)
        XCTAssertEqual(created?.service, "Fastmail")
        XCTAssertEqual(created?.identifier, "me@example.com")
    }
}

/// The one rule for whether two names mean the same account.
final class AccountMatchKeyTests: XCTestCase {
    func testCaseDoesNotMakeADifferentAccount() {
        XCTAssertEqual(Account.matchKey(service: "GitHub", identifier: "Elie"),
                       Account.matchKey(service: "github", identifier: "elie"))
    }

    func testSurroundingSpaceDoesNotMakeADifferentAccount() {
        XCTAssertEqual(Account.matchKey(service: "  GitHub ", identifier: "elie\n"),
                       Account.matchKey(service: "GitHub", identifier: "elie"))
    }

    func testDifferentAccountsStayDifferent() {
        XCTAssertNotEqual(Account.matchKey(service: "GitHub", identifier: "elie"),
                          Account.matchKey(service: "GitHub", identifier: "someone"))
        XCTAssertNotEqual(Account.matchKey(service: "GitHub", identifier: "elie"),
                          Account.matchKey(service: "GitLab", identifier: "elie"))
    }

    /// The separator stops two different splits colliding: "ab" + "c" must not
    /// key the same as "a" + "bc".
    func testFieldsCannotRunTogether() {
        XCTAssertNotEqual(Account.matchKey(service: "ab", identifier: "c"),
                          Account.matchKey(service: "a", identifier: "bc"))
    }

    /// The document's own lookup and the key agree, which is the whole point
    /// of there being one function.
    func testLookupAgreesWithTheKey() {
        var document = VaultDocument(
            vaultId: "v1",
            accounts: [Account(id: "a1", service: "İşbank", identifier: "elie")])

        let found = document.accountId(forService: "İŞBANK", identifier: "ELIE")
        XCTAssertEqual(found, "a1")
        XCTAssertEqual(document.accounts.count, 1)
    }
}

/// The password item type.
final class PasswordItemTests: XCTestCase {
    private func roundTrip(_ json: String) throws -> (Item, [String: Any]) {
        let item = try JSONDecoder().decode(Item.self, from: Data(json.utf8))
        let encoded = try JSONEncoder().encode(item)
        return (item, try JSONSerialization.jsonObject(with: encoded) as! [String: Any])
    }

    func testAPasswordSurvivesARoundTrip() throws {
        let (item, output) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2","username":"elie","site":"github.com","note":"work"}
        """)

        guard case .password(let password) = item.payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertEqual(password.password, "hunter2")
        XCTAssertEqual(password.username, "elie")
        XCTAssertEqual(password.site, "github.com")
        XCTAssertEqual(output["type"] as? String, "password")
        XCTAssertEqual(output["password"] as? String, "hunter2")
    }

    /// Absent stays absent rather than becoming an empty string, like every
    /// other optional on an item.
    func testOnlyThePasswordIsRequired() throws {
        let (item, output) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2"}
        """)

        guard case .password(let password) = item.payload else {
            return XCTFail("wrong payload")
        }
        XCTAssertNil(password.username)
        XCTAssertFalse(output.keys.contains("username"))
    }

    /// It is a type this version understands, not something carried through
    /// as unknown.
    func testItIsNotTreatedAsSomethingFromTheFuture() throws {
        let (item, _) = try roundTrip("""
        {"id":"i1","accountId":"a1","type":"password","createdAt":"2026-08-24T00:00:00Z",
         "password":"hunter2"}
        """)
        XCTAssertTrue(item.payload.isUnderstood)
        XCTAssertTrue(item.unrecognised.isEmpty)
    }
}

/// Documents written by another implementation following the specification.
///
/// The specification says an absent array and an empty array mean the same
/// thing, and that an account's identifier is optional. The decoder required
/// both, so a file that the specification calls valid, and that the reference
/// Python decoder accepts, would not open here. A format nobody else can write
/// for is not a format.
final class SpecValidDocumentTests: XCTestCase {
    private func decode(_ json: String) throws -> VaultDocument {
        try JSONDecoder().decode(VaultDocument.self, from: Data(json.utf8))
    }

    func testACollectionMayBeAbsent() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
        """)

        XCTAssertTrue(document.accounts.isEmpty)
        XCTAssertTrue(document.items.isEmpty)
        XCTAssertTrue(document.links.isEmpty)
        XCTAssertTrue(document.keepers.isEmpty)
    }

    func testAnAccountIdentifierMayBeAbsent() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
         "accounts":[{"id":"acc_1","service":"Google",
                      "createdAt":"2026-01-01T00:00:00Z"}],
         "items":[],"links":[],"keepers":[]}
        """)

        XCTAssertEqual(document.accounts.first?.identifier, "")
    }

    /// Absent goes in, empty comes out. The specification says a writer should
    /// emit the empty array, so a document read from a sparse file and written
    /// back is a document the next reader does not have to guess about.
    func testAbsentCollectionsAreWrittenBackAsEmpty() throws {
        let document = try decode("""
        {"formatVersion":1,"vaultId":"vlt_1",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
        """)

        let written = try JSONEncoder().encode(document)
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: written) as? [String: Any])

        for key in ["accounts", "items", "links", "keepers"] {
            XCTAssertNotNil(root[key] as? [Any], "\(key) should be written as an array")
        }
    }
}
