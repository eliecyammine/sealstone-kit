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
