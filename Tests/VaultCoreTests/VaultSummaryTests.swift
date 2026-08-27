import XCTest
@testable import VaultCore

final class VaultSummaryTests: XCTestCase {
    func testEmptyVaultCountsZero() {
        let summary = VaultDocument().summary

        XCTAssertTrue(summary.itemCounts.isEmpty)
        XCTAssertEqual(summary.totalItems, 0)
        XCTAssertEqual(summary.accounts, 0)
        XCTAssertEqual(summary.services, 0)
        XCTAssertEqual(summary.links, 0)
        XCTAssertEqual(summary.keepers, 0)
    }

    func testCountsEveryStoredType() {
        let document = VaultDocument(
            accounts: [Account(id: "a1", service: "Google", identifier: "me@example.com")],
            items: [
                Item(id: "1", accountId: "a1",
                     payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP"))),
                Item(id: "2", accountId: "a1",
                     payload: .authenticator(Authenticator(secret: "GEZDGNBVGY3TQOJQ"))),
                Item(id: "3", accountId: "a1",
                     payload: .recoveryCodes([RecoveryCode(code: "AA-BB-CC")])),
                Item(id: "4", accountId: "a1",
                     payload: .note(Note(title: "Title", body: "Body"))),
            ])

        let summary = document.summary
        let rows = counts(by: summary.itemCounts)

        XCTAssertEqual(rows["authenticator"], 2)
        XCTAssertEqual(rows["recoveryCodes"], 1)
        XCTAssertEqual(rows["note"], 1)
        XCTAssertEqual(summary.itemCounts.count, 3)
        XCTAssertEqual(summary.totalItems, 4)
        XCTAssertEqual(summary.accounts, 1)
    }

    func testZeroCountRowsAreOmitted() {
        let document = VaultDocument(
            accounts: [Account(id: "a1", service: "S", identifier: "i")],
            items: [
                Item(id: "1", accountId: "a1",
                     payload: .seedPhrase(SeedPhrase(words: ["alpha", "bravo"]))),
            ])

        XCTAssertEqual(document.summary.itemCounts.map(\.typeName), ["seedPhrase"])
    }

    func testUnknownTypesAreCountedUnderTheirOwnName() {
        let document = VaultDocument(
            accounts: [Account(id: "a1", service: "S", identifier: "i")],
            items: [
                Item(id: "1", accountId: "a1", payload: .unknown(type: "futureThing", fields: [:])),
                Item(id: "2", accountId: "a1", payload: .unknown(type: "futureThing", fields: [:])),
                Item(id: "3", accountId: "a1", payload: .unknown(type: "wallet", fields: [:])),
            ])

        let rows = counts(by: document.summary.itemCounts)
        let unknown = document.summary.itemCounts.filter { !$0.isKnown }

        XCTAssertEqual(rows["futureThing"], 2)
        XCTAssertEqual(rows["wallet"], 1)
        XCTAssertEqual(unknown.map(\.count).sorted(), [1, 2])
    }

    func testKnownTypesPrecedeUnknownsAndUnknownsAreSorted() {
        let document = VaultDocument(
            accounts: [Account(id: "a1", service: "S", identifier: "i")],
            items: [
                Item(id: "1", accountId: "a1", payload: .unknown(type: "zeta", fields: [:])),
                Item(id: "2", accountId: "a1",
                     payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP"))),
                Item(id: "3", accountId: "a1", payload: .unknown(type: "alpha", fields: [:])),
            ])

        XCTAssertEqual(document.summary.itemCounts.map(\.typeName),
                       ["authenticator", "alpha", "zeta"])
    }

    func testLinksAndKeepersCountTheirArrays() {
        let document = VaultDocument(
            links: [Link(id: "l", sourceAccountId: "a", targetAccountId: "b", method: .email)],
            keepers: [Keeper(id: "k", displayName: "S", contact: "c",
                             bundleId: "b", fragmentIndex: 1)])

        let summary = document.summary

        XCTAssertEqual(summary.links, 1)
        XCTAssertEqual(summary.keepers, 1)
        XCTAssertEqual(summary.totalItems, 0)
    }

    func testDistinctServicesCountsUniqueNonEmptyNames() {
        let document = VaultDocument(
            accounts: [
                Account(id: "a1", service: "Google", identifier: "me@example.com"),
                Account(id: "a2", service: "google", identifier: "work@example.com"),
                Account(id: "a3", service: "Bank", identifier: "elie"),
                Account(id: "a4", service: "   ", identifier: "blank"),
                Account(id: "a5", service: "", identifier: "empty"),
            ],
            items: [
                Item(id: "1", accountId: "a1",
                     payload: .authenticator(Authenticator(secret: "JBSWY3DPEHPK3PXP"))),
            ])

        let summary = document.summary

        XCTAssertEqual(summary.accounts, 5)
        XCTAssertEqual(summary.services, 2)
        XCTAssertEqual(summary.totalItems, 1)
    }

    func testUnknownTypeWithKnownNameRemainsUnknown() {
        let document = VaultDocument(
            items: [
                Item(id: "1", accountId: "a",
                     payload: .unknown(type: "authenticator", fields: [:])),
            ])

        guard let row = document.summary.itemCounts.first else {
            return XCTFail("Expected an unknown item count")
        }

        XCTAssertEqual(row.typeName, "authenticator")
        XCTAssertEqual(row.count, 1)
        XCTAssertFalse(row.isKnown)
    }

    private func counts(by itemCounts: [ItemTypeCount]) -> [String: Int] {
        Dictionary(uniqueKeysWithValues: itemCounts.map { ($0.typeName, $0.count) })
    }
}
