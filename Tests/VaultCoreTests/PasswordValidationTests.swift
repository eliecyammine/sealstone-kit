import XCTest
@testable import VaultCore

/// A password item has to carry a password.
///
/// The specification says only `password` is required of the type, and nothing
/// enforced it in either implementation. An item with an empty one was stored,
/// listed and counted like any other, which is the failure this product exists
/// to prevent: it says the credential is here when it is not.
final class PasswordValidationTests: XCTestCase {
    private func document(with password: Password) -> VaultDocument {
        VaultDocument(
            accounts: [Account(id: "acc_1", service: "Bank", identifier: "me")],
            items: [Item(id: "itm_1", accountId: "acc_1", payload: .password(password))])
    }

    func testAPasswordIsRequired() {
        XCTAssertThrowsError(try VaultValidator.validate(document(with: Password(password: "")))) {
            guard case VaultError.invalidField(let field, _, _) = $0 else {
                return XCTFail("expected an invalid field, got \($0)")
            }
            XCTAssertEqual(field, "password")
        }
    }

    func testAnOrdinaryPasswordPasses() throws {
        try VaultValidator.validate(document(with: Password(password: "correct horse battery")))
    }

    /// Everything else about the type stays optional, so a password with no
    /// username, site or note is a complete item.
    func testTheOtherFieldsStayOptional() throws {
        let password = Password(password: "s", username: nil, site: nil, note: nil)
        try VaultValidator.validate(document(with: password))
    }

    func testAPasswordPastTheStringCeilingIsRefused() {
        let huge = String(repeating: "a", count: VaultValidator.maxStringBytes + 1)
        XCTAssertThrowsError(try VaultValidator.validate(document(with: Password(password: huge))))
    }

    /// A trailing space is load-bearing and must survive, so the check is on
    /// emptiness and never on trimming.
    func testAPasswordThatIsOnlySpacesIsStillAPassword() throws {
        try VaultValidator.validate(document(with: Password(password: "   ")))
    }
}
