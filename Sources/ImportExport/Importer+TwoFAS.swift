public import Foundation
public import VaultCore

/// 2FAS Auth's JSON export.

extension Importer {
    static func stageTwoFAS(_ data: Data) throws -> ImportStaging {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let services = root["services"] as? [[String: Any]] else {
            throw Failure.malformed("This 2FAS export contains no services.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for service in services {
            let name = service["name"] as? String ?? ""
            guard let secret = service["secret"] as? String else {
                rejections.append(.init(source: named(name), reason: "no secret"))
                continue
            }

            let otp = service["otp"] as? [String: Any] ?? [:]
            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (otp["algorithm"] as? String ?? "SHA1").uppercased(),
                    digits: otp["digits"] as? Int
                        ?? ((otp["tokenType"] as? String ?? "").lowercased() == "steam" ? 5 : 6),
                    period: otp["period"] as? Int ?? 30,
                    kindName: (otp["tokenType"] as? String ?? "totp").lowercased(),
                    counter: nonNegative(otp["counter"] as? Int))
                // 2FAS puts the service in `name` and, when it has one, the
                // login in `otp.account`. Falling back to `name` for the
                // account put the service on both halves, so every row read
                // "GitHub (GitHub)". An entry with no login has no login;
                // repeating the service does not supply one.
                candidates.append(.init(issuer: otp["issuer"] as? String
                                            ?? (name.isEmpty ? nil : name),
                                        account: otp["account"] as? String ?? "",
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(name), reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }
}
