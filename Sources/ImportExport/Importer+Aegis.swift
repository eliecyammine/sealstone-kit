public import Foundation
public import VaultCore

/// Aegis Authenticator's plain JSON export.

extension Importer {
    static func stageAegis(_ data: Data) throws -> ImportStaging {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let db = root["db"] as? [String: Any] else {
            throw Failure.malformed(
                "This looks like an Aegis export but the database section is missing. "
                + "If it is encrypted, decrypt it in Aegis before importing.")
        }
        guard let entries = db["entries"] as? [[String: Any]] else {
            throw Failure.malformed("This Aegis export contains no entries.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for entry in entries {
            let name = entry["name"] as? String ?? ""
            guard let info = entry["info"] as? [String: Any],
                  let secret = info["secret"] as? String else {
                rejections.append(.init(source: named(name), reason: "no secret"))
                continue
            }

            let kindName = (entry["type"] as? String ?? "totp").lowercased()
            let algorithmName = (info["algo"] as? String ?? "SHA1").uppercased()
            let digits = info["digits"] as? Int ?? (kindName == "steam" ? 5 : 6)
            let period = info["period"] as? Int ?? 30
            let counter = nonNegative(info["counter"] as? Int)

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret, algorithm: algorithmName, digits: digits,
                    period: period, kindName: kindName, counter: counter)
                candidates.append(.init(issuer: entry["issuer"] as? String,
                                        account: name,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(name), reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }
}
