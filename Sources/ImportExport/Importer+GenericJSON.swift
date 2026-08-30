public import Foundation
public import VaultCore

/// Anything else shaped like JSON.
///
/// The fallback, and the longest, because it has to guess at field names
/// rather than being told them. It is tried last for that reason.

extension Importer {
    /// Handles Ente, Raivo and hand-rolled JSON, which all reduce to a list of
    /// objects carrying a secret and some labels under varying key names.
    static func stageGeneric(_ data: Data) throws -> ImportStaging {
        let object = try? JSONSerialization.jsonObject(with: data)

        let rows: [[String: Any]]
        if let array = object as? [[String: Any]] {
            rows = array
        } else if let root = object as? [String: Any] {
            rows = (root["items"] as? [[String: Any]])
                ?? (root["entries"] as? [[String: Any]])
                ?? (root["accounts"] as? [[String: Any]])
                ?? []
        } else {
            throw Failure.malformed("This file is not a list of credentials.")
        }

        guard !rows.isEmpty else {
            throw Failure.malformed("This file contains no credentials.")
        }

        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for row in rows {
            // Matched without regard to case, and one level into nested
            // objects. Exports disagree about capitalisation as much as about
            // wording, and several bury the interesting fields one object
            // deep. Only the keys named below are followed inwards: taking
            // any string found nested would happily label an account with the
            // name of the folder it was filed in.
            func value(_ keys: [String]) -> Any? {
                for key in keys {
                    if let found = row.first(where: {
                        $0.key.caseInsensitiveCompare(key) == .orderedSame
                    })?.value, !(found is NSNull) {
                        return found
                    }
                }
                for nested in row.values.compactMap({ $0 as? [String: Any] }) {
                    for key in keys {
                        if let found = nested.first(where: {
                            $0.key.caseInsensitiveCompare(key) == .orderedSame
                        })?.value, !(found is NSNull) {
                            return found
                        }
                    }
                }
                return nil
            }
            func string(_ keys: [String]) -> String? {
                guard let text = value(keys) as? String, !text.isEmpty else { return nil }
                return text
            }
            func integer(_ keys: [String]) -> Int? {
                if let number = value(keys) as? Int { return number }
                if let text = value(keys) as? String, let number = Int(text) { return number }
                return nil
            }

            // An unnamed row is left unnamed rather than called "unknown".
            // A placeholder that looks like a name survives the review screen
            // unchallenged and lands in the vault as though the export had
            // said it, and every such row reads the same, so a vault of them
            // cannot be told apart afterwards.
            let label = string(["account", "accountName", "name", "label",
                                "username", "userName", "originalUserName",
                                "user", "login", "email", "displayName"]) ?? ""

            // A whole otpauth URI in a field is common in hand-rolled exports.
            if let uri = string(["uri", "url", "otpauth"]),
               uri.lowercased().hasPrefix("otpauth://") {
                do {
                    let parsed = try OTPAuthURI.parse(uri)
                    candidates.append(.init(issuer: parsed.issuer,
                                            account: parsed.account,
                                            authenticator: parsed.authenticator))
                } catch {
                    rejections.append(.init(source: named(label),
                                            reason: describe(error)))
                }
                continue
            }

            guard let secret = string(["secret", "seed", "key", "secretKey"]) else {
                rejections.append(.init(source: named(label),
                                        reason: "no secret"))
                continue
            }

            do {
                let authenticator = try makeAuthenticator(
                    secret: secret,
                    algorithm: (string(["algorithm", "algo"]) ?? "SHA1").uppercased(),
                    digits: integer(["digits"])
                        ?? ((string(["type", "tokenType", "kind"]) ?? "").lowercased() == "steam" ? 5 : 6),
                    period: integer(["period", "timer", "timeStep"]) ?? 30,
                    kindName: (string(["type", "tokenType", "kind"]) ?? "totp").lowercased(),
                    counter: nonNegative(integer(["counter"])))
                candidates.append(.init(issuer: string(["issuer", "issuerName",
                                                        "originalIssuerName", "service",
                                                        "serviceName", "provider", "site",
                                                        "title"]),
                                        account: label,
                                        authenticator: authenticator))
            } catch {
                rejections.append(.init(source: named(label),
                                        reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }
}
