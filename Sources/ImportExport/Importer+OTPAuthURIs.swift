public import Foundation
public import VaultCore

/// A plain list of otpauth URIs, one per line.
///
/// The lowest common denominator: almost every authenticator can be persuaded
/// to produce this, and several of the formats below are a wrapper around it.

extension Importer {
    static func stageURIs(_ data: Data) -> ImportStaging {
        let text = String(decoding: data, as: UTF8.self)
        var candidates: [ImportStaging.Candidate] = []
        var rejections: [ImportStaging.Rejection] = []

        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            do {
                let parsed = try OTPAuthURI.parse(trimmed)
                candidates.append(.init(issuer: parsed.issuer,
                                        account: parsed.account,
                                        authenticator: parsed.authenticator))
            } catch {
                rejections.append(.init(source: describeURI(trimmed),
                                        reason: describe(error)))
            }
        }
        return ImportStaging(candidates: candidates, rejections: rejections)
    }
}
