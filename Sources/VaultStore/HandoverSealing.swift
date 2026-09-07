public import Foundation
public import VaultCore
import VaultCrypto
import Security

/// Sealing a handover: what the owner chose, turned into one file every keeper
/// gets a copy of and one fragment each that they do not.
///
/// **The vault key is never involved.** A handover is a subset, and the vault
/// key opens the whole vault, so splitting it would hand keepers far more than
/// they were told they held, silently and undetectably. A fresh key is made for
/// this bundle and nothing else, the bundle is sealed under it, and it is that
/// key which is split. Somebody with three handovers has three independent
/// sets, each opening only its own.
///
/// Here rather than in the application because a keeper's ability to
/// reconstruct depends on this being done exactly as the specification says,
/// and a public implementation of it is what makes that checkable by somebody
/// who does not trust us.
public enum HandoverSealing {
    public struct Sealed: Sendable {
        /// The handover as the bundle records it.
        public let handover: Handover

        /// The sealed bundle. **Identical for every keeper**: it is ciphertext,
        /// and it opens for nobody without enough fragments.
        public let bundle: [UInt8]

        /// One per keeper, and no two alike.
        public let fragments: [Fragment]

        /// The record the vault keeps of who holds what.
        public let keepers: [Keeper]
    }

    public enum Failure: Error, Sendable, Equatable {
        case nothingChosen
        case thresholdMakesNoSense(threshold: Int, total: Int)
        case fewerKeepersThanFragments(keepers: Int, total: Int)
    }

    /// One keeper, as the owner described them before anything was sealed.
    public struct Recipient: Sendable, Hashable {
        public let displayName: String
        public let contact: String

        public init(displayName: String, contact: String) {
            self.displayName = displayName
            self.contact = contact
        }
    }

    public static func seal(itemIds: Set<String>,
                            from vault: VaultDocument,
                            to recipients: [Recipient],
                            threshold: Int,
                            note: String? = nil,
                            keeping bundleId: String? = nil,
                            at date: Date = Date()) throws -> Sealed {
        guard !itemIds.isEmpty else { throw Failure.nothingChosen }

        let total = recipients.count
        guard threshold >= 2, threshold <= total, total <= 255 else {
            throw Failure.thresholdMakesNoSense(threshold: threshold, total: total)
        }

        // A fresh key for this bundle and nothing else.
        let key = randomBytes(32)
        let setId = randomBytes(Fragment.setIdLength)
        // Carried over on a reissue, fresh otherwise.
        let bundleId = bundleId ?? SealstoneID.make(.bundle, at: date)

        let handover = Handover(
            bundleId: bundleId,
            setId: setId.map { String(format: "%02X", $0) }.joined(),
            threshold: threshold,
            total: total,
            sealedAt: Timestamp(date),
            note: note)

        let document = HandoverBundle.cut(from: vault, itemIds: itemIds,
                                          handover: handover, at: date)
        let sealed = try Impression.seal(VaultCoding.encode(document),
                                         using: .key(key))

        // Split after sealing, so a failure to seal never produces fragments
        // for a bundle that does not exist.
        let shares = try Shamir.split(secret: key, threshold: threshold, total: total)
        let fragments = try shares.map {
            try Fragment(setId: setId, index: $0.index,
                         threshold: UInt8(threshold), total: UInt8(total),
                         share: $0.bytes)
        }

        let keepers = zip(recipients, fragments).map { recipient, fragment in
            Keeper(id: SealstoneID.make(.keeper, at: date),
                   displayName: recipient.displayName,
                   contact: recipient.contact,
                   bundleId: bundleId,
                   fragmentIndex: Int(fragment.index),
                   issuedAt: Timestamp(date))
        }

        return Sealed(handover: handover, bundle: sealed,
                      fragments: fragments, keepers: keepers)
    }

    /// Reissuing a set, which is the only way to remove a keeper.
    ///
    /// A fresh key, a fresh split, fresh fragments for everybody who is still
    /// in. The bundle identifier does not change: what is being replaced is the
    /// split, not the thing it opens, so somebody looking at their records sees
    /// one arrangement that has been reissued rather than two arrangements.
    ///
    /// **What this cannot do, and the interface has to say so.** It stops the
    /// old fragments working from now on. It does not reach backwards. A keeper
    /// who kept their old sheet *and* the old sealed file, and who can find
    /// enough other old sheets, can still open what they were given then. You
    /// cannot un-give something. The only thing that actually takes access away
    /// is changing the credentials themselves.
    public static func reissue(_ previous: Handover,
                               itemIds: Set<String>,
                               from vault: VaultDocument,
                               to recipients: [Recipient],
                               threshold: Int,
                               note: String? = nil,
                               at date: Date = Date()) throws -> Sealed {
        try seal(itemIds: itemIds, from: vault, to: recipients,
                 threshold: threshold, note: note ?? previous.note,
                 keeping: previous.bundleId, at: date)
    }

    /// Opening one, given enough fragments.
    ///
    /// The fragments are checked against the bundle before the key is put
    /// together, so a fragment from another set is named rather than producing
    /// a key that opens nothing and says nothing about why.
    public static func open(bundle: [UInt8],
                            with fragments: [Fragment]) throws -> VaultDocument {
        let key = try Shamir.combine(fragments.map {
            Shamir.Share(index: $0.index, bytes: $0.share)
        })
        let plaintext = try Impression.open(bundle, using: .key(key)).plaintext
        let document = try VaultCoding.decode(plaintext)

        let problems = HandoverBundle.problems(with: document, given: fragments)
        guard problems.isEmpty else { throw problems[0] }
        return document
    }

    /// The same source the envelope draws its salt and nonce from. A bundle
    /// key is the one secret in this whole arrangement, and it should not come
    /// from a different generator than everything else here.
    private static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess,
                     "the system random number generator failed")
        return bytes
    }
}
