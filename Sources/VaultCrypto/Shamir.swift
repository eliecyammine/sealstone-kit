public import Foundation

/// Shamir's Secret Sharing over GF(2^8).
///
/// Splits a key into `n` fragments, any `k` of which reconstruct it. Fewer than
/// `k` reveal nothing. Field arithmetic uses the AES polynomial 0x11B.
///
/// Every operation here is constant time: no secret-dependent branches and no
/// secret-dependent table indices. Log/exp tables are the usual way to make
/// this fast and are not used, because a table lookup indexed by secret data
/// leaks through the cache.
public enum Shamir {
    public enum Failure: Error, Sendable, Equatable {
        case thresholdOutOfRange(threshold: Int, total: Int)
        case emptySecret
        case duplicateIndex(Int)
        case invalidIndex(Int)
        case mismatchedShareLengths
        case notEnoughShares(supplied: Int, needed: Int)
    }

    public struct Share: Sendable, Hashable {
        public let index: UInt8
        public let bytes: [UInt8]

        public init(index: UInt8, bytes: [UInt8]) {
            self.index = index
            self.bytes = bytes
        }
    }

    // MARK: - Field arithmetic

    /// Branch-free multiplication in GF(2^8).
    static func multiply(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var a = a
        var b = b
        var result: UInt8 = 0

        for _ in 0..<8 {
            // 0xFF when the low bit of b is set, 0x00 otherwise.
            let addMask = UInt8(0) &- (b & 1)
            result ^= a & addMask

            // 0xFF when a is about to overflow, 0x00 otherwise.
            let reduceMask = UInt8(0) &- ((a >> 7) & 1)
            a = (a << 1) ^ (0x1B & reduceMask)
            b >>= 1
        }
        return result
    }

    /// Multiplicative inverse. In GF(2^8) every non-zero element satisfies
    /// a^255 = 1, so a^254 is the inverse. The exponent is fixed, so the
    /// addition chain runs the same way for every input.
    static func inverse(_ a: UInt8) -> UInt8 {
        var result: UInt8 = 1
        var power = a
        for _ in 0..<7 {
            power = multiply(power, power)
            result = multiply(result, power)
        }
        return result
    }

    static func divide(_ a: UInt8, _ b: UInt8) -> UInt8 {
        multiply(a, inverse(b))
    }

    // MARK: - Split

    /// Splits `secret` into `total` shares, any `threshold` of which recombine.
    ///
    /// `randomByte` exists to reproduce fixed test vectors. Overriding it with
    /// anything predictable destroys the security of the split.
    public static func split(
        secret: [UInt8],
        threshold: Int,
        total: Int,
        randomByte: () -> UInt8 = { UInt8.random(in: 0...255) }
    ) throws -> [Share] {
        guard threshold >= 2, threshold <= total, total <= 255 else {
            throw Failure.thresholdOutOfRange(threshold: threshold, total: total)
        }
        guard !secret.isEmpty else { throw Failure.emptySecret }

        var shares = [[UInt8]](repeating: [], count: total)
        for index in 0..<total { shares[index].reserveCapacity(secret.count) }

        for byte in secret {
            // f(0) = byte, with random coefficients above it.
            var coefficients = [byte]
            for _ in 1..<threshold { coefficients.append(randomByte()) }

            for position in 0..<total {
                let x = UInt8(position + 1)
                var accumulator: UInt8 = 0
                for coefficient in coefficients.reversed() {
                    accumulator = multiply(accumulator, x) ^ coefficient
                }
                shares[position].append(accumulator)
            }
        }

        return (0..<total).map { Share(index: UInt8($0 + 1), bytes: shares[$0]) }
    }

    // MARK: - Combine

    /// Reconstructs the secret by Lagrange interpolation at x = 0.
    public static func combine(_ shares: [Share]) throws -> [UInt8] {
        guard shares.count >= 2 else {
            throw Failure.notEnoughShares(supplied: shares.count, needed: 2)
        }

        var seen = Set<UInt8>()
        for share in shares {
            guard share.index != 0 else { throw Failure.invalidIndex(0) }
            guard seen.insert(share.index).inserted else {
                throw Failure.duplicateIndex(Int(share.index))
            }
        }

        let length = shares[0].bytes.count
        guard shares.allSatisfy({ $0.bytes.count == length }) else {
            throw Failure.mismatchedShareLengths
        }

        var secret = [UInt8]()
        secret.reserveCapacity(length)

        for position in 0..<length {
            var accumulator: UInt8 = 0

            for (i, share) in shares.enumerated() {
                var numerator: UInt8 = 1
                var denominator: UInt8 = 1

                for (j, other) in shares.enumerated() where i != j {
                    numerator = multiply(numerator, other.index)
                    denominator = multiply(denominator, share.index ^ other.index)
                }

                accumulator ^= multiply(share.bytes[position],
                                        divide(numerator, denominator))
            }
            secret.append(accumulator)
        }

        return secret
    }
}
