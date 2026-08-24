import Foundation

/// BLAKE2b, RFC 7693.
///
/// Present because Argon2id is defined in terms of it and CryptoKit does not
/// provide it. It is part of the vendored Argon2id rather than a separate
/// choice — Argon2 cannot be implemented without it.
///
/// Validated against the RFC 7693 test vectors. Not used for anything other
/// than Argon2id; everything else takes its hashing from CryptoKit.
struct Blake2b {
    private static let iv: [UInt64] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt64]
    private var buffer = [UInt8]()
    private var counter: UInt64 = 0
    private let digestLength: Int

    /// - Parameters:
    ///   - digestLength: 1 to 64 bytes.
    ///   - key: optional, up to 64 bytes. Argon2 does not use it.
    init(digestLength: Int, key: [UInt8] = []) {
        precondition((1...64).contains(digestLength), "digest length must be 1...64")
        precondition(key.count <= 64, "key must be at most 64 bytes")

        self.digestLength = digestLength
        self.h = Blake2b.iv
        self.h[0] ^= 0x0101_0000 ^ (UInt64(key.count) << 8) ^ UInt64(digestLength)

        if !key.isEmpty {
            var block = key
            block.append(contentsOf: [UInt8](repeating: 0, count: 128 - key.count))
            update(block)
        }
    }

    mutating func update(_ data: some Sequence<UInt8>) {
        for byte in data {
            // A full buffer is only compressed once more data arrives, because
            // the final block is finalised differently.
            if buffer.count == 128 {
                counter &+= 128
                compress(buffer, last: false)
                buffer.removeAll(keepingCapacity: true)
            }
            buffer.append(byte)
        }
    }

    consuming func finalize() -> [UInt8] {
        counter &+= UInt64(buffer.count)

        var block = buffer
        block.append(contentsOf: [UInt8](repeating: 0, count: 128 - block.count))
        compress(block, last: true)

        var digest = [UInt8]()
        digest.reserveCapacity(digestLength)
        for index in 0..<digestLength {
            digest.append(UInt8((h[index / 8] >> (8 * UInt64(index % 8))) & 0xFF))
        }
        return digest
    }

    static func hash(_ data: some Sequence<UInt8>, digestLength: Int) -> [UInt8] {
        var state = Blake2b(digestLength: digestLength)
        state.update(data)
        return state.finalize()
    }

    // MARK: - Compression

    private mutating func compress(_ block: [UInt8], last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for index in 0..<16 {
            var word: UInt64 = 0
            for byte in 0..<8 {
                word |= UInt64(block[index * 8 + byte]) << (8 * UInt64(byte))
            }
            m[index] = word
        }

        var v = [UInt64](repeating: 0, count: 16)
        for index in 0..<8 {
            v[index] = h[index]
            v[index + 8] = Blake2b.iv[index]
        }

        v[12] ^= counter
        // v[13] takes the high half of a 128-bit counter, which no input this
        // implementation sees will ever reach.
        if last { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = Blake2b.sigma[round % 10]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for index in 0..<8 {
            h[index] ^= v[index] ^ v[index + 8]
        }
    }

    private func mix(
        _ v: inout [UInt64],
        _ a: Int, _ b: Int, _ c: Int, _ d: Int,
        _ x: UInt64, _ y: UInt64
    ) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 63)
    }
}

extension UInt64 {
    func rotatedRight(by amount: UInt64) -> UInt64 {
        (self >> amount) | (self << (64 - amount))
    }
}
