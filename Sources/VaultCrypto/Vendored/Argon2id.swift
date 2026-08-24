import Foundation

/// Argon2id key derivation, RFC 9106.
///
/// Vendored because CryptoKit provides no memory-hard key derivation function.
/// Validated against the RFC 9106 test vectors for all three variants.
///
/// The work is deliberately expensive: at the shipping parameters this
/// allocates 64 MiB and takes a noticeable fraction of a second. That cost is
/// the entire point — it is what makes a leaked backup expensive to attack.
///
/// **Known limitation.** The 64 MiB working buffer is not zeroed when the
/// derivation finishes. Swift arrays move under copy-on-write and ARC, so a
/// wipe here would zero one copy while others may persist, which is worse than
/// not claiming it — the buffer holds intermediate state rather than the key,
/// and the key itself is handled by the caller.
public enum Argon2id {
    public enum Variant: UInt32 {
        case d = 0, i = 1, id = 2
    }

    static let version: UInt32 = 0x13
    static let blockSize = 1024
    static let blockWords = 128
    static let syncPoints = 4

    public enum Failure: Error, Sendable, Equatable {
        case parametersOutOfRange(String)
        case allocationRefused(requestedKiB: Int, limitKiB: Int)
    }

    /// The most memory any single derivation may request.
    ///
    /// Enforced here rather than only at the envelope, because this function
    /// is public and a caller reaching it directly would otherwise face no
    /// limit at all. Exceeding what the device can give is not a slow
    /// derivation, it is the process being killed — which a user cannot
    /// distinguish from losing their vault.
    public static let maxMemoryKiB = 1_048_576

    /// - Parameters:
    ///   - memoryKiB: `m`, in kibibytes.
    ///   - iterations: `t`.
    ///   - parallelism: `p`.
    public static func derive(
        password: [UInt8],
        salt: [UInt8],
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        tagLength: Int = 32,
        secret: [UInt8] = [],
        associatedData: [UInt8] = [],
        variant: Variant = .id
    ) throws -> [UInt8] {
        guard parallelism >= 1, parallelism <= 0xFF_FFFF else {
            throw Failure.parametersOutOfRange("parallelism must be at least 1")
        }
        guard iterations >= 1 else {
            throw Failure.parametersOutOfRange("iterations must be at least 1")
        }
        guard tagLength >= 4 else {
            throw Failure.parametersOutOfRange("tag length must be at least 4")
        }
        guard memoryKiB >= 8 * parallelism else {
            throw Failure.parametersOutOfRange(
                "memory must be at least 8 times parallelism")
        }
        guard memoryKiB <= maxMemoryKiB else {
            throw Failure.allocationRefused(requestedKiB: memoryKiB,
                                            limitKiB: maxMemoryKiB)
        }

        let h0 = initialHash(
            password: password, salt: salt, secret: secret,
            associatedData: associatedData, memoryKiB: memoryKiB,
            iterations: iterations, parallelism: parallelism,
            tagLength: tagLength, variant: variant)

        let blockCount = (memoryKiB / (syncPoints * parallelism)) * (syncPoints * parallelism)
        let laneLength = blockCount / parallelism
        let segmentLength = laneLength / syncPoints

        var memory = [UInt64](repeating: 0, count: blockCount * blockWords)

        memory.withUnsafeMutableBufferPointer { blocks in
            fill(blocks, h0: h0, blockCount: blockCount, laneLength: laneLength,
                 segmentLength: segmentLength, iterations: iterations,
                 parallelism: parallelism, variant: variant)
        }

        // XOR the last block of every lane, then expand to the tag length.
        var final = [UInt64](repeating: 0, count: blockWords)
        for lane in 0..<parallelism {
            let base = (lane * laneLength + laneLength - 1) * blockWords
            for word in 0..<blockWords {
                final[word] ^= memory[base + word]
            }
        }

        return variableHash(tagLength, wordsToBytes(final))
    }

    // MARK: - Initial hash

    private static func initialHash(
        password: [UInt8], salt: [UInt8], secret: [UInt8],
        associatedData: [UInt8], memoryKiB: Int, iterations: Int,
        parallelism: Int, tagLength: Int, variant: Variant
    ) -> [UInt8] {
        var state = Blake2b(digestLength: 64)

        func appendUInt32(_ value: UInt32) {
            state.update(withUnsafeBytes(of: value.littleEndian) { Array($0) })
        }
        func appendLengthPrefixed(_ bytes: [UInt8]) {
            appendUInt32(UInt32(bytes.count))
            state.update(bytes)
        }

        appendUInt32(UInt32(parallelism))
        appendUInt32(UInt32(tagLength))
        appendUInt32(UInt32(memoryKiB))
        appendUInt32(UInt32(iterations))
        appendUInt32(version)
        appendUInt32(variant.rawValue)

        appendLengthPrefixed(password)
        appendLengthPrefixed(salt)
        appendLengthPrefixed(secret)
        appendLengthPrefixed(associatedData)

        return state.finalize()
    }

    /// H', the variable-length hash of RFC 9106 section 3.2.
    static func variableHash(_ outputLength: Int, _ input: [UInt8]) -> [UInt8] {
        var prefixed = withUnsafeBytes(of: UInt32(outputLength).littleEndian) { Array($0) }
        prefixed.append(contentsOf: input)

        if outputLength <= 64 {
            return Blake2b.hash(prefixed, digestLength: outputLength)
        }

        let rounds = (outputLength + 31) / 32 - 2
        var output = [UInt8]()
        output.reserveCapacity(outputLength)

        var block = Blake2b.hash(prefixed, digestLength: 64)
        output.append(contentsOf: block.prefix(32))

        for _ in 1..<rounds {
            block = Blake2b.hash(block, digestLength: 64)
            output.append(contentsOf: block.prefix(32))
        }

        output.append(contentsOf: Blake2b.hash(block, digestLength: outputLength - 32 * rounds))
        return output
    }

    // MARK: - Memory filling

    private static func fill(
        _ blocks: UnsafeMutableBufferPointer<UInt64>,
        h0: [UInt8], blockCount: Int, laneLength: Int, segmentLength: Int,
        iterations: Int, parallelism: Int, variant: Variant
    ) {
        // First two blocks of every lane come straight from H0.
        for lane in 0..<parallelism {
            for column in 0..<2 {
                var seed = h0
                seed.append(contentsOf: withUnsafeBytes(of: UInt32(column).littleEndian) { Array($0) })
                seed.append(contentsOf: withUnsafeBytes(of: UInt32(lane).littleEndian) { Array($0) })

                let words = bytesToWords(variableHash(blockSize, seed))
                let base = (lane * laneLength + column) * blockWords
                for index in 0..<blockWords { blocks[base + index] = words[index] }
            }
        }

        var scratch = [UInt64](repeating: 0, count: blockWords)
        var addressBlock = [UInt64](repeating: 0, count: blockWords)
        var inputBlock = [UInt64](repeating: 0, count: blockWords)
        var zeroBlock = [UInt64](repeating: 0, count: blockWords)

        for pass in 0..<iterations {
            for slice in 0..<syncPoints {
                for lane in 0..<parallelism {
                    // Argon2id is data-independent for the first half of the
                    // first pass and data-dependent afterwards.
                    let dataIndependent = variant == .i
                        || (variant == .id && pass == 0 && slice < 2)

                    if dataIndependent {
                        for index in 0..<blockWords { inputBlock[index] = 0 }
                        inputBlock[0] = UInt64(pass)
                        inputBlock[1] = UInt64(lane)
                        inputBlock[2] = UInt64(slice)
                        inputBlock[3] = UInt64(blockCount)
                        inputBlock[4] = UInt64(iterations)
                        inputBlock[5] = UInt64(variant.rawValue)
                    }

                    let start = (pass == 0 && slice == 0) ? 2 : 0

                    // The first segment of the first pass starts at index 2,
                    // because blocks 0 and 1 are already seeded from H0. That
                    // skips the `index % blockWords == 0` trigger below, so the
                    // first address block has to be generated here instead.
                    // Without this the segment reads an all-zero address block,
                    // which is invisible at the RFC's test parameters (segment
                    // length 2, so the loop body never runs) and wrong at every
                    // larger size.
                    if dataIndependent && start == 2 {
                        inputBlock[6] &+= 1
                        compress(&scratch, zeroBlock, inputBlock)
                        compress(&addressBlock, zeroBlock, scratch)
                    }

                    for index in start..<segmentLength {
                        let column = slice * segmentLength + index
                        let previous = lane * laneLength + (column + laneLength - 1) % laneLength

                        let pseudoRandom: UInt64
                        if dataIndependent {
                            if index % blockWords == 0 {
                                inputBlock[6] &+= 1
                                compress(&scratch, zeroBlock, inputBlock)
                                compress(&addressBlock, zeroBlock, scratch)
                            }
                            pseudoRandom = addressBlock[index % blockWords]
                        } else {
                            pseudoRandom = blocks[previous * blockWords]
                        }

                        let j1 = pseudoRandom & 0xFFFF_FFFF
                        let j2 = (pseudoRandom >> 32) & 0xFFFF_FFFF

                        let referenceLane = (pass == 0 && slice == 0)
                            ? lane
                            : Int(j2 % UInt64(parallelism))
                        let sameLane = referenceLane == lane

                        let window: Int
                        if pass == 0 {
                            if slice == 0 {
                                window = index - 1
                            } else if sameLane {
                                window = slice * segmentLength + index - 1
                            } else {
                                window = slice * segmentLength - (index == 0 ? 1 : 0)
                            }
                        } else if sameLane {
                            window = laneLength - segmentLength + index - 1
                        } else {
                            window = laneLength - segmentLength - (index == 0 ? 1 : 0)
                        }

                        // Bias the reference toward recent blocks.
                        let x = (j1 &* j1) >> 32
                        let y = (UInt64(window) &* x) >> 32
                        let z = UInt64(window) - 1 - y

                        let startPosition = pass == 0
                            ? 0
                            : (slice == syncPoints - 1 ? 0 : (slice + 1) * segmentLength)
                        let referenceIndex = (startPosition + Int(z)) % laneLength

                        let reference = referenceLane * laneLength + referenceIndex
                        let here = lane * laneLength + column

                        withUnsafeTemporaryAllocation(of: UInt64.self, capacity: blockWords) { temp in
                            compressInPlace(temp, blocks, previous, reference)

                            if pass == 0 {
                                for word in 0..<blockWords {
                                    blocks[here * blockWords + word] = temp[word]
                                }
                            } else {
                                // Later passes XOR into what is already there.
                                for word in 0..<blockWords {
                                    blocks[here * blockWords + word] ^= temp[word]
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    // MARK: - Compression

    /// G(X, Y). The block is an 8x8 matrix of 16-byte cells; P is applied to
    /// each row, then each column, and the result is XORed back with R.
    private static func compress(_ out: inout [UInt64], _ x: [UInt64], _ y: [UInt64]) {
        var r = [UInt64](repeating: 0, count: blockWords)
        for index in 0..<blockWords { r[index] = x[index] ^ y[index] }
        var q = r
        permuteRowsAndColumns(&q)
        for index in 0..<blockWords { out[index] = q[index] ^ r[index] }
    }

    private static func compressInPlace(
        _ out: UnsafeMutableBufferPointer<UInt64>,
        _ blocks: UnsafeMutableBufferPointer<UInt64>,
        _ xBlock: Int, _ yBlock: Int
    ) {
        var r = [UInt64](repeating: 0, count: blockWords)
        for index in 0..<blockWords {
            r[index] = blocks[xBlock * blockWords + index] ^ blocks[yBlock * blockWords + index]
        }
        var q = r
        permuteRowsAndColumns(&q)
        for index in 0..<blockWords { out[index] = q[index] ^ r[index] }
    }

    private static func permuteRowsAndColumns(_ q: inout [UInt64]) {
        var v = [UInt64](repeating: 0, count: 16)

        // Rows: row i occupies words 16i..16i+15.
        for row in 0..<8 {
            let base = row * 16
            for index in 0..<16 { v[index] = q[base + index] }
            permute(&v)
            for index in 0..<16 { q[base + index] = v[index] }
        }

        // Columns: cell (row, column) occupies words 16*row+2*column and +1.
        for column in 0..<8 {
            for row in 0..<8 {
                v[row * 2] = q[16 * row + 2 * column]
                v[row * 2 + 1] = q[16 * row + 2 * column + 1]
            }
            permute(&v)
            for row in 0..<8 {
                q[16 * row + 2 * column] = v[row * 2]
                q[16 * row + 2 * column + 1] = v[row * 2 + 1]
            }
        }
    }

    private static func permute(_ v: inout [UInt64]) {
        mix(&v, 0, 4, 8, 12); mix(&v, 1, 5, 9, 13)
        mix(&v, 2, 6, 10, 14); mix(&v, 3, 7, 11, 15)
        mix(&v, 0, 5, 10, 15); mix(&v, 1, 6, 11, 12)
        mix(&v, 2, 7, 8, 13); mix(&v, 3, 4, 9, 14)
    }

    /// The Argon2 variant of the BLAKE2b mixing function: the multiply term is
    /// what makes it resist time-memory trade-offs.
    private static func mix(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFF_FFFF) &* (v[b] & 0xFFFF_FFFF)
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 32)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFF_FFFF) &* (v[d] & 0xFFFF_FFFF)
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 24)
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFF_FFFF) &* (v[b] & 0xFFFF_FFFF)
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 16)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFF_FFFF) &* (v[d] & 0xFFFF_FFFF)
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 63)
    }

    // MARK: - Conversion

    private static func bytesToWords(_ bytes: [UInt8]) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: bytes.count / 8)
        for index in 0..<words.count {
            var word: UInt64 = 0
            for byte in 0..<8 {
                word |= UInt64(bytes[index * 8 + byte]) << (8 * UInt64(byte))
            }
            words[index] = word
        }
        return words
    }

    private static func wordsToBytes(_ words: [UInt64]) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(words.count * 8)
        for word in words {
            for byte in 0..<8 {
                bytes.append(UInt8((word >> (8 * UInt64(byte))) & 0xFF))
            }
        }
        return bytes
    }
}
