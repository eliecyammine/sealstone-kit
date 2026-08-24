public import Foundation
private import CryptoKit
private import Security

/// The Impression envelope: header, key derivation, authenticated encryption.
///
/// The header is passed to the AEAD as associated data, so any change to the
/// version, algorithm identifiers or KDF parameters is detected on open.
/// Without this an attacker could downgrade a file's KDF parameters to
/// something cheap to brute-force.
///
/// Decode order is verify the tag, then parse, then validate, then act.
/// Nothing is mutated before the tag verifies.
public enum Impression {
    public static let magic: [UInt8] = Array("SEALSTN".utf8)
    public static let formatMajor: UInt8 = 1
    public static let formatMinor: UInt8 = 0

    public static let saltLength = 16
    public static let nonceLength = 12
    public static let tagLength = 16

    /// RFC 9106 memory-constrained parameter set.
    public static let defaultMemoryKiB = 65536
    public static let defaultIterations = 3
    public static let defaultParallelism = 4

    public static let maxMemoryKiB = 1_048_576
    public static let maxIterations = 16
    public static let maxParallelism = 16

    public enum KDF: UInt8, Sendable {
        /// Key supplied directly, for the at-rest store. Parameter fields are zero.
        case none = 0x00
        case argon2id = 0x01
    }

    public enum AEAD: UInt8, Sendable {
        case aes256GCM = 0x01
        case chaCha20Poly1305 = 0x02   // specified, not implemented in v1
    }

    public struct Header: Sendable, Hashable {
        public let formatMajor: UInt8
        public let formatMinor: UInt8
        public let kdf: KDF
        public let aead: AEAD
        public let memoryKiB: Int
        public let iterations: Int
        public let parallelism: Int
        public let salt: [UInt8]
        public let nonce: [UInt8]

        var bytes: [UInt8] {
            var out = Impression.magic
            out.append(contentsOf: [formatMajor, formatMinor, kdf.rawValue, aead.rawValue])
            out.append(contentsOf: withUnsafeBytes(of: UInt32(memoryKiB).bigEndian) { Array($0) })
            out.append(contentsOf: withUnsafeBytes(of: UInt32(iterations).bigEndian) { Array($0) })
            out.append(UInt8(parallelism))
            out.append(UInt8(salt.count))
            out.append(contentsOf: salt)
            out.append(UInt8(nonce.count))
            out.append(contentsOf: nonce)
            out.append(contentsOf: [0x00, 0x00])
            return out
        }
    }

    public enum KeyMaterial: Sendable {
        case passphrase(String)
        case key([UInt8])
    }

    // MARK: - Sealing

    /// Produces an Impression.
    ///
    /// `salt` and `nonce` exist to reproduce fixed test vectors. Leave them nil
    /// everywhere else — they must be fresh per file, which is what makes
    /// single-shot AES-GCM safe here.
    public static func seal(
        _ plaintext: [UInt8],
        using material: KeyMaterial,
        memoryKiB: Int = defaultMemoryKiB,
        iterations: Int = defaultIterations,
        parallelism: Int = defaultParallelism,
        salt: [UInt8]? = nil,
        nonce: [UInt8]? = nil,
        formatMinor minor: UInt8 = formatMinor
    ) throws -> [UInt8] {
        let usesKDF: Bool
        switch material {
        case .passphrase: usesKDF = true
        case .key(let key):
            guard key.count == 32 else {
                throw ImpressionError.keyMaterialMismatch("The key must be 32 bytes.")
            }
            usesKDF = false
        }

        let header = Header(
            formatMajor: formatMajor,
            formatMinor: minor,
            kdf: usesKDF ? .argon2id : .none,
            aead: .aes256GCM,
            memoryKiB: usesKDF ? memoryKiB : 0,
            iterations: usesKDF ? iterations : 0,
            parallelism: usesKDF ? parallelism : 0,
            salt: salt ?? randomBytes(saltLength),
            nonce: nonce ?? randomBytes(nonceLength)
        )

        let headerBytes = header.bytes
        let derived = try deriveKey(header: header, material: material)

        let box = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: derived),
            nonce: AES.GCM.Nonce(data: header.nonce),
            authenticating: headerBytes
        )

        return headerBytes + Array(box.ciphertext) + Array(box.tag)
    }

    // MARK: - Opening

    /// Opens an Impression, returning the plaintext and the header it declared.
    public static func open(
        _ data: [UInt8],
        using material: KeyMaterial
    ) throws -> (plaintext: [UInt8], header: Header) {
        let (header, offset) = try parseHeader(data)

        let body = Array(data[offset...])
        guard body.count >= tagLength else {
            throw ImpressionError.notAnImpression("The file is truncated — there is no room for an authentication tag.")
        }

        let ciphertext = Array(body[..<(body.count - tagLength)])
        let tag = Array(body[(body.count - tagLength)...])
        let derived = try deriveKey(header: header, material: material)

        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: header.nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            let plaintext = try AES.GCM.open(
                box,
                using: SymmetricKey(data: derived),
                authenticating: Array(data[..<offset])
            )
            return (Array(plaintext), header)
        } catch {
            throw ImpressionError.brokenSeal
        }
    }

    /// Reads the header without needing key material, for confirming a file is
    /// an Impression before going looking for the passphrase.
    public static func inspect(_ data: [UInt8]) throws -> Header {
        try parseHeader(data).header
    }

    // MARK: - Internals

    private static func parseHeader(_ data: [UInt8]) throws -> (header: Header, offset: Int) {
        guard data.count >= magic.count + 4 else {
            throw ImpressionError.notAnImpression("The file is too short.")
        }
        guard Array(data[..<magic.count]) == magic else {
            throw ImpressionError.notAnImpression("It does not start with the Sealstone marker.")
        }

        var offset = magic.count
        let major = data[offset], minor = data[offset + 1]
        let kdfByte = data[offset + 2], aeadByte = data[offset + 3]
        offset += 4

        guard major == formatMajor else {
            throw ImpressionError.unsupportedVersion(
                "This file is Sealstone format version \(major); this version reads \(formatMajor).")
        }
        // Unknown minor versions are readable; only the major version gates.

        guard let kdf = KDF(rawValue: kdfByte) else {
            throw ImpressionError.unsupportedVersion(
                "This file uses an unknown key derivation function (0x\(String(kdfByte, radix: 16))).")
        }
        guard let aead = AEAD(rawValue: aeadByte), aead == .aes256GCM else {
            throw ImpressionError.unsupportedVersion(
                "This file uses an unsupported cipher (0x\(String(aeadByte, radix: 16))).")
        }

        func readUInt32(_ at: Int) -> Int {
            Int(UInt32(data[at]) << 24 | UInt32(data[at + 1]) << 16
                | UInt32(data[at + 2]) << 8 | UInt32(data[at + 3]))
        }

        guard data.count >= offset + 10 else {
            throw ImpressionError.notAnImpression("The header is truncated.")
        }

        let memoryKiB = readUInt32(offset)
        let iterations = readUInt32(offset + 4)
        offset += 8
        let parallelism = Int(data[offset]); offset += 1

        let saltLen = Int(data[offset]); offset += 1
        guard data.count >= offset + saltLen + 1 else {
            throw ImpressionError.notAnImpression("The header is truncated.")
        }
        let salt = Array(data[offset..<(offset + saltLen)]); offset += saltLen

        let nonceLen = Int(data[offset]); offset += 1
        guard data.count >= offset + nonceLen + 2 else {
            throw ImpressionError.notAnImpression("The header is truncated.")
        }
        let nonce = Array(data[offset..<(offset + nonceLen)]); offset += nonceLen

        guard data[offset] == 0, data[offset + 1] == 0 else {
            throw ImpressionError.notAnImpression("The reserved bytes are not zero.")
        }
        offset += 2

        // The format requires the KDF parameter fields to be zero when no key
        // derivation function is in use. The authentication tag catches a file
        // altered after sealing, but not one written this way, so the rule is
        // checked rather than assumed.
        if kdf == .none, memoryKiB != 0 || iterations != 0 || parallelism != 0 {
            throw ImpressionError.notAnImpression(
                "It declares no key derivation function but carries KDF "
                + "parameters, which the format forbids.")
        }

        // Every KDF parameter is range-checked here, before any allocation and
        // before the value reaches the derivation function. Out of range means
        // the header was altered or the file is malformed; either way, refuse.
        if kdf == .argon2id {
            guard (1...maxParallelism).contains(parallelism) else {
                throw ImpressionError.parametersOutOfRange(
                    "This file asks for parallelism \(parallelism), outside the permitted range 1 to \(maxParallelism).")
            }
            guard (1...maxIterations).contains(iterations) else {
                throw ImpressionError.parametersOutOfRange(
                    "This file asks for \(iterations) iterations, outside the permitted range 1 to \(maxIterations).")
            }
            guard memoryKiB >= 8 * parallelism, memoryKiB <= maxMemoryKiB else {
                throw ImpressionError.parametersOutOfRange(
                    "This file asks for \(memoryKiB) KiB of memory, outside the permitted range \(8 * parallelism) to \(maxMemoryKiB) KiB.")
            }
        }

        let header = Header(
            formatMajor: major, formatMinor: minor, kdf: kdf, aead: aead,
            memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism,
            salt: salt, nonce: nonce
        )
        return (header, offset)
    }

    private static func deriveKey(header: Header, material: KeyMaterial) throws -> [UInt8] {
        switch (header.kdf, material) {
        case (.none, .key(let key)):
            guard key.count == 32 else {
                throw ImpressionError.keyMaterialMismatch("The key must be 32 bytes.")
            }
            return key

        case (.none, .passphrase):
            throw ImpressionError.keyMaterialMismatch(
                "This file says its key comes from the keychain, not a passphrase. "
                + "Either it is a vault store rather than a backup, or the file was "
                + "altered. Supply the key, or use a backup you trust.")

        case (.argon2id, .passphrase(let passphrase)):
            // NFC normalisation: without it a passphrase containing a composed
            // character derives a different key depending on which platform
            // typed it.
            let normalised = Array(passphrase.precomposedStringWithCanonicalMapping.utf8)

            return try Argon2id.derive(
                password: normalised,
                salt: header.salt,
                memoryKiB: header.memoryKiB,
                iterations: header.iterations,
                parallelism: header.parallelism,
                tagLength: 32,
                variant: .id
            )

        case (.argon2id, .key):
            throw ImpressionError.keyMaterialMismatch(
                "This file is passphrase-protected. Supply the passphrase.")
        }
    }

    /// Salts and nonces come from the system CSPRNG. Named explicitly rather
    /// than relying on the standard library's default generator, so a reviewer
    /// can see which source is in use without checking documentation.
    private static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess,
                     "the system random number generator failed")
        return bytes
    }
}
