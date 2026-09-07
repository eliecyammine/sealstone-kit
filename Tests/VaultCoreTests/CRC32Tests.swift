import Testing
import Foundation
@testable import VaultCore

/// CRC-32, against the check value everyone publishes.
struct CRC32Tests {
    /// The standard check value for this algorithm: the CRC of the nine ASCII
    /// digits is `0xCBF43926`. Every implementation of IEEE 802.3 CRC-32 agrees
    /// on it, which is what makes it worth checking ours against rather than
    /// against itself.
    @Test func itAgreesWithTheStandardCheckValue() {
        #expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF4_3926)
    }

    @Test func theEmptyInputIsZero() {
        #expect(CRC32.checksum([UInt8]()) == 0)
    }

    /// It is a transcription check, so it has to notice the kind of mistake a
    /// person makes: one character, changed.
    @Test func oneChangedByteChangesIt() {
        let original = Array("the quick brown fox".utf8)
        var altered = original
        altered[4] ^= 0x01
        #expect(CRC32.checksum(original) != CRC32.checksum(altered))
    }

    /// And the kind a scanner makes: two characters, swapped. A checksum that
    /// added bytes together would miss this entirely.
    @Test func twoSwappedBytesChangeIt() {
        let original = Array("abcdefgh".utf8)
        var swapped = original
        swapped.swapAt(2, 5)
        #expect(CRC32.checksum(original) != CRC32.checksum(swapped))
    }
}
