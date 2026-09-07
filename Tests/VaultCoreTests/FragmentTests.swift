import Testing
import Foundation
@testable import VaultCore

/// The container a keeper holds.
///
/// The bytes in `knownGood` were produced by this implementation and then
/// checked, byte for byte, against the Python reference decoder, which also
/// read the sheet this prints and printed a sheet this reads. Frozen here so
/// the two cannot drift apart without something going red.
struct FragmentTests {
    private let setId: [UInt8] = (0..<16).map { UInt8(truncatingIfNeeded: $0 &* 17 &+ 3) }
    private let share: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 11) }

    private var fragment: Fragment {
        get throws {
            try Fragment(setId: setId, index: 2, threshold: 3, total: 5, share: share)
        }
    }

    /// Produced by the Python reference decoder, not by this one. Sixty-five
    /// bytes: twenty-nine of header, thirty-two of share, four of checksum.
    private let knownGood =
        "5345414c46524701031425364758697a8b9cadbecfe0f10202030500200b121920272e353c434a"
        + "51585f666d747b828990979ea5acb3bac1c8cfd6dde40872e8e7"

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - The bytes themselves

    @Test func itWritesTheBytesTheReferenceDecoderWrites() throws {
        #expect(hex(try fragment.encoded) == knownGood)
    }

    @Test func itReadsBackWhatItWrote() throws {
        let read = try Fragment.decode(try fragment.encoded)
        #expect(read == (try fragment))
        #expect(read.share == share)
        #expect(read.setId == setId)
    }

    @Test func theHeaderIsWhatTheSpecificationSays() throws {
        let bytes = try fragment.encoded
        #expect(Array(bytes[0..<7]) == Array("SEALFRG".utf8))
        #expect(bytes[7] == 1)
        #expect(bytes[24] == 2)   // index
        #expect(bytes[25] == 3)   // threshold
        #expect(bytes[26] == 5)   // total
        #expect(Int(bytes[27]) << 8 | Int(bytes[28]) == share.count)
        #expect(bytes.count == 29 + share.count + 4)
    }

    // MARK: - What a mistyped fragment must not do

    /// The whole reason there is a checksum. A keeper copying thirty groups off
    /// a sheet will sometimes get one wrong, and reconstructing from a wrong
    /// share produces a wrong key silently.
    @Test func aSingleFlippedBitIsCaught() throws {
        var broken = try fragment.encoded
        broken[40] ^= 0x01
        #expect(throws: Fragment.Failure.checksumDoesNotMatch) {
            try Fragment.decode(broken)
        }
    }

    @Test func aTruncatedFragmentSaysSoRatherThanGuessing() throws {
        let short = Array(try fragment.encoded.dropLast(6))
        #expect(throws: Fragment.Failure.self) { try Fragment.decode(short) }
    }

    @Test func somethingElseEntirelyIsNotAFragment() {
        #expect(throws: Fragment.Failure.notAFragment) {
            try Fragment.decode(Array("hello there, not a fragment at all".utf8))
        }
    }

    @Test func aVersionThisCannotReadSaysWhichVersionItIs() throws {
        var future = try fragment.encoded
        future[7] = 9
        #expect(throws: Fragment.Failure.unsupportedVersion(9)) {
            try Fragment.decode(future)
        }
    }

    // MARK: - What cannot be built

    /// Index zero is f(0), which is the secret. A share there is the thing the
    /// split exists to avoid handing anybody.
    @Test func indexZeroIsRefused() {
        #expect(throws: Fragment.Failure.indexIsZero) {
            try Fragment(setId: setId, index: 0, threshold: 3, total: 5, share: share)
        }
    }

    @Test func aThresholdNobodyCouldMeetIsRefused() {
        #expect(throws: Fragment.Failure.self) {
            try Fragment(setId: setId, index: 1, threshold: 6, total: 5, share: share)
        }
        // A threshold of one is not a split. It is a copy of the key.
        #expect(throws: Fragment.Failure.self) {
            try Fragment(setId: setId, index: 1, threshold: 1, total: 5, share: share)
        }
    }

    @Test func aSetIdOfTheWrongSizeIsRefused() {
        #expect(throws: Fragment.Failure.setIdIsWrongLength(4)) {
            try Fragment(setId: [1, 2, 3, 4], index: 1, threshold: 3, total: 5, share: share)
        }
    }

    // MARK: - Paper

    /// A keeper pastes the sheet in as they found it, instructions and all.
    /// Payload is recognised by its shape, so rewording the sheet, or printing
    /// it in another language, cannot break reading it back.
    @Test func awholeSheetCanBePastedInWithItsProse() throws {
        let groups = try fragment.paperGroups
        let sheet = """
        Sealstone fragment 2 of 5, any 3 open it together
        Set \(try fragment.setLabel)
        Held by someone

          \(groups.prefix(5).joined(separator: "  "))
          \(groups.dropFirst(5).prefix(5).joined(separator: "  "))
          \(groups.dropFirst(10).joined(separator: "  "))

        This is one piece of a key. On its own it opens nothing.
        """

        #expect(try Fragment.fromPaper(sheet) == (try fragment))
    }

    /// **The reason Crockford was chosen.** Somebody retyping writes what they
    /// see, and a sheet that refused their transcription would be a sheet that
    /// failed at the only moment it was ever used.
    @Test func aRetypedFragmentStillReads() throws {
        let typed = try fragment.paperGroups.joined(separator: " ")
            .replacingOccurrences(of: "0", with: "O")
            .replacingOccurrences(of: "1", with: "l")
            .lowercased()

        #expect(try Fragment.fromPaper(typed) == (try fragment))
    }

    @Test func proseAloneIsNotAFragment() {
        #expect(throws: Fragment.Failure.noFragmentFound) {
            try Fragment.fromPaper("There is nothing here but a sentence.")
        }
    }

    @Test func theSetLabelIsShortEnoughToCompareByEye() throws {
        #expect(try fragment.setLabel == "0314-2536")
    }
}
