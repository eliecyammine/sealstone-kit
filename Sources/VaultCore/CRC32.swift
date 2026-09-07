import Foundation

/// CRC-32, IEEE 802.3, as zlib, gzip and PNG compute it.
///
/// **This detects transcription error and nothing else.** It is not a security
/// control: anyone changing a fragment can recompute it in a line of code. It
/// is here because a keeper typing thirty groups of five characters off a sheet
/// will sometimes get one wrong, and being told so beats watching a
/// reconstruction fail for no stated reason.
///
/// Written out rather than taken from a dependency, like everything else here.
/// The reflected polynomial `0xEDB88320` is `0x04C11DB7` read the other way,
/// which is what "reflected" means and why the loop shifts right.
public enum CRC32 {
    public static func checksum(_ bytes: some Sequence<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }
}
