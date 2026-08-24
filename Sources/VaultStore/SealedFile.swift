public import Foundation

/// A file of sealed bytes on this device, with two guarantees.
///
/// **It is written all or nothing.** The bytes go beside the target and the
/// target is then swapped for them. The swap is the only step that can be
/// observed as a change, and it either happened or it did not, so a write
/// interrupted by a crash or a dying battery cannot leave half a file.
///
/// **It never leaves the device.** Every file written through here is excluded
/// from iCloud Backup, and a failure to exclude is thrown rather than
/// swallowed. Silently failing would leave the file in iCloud while the
/// product went on claiming otherwise, which is worse than not writing it.
///
/// Sealing is the caller's business. This holds ciphertext and knows nothing
/// about what is inside it.
///
/// Not `Sendable`, because `FileManager` is not. Both stores that use it are
/// actors, which is where the isolation belongs anyway.
public struct SealedFile {
    public enum Failure: Error, Sendable, Equatable, LocalizedError {
        case notFound
        case writeFailed(String)
        case backupExclusionFailed(String)

        public var errorDescription: String? {
            switch self {
            case .notFound:
                "There's nothing at that location."
            case .writeFailed(let detail):
                "Couldn't write to this device. \(detail)"
            case .backupExclusionFailed(let detail):
                "Couldn't keep this file out of iCloud Backup, so it wasn't written. \(detail)"
            }
        }
    }

    public let url: URL
    private let fileManager: FileManager

    public init(url: URL, fileManager: FileManager = .default) {
        self.url = url
        self.fileManager = fileManager
    }

    public var exists: Bool {
        fileManager.fileExists(atPath: url.path)
    }

    public func read() throws -> [UInt8] {
        guard exists else { throw Failure.notFound }
        return [UInt8](try Data(contentsOf: url))
    }

    public func write(_ sealed: [UInt8]) throws {
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).writing")

        do {
            try fileManager.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true)

            try Data(sealed).write(to: temporary, options: .atomic)

            // Before the swap, so a failure here changes nothing: the
            // temporary file is removed and what was already there is
            // untouched. Reported as a write failure rather than an exclusion
            // failure, because from the caller's side nothing was written.
            do {
                try excludeFromBackup(temporary)
            } catch {
                throw Failure.writeFailed(
                    "the file couldn't be kept out of iCloud Backup, so it wasn't written")
            }

            if fileManager.fileExists(atPath: url.path) {
                _ = try fileManager.replaceItemAt(url, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: url)
            }

            // After the swap the new contents are in place. Failing here
            // leaves a real file that is not excluded, which is worth saying
            // plainly rather than undoing a save that succeeded.
            try excludeFromBackup(url)
        } catch let failure as Failure {
            try? fileManager.removeItem(at: temporary)
            throw failure
        } catch {
            try? fileManager.removeItem(at: temporary)
            throw Failure.writeFailed(error.localizedDescription)
        }
    }

    /// Removing a file that is not there is not an error. The caller wanted it
    /// gone and it is gone.
    public func destroy() throws {
        guard exists else { return }
        do {
            try fileManager.removeItem(at: url)
        } catch {
            throw Failure.writeFailed(error.localizedDescription)
        }
    }

    private func excludeFromBackup(_ target: URL) throws {
        var mutable = target
        var values = URLResourceValues()
        values.isExcludedFromBackup = true

        do {
            try mutable.setResourceValues(values)
        } catch {
            throw Failure.backupExclusionFailed(error.localizedDescription)
        }
    }
}
