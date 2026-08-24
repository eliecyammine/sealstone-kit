public import Foundation

/// An ISO 8601 timestamp that re-encodes exactly as it was read.
///
/// Vaults are round-tripped by more than one implementation, and a timestamp
/// that arrives as `2026-08-24T10:00:00Z` must leave the same way rather than
/// gaining or losing fractional seconds. The original spelling is kept
/// alongside the parsed value for that reason.
///
/// Parsing and formatting are done arithmetically rather than through
/// `ISO8601DateFormatter`, which is not `Sendable` and cannot be held in a
/// static. The conversion is exact for the proleptic Gregorian calendar.
public struct Timestamp: Sendable, Hashable {
    public let date: Date
    private let spelling: String

    public init(_ date: Date) {
        self.date = date
        self.spelling = Timestamp.format(date)
    }

    public init?(parsing text: String) {
        guard let parsed = Timestamp.parse(text) else { return nil }
        self.date = parsed
        self.spelling = text
    }

    public static func now() -> Timestamp {
        Timestamp(Date())
    }

    /// What this implementation writes when it creates a timestamp:
    /// `YYYY-MM-DDTHH:MM:SSZ`, always UTC, never fractional.
    public var canonical: String {
        Timestamp.format(date)
    }

    /// The spelling this value was read with, which may not be canonical.
    public var asWritten: String { spelling }
}

// MARK: - Conversion

extension Timestamp {
    /// Days from 1970-01-01 for a proleptic Gregorian date.
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = year - (month <= 2 ? 1 : 0)
        let era = (y >= 0 ? y : y - 399) / 400
        let yearOfEra = y - era * 400
        let dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }

    static func civilFromDays(_ days: Int) -> (year: Int, month: Int, day: Int) {
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let dayOfEra = z - era * 146_097
        let yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36_524
                         - dayOfEra / 146_096) / 365
        let year = yearOfEra + era * 400
        let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
        let monthPrime = (5 * dayOfYear + 2) / 153
        let day = dayOfYear - (153 * monthPrime + 2) / 5 + 1
        let month = monthPrime + (monthPrime < 10 ? 3 : -9)
        return (year + (month <= 2 ? 1 : 0), month, day)
    }

    static func format(_ date: Date) -> String {
        let total = Int(date.timeIntervalSince1970.rounded(.down))
        var days = total / 86_400
        var remainder = total % 86_400
        if remainder < 0 {
            remainder += 86_400
            days -= 1
        }

        let (year, month, day) = civilFromDays(days)
        let hour = remainder / 3600
        let minute = (remainder % 3600) / 60
        let second = remainder % 60

        func pad(_ value: Int, _ width: Int) -> String {
            let text = String(value)
            return text.count >= width
                ? text
                : String(repeating: "0", count: width - text.count) + text
        }

        return "\(pad(year, 4))-\(pad(month, 2))-\(pad(day, 2))"
            + "T\(pad(hour, 2)):\(pad(minute, 2)):\(pad(second, 2))Z"
    }

    /// Accepts `YYYY-MM-DDTHH:MM:SS` with optional fractional seconds and an
    /// offset of `Z` or `±HH:MM`.
    static func parse(_ text: String) -> Date? {
        let scalars = Array(text.utf8)
        guard scalars.count >= 19 else { return nil }

        func digits(_ start: Int, _ count: Int) -> Int? {
            var value = 0
            for offset in start..<(start + count) {
                guard offset < scalars.count,
                      scalars[offset] >= 48, scalars[offset] <= 57 else { return nil }
                value = value * 10 + Int(scalars[offset] - 48)
            }
            return value
        }

        guard scalars[4] == UInt8(ascii: "-"), scalars[7] == UInt8(ascii: "-"),
              scalars[10] == UInt8(ascii: "T") || scalars[10] == UInt8(ascii: " "),
              scalars[13] == UInt8(ascii: ":"), scalars[16] == UInt8(ascii: ":"),
              let year = digits(0, 4), let month = digits(5, 2),
              let day = digits(8, 2), let hour = digits(11, 2),
              let minute = digits(14, 2), let second = digits(17, 2),
              (1...12).contains(month), (1...31).contains(day),
              hour < 24, minute < 60, second < 61 else { return nil }

        var index = 19
        var fraction = 0.0

        if index < scalars.count, scalars[index] == UInt8(ascii: ".") {
            index += 1
            var scale = 0.1
            while index < scalars.count, scalars[index] >= 48, scalars[index] <= 57 {
                fraction += Double(scalars[index] - 48) * scale
                scale /= 10
                index += 1
            }
        }

        var offsetSeconds = 0
        if index < scalars.count {
            let marker = scalars[index]
            if marker == UInt8(ascii: "Z") || marker == UInt8(ascii: "z") {
                index += 1
            } else if marker == UInt8(ascii: "+") || marker == UInt8(ascii: "-") {
                guard let offsetHour = digits(index + 1, 2) else { return nil }
                let minuteStart = scalars.count > index + 3
                    && scalars[index + 3] == UInt8(ascii: ":") ? index + 4 : index + 3
                guard let offsetMinute = digits(minuteStart, 2) else { return nil }

                offsetSeconds = offsetHour * 3600 + offsetMinute * 60
                if marker == UInt8(ascii: "-") { offsetSeconds = -offsetSeconds }
                index = minuteStart + 2
            } else {
                return nil
            }
        }

        guard index == scalars.count else { return nil }

        let days = daysFromCivil(year: year, month: month, day: day)
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offsetSeconds
        return Date(timeIntervalSince1970: Double(seconds) + fraction)
    }
}

// MARK: - Conformances

extension Timestamp: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)

        guard let value = Timestamp(parsing: text) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "not an ISO 8601 timestamp: \(text)"
            )
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(spelling)
    }
}

extension Timestamp: Comparable {
    public static func < (lhs: Timestamp, rhs: Timestamp) -> Bool {
        lhs.date < rhs.date
    }
}

extension Timestamp: CustomStringConvertible {
    public var description: String { spelling }
}
