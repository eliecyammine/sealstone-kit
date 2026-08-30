

public struct SeedPhrase: Sendable, Hashable, Codable {
    public var words: [String]
    public var wordlist: String?
    public var passphrase: String?

    public init(words: [String], wordlist: String? = nil, passphrase: String? = nil) {
        self.words = words
        self.wordlist = wordlist
        self.passphrase = passphrase
    }
}
