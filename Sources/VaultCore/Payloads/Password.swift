

/// A password, and where it is used.
///
/// The vault holds seed phrases and security questions already, which are the
/// same kind of secret with the same consequences, so a password is not a new
/// category of risk. It is here because "the things that get you back in"
/// plainly includes it, and because a recovery story that stops short of the
/// password is a recovery story with a hole in the middle.
///
/// `username` rather than an account identifier: the account this belongs to
/// already carries who you are. This is the login as the site asks for it,
/// which is not always the same string.
public struct Password: Sendable, Hashable, Codable {
    public var password: String
    public var username: String?
    /// Where it is used, as the user would recognise it.
    public var site: String?
    public var note: String?

    public init(password: String, username: String? = nil,
                site: String? = nil, note: String? = nil) {
        self.password = password
        self.username = username
        self.site = site
        self.note = note
    }
}
