/// Coding for the document and the three objects it holds.
///
/// All four are written by hand for one reason: a key this version does not
/// recognise has to survive being read and written again. Synthesised `Codable`
/// reads the keys it has properties for and writes the keys it has properties
/// for, so a field added by a later version would be dropped the first time an
/// older build saved the vault.
///
/// The shape is the same every time. Decode the known fields, collect whatever
/// else was there, and on the way out write the collected keys before the known
/// ones so a stale entry cannot shadow a real field.
///
/// Absent optionals are omitted rather than written as null, which is what the
/// synthesised versions did and what the test corpus expects.

extension VaultDocument: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion, vaultId, createdAt, updatedAt
        case accounts, items, links, keepers
    }

    private static let known = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            vaultId: try container.decode(String.self, forKey: .vaultId),
            createdAt: try container.decode(Timestamp.self, forKey: .createdAt),
            updatedAt: try container.decode(Timestamp.self, forKey: .updatedAt),
            accounts: try container.decode([Account].self, forKey: .accounts),
            items: try container.decode([Item].self, forKey: .items),
            links: try container.decode([Link].self, forKey: .links),
            keepers: try container.decode([Keeper].self, forKey: .keepers),
            unrecognised: try UnknownKeys.read(from: decoder, known: Self.known)
        )

        // Read rather than assumed. A file claiming a version this build does
        // not produce still round-trips with the version it arrived with.
        formatVersion = try container.decode(Int.self, forKey: .formatVersion)
    }

    public func encode(to encoder: any Encoder) throws {
        try UnknownKeys.write(unrecognised, known: Self.known, to: encoder)

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(formatVersion, forKey: .formatVersion)
        try container.encode(vaultId, forKey: .vaultId)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encode(accounts, forKey: .accounts)
        try container.encode(items, forKey: .items)
        try container.encode(links, forKey: .links)
        try container.encode(keepers, forKey: .keepers)
    }
}

extension Account: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id, service, identifier, domain, tags, notes, createdAt
    }

    private static let known = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            id: try container.decode(String.self, forKey: .id),
            service: try container.decode(String.self, forKey: .service),
            identifier: try container.decode(String.self, forKey: .identifier),
            domain: try container.decodeIfPresent(String.self, forKey: .domain),
            tags: try container.decodeIfPresent([String].self, forKey: .tags) ?? [],
            notes: try container.decodeIfPresent(String.self, forKey: .notes),
            createdAt: try container.decode(Timestamp.self, forKey: .createdAt),
            unrecognised: try UnknownKeys.read(from: decoder, known: Self.known)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        try UnknownKeys.write(unrecognised, known: Self.known, to: encoder)

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(service, forKey: .service)
        try container.encode(identifier, forKey: .identifier)
        try container.encodeIfPresent(domain, forKey: .domain)
        try container.encode(tags, forKey: .tags)
        try container.encodeIfPresent(notes, forKey: .notes)
        try container.encode(createdAt, forKey: .createdAt)
    }
}

extension Link: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id, sourceAccountId, targetAccountId, method, verifiedAt, note
    }

    private static let known = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            id: try container.decode(String.self, forKey: .id),
            sourceAccountId: try container.decode(String.self, forKey: .sourceAccountId),
            targetAccountId: try container.decode(String.self, forKey: .targetAccountId),
            method: try container.decode(Method.self, forKey: .method),
            verifiedAt: try container.decodeIfPresent(Timestamp.self, forKey: .verifiedAt),
            note: try container.decodeIfPresent(String.self, forKey: .note),
            unrecognised: try UnknownKeys.read(from: decoder, known: Self.known)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        try UnknownKeys.write(unrecognised, known: Self.known, to: encoder)

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(sourceAccountId, forKey: .sourceAccountId)
        try container.encode(targetAccountId, forKey: .targetAccountId)
        try container.encode(method, forKey: .method)
        try container.encodeIfPresent(verifiedAt, forKey: .verifiedAt)
        try container.encodeIfPresent(note, forKey: .note)
    }
}

extension Keeper: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id, displayName, contact, bundleId, fragmentIndex
        case issuedAt, lastConfirmedAt, status
    }

    private static let known = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.init(
            id: try container.decode(String.self, forKey: .id),
            displayName: try container.decode(String.self, forKey: .displayName),
            contact: try container.decode(String.self, forKey: .contact),
            bundleId: try container.decode(String.self, forKey: .bundleId),
            fragmentIndex: try container.decode(Int.self, forKey: .fragmentIndex),
            issuedAt: try container.decode(Timestamp.self, forKey: .issuedAt),
            lastConfirmedAt: try container.decodeIfPresent(Timestamp.self, forKey: .lastConfirmedAt),
            status: try container.decode(Status.self, forKey: .status),
            unrecognised: try UnknownKeys.read(from: decoder, known: Self.known)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        try UnknownKeys.write(unrecognised, known: Self.known, to: encoder)

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(displayName, forKey: .displayName)
        try container.encode(contact, forKey: .contact)
        try container.encode(bundleId, forKey: .bundleId)
        try container.encode(fragmentIndex, forKey: .fragmentIndex)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encodeIfPresent(lastConfirmedAt, forKey: .lastConfirmedAt)
        try container.encode(status, forKey: .status)
    }
}
