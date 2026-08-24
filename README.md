# SealstoneKit

The core of [Sealstone](https://sealstone.app): vault entities, cryptography,
storage, one-time passwords, and import/export.

Apache 2.0. Open because verifying the trust claims and decoding your own data
should not require trusting us.

## What is here

| Module | Responsibility |
|---|---|
| `VaultCore` | Entities, identifiers, validation, the recovery graph model |
| `VaultCrypto` | Key derivation, the Impression envelope, Shamir secret sharing |
| `VaultStore` | Atomic persistence, backups, restore |
| `OTP` | TOTP, HOTP and Steam codes |
| `ImportExport` | `otpauth://` parsing and the import formats |

Dependencies run one way: `VaultCore` knows about nothing, and no module knows
about a UI framework. CI enforces both.

## Dependencies

None. Not "few" — none. `Package.swift` declares no package dependencies and CI
fails if one appears.

Cryptographic primitives come from CryptoKit. The single exception is Argon2id,
which CryptoKit does not provide and which is therefore vendored under
`Sources/VaultCrypto/Vendored/` along with the BLAKE2b it is defined in terms
of. Both are validated against their RFCs' published test vectors — RFC 9106 and
RFC 7693 — so a mistake shows up as a vector failure rather than a silently
wrong key.

## Verification

```
swift test
```

The `ConformanceTests` target runs the vector corpus produced by
[sealstone-format](https://github.com/eliecyammine/sealstone-format), whose
reference decoder is written in Python and shares no code with this. Two
independent implementations agreeing is the evidence that the format is right;
one implementation used twice is not.

Refresh the corpus after it changes upstream:

```
Scripts/sync-vectors.sh
```

## Design notes

**Illegal states are unrepresentable where it matters.** The HOTP counter lives
inside `Authenticator.Kind.hotp(counter:)`, so a counter-less HOTP and a
counter-bearing TOTP are both rejected by the compiler rather than by a runtime
validator.

**Unknown data survives.** Item types and fields this version does not
recognise are preserved verbatim through a decode and encode cycle, so an older
build cannot destroy a newer build's data by opening and saving.

**Shamir is constant time.** No secret-dependent branches, no secret-dependent
table indices. The log/exp tables that make this fast are deliberately not used,
because a table lookup indexed by secret data leaks through the cache.

**Identifiers are time-ordered, except where they are not.** Vault, account,
item and link identifiers use the UUID version 7 layout, so they sort by
creation and a vault dump reads chronologically. Keeper and bundle identifiers
are fully random, because they appear in handover URLs and a timestamp there
would tell whoever holds the link when the handover was configured. The choice
is made by the identifier's kind, never by the caller.

**Writes are atomic.** The vault is written beside the old file and swapped into
place, so a crash mid-write leaves the previous vault intact. It is also
excluded from iCloud Backup: restoring a device restores the app, not the vault,
and the sealed backup is the only restore path.

**Imports are staged.** Everything parses and validates before anything is
applied, duplicates are detected on account *and* secret, and the result is
validated again before it is returned. A partially applied import leaves someone
unable to tell what they now have.

## Branches

`dev` is where work lands. `main` is release, by pull request from `dev`.
Neither branch is ever deleted.

```
git config core.hooksPath .githooks
```
