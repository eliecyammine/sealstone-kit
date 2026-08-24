// swift-tools-version: 6.0

import PackageDescription

// No package dependencies, and there is a CI check that keeps it that way.
// Cryptographic primitives come from CryptoKit; everything above them is here.
let package = Package(
    name: "SealstoneKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SealstoneKit", targets: ["VaultCore", "VaultCrypto", "VaultStore", "OTP", "ImportExport"]),
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .library(name: "VaultCrypto", targets: ["VaultCrypto"]),
        .library(name: "VaultStore", targets: ["VaultStore"]),
        .library(name: "OTP", targets: ["OTP"]),
        .library(name: "ImportExport", targets: ["ImportExport"]),
    ],
    targets: [
        .target(name: "VaultCore"),
        .target(name: "VaultCrypto", dependencies: ["VaultCore"]),
        .target(name: "VaultStore", dependencies: ["VaultCore", "VaultCrypto"]),
        .target(name: "OTP", dependencies: ["VaultCore"]),
        .target(name: "ImportExport", dependencies: ["VaultCore", "OTP"]),

        .testTarget(name: "VaultCoreTests", dependencies: ["VaultCore"]),
        .testTarget(name: "VaultCryptoTests", dependencies: ["VaultCrypto"]),
        .testTarget(name: "VaultStoreTests", dependencies: ["VaultStore"]),
        .testTarget(name: "OTPTests", dependencies: ["OTP"]),
        .testTarget(name: "ImportExportTests", dependencies: ["ImportExport"]),

        // Runs the vector corpus from sealstone-format against this
        // implementation. Both must agree or one of them is wrong.
        .testTarget(
            name: "ConformanceTests",
            dependencies: ["VaultCore", "VaultCrypto", "OTP"],
            resources: [.copy("Vectors")]
        ),
    ]
)

for target in package.targets {
    target.swiftSettings = (target.swiftSettings ?? []) + [
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
    ]
}
