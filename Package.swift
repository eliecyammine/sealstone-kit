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
        .library(name: "SealstoneKit", targets: ["VaultCore", "VaultCrypto", "OTP"]),
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .library(name: "VaultCrypto", targets: ["VaultCrypto"]),
        .library(name: "OTP", targets: ["OTP"]),
    ],
    targets: [
        .target(name: "VaultCore"),
        .target(name: "VaultCrypto", dependencies: ["VaultCore"]),
        .target(name: "OTP", dependencies: ["VaultCore"]),

        .testTarget(name: "VaultCoreTests", dependencies: ["VaultCore"]),
        .testTarget(name: "VaultCryptoTests", dependencies: ["VaultCrypto"]),
        .testTarget(name: "OTPTests", dependencies: ["OTP"]),

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
