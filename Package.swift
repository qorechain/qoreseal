// swift-tools-version:5.9
// SPDX-License-Identifier: Apache-2.0
//
// QoreSeal for Swift: ML-KEM-1024 (FIPS 203) encryption of data to QoreChain
// accounts, over the Rust core in crates/qoreseal through UniFFI.
//
// The native code ships as the binary target QoreSealFFI:
// - Release builds download the xcframework zip attached to the GitHub
//   release. `releaseChecksum` is a placeholder until a release:
//   `scripts/build-xcframework.sh --write-checksum` builds the zip and writes
//   its checksum here; that commit is what gets tagged (see swift/README.md).
// - Local development uses swift/QoreSealFFI.xcframework, built by
//   scripts/build-xcframework.sh. It is selected when the QORESEAL_LOCAL_FFI
//   environment variable is set, or when that directory exists (it is
//   git-ignored, so it never exists in a checkout fetched by SwiftPM).

import Foundation
import PackageDescription

let releaseVersion = "0.1.0"
let releaseChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

let localFFIPath = "swift/QoreSealFFI.xcframework"
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let useLocalFFI = ProcessInfo.processInfo.environment["QORESEAL_LOCAL_FFI"] != nil
    || FileManager.default.fileExists(atPath: packageDir + "/" + localFFIPath)

let ffiTarget: Target = useLocalFFI
    ? .binaryTarget(name: "QoreSealFFI", path: localFFIPath)
    : .binaryTarget(
        name: "QoreSealFFI",
        url: "https://github.com/qorechain/qoreseal/releases/download/v\(releaseVersion)/QoreSealFFI.xcframework.zip",
        checksum: releaseChecksum
    )

let package = Package(
    name: "QoreSeal",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "QoreSeal", targets: ["QoreSeal"]),
    ],
    targets: [
        ffiTarget,
        .target(
            name: "QoreSeal",
            dependencies: ["QoreSealFFI"],
            path: "swift/Sources/QoreSeal"
        ),
        .testTarget(
            name: "QoreSealTests",
            dependencies: ["QoreSeal"],
            path: "swift/Tests/QoreSealTests"
        ),
    ]
)
