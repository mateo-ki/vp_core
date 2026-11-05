// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "VPCore",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "VPCore",
            targets: ["VPCore"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "VPCoreC",
            path: "VPCore.xcframework"
        ),
        .target(
            name: "VPCore",
            dependencies: ["VPCoreC"],
            path: "Sources/VPCore"
        )
    ]
)
