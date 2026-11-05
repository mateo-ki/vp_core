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
            url: "https://github.com/mateo-ki/vp_core/releases/download/v1.6.0/vpcore-ios-xcframework.zip",
            checksum: "4cd084c0db6f651dd61336b08eeb1b2479392ef5da592367f496f7ee4902a94d"
        ),
        .target(
            name: "VPCore",
            dependencies: ["VPCoreC"],
            path: "mobile/ios/Sources/VPCore"
        )
    ]
)
