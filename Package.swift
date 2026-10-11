// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FSProbe",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "FSProbeCore", targets: ["FSProbeCore"])
    ],
    targets: [
        .target(
            name: "FSProbeCore",
            path: "Sources/FSProbeCore"
        ),
        .executableTarget(
            name: "fsprobe-cli",
            dependencies: ["FSProbeCore"],
            path: "Sources/fsprobe-cli"
        ),
        .testTarget(
            name: "FSProbeCoreTests",
            dependencies: ["FSProbeCore"],
            path: "Tests/FSProbeCoreTests"
        )
    ]
)
