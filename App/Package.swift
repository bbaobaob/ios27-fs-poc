// swift-tools-version: 6.0
import PackageDescription

// The iOS application package — the xtool build unit.
//
// xtool's `dev build` expects a SwiftPM package exposing exactly one library
// product, which it packages into an .app using xtool.yml (at the repository
// root) for the bundle identity. See App/README.md.
//
// This package is deliberately separate from the repository-root package: the
// root package is the probe library plus its tests and CLI, and it must stay
// buildable on hosts without SwiftUI (that is how the unit tests are verified
// off-device). The app consumes the library through the path dependency below.
let package = Package(
    name: "FSProbeApp",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        // An xtool project should contain exactly one library product,
        // representing the main app.
        .library(
            name: "FSProbe",
            targets: ["FSProbe"]
        )
    ],
    dependencies: [
        // `name:` pins the dependency's package identity to the manifest name of
        // the root package. Without it SwiftPM derives the identity from the
        // directory name, which would break any clone checked out elsewhere.
        .package(name: "FSProbe", path: "..")
    ],
    targets: [
        .target(
            name: "FSProbe",
            dependencies: [
                .product(name: "FSProbeCore", package: "FSProbe")
            ],
            path: "Sources/FSProbe"
        )
    ]
)
