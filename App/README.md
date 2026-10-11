# FSProbeApp — the iOS application package

This is the xtool build unit. `xtool dev build` (https://github.com/xtool-org/xtool)
expects a SwiftPM package exposing exactly one library product, which it packages
into an `.app` using `xtool.yml` for the bundle identity.

## Layout

```
App/
  Package.swift     the app package: one library product, "FSProbe"
  xtool.yml         xtool configuration: bundle ID and product selection
  Sources/FSProbe/  the SwiftUI app sources
```

The probe engine itself lives in the repository-root package (`Sources/FSProbeCore`,
product `FSProbeCore`) and is consumed here through a path dependency, so the app
and the engine are separate modules with a real dependency edge.

This package is deliberately separate from the root package because the root
package must stay buildable on hosts without SwiftUI — that is how the unit tests
are verified off-device. The app imports `FSProbeCore` under
`#if canImport(FSProbeCore)` so the same sources also compile inside the
generated Xcode project, which builds the engine into the app target for the
iOS Simulator runs.

## Building

```sh
xtool dev build --configuration release --ipa
```

Output lands in `./xtool/`. On macOS xtool uses the Xcode that ships on the host,
so no SDK download is needed; on Linux it requires an `Xcode.xip` to build the
Darwin SDK, which is why the CI job for this runs on a macOS runner.
