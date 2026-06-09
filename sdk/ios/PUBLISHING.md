# Publishing the iOS Access SDK

The iOS SDK is a Swift Package consumed directly from Git — Swift Package
Manager resolves it by repository URL + version tag, so there is no separate
artifact registry to push to.

## Coordinates

| Field | Value |
|-------|-------|
| Package | `ShieldNetAccess` |
| Product (library) | `ShieldNetAccess` |
| Repository | `https://github.com/kennguy3n/fishbone-access` |
| Current version | `0.1.0` |
| Tag prefix | `sdk-ios-v` |

## Consuming the package

```swift
dependencies: [
    .package(url: "https://github.com/kennguy3n/fishbone-access.git", from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "ShieldNetAccess", package: "fishbone-access"),
    ]),
]
```

Because the package lives in a subdirectory (`sdk/ios`), consumers that want to
pin to this path during local development can add it via Xcode's
"Add Local Package…" pointing at `sdk/ios`, or use a `path:` dependency.

## Releasing

1. Bump the version in `CHANGELOG.md`.
2. Build + test green: `swift build && swift test` (authoritative on Linux and
   macOS — the package is UI-free).
3. Tag the release so SPM can resolve it:

   ```bash
   git tag sdk-ios-vX.Y.Z
   git push origin sdk-ios-vX.Y.Z
   ```

> SemVer tags must be reachable from the default branch for `from:` /
> `.upToNextMajor` resolution. If host apps pin by the `sdk-ios-v` prefix, use a
> dedicated tag scheme or a separate published mirror repo.
