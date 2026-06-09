// swift-tools-version:5.7
//
// ShieldNetAccess — iOS Access SDK (Swift Package).
//
// A REST-only client for the ShieldNet Access control plane (`cmd/ztna-api`).
// There is NO on-device inference: no `import CoreML`, no `import MLX`, no
// bundled model weights (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`). Every
// "AI" interaction is a REST call to the server-side `access-ai-agent`.
//
// The package depends only on `Foundation`/`FoundationNetworking`. It mirrors
// the Android SDK (`sdk/android`) contract method-for-method.
//
// NOTE: final iOS build & test must run on macOS / CI with the Swift + Xcode
// toolchain. On Linux only the non-UI core compiles (`swift build`); see the
// README "Build & test" section.

import PackageDescription

let package = Package(
    name: "ShieldNetAccess",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "ShieldNetAccess",
            targets: ["ShieldNetAccess"]
        ),
    ],
    targets: [
        .target(
            name: "ShieldNetAccess",
            path: "Sources/ShieldNetAccess"
        ),
        .testTarget(
            name: "ShieldNetAccessTests",
            dependencies: ["ShieldNetAccess"],
            path: "Tests/ShieldNetAccessTests"
        ),
        .executableTarget(
            name: "AccessExample",
            dependencies: ["ShieldNetAccess"],
            path: "Example/Sources/AccessExample"
        ),
    ]
)
