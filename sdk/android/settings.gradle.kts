/*
 * settings.gradle.kts — Gradle settings for the ShieldNet Access Android SDK.
 *
 * Single-module build. Host apps consume the published Maven artifact
 * (com.shieldnet.access:access-sdk) or include this build via `includeBuild`.
 */
rootProject.name = "shieldnet-access-sdk"

include(":example")
