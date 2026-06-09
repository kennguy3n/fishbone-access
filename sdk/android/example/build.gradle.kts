/*
 * Example module for the ShieldNet Access Android SDK.
 *
 * A tiny, runnable JVM program showing how a host app drives the access
 * flow end-to-end. It is its own Gradle subproject (not shipped in the
 * library artifact) and depends on the library via a project dependency so
 * `./gradlew :example:build` keeps the example compiling against the real
 * SDK API — a stale example fails the build instead of rotting silently.
 */
plugins {
    kotlin("jvm") version "1.9.25"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.shieldnet.access.example.AccessExampleKt")
}
