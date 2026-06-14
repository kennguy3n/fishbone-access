/*
 * build.gradle.kts — ShieldNet Access mobile SDK (Android) library module.
 *
 * This is the JVM compilation surface for the OkHttp-backed [AccessClient].
 * The module deliberately uses the plain Kotlin/JVM plugin (NOT the Android
 * Gradle Plugin) so it builds and tests on a stock JDK in CI without the
 * Android SDK installed. The only Android-specific assumption is `org.json`,
 * which ships on the Android platform and is pulled from Maven for JVM tests.
 *
 * Host apps that want an `.aar` can re-publish through their own Android
 * module; library consumers depend on the Maven coordinates
 * `com.shieldnet.access:access-sdk:<version>`.
 *
 * Build / test locally:
 *   ./gradlew :build        # compile + run the unit/contract tests
 *   ./gradlew :test         # tests only
 */
plugins {
    kotlin("jvm") version "1.9.25"
    `java-library`
    `maven-publish`
}

group = "com.shieldnet.access"
version = (findProperty("sdk.android.version") as String?) ?: "0.2.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // org.json backs the manual JSON parsing path. On Android it is part of
    // the platform; for JVM tests it comes from Maven.
    implementation("org.json:json:20240303")

    testImplementation("org.jetbrains.kotlin:kotlin-test:1.9.25")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:1.9.25")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

kotlin {
    jvmToolchain(17)
}

java {
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
}

sourceSets {
    main { kotlin.srcDirs("src/main/kotlin") }
    test { kotlin.srcDirs("src/test/kotlin") }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            artifactId = "access-sdk"
            pom {
                name.set("ShieldNet Access SDK (Android)")
                description.set(
                    "Kotlin / JVM REST client for the ShieldNet Access control plane. " +
                        "Thin client — no on-device inference.",
                )
                url.set("https://github.com/kennguy3n/fishbone-access")
                licenses {
                    license { name.set("UNLICENSED — internal use only") }
                }
                scm {
                    url.set("https://github.com/kennguy3n/fishbone-access")
                    connection.set("scm:git:https://github.com/kennguy3n/fishbone-access.git")
                    developerConnection.set("scm:git:ssh://git@github.com/kennguy3n/fishbone-access.git")
                }
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri(
                (findProperty("sdk.android.maven.url") as String?)
                    ?: "https://maven.pkg.github.com/kennguy3n/fishbone-access",
            )
            credentials {
                username = (findProperty("sdk.android.maven.user") as String?)
                    ?: System.getenv("MAVEN_USERNAME") ?: System.getenv("GITHUB_ACTOR")
                password = (findProperty("sdk.android.maven.token") as String?)
                    ?: System.getenv("MAVEN_PASSWORD") ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
