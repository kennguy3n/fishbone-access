# Publishing the Android Access SDK

The Android SDK is a Kotlin / JVM library distributed as a Maven artifact. The
registry URL and credentials are driven by Gradle properties / environment
variables, so any internal Maven repository (Artifactory, Nexus, GitHub
Packages) can be targeted without editing `build.gradle.kts`.

## Coordinates

| Field | Value |
|-------|-------|
| Group ID | `com.shieldnet.access` |
| Artifact ID | `access-sdk` |
| Current version | `0.2.0` |
| Repository (default) | `https://maven.pkg.github.com/kennguy3n/fishbone-access` |
| Tag prefix | `sdk-android-v` |

## Consuming the artifact

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
        maven {
            url = uri("https://maven.pkg.github.com/kennguy3n/fishbone-access")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.token").orNull ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.shieldnet.access:access-sdk:0.2.0")
}
```

## Releasing

1. Bump the version: pass `-Psdk.android.version=X.Y.Z` or edit the default in
   `build.gradle.kts`, and add a `CHANGELOG.md` entry.
2. Build + test green locally: `./gradlew build`.
3. Publish:

   ```bash
   ./gradlew publish \
     -Psdk.android.version=X.Y.Z \
     -Psdk.android.maven.url=<registry-url> \
     -Psdk.android.maven.user=<user> \
     -Psdk.android.maven.token=<token>
   ```

   (or set `MAVEN_USERNAME` / `MAVEN_PASSWORD`, falling back to `GITHUB_ACTOR` /
   `GITHUB_TOKEN`). Use `publishToMavenLocal` to stage into `~/.m2` first.
4. Tag the release: `git tag sdk-android-vX.Y.Z && git push origin sdk-android-vX.Y.Z`.

The publication includes a sources JAR (`withSourcesJar()`) and a POM with the
project URL, license, and SCM coordinates.
