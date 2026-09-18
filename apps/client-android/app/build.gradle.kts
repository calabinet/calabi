plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The control plane this build talks to. Release builds use the public API; a
// development build can point elsewhere with -PcalabiBffUrl=http://192.0.2.10:8002
// (and -PcalabiCoordPlaintext=true for a coordinator without TLS).
val bffUrl = (findProperty("calabiBffUrl") as String?) ?: "https://api.calabi.net"
val consoleUrl = (findProperty("calabiConsoleUrl") as String?) ?: "https://console.calabi.net"
val coordPlaintext = (findProperty("calabiCoordPlaintext") as String?)?.toBoolean() ?: false

// The version is the repository's VERSION file, like every other client artifact
// (docs/runbook/versioning.md). versionCode has to grow with every release or
// Android refuses the update: MAJOR*1000000 + MINOR*1000 + PATCH, 1.12.0 -> 1012000.
// A pre-release suffix (1.12.0-rc.1) shares its release's code. The public source
// tree has no VERSION file, so a build there passes -PcalabiVersion=<version>
// (scripts/mobile/build-release-android.ps1 always does).
val repoVersion = (findProperty("calabiVersion") as String?)
    ?: rootProject.file("../../VERSION").takeIf { it.exists() }?.readText()?.trim()
    ?: "0.0.1-dev"
val versionParts = repoVersion.substringBefore('-').substringBefore('+').split('.').map { it.toInt() }
require(versionParts.size == 3 && versionParts[1] < 1000 && versionParts[2] < 1000) { "version must be MAJOR.MINOR.PATCH: $repoVersion" }

// Release signing comes from the environment (scripts/mobile/build-release-android.ps1
// sets it). Without it assembleRelease produces an UNSIGNED apk, which is what a
// reproducibility check rebuilds; a release build is never debug-signed.
val releaseKeystore: String? = System.getenv("CALABI_ANDROID_KEYSTORE")

android {
    namespace = "net.calabi.app"
    compileSdk = 35

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("CALABI_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("CALABI_ANDROID_KEY_ALIAS") ?: "calabi"
                // keytool's default PKCS12 store has one password for the store and the key.
                keyPassword = System.getenv("CALABI_ANDROID_KEY_PASSWORD") ?: System.getenv("CALABI_ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }

    defaultConfig {
        applicationId = "net.calabi.app"
        minSdk = 26
        targetSdk = 35
        versionCode = versionParts[0] * 1_000_000 + versionParts[1] * 1_000 + versionParts[2]
        versionName = repoVersion
        buildConfigField("String", "BFF_URL", "\"$bffUrl\"")
        buildConfigField("String", "CONSOLE_URL", "\"$consoleUrl\"")
        buildConfigField("boolean", "COORD_PLAINTEXT", "$coordPlaintext")
        ndk {
            // What scripts/mobile/build-core-android.ps1 builds by default.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            // The Go core's JNI bindings are looked up by class name; shrinking
            // needs its own keep rules and a real-device pass before it is turned on.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }
    // An encrypted list of dependencies that AGP writes into the signing block for
    // Google Play. This app is not on Play, and the blob is not reproducible.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    lint {
        // The release machine builds offline and the lint jars are not in its
        // Gradle cache, so lintVital would fail every release build (2026-09-17).
        checkReleaseBuilds = false
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs {
            // The Go core must be extracted to be loaded; keep it uncompressed and aligned.
            useLegacyPackaging = false
        }
    }
}

dependencies {
    // The Go core: apps/client/mobile, bound by scripts/mobile/build-core-android.ps1.
    implementation(files("libs/calabicore.aar"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
}
