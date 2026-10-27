// SPDX-License-Identifier: Apache-2.0

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

rootProject.name = "qoreseal"

// The Android library builds only when asked for (-PqoresealAndroid=true), so
// the JVM build and tests need no Android SDK.
if (providers.gradleProperty("qoresealAndroid").orNull == "true") {
    include(":android")
}
