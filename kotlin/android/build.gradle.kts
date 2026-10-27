// SPDX-License-Identifier: Apache-2.0
//
// io.github.qorechain:qoreseal-android - the same bindings as the JVM artifact
// (../src/main/kotlin) packaged as an AAR with jniLibs for arm64-v8a,
// armeabi-v7a and x86_64, built by
// `scripts/build-kotlin-natives.sh android` (needs ANDROID_NDK_HOME).
// Enabled with -PqoresealAndroid=true; needs an Android SDK (ANDROID_HOME).

plugins {
    id("com.android.library")
    id("com.vanniktech.maven.publish")
}

group = "io.github.qorechain"
version = "0.1.0"

val jnaVersion = "5.19.1"

android {
    namespace = "io.github.qorechain.qoreseal"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir("../src/main/kotlin")
        }
    }
}

dependencies {
    api("net.java.dev.jna:jna:$jnaVersion@aar")
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = false)
    if (project.hasProperty("signingInMemoryKey") || project.hasProperty("signing.keyId")) {
        signAllPublications()
    }

    coordinates("io.github.qorechain", "qoreseal-android", version.toString())

    pom {
        name.set("QoreSeal for Android")
        description.set(
            "ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts " +
                "for Android."
        )
        url.set("https://github.com/qorechain/qoreseal")
        licenses {
            license {
                name.set("Apache License 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("qorechain")
                name.set("QoreChain Association")
                url.set("https://github.com/qorechain")
            }
        }
        scm {
            url.set("https://github.com/qorechain/qoreseal")
            connection.set("scm:git:https://github.com/qorechain/qoreseal.git")
            developerConnection.set("scm:git:ssh://git@github.com/qorechain/qoreseal.git")
        }
    }
}
