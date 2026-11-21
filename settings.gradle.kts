pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        // using the local maven repository with Kotlin Multi Platform can lead to build errors that are hard to diagnose.
        // uncomment this only if you need to experiment with snapshot dependencies that have not yet be published.
        // mavenLocal()
        mavenCentral()
        google()
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }
}

rootProject.name = "lightning-kmp"

// Use the local experimental bitcoin-kmp fork instead of the artifacts published on Maven Central.
// This also recursively uses bitcoin-kmp's own secp256k1-kmp fork (included by bitcoin-kmp's build):
// note that secp256k1-kmp cannot be included again here, Gradle deduplicates included builds by directory.
includeBuild("experimental/bitcoin-kmp") {
    dependencySubstitution {
        substitute(module("fr.acinq.bitcoin:bitcoin-kmp")).using(project(":"))
    }
}

include(":lightning-kmp-ios-crypto")
include(":lightning-kmp-core")

project(":lightning-kmp-ios-crypto").projectDir = file("./modules/ios-crypto")
project(":lightning-kmp-core").projectDir = file("./modules/core")