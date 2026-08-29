pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        // The Iceberg fork of secp256k1-kmp (0.23.0-iceberg) only exists in the local Maven
        // repository: run publish-iceberg-secp256k1.sh once to install it there. It is only ever
        // resolved by the JVM source sets, which is the safe way to use mavenLocal with KMP.
        mavenLocal()
        mavenCentral()
        google()
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }
}

rootProject.name = "lightning-kmp"

include(":lightning-kmp-ios-crypto")
include(":lightning-kmp-core")

project(":lightning-kmp-ios-crypto").projectDir = file("./modules/ios-crypto")
project(":lightning-kmp-core").projectDir = file("./modules/core")