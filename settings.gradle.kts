pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "guard-core-jvm"

include("guard-core-engine")
include("guard-core")
include("guard-core-conformance")
include("guard-core-benchmark")
