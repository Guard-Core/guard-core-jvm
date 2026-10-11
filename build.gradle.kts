import com.diffplug.gradle.spotless.SpotlessExtension
import io.gitlab.arturbosch.detekt.extensions.DetektExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.spotless) apply false
    alias(libs.plugins.jmh) apply false
    alias(libs.plugins.dokka) apply false
}

// Maven coordinates: groupId com.guard-core (the Central Portal namespace;
// it reverses to guard-core.com). Kotlin packages stay com.guardcore.*:
// hyphens are illegal in JVM packages and the groupId/package mismatch is
// standard practice for hyphenated domains.
allprojects {
    group = "com.guard-core"
    version = "4.3.2"
}

subprojects {
    // JaCoCo applied but no coverage gate yet: lands with real code in W1+.
    apply(plugin = "jacoco")
    apply(plugin = "io.gitlab.arturbosch.detekt")
    apply(plugin = "com.diffplug.spotless")
    apply(plugin = "org.jetbrains.dokka")

    // Section 14.3 lockfile analog: every configuration resolves against the
    // committed gradle/gradle.lockfile state (per module directory). A
    // dependency change without `./gradlew --write-locks` fails the build,
    // and the lockfiles are what the osv-scanner dependency-audit job reads.
    dependencyLocking {
        lockAllConfigurations()
    }

    configure<DetektExtension> {
        buildUponDefaultConfig = true
        config.setFrom(rootProject.files("detekt.yml"))
    }

    configure<SpotlessExtension> {
        kotlin {
            ktfmt()
        }
        kotlinGradle {
            ktfmt()
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }

    tasks.named("check") {
        dependsOn("detekt")
    }
}
