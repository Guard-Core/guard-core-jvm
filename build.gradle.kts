import com.diffplug.gradle.spotless.SpotlessExtension
import io.gitlab.arturbosch.detekt.extensions.DetektExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.spotless) apply false
    alias(libs.plugins.jmh) apply false
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
