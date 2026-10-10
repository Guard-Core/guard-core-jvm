import org.gradle.api.tasks.bundling.AbstractArchiveTask

// JMH benchmark module (unpublished). W0 ships one no-op placeholder
// benchmark so the toolchain is proven; real benches land in W1+.
plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.jmh)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  implementation(project(":guard-core-engine"))
}

// Compile the jmh source set as part of the default build so CI catches
// benchmark breakage. Real bench tuning (forks, warmup, profilers) lands in W1+.
tasks.named("check") {
  dependsOn(tasks.named("jmhClasses"))
}

tasks.withType<AbstractArchiveTask>().configureEach {
  duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
