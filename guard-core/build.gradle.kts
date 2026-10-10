// Published facade module: wires the framework-free engine into a single
// Kotlin/JVM artifact for adapters. W0 is a placeholder only.
plugins {
  alias(libs.plugins.kotlin.jvm)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  api(project(":guard-core-engine"))
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.serialization.json)
  api(libs.lettuce.core)
  api(libs.maxmind.db)
  api(libs.slf4j.api)

  testImplementation(libs.kotlin.test)
}
