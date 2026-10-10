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

  testImplementation(libs.kotlin.test)
}
