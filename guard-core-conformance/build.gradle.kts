// Corpus runner module (unpublished). W2 adds the detect-suite runner; the full runner,
// cost budgets, and xfail manifests land in W5.
plugins {
  alias(libs.plugins.kotlin.jvm)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  implementation(project(":guard-core-engine"))
  implementation(project(":guard-core"))
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.kotlin.test)
}

tasks.withType<Test>().configureEach {
  maxHeapSize = "3g"
  systemProperty(
      "guardcore.update.ledger",
      System.getenv("GUARD_UPDATE_LEDGER") ?: "0",
  )
}
