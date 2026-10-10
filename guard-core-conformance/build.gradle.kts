// Corpus runner module (unpublished). W0 ships only the corpus smoke test;
// the full runner, cost budgets, and xfail manifests land in W5.
plugins {
  alias(libs.plugins.kotlin.jvm)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  testImplementation(libs.kotlin.test)
  testImplementation(libs.kotlinx.serialization.json)
}
