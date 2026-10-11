// Corpus runner module (unpublished). W5 adds the full-corpus certification gate: a single task
// that runs ALL 21 suites + the cost budgets in one command with a summary printout.
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

val fullCorpusGate =
    tasks.register<Test>("fullCorpusGate") {
      group = "verification"
      description =
          "W5 full-corpus certification gate: all 21 suites + cost budgets in one command " +
              "with a per-suite summary."
      testClassesDirs = sourceSets["test"].output.classesDirs
      classpath = sourceSets["test"].runtimeClasspath
      filter {
        includeTestsMatching("com.guardcore.conformance.FullCorpusTest")
      }
      // The summary lines must reach the console log.
      testLogging {
        showStandardStreams = true
      }
      maxHeapSize = "3g"
      systemProperty(
          "guardcore.update.ledger",
          System.getenv("GUARD_UPDATE_LEDGER") ?: "0",
      )
    }
