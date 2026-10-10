// Framework-free engine module. This module must stay dependency-free going
// forward: no coroutines, no redis, no frameworks. The W2 detection engine
// (regex compiler, redos chain, suspatterns tables) lives here.
plugins {
  alias(libs.plugins.kotlin.jvm)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  implementation(libs.kotlin.stdlib)

  testImplementation(libs.kotlin.test)
}
