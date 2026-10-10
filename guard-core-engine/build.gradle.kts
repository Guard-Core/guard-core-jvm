// Framework-free engine module. This module must stay dependency-free going
// forward: no coroutines, no redis, no frameworks. W0 is a placeholder only;
// the ported engine code lands in W1+.
plugins {
  alias(libs.plugins.kotlin.jvm)
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  implementation(libs.kotlin.stdlib)
}
