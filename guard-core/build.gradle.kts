// Published facade module: wires the framework-free engine into a single
// Kotlin/JVM artifact for adapters. W0 is a placeholder only.
import org.gradle.jvm.tasks.Jar

plugins {
  alias(libs.plugins.kotlin.jvm)
  `maven-publish`
  signing
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  api(project(":guard-core-engine"))
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.serialization.json)
  api(libs.lettuce.core)
  api(platform(libs.netty.bom))
  api(libs.maxmind.db)
  api(libs.slf4j.api)

  testImplementation(libs.kotlin.test)
}

// --- Publishing (Maven Central via the Central Portal; see docs/release.md) --
//
// The release workflow publishes this module's staging bundle to the Portal
// Publisher API, after the guard-core-engine deployment (engine-before-facade).
// Locally the rehearsal uses publishToMavenLocal; signing activates only when
// the GPG secrets are present so the local rehearsal needs no key material.

val sourcesJar by
    tasks.registering(Jar::class) {
      archiveClassifier = "sources"
      from(sourceSets["main"].allSource)
    }

// The javadoc jar carries the Dokka HTML rendering of the KDoc surface (the
// standard javadoc task renders nothing for Kotlin-only sources, and the
// Portal validator rejects empty javadoc jars).
val javadocJar by
    tasks.registering(Jar::class) {
      archiveClassifier = "javadoc"
      from(tasks.named("dokkaGeneratePublicationHtml"))
      from(rootProject.file("README.md"))
    }

publishing {
  publications {
    create<MavenPublication>("maven") {
      groupId = project.group.toString()
      artifactId = project.name
      version = project.version.toString()

      from(components["java"])
      artifact(sourcesJar)
      artifact(javadocJar)

      pom {
        name = "guard-core"
        description =
            "The Guard engine facade for the JVM: config, security-check pipeline, " +
                "handlers, protocols, and Java bridges over guard-core-engine " +
                "(Kotlin port of guard-core)."
        url = "https://github.com/Guard-Core/guard-core-jvm"

        licenses {
          license {
            name = "MIT License"
            url = "https://opensource.org/licenses/MIT"
          }
          license {
            name = "Apache License, Version 2.0"
            url = "https://www.apache.org/licenses/LICENSE-2.0"
            distribution = "repo"
          }
        }

        developers {
          developer {
            id = "rennf93"
            name = "Renzo Franceschini"
            email = "rennf93@guard-core.com"
            organization = "Guard-Core"
            organizationUrl = "https://github.com/Guard-Core"
          }
        }

        scm {
          connection = "scm:git:https://github.com/Guard-Core/guard-core-jvm.git"
          developerConnection = "scm:git:ssh://github.com/Guard-Core/guard-core-jvm.git"
          url = "https://github.com/Guard-Core/guard-core-jvm"
        }
      }
    }
  }

  repositories {
    maven {
      name = "CentralStaging"
      url = uri(layout.buildDirectory.dir("central-staging"))
    }
  }
}

signing {
  val signingKey = System.getenv("GPG_PRIVATE_KEY")
  val signingPassphrase = System.getenv("GPG_PASSPHRASE")
  if (signingKey != null && signingPassphrase != null) {
    useInMemoryPgpKeys(signingKey, signingPassphrase)
    sign(publishing.publications)
  }
}
