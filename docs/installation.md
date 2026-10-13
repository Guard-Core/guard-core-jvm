# Installation

## Supported runtimes

- **JDK 17 or newer** (the build pins the JVM toolchain to 17; adapters test
  on 17). Spring Boot 3.x and Ktor 3.x both require Java 17+, so the family
  baseline is 17.
- **Kotlin**: artifacts are consumed from Java or Kotlin; the facade exposes
  suspend-primary APIs with blocking (`xBlocking`) and `CompletableFuture`
  (`xFuture`) bridges for Java-only consumers.

## Coordinates

Maven Central:

```kotlin
dependencies {
    // the facade: one artifact with config, pipeline, handlers, protocols
    implementation("com.guard-core:guard-core:4.3.3")
    // framework-free detection engine only (no coroutines/redis deps)
    implementation("com.guard-core:guard-core-engine:4.3.3")
}
```

The group ID is `com.guard-core` (the Central Portal namespace; it reverses
to guard-core.com). Kotlin packages stay `com.guardcore.*` (hyphens are
illegal in package names; the groupId/package mismatch is standard for
hyphenated domains).

The facade pins netty through `io.netty:netty-bom` (4.1.139.Final, above the version lettuce-core 6.8.2 declares). Gradle builds apply that pin automatically from the published module metadata. Maven does not inherit a dependency's `dependencyManagement`, so in a Maven build, import the same BOM in your own `dependencyManagement` to get the patched netty. Maven applies the first management entry it finds for a module, so place the netty BOM import before any other BOM that manages netty, such as the Spring Boot BOM.

Adapters normally consume the adapter artifact, not the facade directly:

```kotlin
implementation("com.guard-core:spring-boot-guard:1.0.0") // Spring Boot 3.x
implementation("com.guard-core:ktor-guard:1.0.0")        // Ktor 3.x
```

## Building from source

```bash
git clone https://github.com/Guard-Core/guard-core-jvm.git
cd guard-core-jvm
./gradlew build --no-daemon
```

## Redis requirement

Distributed features (shared rate limiting, IP bans, behavioral state) need a
Redis 6+ server configured through `redis_url` (default
`redis://localhost:6379`). Set `enable_redis = false` to run without Redis:
all state is per-process. The conformance corpus's `redis_interop` suite
additionally asserts the Redis key schema byte-exact against a live server
(CI pins `redis:7-alpine`).

## Version catalog

All third-party pins live in `gradle/libs.versions.toml` and are locked:
`gradle.lockfile` per module is committed, and a dependency change without
`./gradlew --write-locks` fails the build (the supply-chain frozen-lock rule).
