<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Kotlin/JVM port of the [guard-core](https://github.com/Guard-Core/guard-core) engine: the framework-free engine artifact, the facade, and the conformance harness behind the JVM adapter family (spring-boot-guard, ktor-guard, guard-agent-jvm).</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/docs.yml/badge.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-jvm/blob/master/LICENSE-APACHE">
        <img src="https://img.shields.io/badge/License-Apache_2.0%20%2B%20MIT-blue.svg" alt="License Apache-2.0 + MIT">
    </a>
    <img src="https://img.shields.io/badge/version-4.3.2-0080ff.svg" alt="Version 4.3.2">
</p>

___

## Status

**Certified, pre-release.** Full parity is certified against the guard-core
spec 4.1.0 corpus and the every-feature matrix (see
[Conformance](#conformance)); the artifacts ship to Maven Central with the
first synchronized release, on explicit operator go
([docs/release.md](docs/release.md)). Until then nothing is published: build
from source or consume the composite as described below.

**Mirror statement:** guard-core-jvm 4.3.2 mirrors the
[guard-core 4.3.2](https://github.com/Guard-Core/guard-core) release. Versions
move in lockstep, and the conformance corpus records the exact engine commit
it was regenerated at (see
[conformance/README.md](conformance/README.md) for provenance). The Maven
group ID is `com.guard-core` (the Central Portal namespace; it reverses to
guard-core.com). Kotlin/JVM packages stay `com.guardcore.*` (hyphens are
illegal in package names; the groupId/package mismatch is standard for
hyphenated domains).

## Modules

| Module | Path | Artifact | Contents |
|---|---|---|---|
| Engine | `guard-core-engine/` | `com.guard-core:guard-core-engine:4.3.2` | Framework-free detection core, `kotlin-stdlib` only (no coroutines, no redis, no frameworks): the PyRe layer (python-grammar fail-closed regex parser, translation + flag mapping + match semantics over `java.util.regex`), the full 25-module ReDoS static-safety chain (IntervalSet through CostArbiter) with hard match deadlines via `DeadlineCharSequence`, the semantic analyzer and monitor, and SusPatterns (157-row pattern table, matchers, file-upload/template/shell/ldap/xml-xxe/pickle sources) |
| Facade | `guard-core/` | `com.guard-core:guard-core:4.3.2` | The single integration artifact: `SecurityConfig` (129 fields, field-for-field with the reference, byte-matched rejection messages), the 17-check pipeline in the reference's fixed order, the handler set (Redis/Lettuce rate limiting + bans, IP bans, cloud providers, GeoIP, security headers, CORS, behavioral tracking, dynamic rules), the event bus with the guard-agent envelope, 25 decorator factories, and the Java bridges (suspend primary, `xBlocking` and `xFuture` variants for Java-only consumers) |
| Conformance | `guard-core-conformance/` | unpublished | The spec 4.1.0 corpus runner: the full-corpus gate runs all 21 vendored suites (375 cases) plus 9 self-relative cost budgets in one command, fail-closed on totals |
| Benchmark | `guard-core-benchmark/` | unpublished | JMH cost-ceiling benchmarks backing the corpus budgets (all workloads run 5.7-16x under ceiling at certification) |

## Quick start (library consumers)

The engine is not wired into a framework by hand. Use an adapter:

- **Spring Boot 3.x**: [spring-boot-guard](https://github.com/Guard-Core/spring-boot-guard) - add the dependency and your `guard.*` properties; `GuardSecurityAutoConfiguration` wires the pipeline as a servlet filter, with `@GuardRateLimit`, `@GuardBypass`, and 23 more annotations for per-route config.
- **Ktor 3.x**: [ktor-guard](https://github.com/Guard-Core/ktor-guard) - `install(GuardCore) { config = ... }` plus `GuardRouteDecorator` per-route config, suspend-native.
- **Telemetry**: [guard-agent-jvm](https://github.com/Guard-Core/guard-agent-jvm) - the buffering/transport agent behind the facade's sink seam.

Once the first release is on Maven Central, the coordinates are:

```kotlin
dependencies {
    implementation("com.guard-core:spring-boot-guard:1.0.0") // adapter of your choice
    // or the facade directly:
    implementation("com.guard-core:guard-core:4.3.2")
}
```

## Building from source

```bash
git clone https://github.com/Guard-Core/guard-core-jvm.git
cd guard-core-jvm
./gradlew build --no-daemon
```

JDK 17 (Gradle JVM toolchain), Kotlin 2.4.21, Gradle 9.8.1 (wrapper-pinned).
Quality gates wired into `check`: detekt and Spotless (`ktfmt`); the
dependency vulnerability audit (`osv-scanner` over the committed
`gradle.lockfile` state, a job in CI) fails on any known CVE in the resolved
graph.

## Conformance

The `conformance/guard-core-spec-4.1.0/cases/` directory vendors the shared
adversarial corpus byte-identical from the guard-core specs/fixtures, generated
by the reference engine and never hand-written. One command runs the gate:

```bash
./gradlew :guard-core-conformance:fullCorpusGate --no-daemon
```

Certification state: 375 cases + 9 cost budgets, 0 failing, 8 ledgered entries
(2 event reason-string shapes at the TS divergence class, 6 pattern-safety
timing facts at the RS class). The pattern ledger holds 158 entries, all
compiling as-is under `java.util.regex`. See
[conformance/README.md](conformance/README.md) for the runner map,
[docs/every-feature-matrix.md](docs/every-feature-matrix.md) for the 880-row
feature matrix (826 FULL / 54 IDIOMATIC / 0 PARTIAL / 0 MISSING), and the
[jvm column of the spec section table](https://github.com/Guard-Core/guard-core/blob/master/specs/README.md#parity-matrix)
for the family-level status. The targeted spec version is 4.1.0.

## Documentation

The docs tree lives in [docs/](docs/) (start at
[docs/index.md](docs/index.md)): installation, the full 129-field
configuration reference, the API surface, architecture, detection coverage and
limits, adapters, and migration notes. The KDoc API reference generates with
Dokka:

```bash
./gradlew :guard-core:dokkaGeneratePublicationHtml :guard-core-engine:dokkaGeneratePublicationHtml --no-daemon
```

## License

Dual licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
