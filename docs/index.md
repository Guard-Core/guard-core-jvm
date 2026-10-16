# guard-core-jvm

Kotlin/JVM port of the [guard-core](https://github.com/Guard-Core/guard-core)
engine: the framework-free detection engine, the facade artifact that adapters
integrate, and the conformance harness that proves behavior parity against the
guard-core spec 4.1.0 corpus.

- **Spec version targeted**: 4.1.0 (corpus regenerated at engine 4.3.2;
  provenance in the
  [conformance README](https://github.com/Guard-Core/guard-core-jvm/blob/master/conformance/README.md))
- **Parity status**: [every-feature matrix](every-feature-matrix.md) (880
  rows: 826 FULL / 54 IDIOMATIC / 0 PARTIAL / 0 MISSING) and the
  [jvm column of the spec section table](https://github.com/Guard-Core/guard-core/blob/master/specs/README.md#parity-matrix)
- **Mirror statement**: guard-core-jvm 4.4.1 mirrors
  [guard-core 4.4.1](https://github.com/Guard-Core/guard-core); versions move
  in lockstep
- **Maven group ID**: `com.guard-core` (Kotlin packages `com.guardcore.*`)

## The family

| Repo | Artifact | Role |
|---|---|---|
| [guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm) | `com.guard-core:guard-core-engine`, `com.guard-core:guard-core` | Engine + facade + conformance + benchmarks (this repo) |
| [spring-boot-guard](https://github.com/Guard-Core/spring-boot-guard) | `com.guard-core:spring-boot-guard` | Spring Boot 3.x adapter (servlet filter, `@Guard*` annotations) |
| [ktor-guard](https://github.com/Guard-Core/ktor-guard) | `com.guard-core:ktor-guard` | Ktor 3.x adapter (suspend-native server plugin) |
| [guard-agent-jvm](https://github.com/Guard-Core/guard-agent-jvm) | `com.guard-core:guard-agent-jvm` | Telemetry agent behind the facade's sink seam |

## Documentation map

- [Installation](installation.md) - supported runtimes, coordinates, Redis requirement
- [Configuration](configuration.md) - all 129 `SecurityConfig` fields with type, default, and effect
- [API](api.md) - public surface and the Dokka reference
- [Architecture](architecture.md) - module layout and how it maps to the spec sections
- [Detection](detection.md) - coverage taxonomy (verbatim category names) and the bounded-read detection limits
- [Adapters](adapters.md) - how the adapters consume the facade
- [Migration](migration.md) - versioning and mixed-version interop constraints
- [Release notes](release-notes.md) - the CHANGELOG

The KDoc API reference generates with Dokka (see [API](api.md)).
