# Changelog

## [4.3.3] - 2026-10-13

### Changed

- guard-core-jvm 4.3.3 mirrors the guard-core 4.3.3 parity release (lockstep version, no functional change); the corpus remains the 4.3.2-generation vendored set (behavior identical). The corpus index's `engine_version` pin stays 4.3.2: it tracks the corpus revision (the generating engine), not the release.
- The SusPatterns detection-state builder now keys the pattern validation cache on `GuardCoreEngine.VERSION` instead of a hardcoded literal (the facade's dynamic-rule manager already wired the constant; the cache version follows the release, matching the reference's engine-versioned cache key). No behavior change on any single version.

## [4.3.2] - 2026-10-10

### Added

- guard-core-jvm 4.3.2 is a mirror release of the guard-core 4.3.2 engine (same version number, same detection contract, lockstep with the reference implementation).
- Workspace scaffold with four Gradle modules (Kotlin DSL, JVM toolchain 17): guard-core-engine (framework-free, dependency-free placeholder), guard-core (facade with kotlinx-coroutines-core wiring), guard-core-conformance (corpus runner, unpublished), guard-core-benchmark (JMH, unpublished).
- Vendored spec 4.1.0 conformance corpus regenerated at engine 4.3.2 (commit 37b6a132): 21 suites plus index, byte-identical fixtures under conformance/guard-core-spec-4.1.0/cases/, smoke-tested via index assertions (spec version, engine version, suite count, cost budget k, fixed IP).
- Toolchain pins: JDK 17, Kotlin 2.4.21, Gradle 9.8.1 (wrapper), kotlinx-coroutines-core 1.11.0, kotlinx-serialization-json 1.11.0.
- CI gates: ci (wrapper validation, ./gradlew build), code-ql (kotlin), issue-link, plus the org-standard hygiene workflows (greetings, labeler, stale, summary, sync-labels).
- Quality gates wired into check: detekt (default config plus minimal detekt.yml) and Spotless with ktfmt; JaCoCo applied with no coverage gate yet (lands with real code in W1+).

### Changed

- Maven coordinates move to groupId `com.guard-core` (the Central Portal namespace; guardcore.com proved unverifiable and is not owned by the operator; nothing was ever published under `com.guardcore`). Kotlin/JVM packages stay `com.guardcore.*` (hyphens are illegal in JVM packages).
- Publishing surface (W8b): `maven-publish` + `signing` on the two published modules (guard-core-engine, guard-core) with sources/javadoc jars and the full Portal-required POM (licenses MIT + Apache-2.0, developers, scm), a CentralStaging local repository the release workflow zips and uploads to the Central Portal Publisher API, and `.github/workflows/release.yml` (tag gates + per-artifact existence check + Portal deployment, engine before facade). See docs/release.md and docs/release-rehearsal.md.
