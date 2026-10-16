# Changelog

## [4.4.1] - 2026-10-16

guard-core-jvm 4.4.1 mirrors the guard-core 4.4.1 release and cuts the CPU cost of the scan time budget.

### Fixed

- The scan time budget charges CPU once per pass instead of once per pattern (#62, #63). `checkRegexPatterns` and the fallback scan read `ThreadMXBean.currentThreadCpuTime` twice per pattern check. `ScanTimeBudget` now reads the worker thread's CPU clock when a pass opens, charges it only when the 2 ms wall slice has elapsed, and makes a final charge when the pass closes. The slice starts with the request budget, so it spans every value of the request. `exhausted()` stays arithmetic only, and the fallback scan charges after each pattern like the reference. Measured detection CPU on a ~1.1 KB JSON-like body plus 10 headers: 14.7 ms to 10.4 ms.
- The performance monitor iterates the window directly under its lock instead of taking snapshot copies, computes the variance with a compensated sum and no list allocation, and skips the sanitized anomaly copy when no callback is registered (#62, #63).

### Changed

- `ScanTimeBudget` API (guard-core-engine): `currentCpuNanos()` and `record(cpuNanos)` are removed and replaced by `openPass()`, `sliceCheck()`, `charge()` and `closePass()`. The constructor takes optional `cpuClock` and `wallClock` parameters so tests can inject clocks. Code that called `currentCpuNanos()` and `record(...)` around its own scan loop must call `openPass()` before the loop, `sliceCheck()` after each pattern and `closePass()` after it.
- The release workflow publishes a tag only from green CI and can be re-driven by tag input (#61).

## [4.4.0] - 2026-10-15

guard-core-jvm 4.4.0 mirrors the guard-core 4.4.0 scan-budget release and carries the JVM agent telemetry fixes.

### Added

- `detectionMaxScanSeconds` (`detection_max_scan_seconds`, default 10.0, range 0.1 to 60): a per-request cap on regex scan time (guard-core #166, #167). It is measured in thread CPU time inside the scan worker, not wall time, so a loaded host does not flag benign requests. Exhausting it records a weighted `pattern_timeout` threat named `scan_time_budget_exhausted`, fails closed, and the trigger text names it when it tips the score.
- `excludedSemanticDetectionHeaders` (`excluded_semantic_detection_headers`, global, default empty) and `detectionExclusion(semanticHeaders = ...)` (route): header names that skip the semantic analyzer only, while regex scanning of those headers is unchanged (guard-core #166, #167).

### Fixed

- Empty whitelist: an empty global `whitelist` now means no whitelist, as `if config.whitelist:` does in the reference. Before, `whitelist = emptyList()` denied every client with a 403. The fix is in `AccessControl` (`checkWhitelist`, `checkIpListsDetail`, `checkUnknownIdentityAccess`).
- IP list precedence: a configured whitelist decides alone and the blacklist applies only without a whitelist, for the global and route checks, and a route whitelist skips the global lists. This already matched the reference and is now pinned by `IpListPrecedenceTest` with tables generated from the reference (120 rows for the global and route checks, 243 rows composing route and global lists).
- Client IP parity: client IP resolution is guarded by `ClientIpParityTest` (104 + 78 reference rows), which passes unchanged.
- The Cookie header is scanned one `name=value` pair at a time, each pair through the same header path and value budget, so the `;` between cookies no longer counts as a command separator in the semantic score (guard-core #161, #162).
- A header whose threats are all category-filtered no longer ends the request scan early: an SSRF value in an address header followed by an XSS header still flags (probe test `HeaderScanContinuesTest`).
- Passive-mode log lines keep the reason. A passive hit without trigger info now logs `[PASSIVE MODE] Suspicious activity detected from ... - Reason: ...` instead of the penetration wording with the reason dropped (guard-core #164, #165). If you match on the old passive log text, update the match.
- Agent telemetry: an injected agent was never started and received no events, and metrics reached agents as blank security events. See the Changed entries on agent wiring and metrics below.
- Dynamic rules: each rule version now applies over the base config instead of over the previous version's result (`DynamicRuleManager.applyRules`, `_apply_rules` in guard-core #169). The active base snapshot is restored first, so the emergency auto-ban halving no longer compounds (16 went 8, 4, 2 across versions 1 to 3, and now stays 8), a change from an earlier version no longer lingers when a later version omits it, and expiry restores the true base. A failed apply restores the config as it was before the call, so the previously active version keeps running. Snapshot and restore copy collection values (`deepcopy` in the reference). `suspiciousPatterns` the registry already holds are skipped instead of re-added on every version.

### Changed

- Behavior to know before upgrading: a dynamic rule version no longer carries over the previous version's changes, so a field the new version does not set returns to the base value and rules that relied on stacking versions must set every field they want. A request that spends `detectionMaxScanSeconds` of regex CPU time is flagged with a `pattern_timeout` threat instead of being scanned to the end.
- Agent wiring: `HandlerInitializer.buildCompositeHandler()` now adds any injected agent handler to the composite, as `handler_initializer.py:87-105` does. An `AgentTelemetryMember` (the `GuardAgentTelemetry` bridge) is used directly, a `HandlerAgentSink` goes through `SinkTelemetryMember`, and a plain `AgentHandlerProtocol` goes through the new `ProtocolTelemetryMember`. Before, only a `HandlerAgentSink` was composed, so the protocol-typed agent the adapters inject was never started and received no events.
- Metrics: `MetricsCollector` now calls `sendMetric` (`metrics.py:45`) instead of `sendEvent`. `HandlerAgentSink` gains `sendMetric` (default: `sendEvent`, so existing sinks keep their behavior), `SinkTelemetryMember.sendMetric` and the initializer's composite sink forward to it, and `CompositeAgentHandler.sendMetric` is now `open`. Before, metrics reached agents as blank security events.
- Dependencies: the facade pins netty to 4.1.139.Final through `api(platform(io.netty:netty-bom))`. lettuce-core 6.8.2 declares netty 4.1.125, which carries twelve advisories (GHSA-3qp7-7mw8-wx86, GHSA-558v-64gr-wgg4, GHSA-5pvg-856g-cp85, GHSA-676x-f7gg-47vc, GHSA-c4c3-7fpv-j4q5, GHSA-c653-97m9-rcg9, GHSA-cm33-6792-r9fm, GHSA-fccg-mwvh-qqg4, GHSA-mfg7-5gfp-c4w3, GHSA-mj4r-2hfc-f8p6, GHSA-x4gw-5cx5-pgmh, GHSA-xmv7-r254-6q78), all fixed by 4.1.137 at the latest. Their osv-scanner suppressions are removed. Gradle consumers get the pin from the module metadata; Maven consumers import the same BOM (docs/installation.md).
- The release workflow's registry check now names the facade artifact correctly in its log (`com.guard-core:guard-core`, not `guard-core-facade`). The URLs it checks were already right.
- The geo-IP agent adapter built in `initializeAgentForHandlers` now routes metrics to `sendMetric` (its composite sink forwards `sendMetric` too), and an injected agent that implements none of AgentTelemetryMember, HandlerAgentSink or AgentHandlerProtocol is logged as a warning instead of being dropped silently.

### Docs

- `enable_dynamic_rules` documentation lists exactly what a dynamic rule can change, the install sections point at Maven Central, and the mkdocs `site_url` is set so the sitemap and canonical links are generated.

## [4.3.3] - 2026-10-13

### Changed

- guard-core-jvm 4.3.3 mirrors the guard-core 4.3.3 parity release (lockstep version, no functional change); the corpus remains the 4.3.2-generation vendored set (behavior identical). The corpus index's `engine_version` pin stays 4.3.2: it tracks the corpus revision (the generating engine), not the release.
- The SusPatterns detection-state builder now keys the pattern validation cache on `GuardCoreEngine.VERSION` instead of a hardcoded literal (the facade's dynamic-rule manager already wired the constant; the cache version follows the release, matching the reference's engine-versioned cache key). No behavior change on any single version.
- Dependencies: lettuce-core 6.7.1.RELEASE -> 6.8.2.RELEASE (netty 4.1.118 -> 4.1.125) and slf4j-api 2.0.17 -> 2.0.20, with the lockfiles regenerated. The osv-scanner suppression GHSA-3p8m-j85q-pgmj is removed (fixed in netty 4.1.125); the other twelve netty suppressions still apply at 4.1.125 and stay.

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
