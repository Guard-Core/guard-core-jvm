# Architecture

How the workspace maps to the guard-core behavioral spec sections. The
behavioral spec is normative for observable behavior; internal architecture is
free, and this page is where the JVM port's structure is documented.

## Module layout

```
guard-core-jvm/
├── guard-core-engine/        framework-free detection core (kotlin-stdlib only)
│   └── com.guardcore.engine  PyRe (parser/translation/semantics), redos chain,
│                             detection core, suspatterns tables
├── guard-core/               the facade (the adapter integration artifact)
│   └── com.guardcore         config, protocols, handlers, core, decorators, java bridges
├── guard-core-conformance/   the spec 4.1.0 corpus runner (unpublished)
└── guard-core-benchmark/     JMH cost-ceiling benchmarks (unpublished)
```

The engine/facade split mirrors guard-core-rs (framework-free crate + facade)
and guard-core-go (single-package engine): nothing in `guard-core-engine`
imports coroutines, Lettuce, or any framework, so the detection core can be
embedded with no transport dependencies at all.

## Mapping to the spec sections

| Spec section | JVM surface |
|---|---|
| 01 contract | `com.guardcore.protocols` (request, response, middleware, bounded reads; 8 files, 1:1 with `protocols/`) |
| 02 config | `com.guardcore.config.SecurityConfig` + `ConfigFieldRegistry` (129 fields, field-for-field) |
| 03 pipeline | `com.guardcore.core.checks` (17 checks, fixed order) |
| 04 detection | `com.guardcore.engine` (PyRe layer, deadline pools, monitor) |
| 05 content pipeline | `com.guardcore.engine` (decode chain, scan window, truncation, semantic analyzer) |
| 06 suspatterns | `com.guardcore.engine` (157-row table, matchers) + `handlers.SusPatternsRegistry` |
| 07 rate limiting | `handlers.RateLimitManager` + `RateLimitScript` + `ThresholdBans` (Redis Lua byte-exact) |
| 08 redis schema | `handlers.RedisManager` (Lettuce; keys/prefixes byte-exact, interop-tested) |
| 09 ip bans | `handlers.IpBanManager` + bans/queries/migration |
| 10 cloud/geo | `handlers.CloudManager` + fetchers/registry + `IpInfoManager` (MaxMind) |
| 11 responses/headers | `core.responses` + `handlers.SecurityHeadersManager` + `CorsHandler` |
| 12 behavior/events | `core.behavioral` + `handlers.BehaviorTracker` + `core.events` (bus, envelope, metrics) |

## The async model

The reference is asyncio-based; the JVM port is coroutine-based. `suspend`
functions map 1:1 to the asyncio source; blocking scan pools (spec section 04)
map to dedicated dispatchers with bounded parallelism; and the facade exposes
Java-idiomatic entry points (`xBlocking` for blocking callers, `xFuture` for
`CompletableFuture` consumers) - the unasync sync-mirror analog, confined to
entry points. These are idiom mappings, not omissions: the
[every-feature matrix](every-feature-matrix.md) classifies each as IDIOMATIC
with the reference anchor.

## Regex engine and ReDoS posture

`java.util.regex` (backtracking, semantics close to Python `re`), with the
Go posture layered on top: hard match deadlines via `DeadlineCharSequence`
(the MatchTimeout analog), the full static-safety chain (25 `_redos_*`
modules, cost arbiter, fail-closed strays), and the pattern ledger
(`conformance/`, 158 entries, every corpus pattern compiling as-is or carrying
a corpus-verified translation; a pattern with neither fails CI).

## Conformance and gates

`guard-core-conformance` runs the vendored corpus (byte-identical fixtures,
regenerated from the reference engine, never hand-written). The
`fullCorpusGate` task pins the totals (375 cases + 9 cost budgets): a red
suite blocks merge, a growing ledger is red, and a listed cost workload that
returns under ceiling also fails (fail-closed xfail manifests). See the
[conformance README](https://github.com/Guard-Core/guard-core-jvm/blob/master/conformance/README.md).
