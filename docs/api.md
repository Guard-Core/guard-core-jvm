# API

The API reference is the KDoc surface of the two published artifacts,
generated with Dokka. The [facade](#facade-comguard-coreguard-core) is the
integration artifact; the [engine](#engine-comguard-coreguard-core-engine) is
the framework-free detection core.

Generate the HTML reference locally:

```bash
./gradlew :guard-core:dokkaGeneratePublicationHtml :guard-core-engine:dokkaGeneratePublicationHtml --no-daemon
```

## Facade (`com.guard-core:guard-core`)

Entry point and wiring (package `com.guardcore`):

- `GuardCore` - the facade middleware: construction over a `SecurityConfig`,
  lazy handler initialization, per-request `dispatch` through the 17-check
  pipeline, and the response path (behavioral return rules, metrics, security
  headers, CORS).
- `SecurityConfig` / `SecurityConfigBuilder` - the 129-field configuration
  ([Configuration](configuration.md)); construction and assignment run the
  reference's validator chain with byte-matched rejection messages.
- `DetectionResult` - the verdict type (threats, attack types, categories,
  scores).

Protocols (package `com.guardcore.protocols`, 8 files, the section 01
porting-contract equivalents): `RequestProtocol`, `ResponseProtocol`,
`MiddlewareProtocol` and the middleware surface protocols, `RedisProtocol`,
`GeoIpProtocol`, `CloudIpStoreProtocol`, `AgentProtocol`. Framework adapters
implement these; nothing in the facade imports a framework.

Handlers (package `com.guardcore.handlers`): `RedisManager`, `RateLimitManager`
(+ `ThresholdBans`), `IpBanManager` (+ bans/queries/migration), `IpInfoManager`,
`CloudManager` (+ fetchers, registry, IP stores), `SecurityHeadersManager`,
`CorsHandler`, `BehaviorTracker`, `DynamicRuleManager`, `SusPatternsRegistry`,
and the seams (`HandlerSeams`) that let adapters inject implementations.

Core (package `com.guardcore.core`): the 17 security checks in fixed order
(`checks`), the event bus with the guard-agent envelope and metrics (`events`),
initialization, behavioral processing, validation, responses, bypass, and
routing.

Decorators (package `com.guardcore.decorators`): `SecurityDecorator` with the
25 per-feature factories (rate limiting, access control, authentication,
content filtering, behavioral analysis, honeypot, and so on), 1:1 with the
reference's parameter surface.

Java bridges (package `com.guardcore.java`): `JavaBridges` exposes `xBlocking`
(the unasync analog) and `xFuture` variants next to the suspend-primary API so
Java-only consumers need no coroutine dependency.

## Engine (`com.guard-core:guard-core-engine`)

Package `com.guardcore.engine` (framework-free; `kotlin-stdlib` is its only
dependency):

- The PyRe layer: python-grammar fail-closed regex parser (sre AST), pattern
  translation + flag mapping, and python match semantics over
  `java.util.regex`.
- The ReDoS static-safety chain: 25 modules ported 1:1 (IntervalSet through
  CostArbiter), plus hard match deadlines via `DeadlineCharSequence` and the
  validation cache.
- The detection core: compiler, preprocessor, truncation, base64/encoding
  decoders, scan window, binary-prefix islands, semantic analyzer, monitor,
  and the python-unicode tables.
- SusPatterns: the 157-row pattern table (byte-identical with the reference),
  matchers per source context, and the registry.

The engine has no public configuration surface: the facade's `SecurityConfig`
drives it (the detection knobs are documented under
[Configuration](configuration.md)).
