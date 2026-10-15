# Adapters

The adapters implement the facade protocols for their framework's native
request/response types and contain no security logic of their own: every
decision is the engine's, and every adapter drives the same 17-check
pipeline, byte-exact response factory, and per-route decorator resolution.

| Adapter | Repo | Envelope | Idiom |
|---|---|---|---|
| spring-boot-guard | [Guard-Core/spring-boot-guard](https://github.com/Guard-Core/spring-boot-guard) | Spring Boot 3.x (WebMVC servlet filter, pre-routing so unmatched paths are also enveloped) | `GuardFilter` + `@Guard*` annotations (25 decorator factories), `guard.*` properties binding all 129 `SecurityConfig` fields (object-typed fields through `SecurityConfigCustomizer` beans) |
| ktor-guard | [Guard-Core/ktor-guard](https://github.com/Guard-Core/ktor-guard) | Ktor 3.x (custom plugin hook at the Plugins phase for the required short-circuit; response side on `ResponseBodyReadyForSend`) | `install(GuardCore)` + `GuardRouteDecorator`, suspend-native |
| guard-agent-jvm | [Guard-Core/guard-agent-jvm](https://github.com/Guard-Core/guard-agent-jvm) | Telemetry sidecar behind the facade's `AgentProtocol` sink seam | buffering, transport, circuit breaker, Redis persistence, AES-GCM + HMAC signing, redaction, dynamic rules |

## Versioning

The engine and facade mirror guard-core releases (4.4.0). The adapters start
a fresh family version at 1.0.0 and pin the engine artifact version; the
agent mirrors guard-agent (3.2.3). In CI, the adapters run against the
engine at a pinned ref (the `ecosystem-gate` workflow in this repo runs both
adapters' suites on every engine PR and master push), and the pins move to
the released engine tag at train time.

## Writing a new adapter

1. Implement the protocols in `com.guardcore.protocols` for the native
   request/response types: request surface (headers, path, method, client
   IP, bounded body read), response surface (status, headers, tee-able body
   for behavioral return patterns), and the middleware protocol.
2. Drive `GuardCore` (the facade middleware) per request; short-circuit on a
   block response before the handler runs; run the response path after it.
3. Surface the decorator factories in the framework's idiom (annotations,
   plugins, interceptors - syntax, not substitutes).
4. Re-export `SecurityConfig` and the user-facing types from the adapter
   package (the `guard/__init__.py` convention): consumers import from the
   adapter, never from the engine coordinates directly.
