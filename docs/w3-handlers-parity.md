# W3 handlers parity (guard-core-jvm)

Wave 3 of the guard-core port: the remaining handler surface of the Python
reference (`guard_core/handlers/`) into the `guard-core` facade module, with
the handler test surface ported and green as the wave gate.

Reference scope: `guard_core/handlers/` is 10,353 LOC across 46 files
(measured 2026-10-10, specs/impl/jvm.md module map). The `_suspatterns_*`
family (4,414 LOC) landed engine-side in W2 and is out of W3 scope; the W3
handler scope is therefore ~5,875 reference LOC plus `scripts/rate_lua.py`
(19 LOC) and the models slice `DynamicRules`/`LastKnownRulesSnapshot`
(`guard_core/_dynamic_rules.py`, 124 LOC) that the dynamic-rule handler owns.

## Wave gate

- Handler test surface ported to JUnit: **307 tests** across 12 classes in
  `guard-core/src/test/kotlin/com/guardcore/handlers/`, all green.
- Redis key schema byte-exact per spec section 08: unit-asserted against the
  pinned key strings/TTLs and proven by the vendored `redis_interop` corpus
  (14/14 cases, `RedisInteropTest` in `guard-core-conformance`, run against a
  live Redis under the suite prefix).
- The live-Redis tests run under the conftest-identical isolation scheme
  (`test:guard_core:<pid>:<hex>:` prefix per run, HandlerTestSupport.kt).

## Handler-by-handler map

| python file | LOC | kotlin file | status |
|---|---|---|---|
| `handlers/redis_handler.py` | 368 | `handlers/RedisManager.kt` (RedisHandlerProtocol impl, lettuce ops at `LettuceRedisOperations`, url redaction `redactRedisUrl` at RedisManager.kt:692) | ported, tests green |
| `scripts/rate_lua.py` | 19 | `handlers/RateLimitScript.kt` (byte-exact Lua) | ported |
| `handlers/ratelimit_handler.py` | 576 | `handlers/RateLimitManager.kt` (module state `RateLimitState`, primitive `checkRateLimitByIp` at RateLimitManager.kt:264, manager at :380) | ported, tests green |
| `handlers/ipban_handler.py` | 77 | `handlers/IpBanManager.kt` (singleton + eviction counter + reset) | ported, tests green |
| `handlers/_ipban_bans.py` | 160 | `handlers/IpBanBans.kt` (banIp at IpBanBans.kt:196, self-DoS guard at :143) | ported, tests green |
| `handlers/_ipban_cache.py` | 23 | `handlers/TtlCache.kt` (cachetools TTLCache port, injectable `clock` = cachetools `timer`, eviction callback = `_ObservableTTLCache`) | ported, tests green |
| `handlers/_ipban_events.py` | 55 | `handlers/IpBanBans.kt` (IpBanEvents group, IpBanBans.kt:20-63) | ported, tests green |
| `handlers/_ipban_migration.py` | 65 | `handlers/IpBanMigration.kt` (legacy `::ffff:` key migration over SCAN/PTTL/PSETEX) | ported, tests green |
| `handlers/_ipban_queries.py` | 91 | `handlers/IpBanQueries.kt` (isIpBanned at IpBanQueries.kt:47) | ported, tests green |
| `handlers/security_headers_handler.py` | 129 | `handlers/SecurityHeadersManager.kt` (getHeaders at SecurityHeadersManager.kt:330, default header table at :68) | ported, tests green |
| `handlers/_security_headers_config.py` | 287 | `handlers/SecurityHeadersManager.kt` (config-method group :117-322) | ported, tests green |
| `handlers/_security_headers_cache.py` | 130 | `handlers/SecurityHeadersManager.kt` (cache group :393-497) | ported, tests green |
| `handlers/_security_headers_cors.py` | 99 | `handlers/SecurityHeadersManager.kt` (CORS group :502-576) | ported, tests green |
| `handlers/_security_headers_events.py` | 110 | `handlers/SecurityHeadersManager.kt` (events group :581-660) | ported, tests green |
| `handlers/cors_handler.py` | 169 | `handlers/CorsHandler.kt` (buildPreflightResponse at CorsHandler.kt:130) | ported, tests green |
| `handlers/cloud_handler.py` | 427 | `handlers/CloudManager.kt` (isCloudIp at CloudManager.kt:262, schedule_refresh single-flight at :100) | ported, tests green |
| `handlers/_cloud_provider_registry.py` | 47 | `handlers/CloudProviderRegistry.kt` | ported, tests green |
| `handlers/_cloud_provider_fetchers.py` | 134 | `handlers/CloudFetchers.kt` (java.net.http; same endpoints, 10s timeouts, CSV/JSON parsing) | ported |
| `handlers/_cloud_azure_fetch.py` | 198 | `handlers/CloudAzureFetch.kt` (trusted-host extraction, failover link, newest-date selection, no-redirect download) | ported |
| `handlers/cloud_ip_stores.py` | 72 | `handlers/CloudIpStores.kt` (InMemory + Redis `cloud_ip_v2` JSON store) | ported, tests green |
| `handlers/dynamic_rule_handler.py` | 277 | `handlers/DynamicRuleManager.kt` (manager + update loop + match_event + expiry) | ported, tests green |
| `handlers/_dynamic_rule_application.py` | 225 | `handlers/DynamicRuleManager.kt` (open member group under the `_dynamic_rule_application.py` banner, DynamicRuleManager.kt:313+) | ported, tests green |
| `handlers/_dynamic_rule_events.py` | 102 | `handlers/DynamicRuleEvents.kt` | ported, tests green |
| `handlers/_dynamic_rule_snapshot.py` | 142 | `handlers/DynamicRuleManager.kt` (hydration/persistence group, DynamicRuleManager.kt:600+) | ported, tests green |
| `handlers/_dynamic_rule_persistence.py` | 11 | `handlers/DynamicRuleManager.kt` (namespace constants, DynamicRuleManager.kt:24-25) | ported |
| `_dynamic_rules.py` (models slice) | 124 | `handlers/DynamicRules.kt` (model + `dumpLastKnownRulesSnapshot`/`loadLastKnownRulesSnapshot`, pydantic-exact JSON pinned against the interop case) | ported, tests green |
| `handlers/behavior_handler.py` | 191 | `handlers/BehaviorTracker.kt` (BehaviorRule, usage/return tracking, `config_to_rule`) | ported, tests green |
| `handlers/_behavior_action_dispatch.py` | 152 | `handlers/BehaviorActionDispatch.kt` | ported, tests green |
| `handlers/_behavior_response_pattern.py` | 90 | `handlers/BehaviorResponsePattern.kt` | ported, tests green |
| `handlers/_behavior_json_pattern.py` | 54 | `handlers/BehaviorResponsePattern.kt` (json-pattern group) | ported, tests green |
| `handlers/ipinfo_handler.py` | 339 | `handlers/IpInfoManager.kt` (GeoIPHandler impl; maxmind-db JVM reader; download retry/backoff; latin-1 Redis cache) | ported, tests green |
| `handlers/_suspatterns_registry.py` | 269 | `handlers/SusPatternsRegistry.kt` (W3 slice: add/remove pattern, `patterns:custom` Redis schema, restore-on-initialize, pattern_added/pattern_removed events; the compile/validate/detect surface is the W2 engine `SusPatternsManager`) | ported (W3 slice), tests green |
| `handlers/suspatterns_handler.py` | 1075 | engine-side from W2 (`com.guardcore.engine.suspatterns.SusPatternsManager.detect()`); the W3 registry surface above carries the handler's Redis/event/persistence behavior | engine-side (W2) + W3 slice |
| `handlers/__init__.py` | 64 | Kotlin package surface: every handler is a top-level type in `com.guardcore.handlers` (no lazy-import machinery needed) | structure mapping |
| `handlers/_suspatterns_*.py` (14 files) | 4,414 | engine-side from W2 | engine-side (W2) |

Support modules ported as part of the wave (python source in parentheses):
`handlers/ThresholdBans.kt` (`core/checks/helpers.py:375-411`
`_resolve_and_apply_threshold_ban`, the minimal real surface the rate-limit
auto-ban path needs, G-9), `handlers/DetectionScanRedaction.kt`
(`_utils/detection_scan.py:137-178`, the `_redact_pattern_source` slice with
the sensitive-name unions as registered seams), `handlers/PyJsonDumps.kt`
(CPython `json.dumps` + pydantic `model_dump_json` renderers, byte-exact
separators), `handlers/HandlerSeams.kt` (G-2/G-6 registration).

## Observable identifiers (byte-exact)

- Redis key schema (spec 08): `{prefix}rate_limit:rate:{ip}[:{sha256(path)}]`
  (zset, ttl window*2), `{prefix}banned_ips:{ip}` / `{prefix}banned_networks:{cidr}`
  (string ttl=duration), `{prefix}behavior_usage:behavior:usage:{h}:{h}` /
  `{prefix}behavior_returns:behavior:return:{h}:{h}:{h}` (zset, uuid4-hex
  members, ttl=window), `{prefix}security_headers:{csp_config,hsts_config,custom_headers}`
  (json, ttl 86400), `{prefix}patterns:custom` (comma-joined, persistent),
  `{prefix}ipinfo:database` (latin-1 blob, ttl=max_age),
  `{prefix}cloud_ranges_v2:{provider}` (sorted CSV, ttl),
  `{prefix}cloud_ip_v2:{provider}` (sorted-range JSON, persistent),
  `{prefix}dynamic_rules:last_known` (pydantic snapshot, persistent).
- Event type strings: every handler event uses `EventTypes` constants
  (`rate_limited`, `rate_limit_script_reloaded`, `redis_connection`,
  `redis_error`, `ip_banned`, `ip_unbanned`, `cloud_blocked`,
  `dynamic_rule_updated`, `dynamic_rule_applied`, `emergency_mode_activated`,
  `behavioral_violation`, `security_headers_applied`, `csp_violation`,
  `country_blocked`, `geo_lookup_failed`, `pattern_added`,
  `pattern_removed`) with the python handler names (`redis`, `rate_limit`,
  `ip_ban`, `cloud`, `dynamic_rules`, `behavior`, `security_headers`,
  `ipinfo`, `sus_patterns`).
- Header names/values: the security-headers default table, CORS response
  headers, and `Retry-After` are string-identical.
- Check name `rate_limit` for the rate-limit log_activity path.
- Rate-limit Lua script: byte-exact (`RateLimitScript.kt`), SCRIPT LOAD +
  NOSCRIPT reload recovery with the `rate_limit_script_reloaded` event.

## Test surface

| kotlin test class | tests | python source |
|---|---|---|
| RedisManagerTest | 30 | tests/test_redis/test_redis.py, test_redis_resilience.py |
| IpBanManagerTest | 38 | test_ipban_lifecycle.py, test_ipban_ttl.py, test_ipban_eviction.py, test_ipban_cidr.py |
| IpBanGuardAndRaceTest | 24 | test_ipban_loopback_guard.py, test_ipban_expiry_race.py |
| IpBanLegacyKeyMigrationTest | 11 | test_ipban_legacy_key_migration.py |
| RateLimitManagerTest + CheckRateLimitByIpTest + CheckRateLimitByIpAutobanTest + RateLimitSingletonIsolationTest | 38 | test_core/test_rate_limit_noscript.py, test_check_rate_limit_by_ip.py, test_check_rate_limit_by_ip_autoban.py, test_rate_limit_singleton_isolation.py, handler tests of test_rate_limit_edge_cases.py |
| SecurityHeadersTest (3 classes) | 32 | test_security_headers/ (validation, edge cases, csp, per-config, redis integration) |
| CorsHandlerTest | 20 | test_cors_handler.py |
| CloudTest (2 classes) | 36 | test_cloud_ip_stores.py, test_cloud_region_scope.py, store surface of test_cloud_ips |
| DynamicRuleManagerTest (2 classes) | 18 | test_dynamic_rule_atomicity.py, test_dynamic_rule_persistence.py |
| BehaviorAndIpInfoTest (2 classes) | 30 | test_behavior_rule_ban_duration.py, tracker/response-pattern ports, test_ipinfo core |
| HandlerEdgeCasesTest | 18 | handler-scope tests of test_handler_edge_cases.py |
| SusPatternsRegistryTest | 12 | _suspatterns_registry.py W3 surface |
| RedisInteropTest (conformance) | 14 cases | conformance/guard-core-spec-4.1.0/cases/redis_interop.json |

Total: 307 handler tests green + 14/14 redis_interop cases green.

Python tests NOT ported here (owned by later waves): the `RateLimitCheck`
middleware-check halves of test_rate_limit_edge_cases.py /
test_rate_limit_singleton_isolation.py (W4 pipeline surface), the response
factory halves of test_security_headers/test_per_config_isolation.py and
test_handler_edge_cases.py (W4 responses), the live HTTP fetcher halves of
test_cloud_ips (environment-bound network calls; the fetch parsing kernel is
ported and the fetch path is seam-scripted in the interop runner), and the
mock-heavy halves of test_ipinfo that stub the maxminddb reader with fixtures
(the JVM port uses the real maxmind-db reader; reader-bound behavior is
exercised through the corruption/redis-cache paths).

## Idiom mappings

- `redis.asyncio.Redis` -> Lettuce `StatefulRedisConnection` behind the
  `RedisOperations` interface; `pipeline(transaction=True)` -> MULTI/EXEC with
  per-command futures read in order. The redis-py client-level retry
  (`Retry(ExponentialBackoff(), retries)`, redis_handler.py:116) maps to the
  Lettuce reconnect/timeout options: transient failures surface as
  `GuardRedisError(503, ...)` after the timeout budget either way.
- `cachetools.TTLCache` -> `handlers/TtlCache.kt` (expiry-ordered eviction,
  lazy purge, injectable clock standing in for cachetools `timer`).
- `aiohttp.ClientSession` -> JDK `java.net.http.HttpClient` (no redirects on
  the Azure download path, matching `allow_redirects=False`).
- `maxminddb.open_database` -> `com.maxmind.db:maxmind-db` reader with a
  `@MaxMindDbConstructor` country record projection.
- Mixins -> one class per python module group with `internal`/open members;
  `_apply_blocking_rules` and the application steps are open members so the
  python test idiom of overriding a step to drive the rollback path ports
  verbatim (`ScriptedStepManager` in the tests).
- asyncio singletons (`__new__`-based) -> companion `getInstance` with
  `resetInstance()` test seams.
- `monkeypatch.setattr(manager, "ban_ip", fake)` -> assertions against the
  real ban store (local TTL cache expiry) since Kotlin extension dispatch is
  static; durations pinned below the 3600s local cache cap to keep the same
  distinguishing power.
- `asyncio.create_task` (ipinfo lookup-failure event) -> a manager-scope
  coroutine scope launch.

## Seams closed

- G-2: `ConfigSeams.geoIpHandlerFactory` now constructs the real
  `IpInfoManager` (`handlers/HandlerSeams.kt`, registered from the facade
  entry point and the tests; python resolves the same construction lazily
  inside `_security_config_geo_validators.py:69-94`).
- G-6: `AccessControl.cloudIpChecker` resolves through `CloudManager`'s
  `get_cloud_provider_details` (`handlers/HandlerSeams.kt`).
