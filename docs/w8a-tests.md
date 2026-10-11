# W8a: the G-13 remainder test surface

Wave 8a lands the last code-bearing item of the JVM family campaign before
release engineering: the deferred python test surface from KNOWN_GAPS G-13
(the W4b/W5 remainder list, ~4,310 reference LOC under tests/test_core plus
the rate-limit primitive halves). Tests only; no engine behavior change
unless a port exposed a genuine divergence (three did - see the fixes
section). Full build green; full corpus gate unchanged at 375 cases + 9
budget workloads, 0 failing, 8 ledgered; pipeline 35/35, events 39, redis
14, detect 193 all untouched.

## File-by-file port table

| python file | kotlin test file | python tests | JVM tests | status |
|---|---|---|---|---|
| tests/test_core/test_edge_cases.py | guard-core/src/test/kotlin/com/guardcore/core/EdgeCasesTest.kt | 12 | 12 | ported (3 halves documented python-mock-only, see below) |
| tests/test_core/test_ip_security_global_route_merge.py | guard-core/src/test/kotlin/com/guardcore/core/IpSecurityGlobalRouteMergeTest.kt | 20 | 20 | ported 1:1 |
| tests/test_core/test_pipeline_route_config_revision.py | guard-core/src/test/kotlin/com/guardcore/core/PipelineRouteConfigRevisionTest.kt | 10 | 10 | ported 1:1 |
| tests/test_core/test_initialization.py | guard-core/src/test/kotlin/com/guardcore/core/InitializationTest.kt | 25 | 38 | ported (parametrized halves expanded; dynamic-rule-manager class-patch observations documented) |
| tests/test_core/test_escalate_identity_violation.py | guard-core/src/test/kotlin/com/guardcore/core/EscalateIdentityViolationTest.kt | 23 | 24 | ported (muted-log half carries an unmuted contrast; uncategorized fallback documented) |
| tests/test_core/test_block_vs_ban_escalation.py | guard-core/src/test/kotlin/com/guardcore/core/BlockVsBanEscalationTest.kt | 19 | 21 | ported (private-step halves reached through check() with the deciding config attached) |
| tests/test_core/test_check_rate_limit_by_ip.py (handler-side halves) | guard-core/src/test/kotlin/com/guardcore/handlers/CheckRateLimitByIpHalvesTest.kt | 16 remaining | 14 | ported (first halves landed W3 in RateLimitManagerTest) |
| tests/test_core/test_check_rate_limit_by_ip_autoban.py (handler-side halves) | guard-core/src/test/kotlin/com/guardcore/handlers/CheckRateLimitByIpAutobanHalvesTest.kt | 4 remaining | 4 | ported (first halves landed W3) |

Totals: 143 new JUnit tests; guard-core module 694 tests green.

## Divergences found by the port (fixed byte-exact, the W4b/W5 precedent)

1. `util/DetectionScan.kt` fallbackPatternCheck caught `Exception` per
   pattern; the reference catches ONLY RecursionError
   (detection_scan.py:216-222), logs the redacted pattern source, and
   continues. The JVM recursion analog (StackOverflowError) is an Error the
   catch-all never saw, and real exceptions were over-swallowed. Now catches
   StackOverflowError only, with the reference warning text. Regression:
   EdgeCasesTest.fallbackPatternCheckRecursionErrorIsLoggedAndSkipped drives
   a real StackOverflowError through a crafted engine table row on a
   bounded-stack thread.
2. `util/DetectionScan.kt` checkValueEnhanced routed every engine failure
   into the fallback branch; the reference re-raises RecursionError ahead of
   the generic handler (detection_scan.py:337-339). The engine pool delivers
   worker failures as ExecutionException, so the unwrap now rethrows a
   StackOverflowError cause ahead of the fallback. Regression:
   EdgeCasesTest.recursionClassFailureEscapesTheEnhancedFailureFallback pins
   the delivery shape and the fallback-layer catch.
3. `decorators/RouteConfig.kt` shipped the tracked-container PORTS
   (TrackedList/TrackedMap/TrackedSet) without wiring them into the tracked
   fields, so IN-PLACE mutation of custom_validators, required_headers,
   blocked_user_agents, block_cloud_providers (and the assigned
   require_referrer/allowed_content_types/time_restrictions/geo_rate_limits
   payloads) never bumped the route-config revision - the exact rebuild
   trigger the revision system exists for (route_config.py:265-302). Now
   wired at construction with wrap-on-assignment setters. Regression:
   PipelineRouteConfigRevisionTest (the whole file exercises it).

## Seam mapping notes (python mocks to JVM real seams)

- The detection verdicts the python files fake with
  `monkeypatch.setattr(...detect_penetration_patterns...)` are produced by
  the real engine: the payload rides the request path, so the counted
  threat categories ARE the engine's own output (xss / sqli).
- The ban mocks are the established `IpBanManager.banIpOverride`
  record-then-throw fault-injection seam (the AsyncMock(side_effect=...)
  shape); dropped after every test that installs it (AfterEach) and at every
  reset (resetCoreBanState), so it never intercepts real bans in later
  classes.
- The failing loggers subclass java.util.logging.Logger the way the python
  MagicMock loggers do (counting severe logs, optionally throwing); the
  failing event buses are protocol fakes selective on event_type.
- The capacity halves run at the production caps (10,000) over prefilled
  maps/stores, since the python caps are module constants the tests shrink
  by monkeypatch.
- The init tests drive the real singletons with recording protocol fakes
  (counting redis, counting geo handler, bare objects for the duck-typing
  halves) and assert the composite-sink fan-out through the managers' public
  handler fields; the get_initialization_status reflection branch uses a
  top-level class for the reflective getStatus probe.

## Documented python-mock-only halves (no JVM-producible analog)

- The uncategorized fallback label (a threat verdict with no categories is
  unreachable through the real engine, where every is_threat verdict carries
  at least one threat).
- The empty-threats verdict in _check_value_enhanced (same reachability
  argument) - the quadruple shape is pinned on the real threat path.
- The non-recursion engine failure injection in the fallback scan (the
  per-pattern check is total on real inputs; the catch is StackOverflowError
  -only, which carries the python contract).
- The dynamic-rule-manager class-patch observations (the manager is
  constructed and wired inside the initializer; the JVM tests assert the
  completion and warning surfaces).

## Gates

- `./gradlew build` green (694 guard-core tests + engine + conformance).
- `:guard-core-conformance:fullCorpusGate` green: TOTAL 375 cases + 9 budget
  workloads, 0 failing, 8 ledgered - the pinned totals identical to W5.
