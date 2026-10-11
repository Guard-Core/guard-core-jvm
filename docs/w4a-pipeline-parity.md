# W4a Pipeline Parity (guard-core-jvm)

Wave gate: the 17 pipeline checks in the reference's fixed order plus the core support modules,
gated by the vendored pipeline conformance suites (35 cases) in
`conformance/guard-core-spec-4.1.0/cases/`. Result: **35/35 GREEN**
(`PipelineConformanceTest.pipelineSuitesMatchCorpus`, no xfails), plus a 32-test core unit
surface. The runner is the JVM port of `specs/fixtures/tools/pipeline_harness.py`
(`guard-core-conformance/src/main/kotlin/com/guardcore/conformance/PipelineHarness.kt`),
driving the real fixed-order pipeline and the real response factory in-process over harness
stubs, comparing per the index.json `pipeline_records` rule (only the keys present in each
expected record; the recording bus observes `(event_type, action_taken)` pairs exactly like the
reference harness).

## Suite results

| suite | cases | result |
|---|---|---|
| pipeline_detection_response | 8 | GREEN |
| pipeline_ip_control | 12 | GREEN |
| pipeline_rate_limits | 5 | GREEN |
| pipeline_headers_cors | 7 | GREEN |
| pipeline_behavior_rules | 3 | GREEN |
| **total** | **35** | **GREEN (0 xfails)** |

## Module mapping (python -> kotlin, reference line anchors)

### checks/ (fixed order preserved; factory.py:30-48 is the order authority)

| python | kotlin | py LOC | kt LOC |
|---|---|---|---|
| `core/checks/base.py` (SecurityCheck base.py:14) | `core/checks/SecurityCheck.kt` | 88 | 85 |
| `core/checks/pipeline.py` (SecurityCheckPipeline pipeline.py:16) | `core/checks/SecurityCheckPipeline.kt` | 221 | 245 |
| `core/checks/helpers.py` (helpers.py:32-544) | `core/checks/ChecksHelpers.kt` (G-9 fold: ThresholdBans.kt deleted; resolveAndApplyThresholdBan = helpers.py:375) | 544 | 642 |
| `core/checks/factory.py` (DEFAULT_CHECK_CLASSES factory.py:30, build_default_pipeline factory.py:86) | `core/checks/ChecksFactory.kt` | 97 | 110 |
| `core/checks/_verifier.py` (resolve_verifier_result _verifier.py:7) | `core/checks/Verifier.kt` | 8 | 29 |
| `core/checks/implementations/route_config.py` (:12) | `core/checks/implementations/RouteConfigCheck.kt` | 61 | 75 |
| `core/checks/implementations/emergency_mode.py` (:13) | `core/checks/implementations/EmergencyModeCheck.kt` | 93 | 106 |
| `core/checks/implementations/https_enforcement.py` (:11) | `core/checks/implementations/HttpsEnforcementCheck.kt` | 77 | 99 |
| `core/checks/implementations/request_logging.py` (:11) | `core/checks/implementations/RequestLoggingCheck.kt` | 35 | 46 |
| `core/checks/implementations/request_size_content.py` (:14) | `core/checks/implementations/RequestSizeContentCheck.kt` | 141 | 153 |
| `core/checks/implementations/required_headers.py` (:26; _classify_header_violation :16) | `core/checks/implementations/RequiredHeadersCheck.kt` | 111 | 122 |
| `core/checks/implementations/authentication.py` (:19) | `core/checks/implementations/AuthenticationCheck.kt` | 155 | 159 |
| `core/checks/implementations/referrer.py` (:18) | `core/checks/implementations/ReferrerCheck.kt` | 125 | 141 |
| `core/checks/implementations/custom_validators.py` (:13) | `core/checks/implementations/CustomValidatorsCheck.kt` | 67 | 92 |
| `core/checks/implementations/time_window.py` (:18) | `core/checks/implementations/TimeWindowCheck.kt` | 92 | 109 |
| `core/checks/implementations/cloud_ip_refresh.py` (:16) | `core/checks/implementations/CloudIpRefreshCheck.kt` | 61 | 72 |
| `core/checks/implementations/ip_security.py` (:78; helpers :24-75) | `core/checks/implementations/IpSecurityCheck.kt` | 323 | 337 |
| `core/checks/implementations/cloud_provider.py` (:20) | `core/checks/implementations/CloudProviderCheck.kt` | 125 | 135 |
| `core/checks/implementations/user_agent.py` (:26) | `core/checks/implementations/UserAgentCheck.kt` | 129 | 129 |
| `core/checks/implementations/rate_limit.py` (:42; module fns :26-39) | `core/checks/implementations/RateLimitCheck.kt` | 322 | 338 |
| `core/checks/implementations/suspicious_activity.py` (:25) | `core/checks/implementations/SuspiciousActivityCheck.kt` | 182 | 187 |
| `core/checks/implementations/custom_request.py` (:11) | `core/checks/implementations/CustomRequestCheck.kt` | 52 | 64 |

Check-name values are byte-exact against `core/events/event_types.py:102-122`
(`EventTypes.CHECK_NAME_VALUES`).

### Core support modules (context-object DI preserved)

| python | kotlin | py LOC | kt LOC |
|---|---|---|---|
| `core/responses/context.py` (:10) + `core/responses/factory.py` (:13) | `core/responses/ErrorResponseFactory.kt` (ResponseContext + ErrorResponseFactory) | 179 | 179 |
| `core/routing/context.py` (:7) + `core/routing/resolver.py` (:6) | `core/routing/RouteConfigResolver.kt` (RoutingContext + RouteConfigResolver) | 53 | 62 |
| `core/validation/context.py` (:7) + `core/validation/validator.py` (:18) | `core/validation/RequestValidator.kt` (ValidationContext + RequestValidator; path_matching.py already landed as W1 `util/PathMatching.kt`) | 101 | 147 |
| `core/bypass/context.py` (:9) + `core/bypass/handler.py` (:36) | `core/bypass/BypassHandler.kt` (BypassContext + BypassHandler) | 125 | 138 |
| `core/behavioral/context.py` (:10) + `core/behavioral/processor.py` (:12) | `core/behavioral/BehavioralProcessor.kt` (BehavioralContext + BehavioralProcessor) | 240 | 286 |
| `core/initialization/handler_initializer.py` (:15) + `_handler_initializer_steps.py` (:12) | `core/initialization/HandlerInitializer.kt` | 385 | 494 |
| `detection_result.py` (:5) | `DetectionResult.kt` | 13 | 13 |

### Events slice (the W4a real-minimum bus; remainder is G-11/W4b)

| python | kotlin | py LOC | kt LOC |
|---|---|---|---|
| `core/events/event_types.py` (constants :5-43, EventFilter :135) | `core/events/EventTypes.kt` (EventTypes + EventFilter; vocab sets/enrichment keys close with W4b) | 144 | 87 |
| `core/events/middleware_events.py` (:26) | `core/events/SecurityEventBus.kt` | 198 | 212 |
| `core/events/metrics.py` (:16) | `core/events/MetricsCollector.kt` | 78 | 101 |
| `core/events/composite_handler.py` (:11) | `core/events/CompositeAgentHandler.kt` (+ AgentTelemetryMember/SinkTelemetryMember) | 112 | 172 |

### G-7a..G-7d closure (the 8 _utils scan-caller modules)

| python | kotlin | py LOC | kt LOC |
|---|---|---|---|
| `_utils/detection_config.py` (:14-234) [G-7a] | `util/DetectionConfig.kt` | 234 | 216 |
| `_utils/detection_scan.py` (:19-442) [G-7b; budget contextvars] | `util/DetectionScan.kt` + `util/DetectionScanBudget.kt` (extends the W1 `util/DetectionScanContext.kt` depth-cap seam) | 442 | 295 + 168 |
| `_utils/body_json_scan.py` (:15-291) [G-7c] | `util/BodyJsonScan.kt` | 291 | 334 |
| `_utils/body_form_scan.py` (:12-201) [G-7c] | `util/BodyFormScan.kt` (multipart reader = focused email.parser port) | 201 | 327 |
| `_utils/body_content_scan.py` (:56-478) [G-7c] | `util/BodyContentScan.kt` | 478 | 492 |
| `_utils/embedded_json_scan.py` (:11-77) [G-7c] | `util/EmbeddedJsonScan.kt` | 77 | 81 |
| `_utils/detection_result_builders.py` (:5-43) [G-7d] | `util/DetectionResultBuilders.kt` | 43 | 57 |
| `_utils/penetration_detection.py` (:46-224) [G-7d] | `util/PenetrationDetection.kt` | 224 | 324 |

### Decorators surface the checks require

| python | kotlin | notes |
|---|---|---|
| `decorators/route_config.py` (:13-291) | `decorators/RouteConfig.kt` (RouteConfigRevision :17, TrackedList/Map/Set :33/:100/:147, RouteConfig :241) | revision bumps: container mutations bump through the tracked wrappers; scalar writes bump via `touch()` (the Kotlin idiom for `__setattr__`, route_config.py:280-291) |
| `decorators/base.py` (:61-247) | `decorators/BaseSecurityDecorator.kt` + `decorators/RouteConfigProvider.kt` | `_get_route_id` (base.py:84): the `__wrapped__` owner chain collapses to the JVM route key (method identity is naturally strong); capability comparison recorded in KNOWN_GAPS.md G-11 notes |

### Conformance runner

| python | kotlin |
|---|---|
| `specs/fixtures/tools/pipeline_harness.py` (harness:116-502) | `guard-core-conformance/.../PipelineHarness.kt` + `PipelineConformanceTest.kt` |

## Semantics pinned during the port

- Escalation checks read `request.state` attributes through the same names python uses
  (`route_config`, `client_ip`, `is_whitelisted`, `is_exempt`, `guard_exclusion_scoped`,
  `_guard_block_stash`, `_guard_detection_result_cache`); the state bag is
  `RequestState.getAttr/setAttr` (protocols/RequestProtocol.kt).
- `pipeline.execute` stamps `_guard_pipeline_start` with the monotonic clock and
  `AgentEvents.getPipelineResponseTime` reads it (agent_events.py:29 analog).
- The pipeline rebuild contract (pipeline.py:56-81): config revision + watched container sizes
  (`block_cloud_providers`, `blocked_user_agents`, `endpoint_rate_limits` = factory.py:50-54) +
  route-config revision token.
- `check_route_ip_access` (helpers.py:219) catches the invalid-IP `ValueError` as
  `ConfigValidationError` (the port's ValueError class); unknown identity with a whitelist
  configured denies (helpers.py:222-223).
- Suspicious-count increments run under a lock with the 10,000-IP LRU bound
  (helpers.py:27, :352-372).
- The harness stubs mirror pipeline_harness.py exactly: `_CaseInsensitiveHeaders` (:352) is the
  JVM `CaseInsensitiveHeaders`; `create_harness_error_response` (:295) applies the security
  headers through the real manager; the rate-limit singleton resets per case (:443-457).

## Test surface (this wave)

- `guard-core/src/test/kotlin/com/guardcore/core/` (32 tests):
  - PipelineTest: fixed order (factory.py:30), add/insert/remove/get_check_names/len
    (test_pipeline.py:155-219), first-block-wins, fail-open/fail-secure split
    (test_pipeline_fail_secure.py), exclusion-scoped enforcement
    (test_enforced_on_excluded_paths_attribute.py).
  - ChecksHelpersTest: ip list membership / country access / route ip access / credential
    extraction / referrer matching (test_helpers.py), threshold-ban resolution via the G-9 fold.
  - BypassRoutingValidatorTest: resolver (test_routing_resolver.py), route-config revision
    bumps, bypass passthrough + security bypass (test_bypass_handler.py), validator path
    exclusion event-once + trusted-proxy https (test_validator.py).
  - ResponseFactoryTest: test_response_factory.py including the W3-deferred response-factory
    halves of the rate-limit (429 custom body + Retry-After) and security-headers per-config
    tests.
  - RateLimitCheckHalvesTest: the W3-deferred RateLimitCheck halves - singleton isolation
    (test_rate_limit_singleton_isolation.py:42-86), autoban wiring (knob off / threshold crossing
    / passive mode / loopback refusal / enable_ip_banning off,
    test_rate_limit_autoban_wiring.py:56-190), endpoint-tier edge case.
- Conformance: PipelineConformanceTest (35 pipeline cases) + the W2 detect suites + redis_interop
  remain green.
