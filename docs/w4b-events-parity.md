# W4b Events + Decorators + Bridges Parity (guard-core-jvm)

Wave 4b closed the events remainder (G-11), the decorators idiom closure with the route-id
collision study (G-12), the Java bridge surface, and the pipeline-rebuild/events halves of the
deeper test_core port (G-13, remainder re-scoped to W5). Gate: the vendored `event_stream`
corpus (39 cases, 38 pinning 47 real envelopes + 1 advisory) green through a real-pipeline
runner; 37 cases compare byte-exact and the 2 residual divergences are the TS family's
documented reason-string-shape class.

## Event surface (G-11)

Python reference: `guard_core/core/events/` (event_types.py, middleware_events.py,
composite_handler.py, enricher.py, metrics.py, otel_handler.py, logfire_handler.py).

| Python | JVM | Parity notes |
|---|---|---|
| event_types.py:5-44 event constants | core/events/EventTypes.kt:14-53 | verbatim strings; `config/EventTypes.kt` (W1) remains the muted-field validation copy |
| event_types.py:46-100 EVENT_TYPE_VALUES / METRIC_TYPE_VALUES | core/events/EventTypes.kt:55-105 | 39 event + 3 metric values |
| event_types.py:102-122 CHECK_NAME_VALUES | core/events/EventTypes.kt (W4a) | 17 check names |
| event_types.py:125-131 enrichment keys | core/events/EventTypes.kt:107-120 | 8 `guard.*` keys verbatim |
| event_types.py:135-144 EventFilter | core/events/EventTypes.kt:123-132 | muted set membership |
| middleware_events.py:26 SecurityEventBus | core/events/SecurityEventBus.kt:31 | agent_enable_events + filter gating (middleware_events.py:119-121) |
| middleware_events.py:40 _lookup_country | SecurityEventBus.lookupCountry:34 | warning + on_error hook, null country |
| middleware_events.py:56 _forward_trace_headers | SecurityEventBus.forwardTraceHeaders:46 | traceparent/tracestate fold |
| middleware_events.py:67 _build_event | SecurityEventBus.buildEvent:65 | full SecurityEvent field set (guard_agent/models.py:208) as the map envelope; middleware passes status_code/pattern_matched as null (middleware_events.py:82-109) |
| middleware_events.py:111 send_middleware_event | SecurityEventBus.sendMiddlewareEvent:127 | extract_client_ip carries the agent handler (middleware_events.py:125-127) so ip_extraction-seam events emit |
| middleware_events.py:137 send_https_violation_event | SecurityEventBus.sendHttpsViolationEvent:152 | require_https decorator branch (middleware_events.py:147-157) |
| middleware_events.py:168 send_cloud_detection_events | SecurityEventBus.sendCloudDetectionEvents:188 | handler event + decorator_violation branch |
| composite_handler.py:11 CompositeAgentHandler | core/events/CompositeAgentHandler.kt:44 | filter + enrichment before member fan-out (composite_handler.py:36-58); degraded/failed-handler semantics (composite_handler.py:67-76) |
| enricher.py:65-106 _THREAT_SCORE_MAP | core/events/EventEnricher.kt ThreatScorer:20 | 39-entry table + default 20 |
| enricher.py:111 ThreatScorer.score_for | EventEnricher.kt ThreatScorer.scoreFor | |
| enricher.py:117 EnrichmentContext | core/events/EventEnricher.kt:117 | config/agent/dynamic-rule/behavior tracker |
| enricher.py:125 EventEnricher.enrich_event | EventEnricher.enrichEvent:131 | identity + threat score + rule correlation + behavior correlation into the metadata bag |
| enricher.py:141 enrich_metric | EventEnricher.enrichMetric:150 | identity into the tags bag |
| enricher.py:150-191 appliers | EventEnricher.applyIdentity/applyThreatScore/applyRuleCorrelation/applyBehaviorCorrelation | sha256(ip\|service\|bucket)[:16] behavior key (enricher.py:188-191) |
| metrics.py:16 MetricsCollector | core/events/MetricsCollector.kt (W4a) | agent_enable_metrics gating (metrics.py:31-32) |
| otel_handler.py:50 OtelHandler | core/events/OtelHandler.kt:34 | the ImportError branch (otel_handler.py:27-38) is the default: absent SDK logs "opentelemetry-sdk not installed, OTEL handler disabled" (otel_handler.py:64) and health_check reports availability (otel_handler.py:229-230); span/attr/enrichment-forward/metric-dispatch logic ported over the OtelSurface seam; _otlp_signal_endpoint port (otel_handler.py:157-165) |
| logfire_handler.py:21 LogfireHandler | core/events/LogfireHandler.kt:32 | absent-SDK branch logs "logfire not installed, Logfire handler disabled" (logfire_handler.py:29); already-configured warning (logfire_handler.py:36-41); span enrichment filter (logfire_handler.py:60-69); metric safe-tags (logfire_handler.py:90) |
| handler_initializer.py:58 build_enricher | core/initialization/HandlerInitializer.kt buildEnricher | real EventEnricher; DynamicRuleManager when enable_dynamic_rules, decorator behavior_tracker fallback (handler_initializer.py:66-84) |
| handler_initializer.py:87 build_composite_handler | HandlerInitializer.buildCompositeHandler | composes agent sink members; enable_otel/enable_logfire through the default composition raises explicitly naming the absent SDK packages (the W4a contract, kept) - a host providing the `core.events` SDK surfaces registers compositeMemberFactory |
| _utils/agent_events.py:39 send_agent_event | util/AgentEvents.kt sendAgentEvent:59 | full envelope; extra kwargs fold into top-level model fields (the `extra="allow"` construction) |
| per-handler SecurityEvent constructors (_ipban_events.py:15/36, _suspatterns_registry.py:32, ipinfo_handler.py:164, redis_handler.py:73, ratelimit_handler.py:345/515, cloud_handler.py:397, _behavior_action_dispatch.py:124, _dynamic_rule_events.py:15/47/77, _security_headers_events.py:35/82) | the same sites through core/events/SecurityEventEnvelope.kt | every emitter carries the model's 17-key envelope with model defaults (ip_address=""/action_taken=""/reason=""/metadata={}), matching model_dump key sets byte-for-byte after volatile drop |
| detection_engine/monitor_anomalies.py:81-133 anomaly + callback-error event data | guard-core-engine Monitor.kt anomalyEventType/buildAnomalyEventData/buildCallbackErrorEventData | 5-key emitter-shaped envelopes (timestamp volatile); _redact_pattern_source is the engine seam param (identity with empty unions) |
| detection_engine/monitor.py:149-176 anomaly send + callback failure emission | Monitor.recordMetric(agentHandler, correlationId) + checkAnomalies/notifyCallbacks | AnomalyEventSink engine seam; callback failures emit detection_engine_callback_error (monitor.py:190-193) |
| suspatterns_handler.py:855 handler detect | handlers/SusPatternsRegistry.kt detect | overall_detection record (suspatterns_handler.py:966-976) + pattern_detected threat event (suspatterns_handler.py:990-1050) |

## event_stream conformance

Runner: `guard-core-conformance/src/main/kotlin/com/guardcore/conformance/EventsHarness.kt`
(Kotlin port of `specs/fixtures/tools/events_harness.py`) driving the REAL SecurityEventBus and
the REAL fixed-order pipeline over the corpus stubs, capturing full envelopes at the agent seam;
comparison per `index.json` `events_envelopes` (only-keys-present per expected envelope,
`events_volatile_fields` dropped recursively, 6-decimal floats) in
`EventsComparison.kt`; fail-closed ledger `guard-core-conformance/src/test/resources/
jvm_events_xfail.json` (failing-not-listed red, listed-but-passing red, drifted diff red).

Per-case results (39/39 green: 37 byte-exact + 2 ledgered + 1 advisory, matching the TS floor):

- 36 real-pin cases: exact (penetration_attempt x2, ip_blocked x2, ip_banned/ip_unbanned,
  ip_ban_failed, cloud_blocked+decorator_violation, https_enforced, decorator_violation,
  behavioral_violation, pattern_detected, dynamic_rule_updated/applied/violation,
  emergency_mode_activated, access_denied, authentication_failed, content_filtered,
  country_blocked, csp_violation, custom_request_check, emergency_mode_block, geo country,
  path_excluded, pattern_added/removed, rate_limited, rate_limit_script_reloaded,
  redis_connection, route_unresolved, security_bypass, security_headers_applied,
  user_agent_blocked, suspicious_request, detection_engine_callback_error, pattern anomaly
  timeout/slow_execution/statistical)
- `evt_geo_lookup_failed_download`: LEDGERED - reason embeds the exception CLASS NAME
  (ipinfo_handler.py:221 formats `type(e).__name__`); want `RuntimeError` (python), got
  `RuntimeException` (the JVM generic's class name). Same divergence class as the TS ledger's
  first entry; the engine behavior (class-name embedding) is ported 1:1.
- `evt_redis_error_connection_failed`: LEDGERED - reason embeds the python redis-driver error
  text (`redis.exceptions.ConnectionError` errno text); got the Lettuce driver text
  (`RedisConnectionException: Unable to connect to localhost/<unresolved>:59999`). Same class
  as the TS ledger's second entry; not hiding a missing emitter.
- `evt_decoding_error_unreachable`: advisory xfail (expected `[]`), runs expectation-free.

Emitter fixes the corpus forced (all byte-exact against python):

- RedisManager await unwraps `ExecutionException` so the NOSCRIPT reload path catches
  `RedisNoScriptException` like redis-py's inline raise (ratelimit_handler.py NOSCRIPT recovery).
- `emitBanEscalationFailed` renders `str(error)` (message only, helpers.py:467).
- `sendDecoratorEvent` folds `decorator_type` into the forwarded metadata (the python kwarg
  pass through middleware_events.py:111).
- pattern add/remove events carry `pattern` in metadata with `pattern_matched` null (the python
  `**kwargs` binding, _suspatterns_registry.py:190).
- SecurityEventBus hands the agent handler to extract_client_ip (middleware_events.py:125).
- RedisManager.discardClientQuietlyForCorpus mirrors the harness `_closed/_discard_client`
  teardown (events_harness.py:551-552).

## Decorators (G-12)

`guard-core/src/main/kotlin/com/guardcore/decorators/SecurityDecorator.kt` ports the decorator
factory surface 1:1 (parameter surface, validation, warnings):

| Python | JVM |
|---|---|
| access_control.py:16 require_ip | SecurityDecorator.requireIp |
| access_control.py:30/42 block_countries/allow_countries | blockCountries/allowCountries (upper-cased) |
| access_control.py:54 block_clouds | blockClouds (VALID_CLOUD_PROVIDERS + `:!` selector partition + sorted-invalid warning) |
| access_control.py:71 bypass | bypass (VALID_BYPASS_CHECKS filtering + warning) |
| rate_limiting.py:11/20 rate_limit/geo_rate_limit | rateLimit/geoRateLimit |
| behavioral.py:18/34/52/70 usage_monitor/return_monitor/behavior_analysis/suspicious_frequency | usageMonitor/returnMonitor/behaviorAnalysis/suspiciousFrequency (_validate_return_pattern_body_scan enforced) |
| authentication.py:15/22/44/68/82 require_https/require_auth/api_key_auth/require_authorization_header/require_headers | requireHttps/requireAuth/apiKeyAuth/requireAuthorizationHeader/requireHeaders (mutual-exclusion ValueErrors) |
| content_filtering.py:17 block_user_agents | blockUserAgents (ReDoS gate BEFORE route mutation, redacted-pattern rejection message) |
| content_filtering.py:40/50/60/70/79 content_type_filter/max_request_size/require_referrer/custom_validation/detection_exclusion | contentTypeFilter/maxRequestSize/requireReferrer/customValidation/detectionExclusion |
| advanced.py:52/64/72 time_window/suspicious_detection/honeypot_detection | timeWindow/suspiciousDetection/honeypotDetection (honeypot closure over readCappedBody + parse_qs; PyUrllib.parseQs port) |

Route-id collision study (the guard-core #141/#142 class): the python bug was factory-built
endpoints (closures sharing one `__qualname__`) deriving the same `module.qualname` route id, so
one endpoint could select another's RouteConfig; python's defense
(decorators/base.py:84-105) reuses a stamped id only when the SAME instance assigned it to the
SAME function object (owner chain over `id(func)`/`__wrapped__`), else allocates `key#2`.

JVM capability comparison: route identity is caller-supplied object identity (`StampedRoute`
carrying `stampedRouteId`, or a string key) - the analog of the TS WeakMap case. Two factory-built
endpoints in the JVM are two distinct `StampedRoute` objects, so the derived-key collision class
python had cannot occur: identical base keys get `key#2`-style suffixes per instance, and stamped
ids are never reused across instances (the owner map). `SecurityDecoratorTest`
(route-id collision campaign) ports tests/test_decorators/test_route_id_per_function.py 1:1:
own-rate-limit isolation, settings not leaking, first endpoint keeps the plain key, stacked
decorators share one config (the intentional case), and cross-instance stamped-id non-reuse.

## Java bridges

`guard-core/src/main/kotlin/com/guardcore/java/JavaBridges.kt` - the convention: every public
async entry point ships three shapes (suspend for Kotlin, `blocking` static = runBlocking
confined to the entry point (the unasync analog per specs/impl/jvm.md), `future` static =
CompletableFuture over the IO dispatcher):

- pipeline run: executePipeline / executePipelineBlocking
- detection: detect / detectBlocking (SusPatternsManager.detect)
- handlers: banIp, unbanIp, checkRateLimit (adapter supplies the error factory),
  getSecurityHeaders, initializeRedis, applyBehaviorAction (+ blocking pairs)

Proven from Java source in `guard-core/src/test/java/com/guardcore/java/JavaBridgeConsumerTest.java`.

## G-13 deeper test_core halves landed this wave

- PipelineRebuildPolicyTest.kt: test_pipeline_concurrent_rebuild.py (race self-heal through the
  public execute surface) + test_pipeline_rebuild_failure_policy.py (fail-secure block,
  last-known-good continuation, transient recovery, empty-pipeline reraise) + the
  user_agent/cloud_provider/custom_request config-revision halves of
  test_pipeline_config_revision.py (the EmptyRoutesMiddleware shape mirrors the python Mock
  decorator presenting an empty route-config collection).
- EventsGatingTest.kt: test_events.py halves (metrics no-agent/disabled/send/exception +
  collect counts; bus no-agent/disabled/send/geo/geo-failure/muted-filter/https routing).

## Known residuals

- The 2 ledgered reason-string shapes above (TS divergence class; fail-closed ledger).
- G-13 remainder re-scoped to W5 in KNOWN_GAPS.md (check_applies_to matrix, edge cases,
  exempt_ips, ip_security variants, authentication verifier, behavioral global variants,
  initialization variants, escalate-identity/block-vs-ban escalation, rate-limit-by-ip handler
  halves, pipeline route-config revision).
- guard-agent SecurityEvent/SecurityMetric model classes remain the W7 seam; the envelope
  field set they produce is already byte-shaped here.
