# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W4a (pipeline) - open, closes with W4b

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-11 | The events wave remainder: `core/events/enricher.py` (EventEnricher), `otel_handler.py`, `logfire_handler.py`, the `EVENT_TYPE_VALUES`/`METRIC_TYPE_VALUES` vocab sets + enrichment keys (event_types.py:46-131), and the guard-agent SecurityEvent/SecurityMetric telemetry-model construction (the JVM bus forwards the same field envelope as a map until the W7 agent model lands). `HandlerInitializer.buildCompositeHandler` composes agent-only and raises explicitly when enable_otel/enable_logfire is requested until W4b registers the member factory; `build_enricher` raises the same way. | W4b (events + telemetry sink seam) | The W4b events port registers the composite member factory + enricher and the vocab sets; the raising seams flip to real construction. |
| G-12 | Decorators idiom mapping follow-ups beyond the W4a route surface: the per-feature decorator factories (`@guard` builders, decorators/ package minus route_config/base) and the `guard_route_id` collision validation campaign (specs/impl/jvm.md route-id lesson). `BaseSecurityDecorator._get_route_id` keys on the JVM route key (method identity); the collision study records the capability comparison. | W4 (pipeline + facade) closure / W6 (adapters consume) | Decorator factories port with the adapter-facing surface; route-id collision tests + capability note land. |
| G-13 | Deeper test_core halves deferred behind the wave gate (the wave gate is the 35 pipeline cases + the enumerated surface: pipeline order, exclusion, passive mode, bypass, routing resolution, per-check units, W3-deferred halves - all landed). Remaining python files: the pipeline concurrency/rebuild-policy variants (test_pipeline_concurrent_rebuild.py, test_pipeline_rebuild_failure_policy.py, test_pipeline_config_revision.py, test_pipeline_route_config_revision.py), test_check_applies_to.py exhaustive matrix, test_edge_cases.py, test_exempt_ips.py, test_ip_security_* variants, test_authentication_verifier.py, test_behavioral*_global variants, test_events.py, test_initialization*.py variants, test_escalate_identity_violation.py, test_block_vs_ban_escalation.py, test_check_rate_limit_by_ip*.py handler-side halves. | W4b/W5 (with the events port and the corpus gate) | Each ports file-for-file with its kotlin counterpart in `guard-core/src/test/kotlin/com/guardcore/core/`. |

Closed this wave (2026-10-11, PR W4a):

| id | gap | closed in |
|---|---|---|
| G-7a | `util/DetectionConfig.kt` ports `detection_config.py` file-for-file; the full scan budget (value/char/depth/min-run contextvars) is `util/DetectionScanBudget.kt` over the W1 `DetectionScanContext` seam. | W4a |
| G-7b | `util/DetectionScan.kt` ports `detection_scan.py` (threat-message builders, fallback pattern check, embedded-JSON gate, component scans). | W4a |
| G-7c | `util/BodyJsonScan.kt` + `util/BodyFormScan.kt` + `util/BodyContentScan.kt` + `util/EmbeddedJsonScan.kt` port the body-scan family file-for-file. | W4a |
| G-7d | `util/DetectionResultBuilders.kt` + `util/PenetrationDetection.kt` port result shaping and the auto-configure penetration entry (configureDetection registers the live engine view). | W4a |
| G-9 | `core/checks/ChecksHelpers.kt` ports `checks/helpers.py` file-for-file; `handlers/ThresholdBans.kt` folds into it (deleted; the rate-limit primitive calls ChecksHelpers.resolveAndApplyThresholdBan); the RateLimitCheck test halves landed (RateLimitCheckHalvesTest). | W4a |
| G-10 | `DetectionScanRedaction` sensitive unions register live at configure time (`PenetrationDetection.configureDetection`, mirroring `_suspatterns_enhanced.py:29-38`). | W4a |

## W3 (handlers) - closed

| id | gap | closed in |
|---|---|---|
| G-2 | `ConfigSeams.geoIpHandlerFactory` constructs the real `IpInfoManager`. | W3 |
| G-6 | `AccessControl.cloudIpChecker` resolves through `CloudManager.get_cloud_provider_details`. | W3 |

## W2 (detection engine) - closed

| id | gap | closed in |
|---|---|---|
| G-1 | `ConfigSeams.blockedUserAgentsPatternGate` (ReDoS gate). | W2 |
| G-4 | `BodyReader.straddleOverlapBytesProvider`. | W2 |
| G-5 | `AccessControl.userAgentBlockedPatternMatcher`. | W2 |
| G-8 | Scan budget JSON depth cap - superseded by the engine-side budget accounting; the remaining value/char budgets closed with G-7a in W4a. | W2 (superseded), W4a (closure) |

## W1 (foundation) - G-3 open, closes with W7

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-3 | `ConfigSeams.agentConfigFactory` raises AgentPackageNotInstalledError until guard-agent-jvm lands; the None short-circuit paths are live (`models.py:317-365`). | W7 (agent) | W7 registers the AgentConfig factory; to_agent_config parity tests extend to the constructed object. |
