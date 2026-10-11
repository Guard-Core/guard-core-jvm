# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W4b/W5/W8a (events, W5 tranches, G-13 remainder) - closed

| id | gap | closed in |
|---|---|---|
| G-11 | The events wave remainder. W4b landed: `core/events/EventEnricher.kt` (EventEnricher + ThreatScorer + EnrichmentContext), the otel/logfire member-handler ports (`OtelHandler.kt`/`LogfireHandler.kt` - the python ImportError branches are the default with byte-exact warning strings and availability-backed health_check; the SDK surfaces are injectable seams; requesting otel/logfire through the default composite composition still raises explicitly naming the absent packages, the W4a contract kept), the EVENT_TYPE_VALUES/METRIC_TYPE_VALUES vocab sets + the 8 `guard.*` enrichment keys, the real `buildEnricher` construction, and the full guard-agent SecurityEvent envelope (guard_agent/models.py:208, 17 keys) carried by every emitter through `core/events/SecurityEventEnvelope.kt` (model defaults: ip_address=""/action_taken=""/reason=""/metadata={}), plus the engine Monitor anomaly send seam (build_anomaly_event_data/build_callback_error_event_data) and the handler-level SusPatternsRegistry.detect (overall_detection record + pattern_detected threat event). Gate: event_stream suite 39/39 green through the real-pipeline events runner (37 byte-exact + 2 ledgered reason-string shapes in `guard-core-conformance/src/test/resources/jvm_events_xfail.json`, the TS divergence class; 1 advisory). Proof: docs/w4b-events-parity.md. The SecurityEvent/SecurityMetric model CLASSES remain the W7 agent seam; the envelope field set is byte-shaped here. | W4b |
| G-12 | Decorators idiom closure. `decorators/SecurityDecorator.kt` ports the per-feature factories with the same parameter surface, validation, and warnings (access_control, rate_limiting, behavioral incl. return-pattern scan validation, authentication mutual-exclusion, content_filtering with the pre-mutation ReDoS gate, advanced incl. the honeypot closure + PyUrllib.parseQs). Route-id collision study (guard-core #141/#142 class): python derived route ids from module.qualname, so factory-built closures collided and the defense reuses a stamped id only within one instance/function owner chain (base.py:84-105); the JVM keys on caller-supplied object identity (StampedRoute/string), the TS WeakMap analog - that collision class cannot occur, suffixed allocation and cross-instance non-reuse are still validated. Tests: SecurityDecoratorTest ports test_route_id_per_function.py 1:1. | W4b |
| G-13 CLOSED | The W8a remainder landed (143 JUnit tests over the listed python surface; docs/w8a-tests.md has the file-by-file table): EdgeCasesTest (test_edge_cases.py), IpSecurityGlobalRouteMergeTest (test_ip_security_global_route_merge.py), PipelineRouteConfigRevisionTest (test_pipeline_route_config_revision.py), InitializationTest (test_initialization.py), EscalateIdentityViolationTest (test_escalate_identity_violation.py), BlockVsBanEscalationTest (test_block_vs_ban_escalation.py), CheckRateLimitByIpHalvesTest + CheckRateLimitByIpAutobanHalvesTest (the handler-side halves of test_check_rate_limit_by_ip.py + test_check_rate_limit_by_ip_autoban.py). Documented python-mock-only halves (no JVM-producible analog through the real seam, pinned in the test KDocs): the uncategorized fallback label in the escalation helper, the empty-threats verdict in _check_value_enhanced, the non-recursion engine failure injection in the fallback scan, the dynamic-rule-manager class-patch observations, and the plain-Exception row failure of the fallback scan. The port surfaced two byte-exact detection-scan routing fixes and the RouteConfig revision-tracked container wiring (all three anchored at their python file:line in the commit history). | W8a |

## W4a (pipeline) - closed

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

## W1 (foundation) - closed

| id | gap | closed in |
|---|---|---|
| G-3 | The agent seam closed when guard-agent-jvm landed (W7): its FacadeBridge (`GuardAgentTelemetry`, `com.guardcore.agent`) implements the facade's `AgentHandlerProtocol` (+ the `AgentTelemetryMember` composite shape, the Rust trait pattern), carrying the full 17-key SecurityEvent envelope into the agent's buffer - proven in the agent's FacadeBridgeTest (protocol shape, envelope field mapping, error swallowing, composite plug-in). Wiring an agent is constructing `GuardAgentTelemetry(GuardAgent.create(config))` and handing it to the facade's composite sink; `ConfigSeams.agentConfigFactory` remains the documented injection point for auto-wiring `toAgentConfig` (python's import-based auto-detection has no JVM analog - classloading is explicit, which the `toAgentConfig` KDoc records), and the `AgentPackageNotInstalledError` raise stays byte-exact on the unregistered path (`models.py:317-365`, None short-circuits live). | W7 |
