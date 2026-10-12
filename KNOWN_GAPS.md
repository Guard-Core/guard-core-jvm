# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W9b (100 percent line-coverage ruling) - IN FLIGHT

Operator ruling 14.2 (option A): push the family to the 100 percent line
gate. W9b landed the engine coverage push and productized the gate.

| id | state | remainder |
|---|---|---|
| G-C1 | DONE (W9b): the fail-closed 100 percent line gate productized - `scripts/enforce_line_coverage.sh` + `scripts/enforce_line_coverage.py` (jacococli 0.8.15 nodeps, sha256-pinned d2b74b20b415163c1f53261e7c5ef4445b788327094208ff821e0c2baf9bc8f1; merges ALL exec files against ALL kotlin classes; exits 1 unless workspace total AND every module hold 100.0 percent lines; prints uncovered-line ranges per class on failure). Seeded-regression proof in docs/w9b-coverage.md. | The ci.yml coverage job (byte-for-byte block in docs/w9b-coverage.md) lands ONLY when the numbers hold: after W9c batch 1 the workspace holds at 1,574 missed (was 2,160), so the gate stays unwired. |
| G-C2 | IN FLIGHT (W9e batch 4 landed: the negated-shorthand render arms closed by tests; the remaining 62 engine lines carry reasoned EXCLUDES in scripts/enforce_line_coverage.py - every entry verified against the parser/normalization code (bare CATEGORY/NOT_LITERAL/ATOMIC_GROUP/multi-atom-repeat shapes the sre port never emits, the scoped-emitter fail-closed arm, the thread-CPU fallback and the timing-race arms)). | residual: 62 excluded lines, each with a written proof in the gate. |
| G-C3 | IN FLIGHT: facade module at 96.84 percent (465 missed; was 784 after W9d). W9e batches 3+4 landed the harness-surface, agent-wired manager tails, decorator factory, per-check, initializer-composite and full builder/validator sweeps (docs/w9e-coverage.md). | ~465 lines: the IpInfoManager refresh-success arms (need a valid MaxMindDB database fixture - the JVM engine vendors none), the DynamicRuleManager persistence flows, the CloudManager fetcher paths, and the per-file singles printed by the gate. |
| G-C4 | IN FLIGHT: conformance at 99.76 percent (3 missed; was 116). W9e batch 3 closed the PipelineHarness/EventsHarness seeded arms (HarnessArmsW9eTest) and the DetectRunner/PatternSafety/CostBudget/EventsComparison failure tables. | residual: 3 lines printed by the gate. |
| G-C5 | DONE (W9b): six byte-exact bugs fixed with regression tests (Monitor anomaly cooldown ns-vs-seconds, positiveAssertion negative-slice crash, unterminated-char-class slice crashes x5 sites, JsonMini null-coercion, 3-digit octal escapes as group refs, overflowed brace bounds as {0,0}). Anchors in docs/w9b-coverage.md. | - |
| G-C6 | DONE (W9c batch 1): six more byte-exact bugs fixed with regression tests - the PyAst aug-assignment infinite loop (`**=` pinned the tokenizer CPU-side, no deadline escape), the (?-i:...) scoped-emitter case-sensitivity inversion outside the scope, the call-arg walrus value never parsed, the `*args/**kwargs` + interleaved-comprehension rejections against python-valid input, and the `\g<num>/\g<name>` parse rejection; plus the behavior-preserving dead-defensive-code removals (AmbiguousTail shape-only parser, PyReParser unreachable arms, RegexWorkers catch, PyRe NOT_LITERAL/CATEGORY emitter arms). Anchors in docs/w9c-coverage.md. | - |

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
