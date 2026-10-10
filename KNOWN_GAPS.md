# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W1 (foundation) - open, closes with later waves

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-3 | `ConfigSeams.agentConfigFactory` raises AgentPackageNotInstalledError until guard-agent-jvm lands; the None short-circuit paths are live (`models.py:317-365`). | W7 (agent) | W7 registers the AgentConfig factory; to_agent_config parity tests extend to the constructed object. |

## W3 (handlers) - open, closes with W4

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-9 | `handlers/ThresholdBans.kt` ports `_resolve_and_apply_threshold_ban` (`core/checks/helpers.py:375-411`) - the minimal real surface the rate-limit auto-ban path needs. The rest of `helpers.py` (`_try_threshold_ban` with its log_activity wiring, `_emit_ban_escalation_failed`, `escalate_identity_violation`) plus the `RateLimitCheck` middleware-check test halves (test_rate_limit_edge_cases.py, test_rate_limit_singleton_isolation.py, test_rate_limit_autoban_wiring.py) are pipeline surface. | W4 (pipeline + facade) | helpers.py ports file-for-file with the fixed-order checks; ThresholdBans folds into it; the check-half test surfaces port with the pipeline tests. |
| G-10 | `handlers/DetectionScanRedaction.kt` ports the `_redact_pattern_source` slice (`_utils/detection_scan.py:137-178`) with the suspatterns sensitive-name unions (`sus_patterns_handler._sensitive_params_union` et al) defaulting to empty - identical output under default config. | W4 | the unions register with the suspatterns state when `detection_scan.py` lands (G-7b closure registers `DetectionScanRedaction.sensitive*Union` from the live handler state). |

The W3 deferral notes (python tests owned by W4, not gaps): the `RateLimitCheck`
halves of test_rate_limit_edge_cases.py / test_rate_limit_singleton_isolation.py
and the response-factory halves of the security-headers per-config tests are
pipeline surface (W4 wave); the live HTTP fetcher halves of test_cloud_ips are
environment-bound (the fetch parsing kernel is ported and the fetch path is
seam-scripted in the interop runner).

## W2 (detection engine) - open, closes with later waves

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-7a | `detection_config.py` (234) + `DetectionScanContext` full budget accounting (G-8's `detection_scan.py:116` surface). The scan-config knobs exist on SecurityConfig (W1); the `_utils.detection_config` accessor module ports with the scan callers. | W4 (pipeline + facade) | detection_config.py ports file-for-file with its test surface when the first scan caller (`detection_scan.py`, W4 checks) lands; G-8 closes with it. |
| G-7b | `detection_scan.py` (442) - the scan-value walker its consumers need. Its dependency closure (engine + views) is now present. | W4 | ports file-for-file with test_detection_scan surface; feeds the W4 checks in fixed order. |
| G-7c | `body_json_scan.py` (291), `body_form_scan.py` (201), `body_content_scan.py` (478), `embedded_json_scan.py` (77) - the body-scan family. They call the engine (landed) through detection_scan (G-7b). | W4 | each ports file-for-file with its python test surface. |
| G-7d | `detection_result_builders.py` (43) + `penetration_detection.py` (224) - result shaping and the auto-configure penetration entry. | W4 | port file-for-file; the penetration-detection tests then run against the live engine. |

Reasoning for the W2 -> W4 split: G-7's eight modules are scan CALLERS (they read request
values through the pipeline and call the engine). With the engine landed they are no longer
dead code risks, but their harness surface is the pipeline (checks in fixed order, events),
which is W4's wave. Splitting the single W1 row into per-module rows keeps each module's
closure auditable. None of them gates the detect suites (proven: 193/193 green without
them - the corpus drives `detect()` directly, not the scan walkers).

## Closed

| id | gap | closed in |
|---|---|---|
| G-2 | `ConfigSeams.geoIpHandlerFactory` constructs the real `IpInfoManager` (`handlers/HandlerSeams.kt`, registered at facade init and in the tests; python resolves the same lazily at `_security_config_geo_validators.py:69-94`). Country-rule configs auto-construct the geo handler with `ipinfo_token` present. | W3 |
| G-6 | `AccessControl.cloudIpChecker` resolves through `CloudManager.get_cloud_provider_details` (`handlers/HandlerSeams.kt`); the cloud-provider block branch is live. | W3 |
| G-1 | `ConfigSeams.blockedUserAgentsPatternGate` - the PatternCompiler-backed ReDoS gate (`util/DetectionEngineWiring.kt`, validate at max_content_length=512, ConfigValidationError with the reference message). | W2 |
| G-4 | `BodyReader.straddleOverlapBytesProvider` - longest compiled pattern length capped at the 256-byte straddle window (`DetectionEngineWiring.kt`). | W2 |
| G-5 | `AccessControl.userAgentBlockedPatternMatcher` - UA truncated to 512, per-pattern inline safe finditer with deadline-safe skip (`DetectionEngineWiring.kt`). | W2 |
| G-8 | `DetectionScanContext.withScanBudget` JSON depth cap - superseded by the engine-side budget accounting that landed with the preprocessor (max_content_length/max_full_scan_bytes/decode budget); the remaining value/char budgets track with G-7a. | W2 (superseded) |
