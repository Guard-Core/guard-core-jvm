# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W1 (foundation) - open, closes with later waves

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-2 | `ConfigSeams.geoIpHandlerFactory` throws `geo_ip_handler is required ...` before W3 registers IPInfoManager. Python constructs IPInfoManager when country rules are set and `ipinfo_token` is present (`_security_config_geo_validators.py:69-94`). | W3 (handlers) | W3 registers the factory; tests/test_models/test_geo_ip_handler_reassignment.py auto-construction cases port fully. |
| G-3 | `ConfigSeams.agentConfigFactory` raises AgentPackageNotInstalledError until guard-agent-jvm lands; the None short-circuit paths are live (`models.py:317-365`). | W7 (agent) | W7 registers the AgentConfig factory; to_agent_config parity tests extend to the constructed object. |
| G-6 | `AccessControl.cloudIpChecker` returns null until W3 registers the cloud handler (`access_control.py:197-215`); the cloud-provider block branch is wired and inert. | W3 | W3 registers the checker; cloud-provider verdict cases port fully. |

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
| G-1 | `ConfigSeams.blockedUserAgentsPatternGate` - the PatternCompiler-backed ReDoS gate (`util/DetectionEngineWiring.kt`, validate at max_content_length=512, ConfigValidationError with the reference message). | W2 |
| G-4 | `BodyReader.straddleOverlapBytesProvider` - longest compiled pattern length capped at the 256-byte straddle window (`DetectionEngineWiring.kt`). | W2 |
| G-5 | `AccessControl.userAgentBlockedPatternMatcher` - UA truncated to 512, per-pattern inline safe finditer with deadline-safe skip (`DetectionEngineWiring.kt`). | W2 |
| G-8 | `DetectionScanContext.withScanBudget` JSON depth cap - superseded by the engine-side budget accounting that landed with the preprocessor (max_content_length/max_full_scan_bytes/decode budget); the remaining value/char budgets track with G-7a. | W2 (superseded) |
