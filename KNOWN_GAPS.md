# KNOWN_GAPS (guard-core-jvm)

The gap ledger tracks in-flight work to closure, not permanent documentation.
An entry is open only while its wave is in flight. Parity bar: zero PARTIAL
and zero MISSING rows at release (specs/impl/jvm.md, "Parity bar").

## W1 (foundation) - open, closes with later waves

| id | gap | owner wave | closure condition |
|---|---|---|---|
| G-1 | `ConfigSeams.blockedUserAgentsPatternGate` is a no-op until the ReDoS validator lands. Python rejects unsafe `blocked_user_agents` patterns at construction (`_security_config_field_validators.py:324-340`, PatternCompiler). Str-list validation is live; the pattern-safety gate is the seam. | W2 (detection engine) | W2 registers the PatternCompiler-backed gate; tests/test_models revalidator cases for unsafe patterns go green. |
| G-2 | `ConfigSeams.geoIpHandlerFactory` throws `geo_ip_handler is required ...` before W3 registers IPInfoManager. Python constructs IPInfoManager when country rules are set and `ipinfo_token` is present (`_security_config_geo_validators.py:69-94`). | W3 (handlers) | W3 registers the factory; tests/test_models/test_geo_ip_handler_reassignment.py auto-construction cases port fully. |
| G-3 | `ConfigSeams.agentConfigFactory` raises AgentPackageNotInstalledError until guard-agent-jvm lands; the None short-circuit paths are live (`models.py:317-365`). | W7 (agent) | W7 registers the AgentConfig factory; to_agent_config parity tests extend to the constructed object. |
| G-4 | `BodyReader.straddleOverlapBytesProvider` defaults to 0 (the python function's own failure-path result, `body_reader.py:46-58`); the longest-pattern overlap needs the compiled pattern set. | W2 | W2 registers the provider; test_body_read_boundary_overlap.py cases port fully. |
| G-5 | `AccessControl.userAgentBlockedPatternMatcher` allows every UA until W2 registers `_user_agent_matches_blocked_pattern` (`access_control.py:16`). | W2 | W2 registers the matcher; test_request_checks.py UA cases port fully. |
| G-6 | `AccessControl.cloudIpChecker` returns null until W3 registers the cloud handler (`access_control.py:197-215`); the cloud-provider block branch is wired and inert. | W3 | W3 registers the checker; cloud-provider verdict cases port fully. |
| G-7 | Eight `_utils` modules deferred to the detection-engine wave because their dependency closure is the pattern engine: detection_config.py (234), detection_scan.py (442), body_json_scan.py (291), body_form_scan.py (201), body_content_scan.py (478), embedded_json_scan.py (77), detection_result_builders.py (43), penetration_detection.py (224). Reasoning in docs/w1-config-parity.md; landing them now would be dead code, not a port. | W2 | Each module ports file-for-file with its python test surface; this row splits into per-module rows at W2 and closes there. |
| G-8 | `DetectionScanContext.withScanBudget` wires only the JSON depth cap (the sole consumer in the W1 modules, `detection_scan.py:116`); value/char budget accounting lands with detection_scan itself. | W2 | Full context-var budget ported with the engine. |

## Closed

(none yet)
