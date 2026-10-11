# Every-Feature Parity Matrix (guard-core-jvm)

Parity bar arm 2 (specs/impl/jvm.md): the mechanical, full-surface audit of
the JVM port against the python reference. Every public feature of
`guard_core` (authored surface, `sync/` excluded) is enumerated by script
(`docs/tools/w8c_extract.py` + `w8c_matrix.py`) and mapped to its JVM
counterpart with file:line proof on both sides.

- Reference: guard-core @ `866f80c7` (engine 4.3.2, corpus spec 4.1.0).
- Port: guard-core-jvm @ master `3ca64f2` (W1-W8a merged).
- Statuses: FULL = ported and behavior-verified by the corpus or the
  ported test surface; IDIOMATIC = same behavior through a documented
  language-idiom mapping (see Idiom mappings). PARTIAL / MISSING = an
  incomplete or absent port; the parity bar requires ZERO of both.

## Result

| Family | Rows | FULL | IDIOMATIC | PARTIAL | MISSING |
|---|---|---|---|---|---|
| Configuration | 177 | 172 | 5 | 0 | 0 |
| Protocols | 61 | 61 | 0 | 0 | 0 |
| Utilities | 25 | 25 | 0 | 0 | 0 |
| Handlers | 152 | 132 | 20 | 0 | 0 |
| Detection engine | 148 | 143 | 5 | 0 | 0 |
| Core | 195 | 195 | 0 | 0 | 0 |
| Decorators | 72 | 48 | 24 | 0 | 0 |
| Observable constants | 50 | 50 | 0 | 0 | 0 |
| **Total** | **880** | **826** | **54** | **0** | **0** |

**880 rows: 826 FULL, 54 IDIOMATIC, 0 PARTIAL, 0 MISSING.**
Behavioral basis: the W5 full-corpus certification gate (375 cases across
21 suites + 9 cost budgets, 0 failing, 8 ledgered), plus the per-family
test surfaces cited below. The 8 ledgered entries are documented in
[Ledger cross-reference](#ledger-cross-reference); they are the TS-floor
reason-string class and RS-class timing facts, not missing surface.

Row granularity: public classes, public functions and methods, the 129
field-registry entries, and the observable identifier sets. Private
helpers are internals of their module's public entry points and are
proven per-module by the cited suites (the wave gates ported
file-for-file; see docs/w1..w8a).

## Configuration (models.py + field registry + validators)

177 rows: 172 FULL, 5 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: W1 field-for-field gate 129/129 with byte-matched rejection messages (docs/w1-config-parity.md); SecurityConfigTest + validator suites green (guard-core module 694 tests, W8a).

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `_config_capabilities.py:12` | cloud_blocking_enabled | `CloudProviderCheck.kt:125` | IDIOMATIC | capability probe -> inlined applies-to disjunct (block_cloud_providers non-empty or enable_dynamic_rules), the W5-certified line |
| `_dynamic_rules.py:6` | DynamicRules | `DynamicRules.kt:18` | FULL | |
| `_dynamic_rules.py:74` | LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION | `DynamicRules.kt:46` | FULL | |
| `_dynamic_rules.py:77` | LastKnownDynamicRules | `DynamicRules.kt:90` | IDIOMATIC | pydantic snapshot model -> pinned field-order serializer dumpLastKnownRulesSnapshot (schema-versioned, interop-pinned) |
| `_dynamic_rules.py:81` | LastKnownRulesSnapshot | `DynamicRules.kt:153` | IDIOMATIC | pydantic snapshot envelope -> loadLastKnownRulesSnapshot parser with schema version + payload verification |
| `_dynamic_rules.py:88` | dump_last_known_rules_snapshot | `DynamicRules.kt:91` | FULL | |
| `_dynamic_rules.py:97` | load_last_known_rules_snapshot | `DynamicRules.kt:157` | FULL | |
| `_pydantic_plugin_mute.py:55` | get_telemetry_model | `SecurityEventEnvelope.kt:11` | IDIOMATIC | pydantic dynamic telemetry model -> direct typed envelope construction (securityEventEnvelope, 17-key model shape); muting machinery has no JVM analog |
| `_security_config_field_validators.py:38` | VALID_CLOUD_PROVIDERS | `DetectionCategories.kt:53` | FULL | |
| `_security_config_field_validators.py:79` | ThreatBanConfig | `RuleConfigs.kt:24` | FULL | |
| `_security_config_field_validators.py:84` | THREAT_BAN_CONFIG_CATEGORIES | `DetectionCategories.kt:37` | FULL | |
| `_security_config_field_validators.py:89` | BehaviorRuleConfig | `RuleConfigs.kt:53` | FULL | |
| `_security_config_field_validators.py:99` | return_pattern_requires_response_body | `RuleConfigs.kt:103` | FULL | |
| `_security_config_fields.py:22` | _SecurityConfigFields.trusted_proxies | `SecurityConfig.kt:95` | FULL | |
| `_security_config_fields.py:27` | _SecurityConfigFields.trusted_proxy_depth | `SecurityConfig.kt:107` | FULL | |
| `_security_config_fields.py:32` | _SecurityConfigFields.trust_x_forwarded_proto | `SecurityConfig.kt:118` | FULL | |
| `_security_config_fields.py:37` | _SecurityConfigFields.passive_mode | `SecurityConfig.kt:129` | FULL | |
| `_security_config_fields.py:42` | _SecurityConfigFields.geo_ip_handler | `SecurityConfig.kt:140` | FULL | |
| `_security_config_fields.py:47` | _SecurityConfigFields.enable_redis | `SecurityConfig.kt:153` | FULL | |
| `_security_config_fields.py:52` | _SecurityConfigFields.redis_url | `SecurityConfig.kt:164` | FULL | |
| `_security_config_fields.py:57` | _SecurityConfigFields.redis_prefix | `SecurityConfig.kt:175` | FULL | |
| `_security_config_fields.py:62` | _SecurityConfigFields.redis_socket_connect_timeout | `SecurityConfig.kt:186` | FULL | |
| `_security_config_fields.py:74` | _SecurityConfigFields.redis_socket_timeout | `SecurityConfig.kt:197` | FULL | |
| `_security_config_fields.py:85` | _SecurityConfigFields.redis_health_check_interval | `SecurityConfig.kt:208` | FULL | |
| `_security_config_fields.py:95` | _SecurityConfigFields.redis_max_connections | `SecurityConfig.kt:219` | FULL | |
| `_security_config_fields.py:103` | _SecurityConfigFields.redis_retries | `SecurityConfig.kt:230` | FULL | |
| `_security_config_fields.py:112` | _SecurityConfigFields.whitelist | `SecurityConfig.kt:241` | FULL | |
| `_security_config_fields.py:121` | _SecurityConfigFields.blacklist | `SecurityConfig.kt:254` | FULL | |
| `_security_config_fields.py:129` | _SecurityConfigFields.exempt_ips | `SecurityConfig.kt:266` | FULL | |
| `_security_config_fields.py:139` | _SecurityConfigFields.whitelist_countries | `SecurityConfig.kt:283` | FULL | |
| `_security_config_fields.py:149` | _SecurityConfigFields.blocked_countries | `SecurityConfig.kt:297` | FULL | |
| `_security_config_fields.py:154` | _SecurityConfigFields.blocked_user_agents | `SecurityConfig.kt:311` | FULL | |
| `_security_config_fields.py:158` | _SecurityConfigFields.auto_ban_threshold | `SecurityConfig.kt:323` | FULL | |
| `_security_config_fields.py:164` | _SecurityConfigFields.auto_ban_duration | `SecurityConfig.kt:335` | FULL | |
| `_security_config_fields.py:170` | _SecurityConfigFields.threat_ban_config | `SecurityConfig.kt:347` | FULL | |
| `_security_config_fields.py:180` | _SecurityConfigFields.enable_rate_limit_auto_ban | `SecurityConfig.kt:359` | FULL | |
| `_security_config_fields.py:193` | _SecurityConfigFields.global_behavior_rules | `SecurityConfig.kt:372` | FULL | |
| `_security_config_fields.py:201` | _SecurityConfigFields.behavior_scan_response_body | `SecurityConfig.kt:390` | FULL | |
| `_security_config_fields.py:220` | _SecurityConfigFields.behavior_max_response_body_inspect_bytes | `SecurityConfig.kt:402` | FULL | |
| `_security_config_fields.py:241` | _SecurityConfigFields.body_read_timeout | `SecurityConfig.kt:413` | FULL | |
| `_security_config_fields.py:266` | _SecurityConfigFields.sync_body_read_max_concurrent | `SecurityConfig.kt:424` | FULL | |
| `_security_config_fields.py:282` | _SecurityConfigFields.custom_log_file | `SecurityConfig.kt:435` | FULL | |
| `_security_config_fields.py:287` | _SecurityConfigFields.log_suspicious_level | `SecurityConfig.kt:446` | FULL | |
| `_security_config_fields.py:291` | _SecurityConfigFields.log_request_level | `SecurityConfig.kt:457` | FULL | |
| `_security_config_fields.py:295` | _SecurityConfigFields.log_country_check_level | `SecurityConfig.kt:468` | FULL | |
| `_security_config_fields.py:307` | _SecurityConfigFields.log_format | `SecurityConfig.kt:21` | FULL | |
| `_security_config_fields.py:312` | _SecurityConfigFields.custom_error_responses | `SecurityConfig.kt:490` | FULL | |
| `_security_config_fields.py:316` | _SecurityConfigFields.rate_limit | `SecurityConfig.kt:502` | FULL | |
| `_security_config_fields.py:320` | _SecurityConfigFields.rate_limit_window | `SecurityConfig.kt:514` | FULL | |
| `_security_config_fields.py:324` | _SecurityConfigFields.enforce_https | `SecurityConfig.kt:526` | FULL | |
| `_security_config_fields.py:328` | _SecurityConfigFields.security_headers | `SecurityConfig.kt:537` | FULL | |
| `_security_config_fields.py:347` | _SecurityConfigFields.custom_request_check | `SecurityConfig.kt:549` | FULL | |
| `_security_config_fields.py:351` | _SecurityConfigFields.auth_verifier | `SecurityConfig.kt:560` | FULL | |
| `_security_config_fields.py:361` | _SecurityConfigFields.custom_response_modifier | `SecurityConfig.kt:571` | FULL | |
| `_security_config_fields.py:368` | _SecurityConfigFields.enable_cors | `SecurityConfig.kt:582` | FULL | |
| `_security_config_fields.py:370` | _SecurityConfigFields.cors_allow_origins | `SecurityConfig.kt:593` | FULL | |
| `_security_config_fields.py:374` | _SecurityConfigFields.cors_allow_methods | `SecurityConfig.kt:606` | FULL | |
| `_security_config_fields.py:379` | _SecurityConfigFields.cors_allow_headers | `SecurityConfig.kt:618` | FULL | |
| `_security_config_fields.py:383` | _SecurityConfigFields.cors_allow_credentials | `SecurityConfig.kt:630` | FULL | |
| `_security_config_fields.py:387` | _SecurityConfigFields.cors_expose_headers | `SecurityConfig.kt:641` | FULL | |
| `_security_config_fields.py:391` | _SecurityConfigFields.cors_max_age | `SecurityConfig.kt:653` | FULL | |
| `_security_config_fields.py:395` | _SecurityConfigFields.block_cloud_providers | `SecurityConfig.kt:664` | FULL | |
| `_security_config_fields.py:408` | _SecurityConfigFields.cloud_ip_refresh_interval | `SecurityConfig.kt:676` | FULL | |
| `_security_config_fields.py:415` | _SecurityConfigFields.lazy_init | `SecurityConfig.kt:687` | FULL | |
| `_security_config_fields.py:434` | _SecurityConfigFields.geo_ip_db_max_age | `SecurityConfig.kt:698` | FULL | |
| `_security_config_fields.py:441` | _SecurityConfigFields.cloud_ip_store | `SecurityConfig.kt:712` | FULL | |
| `_security_config_fields.py:452` | _SecurityConfigFields.exclude_paths | `SecurityConfig.kt:724` | FULL | |
| `_security_config_fields.py:464` | _SecurityConfigFields.enable_ip_banning | `SecurityConfig.kt:736` | FULL | |
| `_security_config_fields.py:468` | _SecurityConfigFields.enable_rate_limiting | `SecurityConfig.kt:748` | FULL | |
| `_security_config_fields.py:472` | _SecurityConfigFields.enable_penetration_detection | `SecurityConfig.kt:760` | FULL | |
| `_security_config_fields.py:476` | _SecurityConfigFields.fail_secure | `SecurityConfig.kt:772` | FULL | |
| `_security_config_fields.py:486` | _SecurityConfigFields.redis_fail_open | `SecurityConfig.kt:783` | FULL | |
| `_security_config_fields.py:498` | _SecurityConfigFields.route_resolution_strict | `SecurityConfig.kt:794` | FULL | |
| `_security_config_fields.py:513` | _SecurityConfigFields.ipinfo_token | `SecurityConfig.kt:805` | FULL | |
| `_security_config_fields.py:519` | _SecurityConfigFields.ipinfo_db_path | `SecurityConfig.kt:816` | FULL | |
| `_security_config_fields.py:525` | _SecurityConfigFields.enable_agent | `SecurityConfig.kt:827` | FULL | |
| `_security_config_fields.py:529` | _SecurityConfigFields.agent_api_key | `SecurityConfig.kt:838` | FULL | |
| `_security_config_fields.py:533` | _SecurityConfigFields.agent_strict | `SecurityConfig.kt:849` | FULL | |
| `_security_config_fields.py:542` | _SecurityConfigFields.on_error | `SecurityConfig.kt:860` | FULL | |
| `_security_config_fields.py:552` | _SecurityConfigFields.on_block | `SecurityConfig.kt:871` | FULL | |
| `_security_config_fields.py:569` | _SecurityConfigFields.agent_endpoint | `SecurityConfig.kt:882` | FULL | |
| `_security_config_fields.py:574` | _SecurityConfigFields.agent_project_id | `SecurityConfig.kt:893` | FULL | |
| `_security_config_fields.py:578` | _SecurityConfigFields.agent_buffer_size | `SecurityConfig.kt:904` | FULL | |
| `_security_config_fields.py:582` | _SecurityConfigFields.agent_flush_interval | `SecurityConfig.kt:915` | FULL | |
| `_security_config_fields.py:586` | _SecurityConfigFields.agent_enable_events | `SecurityConfig.kt:926` | FULL | |
| `_security_config_fields.py:590` | _SecurityConfigFields.agent_enable_metrics | `SecurityConfig.kt:937` | FULL | |
| `_security_config_fields.py:594` | _SecurityConfigFields.agent_timeout | `SecurityConfig.kt:948` | FULL | |
| `_security_config_fields.py:598` | _SecurityConfigFields.agent_retry_attempts | `SecurityConfig.kt:959` | FULL | |
| `_security_config_fields.py:602` | _SecurityConfigFields.agent_project_encryption_key | `SecurityConfig.kt:970` | FULL | |
| `_security_config_fields.py:612` | _SecurityConfigFields.agent_guard_version | `SecurityConfig.kt:981` | FULL | |
| `_security_config_fields.py:622` | _SecurityConfigFields.agent_high_watermark_ratio | `SecurityConfig.kt:992` | FULL | |
| `_security_config_fields.py:630` | _SecurityConfigFields.agent_max_concurrent_flushes | `SecurityConfig.kt:1003` | FULL | |
| `_security_config_fields.py:638` | _SecurityConfigFields.agent_buffer_overflow_policy | `SecurityConfig.kt:1014` | FULL | |
| `_security_config_fields.py:649` | _SecurityConfigFields.agent_backoff_factor | `SecurityConfig.kt:1025` | FULL | |
| `_security_config_fields.py:657` | _SecurityConfigFields.agent_sensitive_headers | `SecurityConfig.kt:1036` | FULL | |
| `_security_config_fields.py:665` | _SecurityConfigFields.agent_max_payload_size | `SecurityConfig.kt:1048` | FULL | |
| `_security_config_fields.py:673` | _SecurityConfigFields.agent_compression_enabled | `SecurityConfig.kt:1059` | FULL | |
| `_security_config_fields.py:682` | _SecurityConfigFields.agent_compression_threshold | `SecurityConfig.kt:1070` | FULL | |
| `_security_config_fields.py:690` | _SecurityConfigFields.agent_install_id | `SecurityConfig.kt:1081` | FULL | |
| `_security_config_fields.py:698` | _SecurityConfigFields.agent_payload_signing_secret | `SecurityConfig.kt:1092` | FULL | |
| `_security_config_fields.py:703` | _SecurityConfigFields.enable_dynamic_rules | `SecurityConfig.kt:1103` | FULL | |
| `_security_config_fields.py:707` | _SecurityConfigFields.dynamic_rule_interval | `SecurityConfig.kt:1114` | FULL | |
| `_security_config_fields.py:713` | _SecurityConfigFields.dynamic_rules_cache_path | `SecurityConfig.kt:1125` | FULL | |
| `_security_config_fields.py:722` | _SecurityConfigFields.agent_status_interval | `SecurityConfig.kt:1137` | FULL | |
| `_security_config_fields.py:729` | _SecurityConfigFields.emergency_mode | `SecurityConfig.kt:1148` | FULL | |
| `_security_config_fields.py:733` | _SecurityConfigFields.emergency_whitelist | `SecurityConfig.kt:1160` | FULL | |
| `_security_config_fields.py:738` | _SecurityConfigFields.endpoint_rate_limits | `SecurityConfig.kt:1172` | FULL | |
| `_security_config_fields.py:743` | _SecurityConfigFields.detection_compiler_timeout | `SecurityConfig.kt:1184` | FULL | |
| `_security_config_fields.py:750` | _SecurityConfigFields.detection_pattern_validation_cache_path | `SecurityConfig.kt:1195` | FULL | |
| `_security_config_fields.py:768` | _SecurityConfigFields.detection_max_content_length | `SecurityConfig.kt:1206` | FULL | |
| `_security_config_fields.py:783` | _SecurityConfigFields.detection_max_body_inspect_bytes | `SecurityConfig.kt:1217` | FULL | |
| `_security_config_fields.py:814` | _SecurityConfigFields.detection_max_scan_values | `SecurityConfig.kt:1228` | FULL | |
| `_security_config_fields.py:833` | _SecurityConfigFields.detection_max_scan_chars | `SecurityConfig.kt:1239` | FULL | |
| `_security_config_fields.py:853` | _SecurityConfigFields.detection_max_json_depth | `SecurityConfig.kt:1250` | FULL | |
| `_security_config_fields.py:871` | _SecurityConfigFields.detection_binary_min_run_length | `SecurityConfig.kt:1261` | FULL | |
| `_security_config_fields.py:899` | _SecurityConfigFields.detection_preserve_attack_patterns | `SecurityConfig.kt:1272` | FULL | |
| `_security_config_fields.py:904` | _SecurityConfigFields.detection_semantic_threshold | `SecurityConfig.kt:1283` | FULL | |
| `_security_config_fields.py:911` | _SecurityConfigFields.detection_anomaly_threshold | `SecurityConfig.kt:1294` | FULL | |
| `_security_config_fields.py:918` | _SecurityConfigFields.detection_slow_pattern_threshold | `SecurityConfig.kt:1305` | FULL | |
| `_security_config_fields.py:925` | _SecurityConfigFields.detection_monitor_history_size | `SecurityConfig.kt:1316` | FULL | |
| `_security_config_fields.py:932` | _SecurityConfigFields.detection_max_tracked_patterns | `SecurityConfig.kt:1327` | FULL | |
| `_security_config_fields.py:939` | _SecurityConfigFields.detection_anomaly_emission_cooldown | `SecurityConfig.kt:1338` | FULL | |
| `_security_config_fields.py:949` | _SecurityConfigFields.detection_min_samples_for_anomaly | `SecurityConfig.kt:1349` | FULL | |
| `_security_config_fields.py:959` | _SecurityConfigFields.detection_threat_score_threshold | `SecurityConfig.kt:1360` | FULL | |
| `_security_config_fields.py:966` | _SecurityConfigFields.muted_event_types | `SecurityConfig.kt:1371` | FULL | |
| `_security_config_fields.py:971` | _SecurityConfigFields.muted_metric_types | `SecurityConfig.kt:1383` | FULL | |
| `_security_config_fields.py:976` | _SecurityConfigFields.muted_check_logs | `SecurityConfig.kt:1395` | FULL | |
| `_security_config_fields.py:981` | _SecurityConfigFields.log_sensitive_headers | `SecurityConfig.kt:1407` | FULL | |
| `_security_config_fields.py:989` | _SecurityConfigFields.log_sensitive_params | `SecurityConfig.kt:1419` | FULL | |
| `_security_config_fields.py:998` | _SecurityConfigFields.log_sensitive_body_fields | `SecurityConfig.kt:1431` | FULL | |
| `_security_config_fields.py:1008` | _SecurityConfigFields.enable_otel | `SecurityConfig.kt:1444` | FULL | |
| `_security_config_fields.py:1013` | _SecurityConfigFields.otel_service_name | `SecurityConfig.kt:1455` | FULL | |
| `_security_config_fields.py:1018` | _SecurityConfigFields.otel_exporter_endpoint | `SecurityConfig.kt:1466` | FULL | |
| `_security_config_fields.py:1023` | _SecurityConfigFields.otel_resource_attributes | `SecurityConfig.kt:1477` | FULL | |
| `_security_config_fields.py:1031` | _SecurityConfigFields.enable_logfire | `SecurityConfig.kt:1489` | FULL | |
| `_security_config_fields.py:1036` | _SecurityConfigFields.logfire_service_name | `SecurityConfig.kt:1500` | FULL | |
| `_security_config_fields.py:1041` | _SecurityConfigFields.enable_enrichment | `SecurityConfig.kt:1511` | FULL | |
| `_security_config_fields.py:1052` | _SecurityConfigFields.excluded_detection_headers | `SecurityConfig.kt:1522` | FULL | |
| `_security_config_fields.py:1061` | _SecurityConfigFields.excluded_detection_params | `SecurityConfig.kt:1534` | FULL | |
| `_security_config_fields.py:1067` | _SecurityConfigFields.excluded_detection_body_fields | `SecurityConfig.kt:1546` | FULL | |
| `_security_config_fields.py:1075` | _SecurityConfigFields.detection_scan_body | `SecurityConfig.kt:1558` | FULL | |
| `_security_config_fields.py:1083` | _SecurityConfigFields.enabled_detection_categories | `SecurityConfig.kt:1570` | FULL | |
| `detection_result.py:5` | DetectionResult | `DetectionResult.kt:8` | FULL | |
| `exceptions.py:1` | GuardCoreError | `Errors.kt:8` | FULL | |
| `exceptions.py:5` | GuardRedisError | `Errors.kt:14` | FULL | |
| `exceptions.py:12` | AgentPackageNotInstalledError | `Errors.kt:22` | FULL | |
| `models.py:76` | VALID_BYPASS_CHECKS | `ConfigFieldRegistry.kt:691` | FULL | |
| `models.py:87` | SecurityConfig | `SecurityConfig.kt:77` | FULL | |
| `models.py:122` | SecurityConfig.revision | `SecurityConfig.kt:2270` | FULL | |
| `models.py:125` | SecurityConfig.model_copy | `SecurityConfig.kt:2455` | IDIOMATIC | pydantic model_copy -> explicit copyWith(strict-validation preserved) |
| `models.py:135` | SecurityConfig.warn_unknown_fields | `SecurityConfigBuilder.kt:1188` | FULL | unknown-key warning at fromMap(warnUnknown=true); same message surface |
| `models.py:155` | SecurityConfig.validate_ip_lists | `ConfigValidators.kt:84` | FULL | validateIpOrCidrList behind the whitelist/blacklist/exempt_ips setters |
| `models.py:159` | SecurityConfig.validate_trusted_proxies | `ConfigValidators.kt:127` | FULL | |
| `models.py:165` | SecurityConfig.validate_proxy_depth | `ConfigValidators.kt:33` | FULL | validatePositiveIntFieldValue + setter bound checks |
| `models.py:171` | SecurityConfig.coerce_country_set | `ConfigValidators.kt:146` | FULL | validateCountrySetValue |
| `models.py:175` | SecurityConfig.validate_cloud_providers | `ConfigValidators.kt:286` | FULL | validateBlockCloudProvidersValue |
| `models.py:179` | SecurityConfig.validate_blocked_user_agents | `ConfigValidators.kt:373` | FULL | |
| `models.py:183` | SecurityConfig.validate_optional_extras_installed | `SecurityConfig.kt:2203` | FULL | port site names models.py:182; extras probing folded into the seams contract |
| `models.py:207` | SecurityConfig.validate_geo_ip_handler_exists | `SecurityConfig.kt:2111` | FULL | geoStateHook resolves the handler requirement per assignment (models.py:207 semantics) |
| `models.py:222` | SecurityConfig.warn_country_allowlist_shadows_blocklist | `SecurityConfig.kt:2178` | FULL | countryShadowShouldWarn, same warning text |
| `models.py:228` | SecurityConfig.validate_agent_config | `SecurityConfig.kt:2575` | FULL | agent config validation through ConfigSeams.agentConfigFactory (models.py:228) |
| `models.py:247` | SecurityConfig.validate_global_return_pattern_body_scan | `ConfigValidators.kt:399` | FULL | validateReturnPatternBodyScan applied to global_behavior_rules (validateGlobalBehaviorRuleAssignment :404) |
| `models.py:255` | SecurityConfig.warn_trusted_proxies_prefix_zero | `ConfigValidators.kt:439` | FULL | |
| `models.py:261` | SecurityConfig.warn_whitelist_prefix_zero | `ConfigValidators.kt:450` | FULL | |
| `models.py:267` | SecurityConfig.warn_exempt_ips_prefix_zero | `ConfigValidators.kt:460` | FULL | |
| `models.py:272` | SecurityConfig.warn_empty_enabled_detection_categories | `ConfigValidators.kt:470` | FULL | |
| `models.py:278` | SecurityConfig.validate_muted_event_types | `ConfigValidators.kt:227` | FULL | |
| `models.py:282` | SecurityConfig.validate_muted_metric_types | `ConfigValidators.kt:240` | FULL | |
| `models.py:286` | SecurityConfig.validate_enabled_detection_categories | `ConfigValidators.kt:214` | FULL | |
| `models.py:290` | SecurityConfig.validate_threat_ban_config | `ConfigValidators.kt:168` | FULL | |
| `models.py:294` | SecurityConfig.validate_muted_check_logs | `ConfigValidators.kt:253` | FULL | validateMutedCheckLogsValue |
| `models.py:298` | SecurityConfig.validate_log_sensitive_headers | `ConfigValidators.kt:266` | FULL | validateSensitiveNameSetValue |
| `models.py:302` | SecurityConfig.validate_log_sensitive_params | `ConfigValidators.kt:266` | FULL | validateSensitiveNameSetValue |
| `models.py:306` | SecurityConfig.validate_log_sensitive_body_fields | `ConfigValidators.kt:266` | FULL | validateSensitiveNameSetValue |
| `models.py:310` | SecurityConfig.validate_exclude_paths | `ConfigValidators.kt:306` | FULL | validateExcludePathsValue |
| `models.py:314` | SecurityConfig.validate_dynamic_rules_cache_path | `ConfigValidators.kt:340` | FULL | validateDynamicRulesCachePathValue |
| `models.py:317` | SecurityConfig.to_agent_config | `SecurityConfig.kt:2578` | FULL | |

## Protocols (framework-facing interfaces)

61 rows: 61 FULL, 0 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: Protocol tests green; both adapters (spring-boot-guard #2 252dc83, ktor-guard #2 7eb37a8) implement these interfaces over native request/response types; servlet/Starlette shapes byte-exact.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `protocols/agent_protocol.py:7` | AgentHandlerProtocol | `AgentProtocol.kt:7` | FULL | |
| `protocols/agent_protocol.py:18` | AgentHandlerProtocol.initialize_redis | `AgentProtocol.kt:9` | FULL | |
| `protocols/agent_protocol.py:22` | AgentHandlerProtocol.send_event | `AgentProtocol.kt:12` | FULL | |
| `protocols/agent_protocol.py:26` | AgentHandlerProtocol.send_metric | `AgentProtocol.kt:15` | FULL | |
| `protocols/agent_protocol.py:30` | AgentHandlerProtocol.start | `AgentProtocol.kt:18` | FULL | |
| `protocols/agent_protocol.py:34` | AgentHandlerProtocol.stop | `AgentProtocol.kt:21` | FULL | |
| `protocols/agent_protocol.py:38` | AgentHandlerProtocol.flush_buffer | `AgentProtocol.kt:24` | FULL | |
| `protocols/agent_protocol.py:42` | AgentHandlerProtocol.get_dynamic_rules | `AgentProtocol.kt:27` | FULL | |
| `protocols/agent_protocol.py:46` | AgentHandlerProtocol.health_check | `AgentProtocol.kt:30` | FULL | |
| `protocols/cloud_ip_store_protocol.py:8` | CloudIpStoreProtocol | `CloudIpStoreProtocol.kt:7` | FULL | |
| `protocols/cloud_ip_store_protocol.py:20` | CloudIpStoreProtocol.get | `CloudIpStoreProtocol.kt:9` | FULL | |
| `protocols/cloud_ip_store_protocol.py:24` | CloudIpStoreProtocol.set | `CloudIpStoreProtocol.kt:12` | FULL | |
| `protocols/cloud_ip_store_protocol.py:30` | CloudIpStoreProtocol.clear | `CloudIpStoreProtocol.kt:15` | FULL | |
| `protocols/geo_ip_protocol.py:8` | GeoIPHandler | `GeoIpProtocol.kt:7` | FULL | |
| `protocols/geo_ip_protocol.py:21` | GeoIPHandler.is_initialized | `GeoIpProtocol.kt:9` | FULL | |
| `protocols/geo_ip_protocol.py:25` | GeoIPHandler.initialize | `GeoIpProtocol.kt:12` | FULL | |
| `protocols/geo_ip_protocol.py:29` | GeoIPHandler.initialize_redis | `GeoIpProtocol.kt:15` | FULL | |
| `protocols/geo_ip_protocol.py:33` | GeoIPHandler.initialize_agent | `GeoIpProtocol.kt:18` | FULL | |
| `protocols/geo_ip_protocol.py:37` | GeoIPHandler.get_country | `GeoIpProtocol.kt:21` | FULL | |
| `protocols/geo_ip_protocol.py:41` | GeoIPHandler.refresh | `GeoIpProtocol.kt:24` | FULL | |
| `protocols/geo_ip_protocol.py:45` | GeoIPHandler.close | `GeoIpProtocol.kt:27` | FULL | |
| `protocols/middleware_protocol.py:13` | GuardMiddlewareProtocol | `MiddlewareProtocol.kt:15` | FULL | |
| `protocols/middleware_protocol.py:34` | GuardMiddlewareProtocol.event_bus | `MiddlewareProtocol.kt:29` | FULL | |
| `protocols/middleware_protocol.py:39` | GuardMiddlewareProtocol.route_resolver | `MiddlewareProtocol.kt:32` | FULL | |
| `protocols/middleware_protocol.py:44` | GuardMiddlewareProtocol.response_factory | `MiddlewareProtocol.kt:35` | FULL | |
| `protocols/middleware_protocol.py:49` | GuardMiddlewareProtocol.rate_limit_handler | `MiddlewareProtocol.kt:38` | FULL | |
| `protocols/middleware_protocol.py:54` | GuardMiddlewareProtocol.agent_handler | `MiddlewareProtocol.kt:41` | FULL | |
| `protocols/middleware_protocol.py:59` | GuardMiddlewareProtocol.geo_ip_handler | `MiddlewareProtocol.kt:44` | FULL | |
| `protocols/middleware_protocol.py:64` | GuardMiddlewareProtocol.guard_response_factory | `MiddlewareProtocol.kt:47` | FULL | |
| `protocols/middleware_protocol.py:68` | GuardMiddlewareProtocol.create_error_response | `MiddlewareProtocol.kt:57` | FULL | |
| `protocols/middleware_protocol.py:78` | GuardMiddlewareProtocol.refresh_cloud_ip_ranges | `MiddlewareProtocol.kt:60` | FULL | |
| `protocols/redis_protocol.py:7` | RedisHandlerProtocol | `RedisProtocol.kt:7` | FULL | |
| `protocols/redis_protocol.py:19` | RedisHandlerProtocol.get_key | `RedisProtocol.kt:9` | FULL | |
| `protocols/redis_protocol.py:23` | RedisHandlerProtocol.set_key | `RedisProtocol.kt:12` | FULL | |
| `protocols/redis_protocol.py:33` | RedisHandlerProtocol.delete | `RedisProtocol.kt:15` | FULL | |
| `protocols/redis_protocol.py:37` | RedisHandlerProtocol.keys | `RedisProtocol.kt:18` | FULL | |
| `protocols/redis_protocol.py:41` | RedisHandlerProtocol.initialize | `RedisProtocol.kt:21` | FULL | |
| `protocols/redis_protocol.py:45` | RedisHandlerProtocol.get_connection | `RedisProtocol.kt:27` | FULL | |
| `protocols/request_protocol.py:6` | GuardRequest | `RequestProtocol.kt:7` | FULL | |
| `protocols/request_protocol.py:19` | GuardRequest.url_path | `RequestProtocol.kt:9` | FULL | |
| `protocols/request_protocol.py:24` | GuardRequest.url_scheme | `RequestProtocol.kt:12` | FULL | |
| `protocols/request_protocol.py:29` | GuardRequest.url_full | `RequestProtocol.kt:15` | FULL | |
| `protocols/request_protocol.py:33` | GuardRequest.url_replace_scheme | `RequestProtocol.kt:18` | FULL | |
| `protocols/request_protocol.py:38` | GuardRequest.method | `RequestProtocol.kt:21` | FULL | |
| `protocols/request_protocol.py:43` | GuardRequest.client_host | `RequestProtocol.kt:24` | FULL | |
| `protocols/request_protocol.py:48` | GuardRequest.headers | `RequestProtocol.kt:27` | FULL | |
| `protocols/request_protocol.py:53` | GuardRequest.query_params | `RequestProtocol.kt:30` | FULL | |
| `protocols/request_protocol.py:57` | GuardRequest.body | `RequestProtocol.kt:35` | FULL | |
| `protocols/request_protocol.py:62` | GuardRequest.state | `RequestProtocol.kt:38` | FULL | |
| `protocols/request_protocol.py:67` | GuardRequest.scope | `RequestProtocol.kt:41` | FULL | |
| `protocols/request_protocol.py:73` | BoundedBodyReader | `RequestProtocol.kt:56` | FULL | |
| `protocols/request_protocol.py:104` | BoundedBodyReader.read_body_prefix | `RequestProtocol.kt:58` | FULL | |
| `protocols/response_protocol.py:6` | GuardResponse | `ResponseProtocol.kt:8` | FULL | |
| `protocols/response_protocol.py:18` | GuardResponse.status_code | `ResponseProtocol.kt:10` | FULL | |
| `protocols/response_protocol.py:23` | GuardResponse.headers | `ResponseProtocol.kt:13` | FULL | |
| `protocols/response_protocol.py:28` | GuardResponse.body | `ResponseProtocol.kt:16` | FULL | |
| `protocols/response_protocol.py:34` | GuardResponseFactory | `ResponseProtocol.kt:20` | FULL | |
| `protocols/response_protocol.py:45` | GuardResponseFactory.create_response | `ResponseProtocol.kt:22` | FULL | |
| `protocols/response_protocol.py:49` | GuardResponseFactory.create_redirect_response | `ResponseProtocol.kt:25` | FULL | |
| `protocols/response_protocol.py:55` | BoundedResponseBodyReader | `ResponseProtocol.kt:33` | FULL | |
| `protocols/response_protocol.py:113` | BoundedResponseBodyReader.read_body_prefix | `ResponseProtocol.kt:35` | FULL | |

## Utilities (_utils/)

25 rows: 25 FULL, 0 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: W1 97 JUnit tests + W4a G-7a..G-7d closure (scan/budget/body-scan family) + W2 PyRe/PyUrllib/PyJson CPython-table probes; body suites green through the corpus.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `_utils/access_control.py:15` | is_user_agent_allowed | `AccessControl.kt:36` | FULL | |
| `_utils/access_control.py:122` | check_ip_country | `AccessControl.kt:158` | FULL | |
| `_utils/access_control.py:166` | IpAccessResult | `AccessControl.kt:201` | FULL | |
| `_utils/access_control.py:241` | check_ip_access | `AccessControl.kt:285` | FULL | |
| `_utils/access_control.py:284` | is_ip_allowed | `AccessControl.kt:320` | FULL | |
| `_utils/agent_events.py:15` | invoke_error_hook | `AgentEvents.kt:18` | FULL | |
| `_utils/agent_events.py:29` | get_pipeline_response_time | `AgentEvents.kt:43` | FULL | |
| `_utils/agent_events.py:39` | send_agent_event | `AgentEvents.kt:63` | FULL | |
| `_utils/block_events.py:11` | ON_BLOCK_EXCLUDED_CHECK_NAMES | `BlockEvents.kt:15` | FULL | |
| `_utils/block_events.py:16` | invoke_block_hook | `BlockEvents.kt:19` | FULL | |
| `_utils/block_events.py:31` | build_block_payload | `BlockEvents.kt:34` | FULL | |
| `_utils/block_events.py:66` | fire_block_hook | `BlockEvents.kt:71` | FULL | |
| `_utils/body_reader.py:27` | _BoundedBodyReader.read_body_prefix | `BodyReader.kt:81` | FULL | readCappedBodyPrefix |
| `_utils/ip_extraction.py:12` | UNKNOWN_CLIENT_IDENTITY | `IpExtraction.kt:18` | FULL | |
| `_utils/ip_extraction.py:324` | extract_client_ip | `IpExtraction.kt:314` | FULL | |
| `_utils/logging_utils.py:176` | JsonFormatter | `LoggingUtils.kt:244` | FULL | JsonLogFormatter |
| `_utils/logging_utils.py:177` | JsonFormatter.format | `LoggingUtils.kt:245` | FULL | |
| `_utils/logging_utils.py:196` | _YieldToHostRootHandlers.filter | `LoggingUtils.kt:292` | FULL | yield-to-host-root filter port (KDoc names logging_utils.py:195) |
| `_utils/logging_utils.py:203` | setup_custom_logging | `LoggingUtils.kt:304` | FULL | |
| `_utils/penetration_detection.py:162` | detect_penetration_attempt | `PenetrationDetection.kt:253` | FULL | |
| `_utils/request_logging.py:216` | redact_url_for_display | `RequestLogging.kt:228` | FULL | |
| `_utils/request_logging.py:259` | redact_endpoint_for_display | `RequestLogging.kt:268` | FULL | |
| `_utils/request_logging.py:295` | redact_blob_for_display | `RequestLogging.kt:300` | FULL | |
| `_utils/request_logging.py:317` | redact_header_value_for_display | `RequestLogging.kt:325` | FULL | |
| `_utils/request_logging.py:432` | log_activity | `RequestLogging.kt:452` | FULL | |

## Handlers (handlers/ + scripts/rate_lua.py)

152 rows: 132 FULL, 20 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: 307 handler tests green (W3, 12 JUnit classes); redis_interop 14/14 GREEN against live Redis (schema byte-exact); rate_lua byte-exact; W8a handler-halves tests.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `handlers/_behavior_action_dispatch.py:15` | BehaviorActionDispatchMixin | `BehaviorActionDispatch.kt:1` | IDIOMATIC | mixin -> top-level dispatch functions over BehaviorTracker |
| `handlers/_behavior_action_dispatch.py:99` | BehaviorActionDispatchMixin.apply_action | `BehaviorActionDispatch.kt:107` | FULL | |
| `handlers/_behavior_json_pattern.py:4` | BehaviorJsonPatternMixin | `BehaviorResponsePattern.kt:1` | IDIOMATIC | mixin -> json-pattern group inside BehaviorResponsePattern.kt |
| `handlers/_behavior_response_pattern.py:16` | _BoundedResponseBodyReader.read_body_prefix | `BodyReader.kt:81` | FULL | readCappedBodyPrefix |
| `handlers/_behavior_response_pattern.py:19` | BehaviorResponsePatternMixin | `BehaviorResponsePattern.kt:1` | IDIOMATIC | mixin fold |
| `handlers/_cloud_azure_fetch.py:161` | fetch_azure_ip_ranges | `CloudAzureFetch.kt:249` | FULL | |
| `handlers/_cloud_provider_fetchers.py:9` | fetch_aws_ip_ranges | `CloudFetchers.kt:48` | FULL | |
| `handlers/_cloud_provider_fetchers.py:36` | fetch_gcp_ip_ranges | `CloudFetchers.kt:79` | FULL | |
| `handlers/_cloud_provider_fetchers.py:90` | fetch_digitalocean_ip_ranges | `CloudFetchers.kt:136` | FULL | fetchDigitalOceanIpRanges |
| `handlers/_cloud_provider_fetchers.py:102` | fetch_linode_ip_ranges | `CloudFetchers.kt:146` | FULL | |
| `handlers/_cloud_provider_fetchers.py:112` | fetch_vultr_ip_ranges | `CloudFetchers.kt:156` | FULL | |
| `handlers/_dynamic_rule_application.py:18` | DynamicRuleApplicationMixin | `DynamicRuleManager.kt:313` | IDIOMATIC | mixin -> member group under the _dynamic_rule_application.py banner in DynamicRuleManager |
| `handlers/_dynamic_rule_events.py:10` | DynamicRuleEventSenderMixin | `DynamicRuleEvents.kt:1` | IDIOMATIC | mixin -> DynamicRuleEvents |
| `handlers/_dynamic_rule_persistence.py:4` | DYNAMIC_RULES_REDIS_NAMESPACE | `DynamicRuleManager.kt:24` | FULL | |
| `handlers/_dynamic_rule_persistence.py:5` | LAST_KNOWN_RULES_KEY | `DynamicRuleManager.kt:25` | FULL | |
| `handlers/_dynamic_rule_persistence.py:8` | resolve_redis_value | `DynamicRuleManager.kt:693` | FULL | |
| `handlers/_dynamic_rule_snapshot.py:21` | DynamicRuleSnapshotMixin | `DynamicRuleManager.kt:600` | IDIOMATIC | mixin -> hydration/persistence group in DynamicRuleManager |
| `handlers/_ipban_bans.py:18` | IpBanOperationsMixin | `IpBanManager.kt:1` | IDIOMATIC | mixin -> extension functions over IpBanManager (IpBanBans.kt and friends) |
| `handlers/_ipban_bans.py:19` | IpBanOperationsMixin.LOCAL_CACHE_TTL_CAP_SECONDS | `IpBanManager.kt:20` | FULL | |
| `handlers/_ipban_bans.py:146` | IpBanOperationsMixin.ban_ip | `IpBanBans.kt:234` | FULL | |
| `handlers/_ipban_cache.py:20` | _ObservableTTLCache.popitem | `TtlCache.kt:61` | FULL | popItem + onEvict callback (the observable wrapper, KDoc names _ObservableTTLCache.popitem) |
| `handlers/_ipban_events.py:8` | IpBanEventMixin | `IpBanManager.kt:1` | IDIOMATIC | mixin -> IpBanBans.kt event extensions over IpBanManager |
| `handlers/_ipban_events.py:12` | IpBanEventMixin.initialize_agent | `BehaviorTracker.kt:86` | FULL | |
| `handlers/_ipban_migration.py:18` | IpBanMigrationMixin | `IpBanManager.kt:1` | IDIOMATIC | mixin -> IpBanMigration.kt extensions |
| `handlers/_ipban_migration.py:22` | IpBanMigrationMixin.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/_ipban_queries.py:12` | IpBanQueryMixin | `IpBanManager.kt:1` | IDIOMATIC | mixin -> IpBanQueries.kt extensions |
| `handlers/_ipban_queries.py:48` | IpBanQueryMixin.is_ip_banned | `IpBanQueries.kt:49` | FULL | |
| `handlers/_ipban_queries.py:72` | IpBanQueryMixin.unban_ip | `IpBanQueries.kt:81` | FULL | |
| `handlers/_ipban_queries.py:82` | IpBanQueryMixin.reset | `IpBanQueries.kt:93` | FULL | |
| `handlers/_security_headers_cache.py:13` | SecurityHeadersCacheMixin | `SecurityHeadersManager.kt:1` | IDIOMATIC | mixin -> cache group SecurityHeadersManager.kt:393-497 |
| `handlers/_security_headers_cache.py:42` | SecurityHeadersCacheMixin.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/_security_headers_cache.py:109` | SecurityHeadersCacheMixin.reset | `SecurityHeadersManager.kt:525` | FULL | |
| `handlers/_security_headers_config.py:10` | SecurityHeadersConfigMixin | `SecurityHeadersManager.kt:1` | IDIOMATIC | mixin -> config group SecurityHeadersManager.kt:117-322 |
| `handlers/_security_headers_config.py:253` | SecurityHeadersConfigMixin.configure | `SecurityHeadersManager.kt:341` | FULL | |
| `handlers/_security_headers_cors.py:8` | SecurityHeadersCorsMixin | `SecurityHeadersManager.kt:1` | IDIOMATIC | mixin -> CORS group SecurityHeadersManager.kt:502-576 |
| `handlers/_security_headers_cors.py:79` | SecurityHeadersCorsMixin.get_cors_headers | `SecurityHeadersManager.kt:615` | FULL | |
| `handlers/_security_headers_events.py:28` | SecurityHeadersEventsMixin | `SecurityHeadersManager.kt:1` | IDIOMATIC | mixin -> events group SecurityHeadersManager.kt:581-660 |
| `handlers/_security_headers_events.py:32` | SecurityHeadersEventsMixin.initialize_agent | `BehaviorTracker.kt:86` | FULL | |
| `handlers/_security_headers_events.py:61` | SecurityHeadersEventsMixin.validate_csp_report | `SecurityHeadersManager.kt:666` | FULL | |
| `handlers/_suspatterns_enhanced.py:29` | _SusPatternsEnhancedMixin.configure | `SecurityHeadersManager.kt:341` | FULL | |
| `handlers/_suspatterns_enhanced.py:144` | _SusPatternsEnhancedMixin.get_performance_stats | `Monitor.kt:475` | IDIOMATIC | classmethod aggregate (summary+slow+problematic) -> the three Monitor accessors getSummaryStats/getSlowPatterns(:462)/getProblematicPatterns(:469) |
| `handlers/_suspatterns_enhanced.py:158` | _SusPatternsEnhancedMixin.get_component_status | `SusPatternsState.kt:20` | IDIOMATIC | introspection dict -> DetectionState exposes the components (compiler/preprocessor/semantic/monitor) |
| `handlers/_suspatterns_enhanced.py:168` | _SusPatternsEnhancedMixin.configure_semantic_threshold | `SusPatternsManager.kt:853` | IDIOMATIC | instance mutation -> build-time knob (clamped at config build, replayed by the detection knobs) |
| `handlers/_suspatterns_ldap_ipv4.py:21` | ALWAYS_SCAN_HEADER_PATTERNS | `SusPatternsLdapIpv4.kt:15` | FULL | |
| `handlers/_suspatterns_pattern_table.py:120` | NOISE_PRONE_PATTERN_SOURCES | `SusPatternsTable.kt:13` | FULL | |
| `handlers/_suspatterns_pattern_table.py:777` | RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES | `SusPatternsTable.kt:508` | FULL | |
| `handlers/_suspatterns_pattern_table.py:789` | DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES | `SusPatternsTable.kt:515` | FULL | |
| `handlers/_suspatterns_pickle.py:29` | _PickleOpcodePrefixUnpickler.find_class | `SusPatternsPickle.kt:214` | IDIOMATIC | unpickler dispatch -> explicit opcode table; blocked resolutions raise (PickleOpcodeError "global") |
| `handlers/_suspatterns_pickle.py:32` | _PickleOpcodePrefixUnpickler.get_extension | `SusPatternsPickle.kt:153` | IDIOMATIC | extension opcodes reject via PickleOpcodeError (buffer-opcode branch) |
| `handlers/_suspatterns_pickle.py:35` | _PickleOpcodePrefixUnpickler.persistent_load | `SusPatternsPickle.kt:214` | IDIOMATIC | persistent_load path raises, mirroring the blocked-resolution exceptions |
| `handlers/_suspatterns_regex.py:95` | DETECTION_CATEGORY_WEIGHTS | `SusPatternsManager.kt:34` | FULL | CATEGORY_WEIGHTS |
| `handlers/_suspatterns_regex.py:99` | DETECTION_PATTERN_WEIGHT_OVERRIDES | `SusPatternsManager.kt:36` | FULL | PATTERN_WEIGHT_OVERRIDES |
| `handlers/_suspatterns_registry.py:63` | _SusPatternsRegistryMixin.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/_suspatterns_registry.py:83` | _SusPatternsRegistryMixin.add_pattern | `SusPatternsRegistry.kt:90` | FULL | |
| `handlers/_suspatterns_registry.py:196` | _SusPatternsRegistryMixin.remove_pattern | `SusPatternsRegistry.kt:195` | FULL | |
| `handlers/_suspatterns_registry.py:216` | _SusPatternsRegistryMixin.get_default_patterns | `SusPatternsRegistry.kt:216` | FULL | |
| `handlers/_suspatterns_registry.py:221` | _SusPatternsRegistryMixin.get_custom_patterns | `SusPatternsRegistry.kt:219` | FULL | |
| `handlers/_suspatterns_registry.py:226` | _SusPatternsRegistryMixin.get_all_patterns | `SusPatternsRegistry.kt:222` | FULL | |
| `handlers/_suspatterns_registry.py:231` | _SusPatternsRegistryMixin.get_default_compiled_patterns | `SusPatternsRegistry.kt:216` | FULL | getDefaultPatterns (compilation lives engine-side) |
| `handlers/_suspatterns_registry.py:238` | _SusPatternsRegistryMixin.get_custom_compiled_patterns | `SusPatternsRegistry.kt:219` | FULL | getCustomPatterns |
| `handlers/_suspatterns_registry.py:245` | _SusPatternsRegistryMixin.get_all_compiled_patterns | `SusPatternsManager.kt:364` | FULL | |
| `handlers/_suspatterns_registry.py:252` | _SusPatternsRegistryMixin.reset | `SusPatternsRegistry.kt:343` | FULL | |
| `handlers/_suspatterns_shell_sources.py:69` | DETECTION_RAW_VIEW_PATTERN_SOURCES | `SusPatternsShell.kt:67` | FULL | |
| `handlers/_suspatterns_shell_sources.py:90` | DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES | `SusPatternsShell.kt:87` | FULL | |
| `handlers/_suspatterns_sources.py:89` | ALL_DETECTION_CATEGORIES | `SusPatternsSources.kt:92` | FULL | |
| `handlers/_suspatterns_sources.py:113` | CATEGORY_CONTEXT_MAP | `SusPatternsSources.kt:115` | FULL | |
| `handlers/_suspatterns_templates.py:51` | template_keyword_matches | `SusPatternsFileUploadTemplates.kt:321` | FULL | |
| `handlers/_suspatterns_templates.py:77` | template_expression_matches | `SusPatternsFileUploadTemplates.kt:358` | FULL | |
| `handlers/behavior_handler.py:28` | BehaviorRule | `BehaviorTracker.kt:22` | FULL | |
| `handlers/behavior_handler.py:54` | BehaviorTracker | `BehaviorTracker.kt:57` | FULL | |
| `handlers/behavior_handler.py:71` | BehaviorTracker.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/behavior_handler.py:74` | BehaviorTracker.initialize_agent | `BehaviorTracker.kt:86` | FULL | |
| `handlers/behavior_handler.py:77` | BehaviorTracker.get_recent_event_count | `BehaviorTracker.kt:91` | FULL | |
| `handlers/behavior_handler.py:89` | BehaviorTracker.track_endpoint_usage | `BehaviorTracker.kt:110` | FULL | |
| `handlers/behavior_handler.py:126` | BehaviorTracker.track_return_pattern | `BehaviorTracker.kt:155` | FULL | |
| `handlers/behavior_handler.py:182` | config_to_rule | `BehaviorTracker.kt:36` | FULL | |
| `handlers/cloud_handler.py:106` | CloudManager | `CloudManager.kt:18` | FULL | |
| `handlers/cloud_handler.py:146` | CloudManager.set_store | `CloudManager.kt:78` | FULL | store var (settable CloudIpStore) |
| `handlers/cloud_handler.py:149` | CloudManager.schedule_refresh | `CloudManager.kt:91` | FULL | |
| `handlers/cloud_handler.py:223` | CloudManager.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/cloud_handler.py:236` | CloudManager.initialize_agent | `BehaviorTracker.kt:86` | FULL | |
| `handlers/cloud_handler.py:239` | CloudManager.refresh | `CloudManager.kt:191` | FULL | |
| `handlers/cloud_handler.py:244` | CloudManager.refresh_async | `CloudManager.kt:199` | FULL | |
| `handlers/cloud_handler.py:328` | CloudManager.is_cloud_ip | `CloudManager.kt:312` | FULL | |
| `handlers/cloud_handler.py:351` | CloudManager.get_status | `CloudManager.kt:343` | FULL | |
| `handlers/cloud_handler.py:361` | CloudManager.get_cloud_provider_details | `CloudManager.kt:352` | FULL | |
| `handlers/cloud_handler.py:376` | CloudManager.send_cloud_detection_event | `CloudManager.kt:377` | FULL | |
| `handlers/cloud_ip_stores.py:8` | InMemoryCloudIpStore | `CloudIpStores.kt:17` | FULL | |
| `handlers/cloud_ip_stores.py:13` | InMemoryCloudIpStore.get | `CloudIpStores.kt:9` | FULL | |
| `handlers/cloud_ip_stores.py:24` | InMemoryCloudIpStore.set | `CloudIpStores.kt:11` | FULL | |
| `handlers/cloud_ip_stores.py:33` | InMemoryCloudIpStore.clear | `CloudIpStores.kt:13` | FULL | |
| `handlers/cloud_ip_stores.py:38` | RedisCloudIpStore | `CloudIpStores.kt:53` | FULL | |
| `handlers/cloud_ip_stores.py:47` | RedisCloudIpStore.get | `CloudIpStores.kt:9` | FULL | |
| `handlers/cloud_ip_stores.py:59` | RedisCloudIpStore.set | `CloudIpStores.kt:11` | FULL | |
| `handlers/cloud_ip_stores.py:65` | RedisCloudIpStore.clear | `CloudIpStores.kt:13` | FULL | |
| `handlers/cors_handler.py:6` | ALLOWED_PREFLIGHT_REQUEST_HEADER | `CorsHandler.kt:6` | FULL | |
| `handlers/cors_handler.py:10` | CorsPreflightResponse | `CorsHandler.kt:12` | FULL | |
| `handlers/cors_handler.py:16` | is_preflight | `CorsHandler.kt:32` | FULL | |
| `handlers/cors_handler.py:26` | CorsHandler | `CorsHandler.kt:46` | FULL | |
| `handlers/cors_handler.py:63` | CorsHandler.is_origin_allowed | `CorsHandler.kt:92` | FULL | |
| `handlers/cors_handler.py:104` | CorsHandler.build_preflight_response | `CorsHandler.kt:137` | FULL | |
| `handlers/cors_handler.py:144` | CorsHandler.build_response_headers | `CorsHandler.kt:174` | FULL | |
| `handlers/dynamic_rule_handler.py:22` | DynamicRuleManager | `DynamicRuleManager.kt:42` | FULL | |
| `handlers/dynamic_rule_handler.py:74` | DynamicRuleManager.initialize_agent | `DynamicRuleManager.kt:104` | FULL | |
| `handlers/dynamic_rule_handler.py:86` | DynamicRuleManager.initialize_redis | `SusPatternsRegistry.kt:65` | FULL | |
| `handlers/dynamic_rule_handler.py:89` | DynamicRuleManager.match_event | `DynamicRuleManager.kt:153` | FULL | |
| `handlers/dynamic_rule_handler.py:187` | DynamicRuleManager.update_rules | `DynamicRuleManager.kt:239` | FULL | |
| `handlers/dynamic_rule_handler.py:259` | DynamicRuleManager.get_current_rules | `DynamicRuleManager.kt:317` | FULL | |
| `handlers/dynamic_rule_handler.py:262` | DynamicRuleManager.force_update | `DynamicRuleManager.kt:320` | FULL | |
| `handlers/dynamic_rule_handler.py:265` | DynamicRuleManager.stop | `DynamicRuleManager.kt:541` | FULL | |
| `handlers/ipban_handler.py:29` | IPBanManager | `IpBanManager.kt:1` | FULL | IpBanManager (initialism casing) |
| `handlers/ipban_handler.py:69` | reset_global_state | `IpBanManager.kt:102` | FULL | resetIpBanGlobalState |
| `handlers/ipinfo_handler.py:33` | IPInfoManager | `IpInfoManager.kt:1` | FULL | IpInfoManager (initialism casing) |
| `handlers/ipinfo_handler.py:74` | IPInfoManager.is_initialized | `IpInfoManager.kt:144` | FULL | isInitialized |
| `handlers/ipinfo_handler.py:78` | IPInfoManager.entry_count | `IpInfoManager.kt:148` | FULL | |
| `handlers/ipinfo_handler.py:83` | IPInfoManager.get_status | `IpInfoManager.kt:152` | FULL | |
| `handlers/ipinfo_handler.py:90` | IPInfoManager.initialize_agent | `IpInfoManager.kt:160` | FULL | |
| `handlers/ipinfo_handler.py:120` | IPInfoManager.initialize | `IpInfoManager.kt:205` | FULL | |
| `handlers/ipinfo_handler.py:239` | IPInfoManager.get_country | `IpInfoManager.kt:342` | FULL | |
| `handlers/ipinfo_handler.py:276` | IPInfoManager.check_country_access | `IpInfoManager.kt:379` | FULL | |
| `handlers/ipinfo_handler.py:313` | IPInfoManager.close | `IpInfoManager.kt:419` | FULL | |
| `handlers/ipinfo_handler.py:317` | IPInfoManager.refresh | `IpInfoManager.kt:431` | FULL | |
| `handlers/ipinfo_handler.py:337` | IPInfoManager.initialize_redis | `IpInfoManager.kt:453` | FULL | |
| `handlers/ratelimit_handler.py:199` | check_rate_limit_by_ip | `RateLimitManager.kt:255` | FULL | |
| `handlers/ratelimit_handler.py:305` | RateLimitManager | `RateLimitManager.kt:330` | FULL | |
| `handlers/ratelimit_handler.py:329` | RateLimitManager.initialize_redis | `RateLimitManager.kt:375` | FULL | |
| `handlers/ratelimit_handler.py:342` | RateLimitManager.initialize_agent | `RateLimitManager.kt:392` | FULL | |
| `handlers/ratelimit_handler.py:450` | RateLimitManager.check_rate_limit | `RateLimitManager.kt:496` | FULL | |
| `handlers/ratelimit_handler.py:561` | RateLimitManager.reset | `RateLimitManager.kt:34` | FULL | |
| `handlers/redis_handler.py:52` | RedisManager | `RedisManager.kt:295` | FULL | |
| `handlers/redis_handler.py:70` | RedisManager.initialize_agent | `RedisManager.kt:319` | FULL | |
| `handlers/redis_handler.py:131` | RedisManager.initialize | `RedisManager.kt:452` | FULL | |
| `handlers/redis_handler.py:181` | RedisManager.close | `RedisManager.kt:202` | FULL | |
| `handlers/redis_handler.py:194` | RedisManager.get_connection | `RedisManager.kt:559` | FULL | |
| `handlers/redis_handler.py:230` | RedisManager.safe_operation | `RedisManager.kt:569` | FULL | |
| `handlers/redis_handler.py:250` | RedisManager.get_key | `RedisManager.kt:595` | FULL | |
| `handlers/redis_handler.py:260` | RedisManager.set_key | `RedisManager.kt:601` | FULL | |
| `handlers/redis_handler.py:275` | RedisManager.incr | `RedisManager.kt:52` | FULL | |
| `handlers/redis_handler.py:298` | RedisManager.record_sliding_window_hit | `RedisManager.kt:637` | FULL | |
| `handlers/redis_handler.py:317` | RedisManager.exists | `RedisManager.kt:48` | FULL | |
| `handlers/redis_handler.py:328` | RedisManager.delete | `RedisManager.kt:668` | FULL | |
| `handlers/redis_handler.py:340` | RedisManager.keys | `RedisManager.kt:50` | FULL | |
| `handlers/redis_handler.py:352` | RedisManager.delete_pattern | `RedisManager.kt:683` | FULL | |
| `handlers/security_headers_handler.py:14` | SecurityHeadersManager | `SecurityHeadersManager.kt:23` | FULL | |
| `handlers/security_headers_handler.py:82` | SecurityHeadersManager.get_headers | `SecurityHeadersManager.kt:402` | FULL | |
| `handlers/security_headers_handler.py:125` | reset_global_state | `SecurityHeadersManager.kt:45` | FULL | resetInstance |
| `handlers/suspatterns_handler.py:690` | SEMANTIC_ATTACK_TYPE_TO_CATEGORY | `SusPatternsManager.kt:65` | FULL | |
| `handlers/suspatterns_handler.py:758` | SusPatternsManager | `SusPatternsManager.kt:276` | FULL | |
| `handlers/suspatterns_handler.py:852` | SusPatternsManager.initialize_agent | `BehaviorTracker.kt:86` | FULL | |
| `handlers/suspatterns_handler.py:855` | SusPatternsManager.detect | `SusPatternsManager.kt:940` | FULL | |
| `handlers/suspatterns_handler.py:1052` | SusPatternsManager.detect_pattern_match | `SusPatternsRegistry.kt:230` | FULL | handler-level detect(content, ip, context, correlation_id) returning (matched, category) |
| `scripts/rate_lua.py:1` | RATE_LIMIT_SCRIPT | `RateLimitScript.kt:7` | FULL | |

## Detection engine (detection_engine/ incl. the 25 _redos_* modules)

148 rows: 143 FULL, 5 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: detect suite 193/193 ZERO xfails; pattern_safety 88 green + 6 ledgered timing facts; cost budgets 9/9 under ceiling (5.7-16x headroom); pattern ledger 158 as_is / 0 translated; 184 W2 unit tests + RedosChainTest/CompilerRedosTest/PyReBehaviorTest.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `detection_engine/_redos_cost_arbiter.py:181` | ReachProbeTiming | `ProbeBatches.kt:15` | FULL | |
| `detection_engine/_redos_ignorecase_fold.py:134` | expand_ignorecase | `IgnorecaseFold.kt:154` | FULL | |
| `detection_engine/_redos_intervals.py:5` | MIN_CODE_POINT | `IntervalSet.kt:10` | FULL | |
| `detection_engine/_redos_intervals.py:6` | MAX_CODE_POINT | `IntervalSet.kt:11` | FULL | |
| `detection_engine/_redos_intervals.py:37` | _IntervalSet.empty | `IntervalSet.kt:36` | FULL | |
| `detection_engine/_redos_intervals.py:41` | _IntervalSet.full | `IntervalSet.kt:38` | FULL | |
| `detection_engine/_redos_intervals.py:45` | _IntervalSet.single | `IntervalSet.kt:41` | FULL | |
| `detection_engine/_redos_intervals.py:49` | _IntervalSet.from_range | `IntervalSet.kt:44` | FULL | |
| `detection_engine/_redos_intervals.py:56` | _IntervalSet.is_empty | `IntervalSet.kt:58` | FULL | |
| `detection_engine/_redos_intervals.py:59` | _IntervalSet.contains | `IntervalSet.kt:68` | FULL | |
| `detection_engine/_redos_intervals.py:73` | _IntervalSet.first_member | `IntervalSet.kt:85` | FULL | |
| `detection_engine/_redos_intervals.py:78` | _IntervalSet.component_first_members | `IntervalSet.kt:87` | FULL | |
| `detection_engine/_redos_intervals.py:81` | _IntervalSet.union | `IntervalSet.kt:89` | FULL | |
| `detection_engine/_redos_intervals.py:84` | _IntervalSet.intersection | `IntervalSet.kt:92` | FULL | |
| `detection_engine/_redos_intervals.py:101` | _IntervalSet.complement | `IntervalSet.kt:109` | FULL | |
| `detection_engine/_redos_intervals.py:112` | _IntervalSet.difference | `IntervalSet.kt:120` | FULL | |
| `detection_engine/_redos_intervals.py:130` | cached_category_intervals | `IntervalSet.kt:137` | FULL | |
| `detection_engine/_redos_probe_batches.py:12` | _ReachProbeTimingLike.samples_by_size | `ProbeBatches.kt:16` | FULL | |
| `detection_engine/_redos_probe_batches.py:15` | _ReachProbeTimingLike.load_factor | `ProbeBatches.kt:17` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:104` | _PrefixWalk.walk | `RepeatPrefix.kt:80` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:119` | _PrefixWalk.check_remaining_repeats | `RepeatPrefix.kt:98` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:123` | _PrefixWalk.atoms | `RepeatPrefix.kt:104` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:133` | _PrefixWalk.record_prefixes | `RepeatPrefix.kt:109` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:141` | _PrefixWalk.repeat | `RepeatPrefix.kt:122` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:174` | _PrefixWalk.pending_repeats | `RepeatPrefix.kt:157` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:194` | _PrefixWalk.branch | `RepeatPrefix.kt:179` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:208` | _PrefixWalk.group | `RepeatPrefix.kt:191` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:231` | _PrefixWalk.assertion | `RepeatPrefix.kt:217` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:252` | _PrefixWalk.backreference | `RepeatPrefix.kt:244` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:265` | _PrefixWalk.node | `RepeatPrefixState.kt:177` | FULL | |
| `detection_engine/_redos_repeat_prefix.py:296` | _PrefixWalk.conditional | `RepeatPrefix.kt:254` | FULL | |
| `detection_engine/_redos_stray_chooser.py:277` | choose_class_intersection_stray | `StrayChooser.kt:241` | FULL | |
| `detection_engine/_redos_stray_chooser.py:307` | choose_repeat_unit_stray | `StrayChooser.kt:265` | FULL | |
| `detection_engine/_redos_structure_primitives.py:158` | GroupNestingTooDeep | `StructurePrimitives.kt:174` | FULL | |
| `detection_engine/_validation_cache.py:36` | ENGINE_VERSION | `GuardCoreEngine.kt:10` | IDIOMATIC | importlib version probe -> build-time const GuardCoreEngine.VERSION = "4.3.2" (lockstep mirror) |
| `detection_engine/_validation_cache.py:39` | PatternValidationCache | `ValidationCache.kt:14` | FULL | |
| `detection_engine/_validation_cache.py:82` | PatternValidationCache.get | `ValidationCache.kt:50` | FULL | |
| `detection_engine/_validation_cache.py:89` | PatternValidationCache.put | `ValidationCache.kt:56` | FULL | |
| `detection_engine/base64_alphabet.py:4` | DATA_CHARS | `Base64.kt:11` | FULL | |
| `detection_engine/base64_alphabet.py:5` | SEPARATOR_CHARS | `Base64.kt:14` | FULL | |
| `detection_engine/base64_alphabet.py:8` | WIDENED_SEPARATOR_CHARS | `Base64.kt:25` | FULL | |
| `detection_engine/base64_alphabet.py:12` | URLSAFE_TRANSLATION | `Base64.kt:31` | IDIOMATIC | translation table -> urlsafeTranslate(ch) total function, same mapping |
| `detection_engine/base64_alphabet.py:13` | WIDENED_CANDIDATE_MARKER_RE | `Base64.kt:25` | IDIOMATIC | marker-char regex -> WIDENED_SEPARATOR_CHARS set + widenedMarker |
| `detection_engine/base64_decode.py:7` | MIN_RUN_LENGTH | `Base64Decode.kt:14` | FULL | |
| `detection_engine/base64_decode.py:8` | DATA_ALPHABET | `Base64Decode.kt:22` | FULL | |
| `detection_engine/base64_decode.py:10` | BASE64_RE | `Base64Decode.kt:28` | FULL | |
| `detection_engine/base64_decode.py:17` | RUN_RE | `Base64Decode.kt:38` | FULL | |
| `detection_engine/base64_decode.py:21` | SUB_FLOOR_RUN_RE | `Base64Decode.kt:44` | FULL | |
| `detection_engine/base64_decode.py:26` | WHITESPACE_RE | `Base64Decode.kt:54` | FULL | |
| `detection_engine/base64_decode.py:27` | HEX_LITERAL_RE | `Base64Decode.kt:52` | FULL | |
| `detection_engine/base64_decode.py:29` | GZIP_MAGIC | `Base64Decode.kt:96` | FULL | gzip magic check inlined at the head of boundedGunzip (comment names it) |
| `detection_engine/base64_decode.py:30` | MAX_GUNZIP_OUTPUT_BYTES | `Base64Decode.kt:16` | FULL | |
| `detection_engine/base64_decode.py:31` | MAX_GUNZIP_ATTEMPTS_PER_PASS | `Base64Decode.kt:15` | FULL | |
| `detection_engine/base64_decode.py:33` | PRINTABLE_RATIO_THRESHOLD | `Base64Decode.kt:17` | FULL | |
| `detection_engine/base64_decode.py:34` | FALLBACK_PRINTABLE_RATIO_THRESHOLD | `Base64Decode.kt:18` | FULL | |
| `detection_engine/base64_decode.py:35` | MAX_REPLACEMENT_CHAR_RATIO | `Base64Decode.kt:19` | FULL | |
| `detection_engine/base64_decode.py:38` | is_hex_literal | `Base64Decode.kt:73` | FULL | |
| `detection_engine/base64_decode.py:42` | printable_ratio | `Base64Decode.kt:76` | FULL | |
| `detection_engine/base64_decode.py:49` | replacement_char_ratio | `Base64Decode.kt:85` | FULL | |
| `detection_engine/base64_decode.py:55` | bounded_gunzip | `Base64Decode.kt:97` | FULL | |
| `detection_engine/base64_decode.py:69` | decode_base64_candidates | `Base64Decode.kt:199` | FULL | |
| `detection_engine/base64_view.py:8` | SHORT_BASE64_TOKEN_RE | `Base64View.kt:17` | FULL | |
| `detection_engine/base64_view.py:9` | MAX_SHORT_BASE64_TOKEN_LENGTH | `Base64View.kt:13` | FULL | |
| `detection_engine/base64_view.py:10` | SHORT_BASE64_MARKER_CHARS | `Base64View.kt:18` | FULL | |
| `detection_engine/base64_view.py:11` | MAX_SHORT_BASE64_CANDIDATES | `Base64View.kt:14` | FULL | |
| `detection_engine/base64_view.py:12` | PRINTABLE_RATIO_THRESHOLD | `Base64View.kt:15` | FULL | |
| `detection_engine/base64_view.py:49` | build_short_base64_additive_view | `Base64View.kt:59` | FULL | |
| `detection_engine/binary_islands.py:12` | value_is_binary_like | `Binary.kt:79` | FULL | |
| `detection_engine/binary_islands.py:19` | extract_binary_islands | `Binary.kt:87` | FULL | |
| `detection_engine/binary_prefix.py:12` | build_binary_prefix | `Binary.kt:32` | FULL | |
| `detection_engine/binary_prefix.py:26` | match_is_binary_dense | `Binary.kt:52` | FULL | |
| `detection_engine/compiler.py:29` | shared_regex_executor | `RegexWorkers.kt:18` | IDIOMATIC | module-level executor -> RegexWorkers object, 512 MiB-stack workers + submit(); same 4-worker shape |
| `detection_engine/compiler.py:41` | report_scan_success | `Compiler.kt:198` | FULL | |
| `detection_engine/compiler.py:48` | report_scan_timeout | `Compiler.kt:194` | FULL | |
| `detection_engine/compiler.py:71` | PatternCompiler | `Compiler.kt:16` | FULL | |
| `detection_engine/compiler.py:87` | PatternCompiler.compile_pattern | `Compiler.kt:25` | FULL | |
| `detection_engine/compiler.py:110` | PatternCompiler.compile_pattern_sync | `Compiler.kt:44` | FULL | |
| `detection_engine/compiler.py:115` | PatternCompiler.validate_pattern_safety | `Compiler.kt:51` | FULL | |
| `detection_engine/compiler.py:146` | PatternCompiler.create_safe_matcher | `Compiler.kt:122` | FULL | |
| `detection_engine/compiler.py:181` | PatternCompiler.create_safe_finditer_matcher | `Compiler.kt:140` | FULL | |
| `detection_engine/compiler.py:218` | PatternCompiler.create_async_safe_finditer_matcher | `Compiler.kt:140` | IDIOMATIC | async-wrapper factory -> createSafeFinditerMatcher called from suspend contexts (structured concurrency replaces the async wrapper) |
| `detection_engine/compiler.py:245` | PatternCompiler.batch_compile | `Compiler.kt:157` | FULL | |
| `detection_engine/compiler.py:265` | PatternCompiler.clear_cache | `Compiler.kt:179` | FULL | |
| `detection_engine/encoding_decoders.py:3` | HEX_ESCAPE_RE | `EncodingDecoders.kt:12` | FULL | |
| `detection_engine/encoding_decoders.py:4` | UNICODE_ESCAPE_RE | `EncodingDecoders.kt:13` | FULL | |
| `detection_engine/encoding_decoders.py:5` | PERCENT_U_ESCAPE_RE | `EncodingDecoders.kt:14` | FULL | |
| `detection_engine/encoding_decoders.py:6` | PERCENT_BYTE_RUN_RE | `EncodingDecoders.kt:15` | FULL | |
| `detection_engine/encoding_decoders.py:8` | OVERLONG_LEAD_SPECS | `EncodingDecoders.kt:18` | FULL | |
| `detection_engine/encoding_decoders.py:16` | decode_hex_escapes | `EncodingDecoders.kt:26` | FULL | |
| `detection_engine/encoding_decoders.py:26` | decode_unicode_escapes | `EncodingDecoders.kt:34` | FULL | |
| `detection_engine/encoding_decoders.py:36` | decode_percent_u_escapes | `EncodingDecoders.kt:39` | FULL | |
| `detection_engine/encoding_decoders.py:62` | lenient_overlong_utf8_decode | `EncodingDecoders.kt:65` | FULL | |
| `detection_engine/encoding_decoders.py:80` | decode_overlong_utf8_percent_runs | `EncodingDecoders.kt:85` | FULL | |
| `detection_engine/monitor.py:40` | PerformanceMonitor | `Monitor.kt:294` | FULL | |
| `detection_engine/monitor.py:69` | PerformanceMonitor.record_metric | `Monitor.kt:316` | FULL | |
| `detection_engine/monitor.py:241` | PerformanceMonitor.get_pattern_report | `Monitor.kt:452` | FULL | |
| `detection_engine/monitor.py:252` | PerformanceMonitor.get_slow_patterns | `Monitor.kt:462` | FULL | |
| `detection_engine/monitor.py:259` | PerformanceMonitor.get_problematic_patterns | `Monitor.kt:469` | FULL | |
| `detection_engine/monitor.py:286` | PerformanceMonitor.get_summary_stats | `Monitor.kt:475` | FULL | |
| `detection_engine/monitor.py:304` | PerformanceMonitor.register_anomaly_callback | `Monitor.kt:485` | FULL | |
| `detection_engine/monitor.py:307` | PerformanceMonitor.clear_stats | `Monitor.kt:489` | FULL | |
| `detection_engine/monitor.py:312` | PerformanceMonitor.remove_pattern_stats | `Monitor.kt:496` | FULL | |
| `detection_engine/monitor_anomalies.py:10` | detect_timeout_anomaly | `Monitor.kt:49` | FULL | |
| `detection_engine/monitor_anomalies.py:20` | detect_slow_execution_anomaly | `Monitor.kt:60` | FULL | |
| `detection_engine/monitor_anomalies.py:33` | detect_statistical_anomaly | `Monitor.kt:88` | FULL | |
| `detection_engine/monitor_anomalies.py:70` | sanitize_anomaly_data | `Monitor.kt:121` | FULL | |
| `detection_engine/monitor_anomalies.py:93` | build_anomaly_event_data | `Monitor.kt:147` | FULL | |
| `detection_engine/monitor_anomalies.py:114` | build_callback_error_event_data | `Monitor.kt:171` | FULL | |
| `detection_engine/monitor_reporting.py:10` | build_pattern_report | `Monitor.kt:192` | FULL | |
| `detection_engine/monitor_reporting.py:37` | collect_slow_patterns | `Monitor.kt:216` | FULL | |
| `detection_engine/monitor_reporting.py:58` | collect_problematic_patterns | `Monitor.kt:234` | FULL | |
| `detection_engine/monitor_reporting.py:86` | empty_summary | `Monitor.kt:258` | FULL | |
| `detection_engine/monitor_reporting.py:95` | extract_metric_components | `Monitor.kt:266` | FULL | |
| `detection_engine/monitor_reporting.py:104` | build_summary_dict | `Monitor.kt:275` | FULL | |
| `detection_engine/monitor_types.py:5` | DEFAULT_RECENT_TIMES_WINDOW | `Monitor.kt:14` | FULL | |
| `detection_engine/monitor_types.py:9` | PerformanceMetric | `Monitor.kt:25` | FULL | |
| `detection_engine/monitor_types.py:19` | PatternStats | `Monitor.kt:34` | FULL | |
| `detection_engine/preprocessor.py:9` | ContentPreprocessor | `Preprocessor.kt:15` | FULL | |
| `detection_engine/preprocessor.py:108` | ContentPreprocessor.normalize_unicode | `Preprocessor.kt:94` | FULL | |
| `detection_engine/preprocessor.py:144` | ContentPreprocessor.remove_excessive_whitespace | `Preprocessor.kt:102` | FULL | |
| `detection_engine/preprocessor.py:149` | ContentPreprocessor.extract_attack_regions | `Preprocessor.kt:87` | FULL | |
| `detection_engine/preprocessor.py:179` | ContentPreprocessor.truncate_safely | `Preprocessor.kt:90` | FULL | |
| `detection_engine/preprocessor.py:182` | ContentPreprocessor.remove_null_bytes | `Preprocessor.kt:108` | FULL | |
| `detection_engine/preprocessor.py:241` | ContentPreprocessor.decode_common_encodings | `Preprocessor.kt:118` | FULL | |
| `detection_engine/preprocessor.py:303` | ContentPreprocessor.preprocess | `Preprocessor.kt:173` | FULL | |
| `detection_engine/preprocessor.py:311` | ContentPreprocessor.preprocess_with_decoded | `Preprocessor.kt:177` | FULL | |
| `detection_engine/preprocessor.py:325` | ContentPreprocessor.preprocess_signal_preserving | `Preprocessor.kt:191` | FULL | |
| `detection_engine/preprocessor.py:332` | ContentPreprocessor.preprocess_url_decoded_newline_preserving | `Preprocessor.kt:198` | FULL | |
| `detection_engine/preprocessor.py:342` | ContentPreprocessor.preprocess_short_base64_additive_view | `Preprocessor.kt:209` | FULL | |
| `detection_engine/preprocessor.py:345` | ContentPreprocessor.preprocess_batch | `Preprocessor.kt:212` | FULL | |
| `detection_engine/scan_window.py:32` | bounded_finditer | `ScanWindow.kt:15` | FULL | |
| `detection_engine/scan_window.py:76` | bounded_search | `ScanWindow.kt:56` | FULL | |
| `detection_engine/semantic.py:12` | looks_like_binary_content | `Semantic.kt:19` | FULL | |
| `detection_engine/semantic.py:23` | SemanticAnalyzer | `Semantic.kt:43` | FULL | |
| `detection_engine/semantic.py:106` | SemanticAnalyzer.extract_tokens | `Semantic.kt:140` | FULL | |
| `detection_engine/semantic.py:130` | SemanticAnalyzer.calculate_entropy | `Semantic.kt:186` | FULL | |
| `detection_engine/semantic.py:151` | SemanticAnalyzer.detect_encoding_layers | `Semantic.kt:205` | FULL | |
| `detection_engine/semantic.py:215` | SemanticAnalyzer.analyze_attack_probability | `Semantic.kt:256` | FULL | |
| `detection_engine/semantic.py:219` | SemanticAnalyzer.detect_obfuscation | `Semantic.kt:262` | FULL | |
| `detection_engine/semantic.py:240` | SemanticAnalyzer.extract_suspicious_patterns | `Semantic.kt:274` | FULL | |
| `detection_engine/semantic.py:327` | SemanticAnalyzer.analyze_code_injection_risk | `Semantic.kt:343` | FULL | |
| `detection_engine/semantic.py:334` | SemanticAnalyzer.analyze | `Semantic.kt:352` | FULL | |
| `detection_engine/semantic.py:348` | SemanticAnalyzer.get_threat_score | `Semantic.kt:366` | FULL | |
| `detection_engine/truncation.py:6` | extract_attack_regions | `Truncation.kt:15` | FULL | |
| `detection_engine/truncation.py:47` | extract_and_concatenate_attack_regions | `Truncation.kt:60` | FULL | |
| `detection_engine/truncation.py:74` | build_result_with_attack_regions_and_context | `Truncation.kt:94` | FULL | |
| `detection_engine/truncation.py:96` | cap_with_tail | `Truncation.kt:123` | FULL | |
| `detection_engine/truncation.py:103` | truncate_safely | `Truncation.kt:132` | FULL | |

## Core (checks, events, initialization, responses, routing, validation, bypass, behavioral)

195 rows: 195 FULL, 0 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: pipeline suite 35/35 ZERO xfails (fixed order, factory.py:30); event_stream 39/39 (37 byte-exact + 2 ledgered); W8a 143 tests over the G-13 remainder; pipeline route-config revision tests.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `core/behavioral/context.py:11` | BehavioralContext | `BehavioralProcessor.kt:20` | FULL | |
| `core/behavioral/processor.py:12` | BehavioralProcessor | `BehavioralProcessor.kt:33` | FULL | |
| `core/behavioral/processor.py:28` | BehavioralProcessor.process_usage_rules | `BehavioralProcessor.kt:52` | FULL | |
| `core/behavioral/processor.py:79` | BehavioralProcessor.process_return_rules | `BehavioralProcessor.kt:111` | FULL | |
| `core/behavioral/processor.py:134` | BehavioralProcessor.process_global_return_rules | `BehavioralProcessor.kt:172` | FULL | |
| `core/behavioral/processor.py:223` | BehavioralProcessor.get_endpoint_id | `BehavioralProcessor.kt:268` | FULL | |
| `core/bypass/context.py:12` | BypassContext | `BypassHandler.kt:21` | FULL | |
| `core/bypass/handler.py:13` | UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME | `BypassHandler.kt:136` | FULL | |
| `core/bypass/handler.py:36` | BypassHandler | `BypassHandler.kt:34` | FULL | |
| `core/bypass/handler.py:40` | BypassHandler.handle_passthrough | `BypassHandler.kt:59` | FULL | |
| `core/bypass/handler.py:78` | BypassHandler.handle_security_bypass | `BypassHandler.kt:100` | FULL | |
| `core/checks/_verifier.py:5` | resolve_verifier_result | `Verifier.kt:10` | FULL | |
| `core/checks/base.py:14` | SecurityCheck | `SecurityCheck.kt:15` | FULL | |
| `core/checks/base.py:25` | SecurityCheck.applies_to | `SecurityCheck.kt:32` | FULL | |
| `core/checks/base.py:33` | SecurityCheck.check | `SecurityCheck.kt:38` | FULL | |
| `core/checks/base.py:37` | SecurityCheck.check_name | `SecurityCheck.kt:1` | FULL | abstract checkName val; each implementation declares it (auto-matched per implementation) |
| `core/checks/base.py:39` | SecurityCheck.send_event | `SecurityCheck.kt:44` | FULL | |
| `core/checks/base.py:55` | SecurityCheck.create_error_response | `SecurityCheck.kt:55` | FULL | |
| `core/checks/base.py:60` | SecurityCheck.is_passive_mode | `SecurityCheck.kt:59` | FULL | |
| `core/checks/base.py:63` | SecurityCheck.log_if_allowed | `SecurityCheck.kt:62` | FULL | |
| `core/checks/factory.py:30` | DEFAULT_CHECK_CLASSES | `ChecksFactory.kt:53` | FULL | |
| `core/checks/factory.py:50` | WATCHED_CONTAINER_FIELDS | `ChecksFactory.kt:75` | FULL | |
| `core/checks/factory.py:86` | build_default_pipeline | `ChecksFactory.kt:99` | FULL | |
| `core/checks/helpers.py:32` | get_guard_decorator | `ChecksHelpers.kt:35` | FULL | |
| `core/checks/helpers.py:43` | emit_access_denied_event | `ChecksHelpers.kt:46` | FULL | |
| `core/checks/helpers.py:69` | emit_authentication_failed_event | `ChecksHelpers.kt:70` | FULL | |
| `core/checks/helpers.py:96` | emit_rate_limit_event | `ChecksHelpers.kt:98` | FULL | |
| `core/checks/helpers.py:122` | emit_decorator_event | `ChecksHelpers.kt:127` | FULL | |
| `core/checks/helpers.py:153` | route_config_applies | `ChecksHelpers.kt:158` | FULL | |
| `core/checks/helpers.py:165` | is_ip_in_blacklist | `ChecksHelpers.kt:174` | FULL | |
| `core/checks/helpers.py:169` | is_ip_in_whitelist | `ChecksHelpers.kt:181` | FULL | |
| `core/checks/helpers.py:177` | check_country_access | `ChecksHelpers.kt:193` | FULL | |
| `core/checks/helpers.py:219` | check_route_ip_access | `ChecksHelpers.kt:252` | FULL | |
| `core/checks/helpers.py:245` | check_user_agent_allowed | `ChecksHelpers.kt:285` | FULL | |
| `core/checks/helpers.py:259` | extract_credential | `ChecksHelpers.kt:307` | FULL | |
| `core/checks/helpers.py:281` | is_referrer_domain_allowed | `ChecksHelpers.kt:337` | FULL | |
| `core/checks/helpers.py:316` | detect_penetration_patterns | `ChecksHelpers.kt:380` | FULL | |
| `core/checks/helpers.py:333` | get_cached_detection_result | `ChecksHelpers.kt:402` | FULL | |
| `core/checks/helpers.py:477` | escalate_identity_violation | `ChecksHelpers.kt:572` | FULL | |
| `core/checks/implementations/authentication.py:19` | AuthenticationCheck | `AuthenticationCheck.kt:19` | FULL | |
| `core/checks/implementations/authentication.py:21` | AuthenticationCheck.check_name | `AuthenticationCheck.kt:22` | FULL | |
| `core/checks/implementations/authentication.py:25` | AuthenticationCheck.applies_to | `AuthenticationCheck.kt:148` | FULL | |
| `core/checks/implementations/authentication.py:120` | AuthenticationCheck.check | `AuthenticationCheck.kt:104` | FULL | |
| `core/checks/implementations/cloud_ip_refresh.py:16` | CloudIpRefreshCheck | `CloudIpRefreshCheck.kt:17` | FULL | |
| `core/checks/implementations/cloud_ip_refresh.py:27` | CloudIpRefreshCheck.check_name | `CloudIpRefreshCheck.kt:27` | FULL | |
| `core/checks/implementations/cloud_ip_refresh.py:31` | CloudIpRefreshCheck.applies_to | `CloudIpRefreshCheck.kt:58` | FULL | |
| `core/checks/implementations/cloud_ip_refresh.py:40` | CloudIpRefreshCheck.check | `CloudIpRefreshCheck.kt:30` | FULL | |
| `core/checks/implementations/cloud_provider.py:20` | CloudProviderCheck | `CloudProviderCheck.kt:19` | FULL | |
| `core/checks/implementations/cloud_provider.py:31` | CloudProviderCheck.check_name | `CloudProviderCheck.kt:29` | FULL | |
| `core/checks/implementations/cloud_provider.py:35` | CloudProviderCheck.applies_to | `CloudProviderCheck.kt:121` | FULL | |
| `core/checks/implementations/cloud_provider.py:44` | CloudProviderCheck.check | `CloudProviderCheck.kt:68` | FULL | |
| `core/checks/implementations/custom_request.py:11` | CustomRequestCheck | `CustomRequestCheck.kt:16` | FULL | |
| `core/checks/implementations/custom_request.py:13` | CustomRequestCheck.check_name | `CustomRequestCheck.kt:19` | FULL | |
| `core/checks/implementations/custom_request.py:17` | CustomRequestCheck.applies_to | `CustomRequestCheck.kt:56` | FULL | |
| `core/checks/implementations/custom_request.py:24` | CustomRequestCheck.check | `CustomRequestCheck.kt:22` | FULL | |
| `core/checks/implementations/custom_validators.py:13` | CustomValidatorsCheck | `CustomValidatorsCheck.kt:19` | FULL | |
| `core/checks/implementations/custom_validators.py:15` | CustomValidatorsCheck.check_name | `CustomValidatorsCheck.kt:22` | FULL | |
| `core/checks/implementations/custom_validators.py:19` | CustomValidatorsCheck.applies_to | `CustomValidatorsCheck.kt:76` | FULL | |
| `core/checks/implementations/custom_validators.py:28` | CustomValidatorsCheck.check | `CustomValidatorsCheck.kt:25` | FULL | |
| `core/checks/implementations/emergency_mode.py:13` | EmergencyModeCheck | `EmergencyModeCheck.kt:21` | FULL | |
| `core/checks/implementations/emergency_mode.py:15` | EmergencyModeCheck.check_name | `EmergencyModeCheck.kt:24` | FULL | |
| `core/checks/implementations/emergency_mode.py:19` | EmergencyModeCheck.applies_to | `EmergencyModeCheck.kt:98` | FULL | |
| `core/checks/implementations/emergency_mode.py:26` | EmergencyModeCheck.check | `EmergencyModeCheck.kt:27` | FULL | |
| `core/checks/implementations/https_enforcement.py:11` | HttpsEnforcementCheck | `HttpsEnforcementCheck.kt:18` | FULL | |
| `core/checks/implementations/https_enforcement.py:13` | HttpsEnforcementCheck.check_name | `HttpsEnforcementCheck.kt:21` | FULL | |
| `core/checks/implementations/https_enforcement.py:17` | HttpsEnforcementCheck.applies_to | `HttpsEnforcementCheck.kt:89` | FULL | |
| `core/checks/implementations/https_enforcement.py:58` | HttpsEnforcementCheck.check | `HttpsEnforcementCheck.kt:66` | FULL | |
| `core/checks/implementations/ip_security.py:78` | IpSecurityCheck | `IpSecurityCheck.kt:87` | FULL | |
| `core/checks/implementations/ip_security.py:88` | IpSecurityCheck.check_name | `IpSecurityCheck.kt:95` | FULL | |
| `core/checks/implementations/ip_security.py:294` | IpSecurityCheck.check | `IpSecurityCheck.kt:301` | FULL | |
| `core/checks/implementations/rate_limit.py:42` | RateLimitCheck | `RateLimitCheck.kt:33` | FULL | |
| `core/checks/implementations/rate_limit.py:53` | RateLimitCheck.check_name | `RateLimitCheck.kt:44` | FULL | |
| `core/checks/implementations/rate_limit.py:57` | RateLimitCheck.applies_to | `RateLimitCheck.kt:328` | FULL | |
| `core/checks/implementations/rate_limit.py:287` | RateLimitCheck.check | `RateLimitCheck.kt:287` | FULL | |
| `core/checks/implementations/referrer.py:18` | ReferrerCheck | `ReferrerCheck.kt:15` | FULL | |
| `core/checks/implementations/referrer.py:20` | ReferrerCheck.check_name | `ReferrerCheck.kt:18` | FULL | |
| `core/checks/implementations/referrer.py:24` | ReferrerCheck.applies_to | `ReferrerCheck.kt:132` | FULL | |
| `core/checks/implementations/referrer.py:112` | ReferrerCheck.check | `ReferrerCheck.kt:110` | FULL | |
| `core/checks/implementations/request_logging.py:11` | RequestLoggingCheck | `RequestLoggingCheck.kt:16` | FULL | |
| `core/checks/implementations/request_logging.py:13` | RequestLoggingCheck.check_name | `RequestLoggingCheck.kt:19` | FULL | |
| `core/checks/implementations/request_logging.py:17` | RequestLoggingCheck.applies_to | `RequestLoggingCheck.kt:38` | FULL | |
| `core/checks/implementations/request_logging.py:24` | RequestLoggingCheck.check | `RequestLoggingCheck.kt:22` | FULL | |
| `core/checks/implementations/request_size_content.py:14` | RequestSizeContentCheck | `RequestSizeContentCheck.kt:18` | FULL | |
| `core/checks/implementations/request_size_content.py:16` | RequestSizeContentCheck.check_name | `RequestSizeContentCheck.kt:21` | FULL | |
| `core/checks/implementations/request_size_content.py:20` | RequestSizeContentCheck.applies_to | `RequestSizeContentCheck.kt:142` | FULL | |
| `core/checks/implementations/request_size_content.py:131` | RequestSizeContentCheck.check | `RequestSizeContentCheck.kt:129` | FULL | |
| `core/checks/implementations/required_headers.py:26` | RequiredHeadersCheck | `RequiredHeadersCheck.kt:30` | FULL | |
| `core/checks/implementations/required_headers.py:28` | RequiredHeadersCheck.check_name | `RequiredHeadersCheck.kt:33` | FULL | |
| `core/checks/implementations/required_headers.py:32` | RequiredHeadersCheck.applies_to | `RequiredHeadersCheck.kt:113` | FULL | |
| `core/checks/implementations/required_headers.py:98` | RequiredHeadersCheck.check | `RequiredHeadersCheck.kt:91` | FULL | |
| `core/checks/implementations/route_config.py:7` | UNRESOLVED_ROUTE_REASON | `RouteConfigCheck.kt:14` | FULL | |
| `core/checks/implementations/route_config.py:12` | RouteConfigCheck | `RouteConfigCheck.kt:22` | FULL | |
| `core/checks/implementations/route_config.py:16` | RouteConfigCheck.check_name | `RouteConfigCheck.kt:27` | FULL | |
| `core/checks/implementations/route_config.py:51` | RouteConfigCheck.check | `RouteConfigCheck.kt:58` | FULL | |
| `core/checks/implementations/suspicious_activity.py:25` | SuspiciousActivityCheck | `SuspiciousActivityCheck.kt:19` | FULL | |
| `core/checks/implementations/suspicious_activity.py:33` | SuspiciousActivityCheck.check_name | `SuspiciousActivityCheck.kt:25` | FULL | |
| `core/checks/implementations/suspicious_activity.py:37` | SuspiciousActivityCheck.applies_to | `SuspiciousActivityCheck.kt:176` | FULL | |
| `core/checks/implementations/suspicious_activity.py:140` | SuspiciousActivityCheck.check | `SuspiciousActivityCheck.kt:122` | FULL | |
| `core/checks/implementations/time_window.py:18` | TimeWindowCheck | `TimeWindowCheck.kt:22` | FULL | |
| `core/checks/implementations/time_window.py:20` | TimeWindowCheck.check_name | `TimeWindowCheck.kt:25` | FULL | |
| `core/checks/implementations/time_window.py:24` | TimeWindowCheck.applies_to | `TimeWindowCheck.kt:98` | FULL | |
| `core/checks/implementations/time_window.py:57` | TimeWindowCheck.check | `TimeWindowCheck.kt:57` | FULL | |
| `core/checks/implementations/user_agent.py:26` | UserAgentCheck | `UserAgentCheck.kt:19` | FULL | |
| `core/checks/implementations/user_agent.py:36` | UserAgentCheck.check_name | `UserAgentCheck.kt:27` | FULL | |
| `core/checks/implementations/user_agent.py:40` | UserAgentCheck.applies_to | `UserAgentCheck.kt:114` | FULL | |
| `core/checks/implementations/user_agent.py:53` | UserAgentCheck.check | `UserAgentCheck.kt:30` | FULL | |
| `core/checks/pipeline.py:16` | SecurityCheckPipeline | `SecurityCheckPipeline.kt:15` | FULL | |
| `core/checks/pipeline.py:166` | SecurityCheckPipeline.execute | `SecurityCheckPipeline.kt:180` | FULL | |
| `core/checks/pipeline.py:200` | SecurityCheckPipeline.add_check | `SecurityCheckPipeline.kt:218` | FULL | |
| `core/checks/pipeline.py:203` | SecurityCheckPipeline.insert_check | `SecurityCheckPipeline.kt:223` | FULL | |
| `core/checks/pipeline.py:206` | SecurityCheckPipeline.remove_check | `SecurityCheckPipeline.kt:228` | FULL | |
| `core/checks/pipeline.py:213` | SecurityCheckPipeline.get_check_names | `SecurityCheckPipeline.kt:238` | FULL | |
| `core/events/composite_handler.py:11` | CompositeAgentHandler | `CompositeAgentHandler.kt:43` | FULL | |
| `core/events/composite_handler.py:25` | CompositeAgentHandler.started | `CompositeAgentHandler.kt:56` | FULL | started property |
| `core/events/composite_handler.py:29` | CompositeAgentHandler.degraded | `CompositeAgentHandler.kt:59` | FULL | degraded = started && failedHandlers.isNotEmpty() |
| `core/events/composite_handler.py:33` | CompositeAgentHandler.failed_handlers | `CompositeAgentHandler.kt:53` | FULL | |
| `core/events/composite_handler.py:36` | CompositeAgentHandler.send_event | `CompositeAgentHandler.kt:13` | FULL | |
| `core/events/composite_handler.py:48` | CompositeAgentHandler.send_metric | `CompositeAgentHandler.kt:15` | FULL | |
| `core/events/composite_handler.py:60` | CompositeAgentHandler.initialize_redis | `CompositeAgentHandler.kt:17` | FULL | |
| `core/events/composite_handler.py:67` | CompositeAgentHandler.start | `CompositeAgentHandler.kt:19` | FULL | |
| `core/events/composite_handler.py:78` | CompositeAgentHandler.stop | `CompositeAgentHandler.kt:21` | FULL | |
| `core/events/composite_handler.py:85` | CompositeAgentHandler.flush_buffer | `CompositeAgentHandler.kt:23` | FULL | |
| `core/events/composite_handler.py:92` | CompositeAgentHandler.get_dynamic_rules | `CompositeAgentHandler.kt:25` | FULL | |
| `core/events/composite_handler.py:102` | CompositeAgentHandler.health_check | `CompositeAgentHandler.kt:27` | FULL | |
| `core/events/enricher.py:111` | ThreatScorer | `EventEnricher.kt:15` | FULL | |
| `core/events/enricher.py:113` | ThreatScorer.score_for | `EventEnricher.kt:64` | FULL | |
| `core/events/enricher.py:118` | EnrichmentContext | `EventEnricher.kt:73` | FULL | |
| `core/events/enricher.py:125` | EventEnricher | `EventEnricher.kt:85` | FULL | |
| `core/events/enricher.py:129` | EventEnricher.enrich_event | `EventEnricher.kt:91` | FULL | |
| `core/events/enricher.py:141` | EventEnricher.enrich_metric | `EventEnricher.kt:105` | FULL | |
| `core/events/event_types.py:136` | EventFilter | `EventTypes.kt:142` | FULL | |
| `core/events/event_types.py:140` | EventFilter.is_event_allowed | `EventTypes.kt:146` | FULL | |
| `core/events/event_types.py:143` | EventFilter.is_metric_allowed | `EventTypes.kt:148` | FULL | |
| `core/events/logfire_handler.py:21` | LogfireHandler | `LogfireHandler.kt:15` | FULL | |
| `core/events/logfire_handler.py:27` | LogfireHandler.start | `LogfireHandler.kt:60` | FULL | |
| `core/events/logfire_handler.py:47` | LogfireHandler.stop | `LogfireHandler.kt:86` | FULL | |
| `core/events/logfire_handler.py:56` | LogfireHandler.send_event | `LogfireHandler.kt:101` | FULL | |
| `core/events/logfire_handler.py:83` | LogfireHandler.send_metric | `LogfireHandler.kt:131` | FULL | |
| `core/events/logfire_handler.py:98` | LogfireHandler.initialize_redis | `LogfireHandler.kt:149` | FULL | |
| `core/events/logfire_handler.py:101` | LogfireHandler.flush_buffer | `LogfireHandler.kt:152` | FULL | |
| `core/events/logfire_handler.py:104` | LogfireHandler.get_dynamic_rules | `LogfireHandler.kt:155` | FULL | |
| `core/events/logfire_handler.py:107` | LogfireHandler.health_check | `LogfireHandler.kt:158` | FULL | |
| `core/events/metrics.py:16` | MetricsCollector | `MetricsCollector.kt:22` | FULL | |
| `core/events/metrics.py:28` | MetricsCollector.send_metric | `MetricsCollector.kt:30` | FULL | |
| `core/events/metrics.py:49` | MetricsCollector.collect_request_metrics | `MetricsCollector.kt:63` | FULL | |
| `core/events/middleware_events.py:26` | SecurityEventBus | `SecurityEventBus.kt:23` | FULL | |
| `core/events/middleware_events.py:111` | SecurityEventBus.send_middleware_event | `SecurityEventBus.kt:112` | FULL | |
| `core/events/middleware_events.py:137` | SecurityEventBus.send_https_violation_event | `SecurityEventBus.kt:138` | FULL | |
| `core/events/middleware_events.py:168` | SecurityEventBus.send_cloud_detection_events | `SecurityEventBus.kt:175` | FULL | |
| `core/events/otel_handler.py:50` | OtelHandler | `OtelHandler.kt:17` | FULL | |
| `core/events/otel_handler.py:62` | OtelHandler.start | `OtelHandler.kt:86` | FULL | |
| `core/events/otel_handler.py:126` | OtelHandler.stop | `OtelHandler.kt:99` | FULL | |
| `core/events/otel_handler.py:143` | OtelHandler.send_event | `OtelHandler.kt:104` | FULL | |
| `core/events/otel_handler.py:201` | OtelHandler.send_metric | `OtelHandler.kt:163` | FULL | |
| `core/events/otel_handler.py:220` | OtelHandler.initialize_redis | `OtelHandler.kt:184` | FULL | |
| `core/events/otel_handler.py:223` | OtelHandler.flush_buffer | `OtelHandler.kt:187` | FULL | |
| `core/events/otel_handler.py:226` | OtelHandler.get_dynamic_rules | `OtelHandler.kt:190` | FULL | |
| `core/events/otel_handler.py:229` | OtelHandler.health_check | `OtelHandler.kt:193` | FULL | |
| `core/initialization/_handler_initializer_steps.py:24` | _HandlerInitializerStepsMixin.build_composite_handler | `HandlerInitializer.kt:120` | FULL | |
| `core/initialization/_handler_initializer_steps.py:26` | _HandlerInitializerStepsMixin.build_event_filter | `HandlerInitializer.kt:143` | FULL | |
| `core/initialization/_handler_initializer_steps.py:141` | _HandlerInitializerStepsMixin.initialize_redis_handlers | `HandlerInitializer.kt:361` | FULL | |
| `core/initialization/_handler_initializer_steps.py:157` | _HandlerInitializerStepsMixin.initialize_agent_for_handlers | `HandlerInitializer.kt:382` | FULL | |
| `core/initialization/_handler_initializer_steps.py:181` | _HandlerInitializerStepsMixin.initialize_dynamic_rule_manager | `HandlerInitializer.kt:436` | FULL | |
| `core/initialization/_handler_initializer_steps.py:202` | _HandlerInitializerStepsMixin.initialize_agent_integrations | `HandlerInitializer.kt:480` | FULL | |
| `core/initialization/_handler_initializer_steps.py:234` | _HandlerInitializerStepsMixin.shutdown_agent_integrations | `HandlerInitializer.kt:511` | FULL | |
| `core/initialization/handler_initializer.py:15` | HandlerInitializer | `HandlerInitializer.kt:42` | FULL | |
| `core/initialization/handler_initializer.py:38` | HandlerInitializer.get_initialization_status | `HandlerInitializer.kt:72` | FULL | |
| `core/initialization/handler_initializer.py:58` | HandlerInitializer.build_enricher | `HandlerInitializer.kt:95` | FULL | |
| `core/initialization/handler_initializer.py:87` | HandlerInitializer.build_composite_handler | `HandlerInitializer.kt:120` | FULL | |
| `core/initialization/handler_initializer.py:107` | HandlerInitializer.build_event_filter | `HandlerInitializer.kt:143` | FULL | |
| `core/initialization/handler_initializer.py:115` | HandlerInitializer.build_event_bus | `HandlerInitializer.kt:150` | FULL | |
| `core/initialization/handler_initializer.py:129` | HandlerInitializer.build_metrics_collector | `HandlerInitializer.kt:163` | FULL | |
| `core/responses/context.py:11` | ResponseContext | `ErrorResponseFactory.kt:20` | FULL | |
| `core/responses/factory.py:13` | ErrorResponseFactory | `ErrorResponseFactory.kt:34` | FULL | |
| `core/responses/factory.py:18` | ErrorResponseFactory.create_error_response | `ErrorResponseFactory.kt:40` | FULL | |
| `core/responses/factory.py:34` | ErrorResponseFactory.create_https_redirect | `ErrorResponseFactory.kt:54` | FULL | |
| `core/responses/factory.py:42` | ErrorResponseFactory.apply_security_headers | `ErrorResponseFactory.kt:64` | FULL | |
| `core/responses/factory.py:55` | ErrorResponseFactory.apply_cors_headers | `ErrorResponseFactory.kt:81` | FULL | |
| `core/responses/factory.py:68` | ErrorResponseFactory.apply_modifier | `ErrorResponseFactory.kt:95` | FULL | |
| `core/responses/factory.py:82` | ErrorResponseFactory.process_response | `ErrorResponseFactory.kt:108` | FULL | |
| `core/routing/context.py:9` | RoutingContext | `RouteConfigResolver.kt:14` | FULL | |
| `core/routing/resolver.py:6` | RouteConfigResolver | `RouteConfigResolver.kt:24` | FULL | |
| `core/routing/resolver.py:10` | RouteConfigResolver.get_route_config | `RouteConfigResolver.kt:28` | FULL | |
| `core/routing/resolver.py:23` | RouteConfigResolver.should_bypass_check | `RouteConfigResolver.kt:46` | FULL | |
| `core/routing/resolver.py:33` | RouteConfigResolver.get_cloud_providers_to_check | `RouteConfigResolver.kt:52` | FULL | |
| `core/validation/context.py:9` | ValidationContext | `RequestValidator.kt:20` | FULL | |
| `core/validation/path_matching.py:51` | normalize_url_path | `PathMatching.kt:95` | FULL | |
| `core/validation/path_matching.py:64` | normalize_exclude_paths | `PathMatching.kt:105` | FULL | |
| `core/validation/path_matching.py:69` | path_matches_exclusions | `PathMatching.kt:111` | FULL | |
| `core/validation/path_matching.py:78` | path_is_excluded | `PathMatching.kt:117` | FULL | |
| `core/validation/validator.py:18` | RequestValidator | `RequestValidator.kt:31` | FULL | |
| `core/validation/validator.py:27` | RequestValidator.is_request_https | `RequestValidator.kt:47` | FULL | |
| `core/validation/validator.py:41` | RequestValidator.is_trusted_proxy | `RequestValidator.kt:65` | FULL | |
| `core/validation/validator.py:51` | RequestValidator.check_time_window | `RequestValidator.kt:81` | FULL | |
| `core/validation/validator.py:77` | RequestValidator.is_path_excluded | `RequestValidator.kt:111` | FULL | |

## Decorators (factories, route config)

72 rows: 48 FULL, 24 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: SecurityDecoratorTest ports test_route_id_per_function.py 1:1; 25/25 factories mirrored by BOTH adapters (Boot annotations, ktor plugin); decorator-violation event cases green in event_stream.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `decorators/access_control.py:9` | AccessControlMixin | `SecurityDecorator.kt:26` | IDIOMATIC | python mixin inheritance -> single SecurityDecorator class hosting all 25 factories |
| `decorators/access_control.py:10` | AccessControlMixin.require_ip | `SecurityDecorator.kt:34` | FULL | |
| `decorators/access_control.py:25` | AccessControlMixin.block_countries | `SecurityDecorator.kt:50` | FULL | |
| `decorators/access_control.py:35` | AccessControlMixin.allow_countries | `SecurityDecorator.kt:57` | FULL | |
| `decorators/access_control.py:45` | AccessControlMixin.block_clouds | `SecurityDecorator.kt:66` | FULL | |
| `decorators/access_control.py:69` | AccessControlMixin.bypass | `SecurityDecorator.kt:91` | FULL | |
| `decorators/advanced.py:23` | _SimpleResponse.status_code | `SecurityDecorator.kt:451` | FULL | SimpleDecoratorResponse implements GuardResponse.statusCode |
| `decorators/advanced.py:27` | _SimpleResponse.headers | `SecurityDecorator.kt:449` | FULL | SimpleDecoratorResponse implements GuardResponse.headers |
| `decorators/advanced.py:31` | _SimpleResponse.body | `SecurityDecorator.kt:452` | FULL | SimpleDecoratorResponse implements GuardResponse.body |
| `decorators/advanced.py:35` | AdvancedMixin | `SecurityDecorator.kt:26` | IDIOMATIC | mixin fold (see access_control row); honeypot closure at SecurityDecorator.kt:394 |
| `decorators/advanced.py:38` | AdvancedMixin.time_window | `SecurityDecorator.kt:357` | FULL | |
| `decorators/advanced.py:52` | AdvancedMixin.suspicious_detection | `SecurityDecorator.kt:374` | FULL | |
| `decorators/advanced.py:62` | AdvancedMixin.honeypot_detection | `SecurityDecorator.kt:384` | FULL | |
| `decorators/authentication.py:11` | AuthenticationMixin | `SecurityDecorator.kt:26` | IDIOMATIC | mixin fold |
| `decorators/authentication.py:12` | AuthenticationMixin.require_https | `SecurityDecorator.kt:202` | FULL | |
| `decorators/authentication.py:20` | AuthenticationMixin.require_auth | `SecurityDecorator.kt:209` | FULL | |
| `decorators/authentication.py:39` | AuthenticationMixin.api_key_auth | `SecurityDecorator.kt:228` | FULL | |
| `decorators/authentication.py:60` | AuthenticationMixin.require_authorization_header | `SecurityDecorator.kt:249` | FULL | |
| `decorators/authentication.py:77` | AuthenticationMixin.require_headers | `SecurityDecorator.kt:263` | FULL | |
| `decorators/base.py:47` | DecoratedFunction | `BaseSecurityDecorator.kt:1` | IDIOMATIC | wrapped-Callable type -> RouteConfigProvider + StampedRoute route key (method identity; guard-core #141/#142 study) |
| `decorators/base.py:53` | BaseSecurityMixin | `BaseSecurityDecorator.kt:1` | IDIOMATIC | mixin fold -> BaseSecurityDecorator + RouteConfigProvider |
| `decorators/base.py:61` | BaseSecurityDecorator | `BaseSecurityDecorator.kt:16` | FULL | |
| `decorators/base.py:78` | BaseSecurityDecorator.route_config_revision | `BaseSecurityDecorator.kt:35` | FULL | |
| `decorators/base.py:81` | BaseSecurityDecorator.get_route_config | `BaseSecurityDecorator.kt:44` | FULL | |
| `decorators/base.py:125` | BaseSecurityDecorator.initialize_behavior_tracking | `BaseSecurityDecorator.kt:99` | FULL | |
| `decorators/base.py:129` | BaseSecurityDecorator.initialize_agent | `BaseSecurityDecorator.kt:108` | FULL | |
| `decorators/base.py:136` | BaseSecurityDecorator.send_decorator_event | `BaseSecurityDecorator.kt:115` | FULL | |
| `decorators/base.py:164` | BaseSecurityDecorator.send_access_denied_event | `BaseSecurityDecorator.kt:143` | FULL | |
| `decorators/base.py:182` | BaseSecurityDecorator.send_authentication_failed_event | `BaseSecurityDecorator.kt:160` | FULL | |
| `decorators/base.py:201` | BaseSecurityDecorator.send_rate_limit_event | `BaseSecurityDecorator.kt:177` | FULL | |
| `decorators/base.py:221` | BaseSecurityDecorator.send_decorator_violation_event | `BaseSecurityDecorator.kt:197` | FULL | |
| `decorators/base.py:240` | get_route_decorator_config | `BaseSecurityDecorator.kt:222` | FULL | |
| `decorators/behavioral.py:9` | BehavioralMixin | `SecurityDecorator.kt:26` | IDIOMATIC | mixin fold |
| `decorators/behavioral.py:12` | BehavioralMixin.usage_monitor | `SecurityDecorator.kt:127` | FULL | |
| `decorators/behavioral.py:29` | BehavioralMixin.return_monitor | `SecurityDecorator.kt:146` | FULL | |
| `decorators/behavioral.py:53` | BehavioralMixin.behavior_analysis | `SecurityDecorator.kt:168` | FULL | |
| `decorators/behavioral.py:67` | BehavioralMixin.suspicious_frequency | `SecurityDecorator.kt:180` | FULL | |
| `decorators/content_filtering.py:10` | ContentFilteringMixin | `SecurityDecorator.kt:26` | IDIOMATIC | mixin fold |
| `decorators/content_filtering.py:13` | ContentFilteringMixin.block_user_agents | `SecurityDecorator.kt:275` | FULL | |
| `decorators/content_filtering.py:39` | ContentFilteringMixin.content_type_filter | `SecurityDecorator.kt:296` | FULL | |
| `decorators/content_filtering.py:49` | ContentFilteringMixin.max_request_size | `SecurityDecorator.kt:303` | FULL | |
| `decorators/content_filtering.py:59` | ContentFilteringMixin.require_referrer | `SecurityDecorator.kt:310` | FULL | |
| `decorators/content_filtering.py:69` | ContentFilteringMixin.custom_validation | `SecurityDecorator.kt:317` | FULL | |
| `decorators/content_filtering.py:80` | ContentFilteringMixin.detection_exclusion | `SecurityDecorator.kt:327` | FULL | |
| `decorators/rate_limiting.py:7` | RateLimitingMixin | `SecurityDecorator.kt:26` | IDIOMATIC | mixin fold |
| `decorators/rate_limiting.py:8` | RateLimitingMixin.rate_limit | `SecurityDecorator.kt:106` | FULL | |
| `decorators/rate_limiting.py:19` | RateLimitingMixin.geo_rate_limit | `SecurityDecorator.kt:118` | FULL | |
| `decorators/route_config.py:17` | RouteConfigRevision | `RouteConfig.kt:20` | FULL | |
| `decorators/route_config.py:21` | RouteConfigRevision.bump | `RouteConfig.kt:23` | FULL | |
| `decorators/route_config.py:43` | _TrackedList.append | `RouteConfig.kt:72` | IDIOMATIC | python list protocol -> Kotlin MutableList override add() with revision bump |
| `decorators/route_config.py:47` | _TrackedList.extend | `RouteConfig.kt:76` | IDIOMATIC | addAll override with revision bump |
| `decorators/route_config.py:51` | _TrackedList.insert | `RouteConfig.kt:74` | IDIOMATIC | add(index, element) override |
| `decorators/route_config.py:55` | _TrackedList.remove | `RouteConfig.kt:83` | FULL | |
| `decorators/route_config.py:59` | _TrackedList.pop | `RouteConfig.kt:81` | IDIOMATIC | removeAt override |
| `decorators/route_config.py:63` | _TrackedList.clear | `RouteConfig.kt:89` | FULL | |
| `decorators/route_config.py:67` | _TrackedList.sort | `RouteConfig.kt:91` | IDIOMATIC | set/sortBy through bumped() mutation helpers |
| `decorators/route_config.py:71` | _TrackedList.reverse | `RouteConfig.kt:89` | IDIOMATIC | clear/mutation helpers through bumped() |
| `decorators/route_config.py:118` | _TrackedDict.update | `RouteConfig.kt:101` | IDIOMATIC | python dict protocol -> Kotlin MutableMap overrides with revision bump (bumped() at :101) |
| `decorators/route_config.py:122` | _TrackedDict.setdefault | `RouteConfig.kt:101` | IDIOMATIC | put override family |
| `decorators/route_config.py:126` | _TrackedDict.pop | `RouteConfig.kt:101` | IDIOMATIC | remove override family |
| `decorators/route_config.py:130` | _TrackedDict.popitem | `RouteConfig.kt:101` | IDIOMATIC | iterator + remove through bumped() |
| `decorators/route_config.py:134` | _TrackedDict.clear | `RouteConfig.kt:89` | FULL | |
| `decorators/route_config.py:157` | _TrackedSet.add | `RouteConfig.kt:72` | FULL | |
| `decorators/route_config.py:161` | _TrackedSet.discard | `RouteConfig.kt:143` | IDIOMATIC | python set protocol -> Kotlin MutableSet overrides with revision bump (bumped() at :143) |
| `decorators/route_config.py:165` | _TrackedSet.remove | `RouteConfig.kt:83` | FULL | |
| `decorators/route_config.py:169` | _TrackedSet.pop | `RouteConfig.kt:143` | IDIOMATIC | iterator + remove through bumped() |
| `decorators/route_config.py:173` | _TrackedSet.clear | `RouteConfig.kt:89` | FULL | |
| `decorators/route_config.py:177` | _TrackedSet.update | `RouteConfig.kt:143` | IDIOMATIC | addAll override |
| `decorators/route_config.py:181` | _TrackedSet.intersection_update | `RouteConfig.kt:143` | IDIOMATIC | retainAll override |
| `decorators/route_config.py:185` | _TrackedSet.difference_update | `RouteConfig.kt:143` | IDIOMATIC | removeAll override |
| `decorators/route_config.py:189` | _TrackedSet.symmetric_difference_update | `RouteConfig.kt:143` | IDIOMATIC | composed addAll/removeAll through bumped() |
| `decorators/route_config.py:241` | RouteConfig | `RouteConfig.kt:187` | FULL | |

## Observable constants (check names, event types, categories, redis namespaces, headers)

50 rows: 50 FULL, 0 IDIOMATIC, 0 PARTIAL, 0 MISSING.

Evidence: Event type strings pinned byte-exact by event_stream envelopes; check names pinned by pipeline + detect suites; redis namespaces pinned by redis_interop 14/14; header names pinned by Boot factory-exact 403/400/413/429/301 shape tests; categories pinned by detect + suspatterns table dump-diff.

| Python anchor | Python symbol | JVM anchor | Status | Note |
|---|---|---|---|---|
| `core/events/event_types.py:5` | `EVENT_PENETRATION_ATTEMPT = penetration_attempt` | `EventTypes.kt:10` | FULL | |
| `core/events/event_types.py:6` | `EVENT_IP_BLOCKED = ip_blocked` | `EventTypes.kt:11` | FULL | |
| `core/events/event_types.py:7` | `EVENT_IP_BANNED = ip_banned` | `EventTypes.kt:12` | FULL | |
| `core/events/event_types.py:8` | `EVENT_IP_BAN_FAILED = ip_ban_failed` | `EventTypes.kt:13` | FULL | |
| `core/events/event_types.py:9` | `EVENT_IP_UNBANNED = ip_unbanned` | `EventTypes.kt:14` | FULL | |
| `core/events/event_types.py:10` | `EVENT_CLOUD_BLOCKED = cloud_blocked` | `EventTypes.kt:15` | FULL | |
| `core/events/event_types.py:11` | `EVENT_HTTPS_ENFORCED = https_enforced` | `EventTypes.kt:16` | FULL | |
| `core/events/event_types.py:12` | `EVENT_DECORATOR_VIOLATION = decorator_violation` | `EventTypes.kt:17` | FULL | |
| `core/events/event_types.py:13` | `EVENT_BEHAVIOR_VIOLATION = behavioral_violation` | `EventTypes.kt:18` | FULL | |
| `core/events/event_types.py:14` | `EVENT_PATTERN_DETECTED = pattern_detected` | `EventTypes.kt:19` | FULL | |
| `core/events/event_types.py:15` | `EVENT_DYNAMIC_RULE_UPDATED = dynamic_rule_updated` | `EventTypes.kt:20` | FULL | |
| `core/events/event_types.py:16` | `EVENT_DYNAMIC_RULE_APPLIED = dynamic_rule_applied` | `EventTypes.kt:21` | FULL | |
| `core/events/event_types.py:17` | `EVENT_DYNAMIC_RULE_VIOLATION = dynamic_rule_violation` | `EventTypes.kt:22` | FULL | |
| `core/events/event_types.py:18` | `EVENT_EMERGENCY_MODE = emergency_mode_activated` | `EventTypes.kt:23` | FULL | |
| `core/events/event_types.py:20` | `EVENT_ACCESS_DENIED = access_denied` | `EventTypes.kt:25` | FULL | |
| `core/events/event_types.py:21` | `EVENT_AUTHENTICATION_FAILED = authentication_failed` | `EventTypes.kt:26` | FULL | |
| `core/events/event_types.py:22` | `EVENT_CONTENT_FILTERED = content_filtered` | `EventTypes.kt:27` | FULL | |
| `core/events/event_types.py:23` | `EVENT_COUNTRY_BLOCKED = country_blocked` | `EventTypes.kt:28` | FULL | |
| `core/events/event_types.py:24` | `EVENT_CSP_VIOLATION = csp_violation` | `EventTypes.kt:29` | FULL | |
| `core/events/event_types.py:25` | `EVENT_CUSTOM_REQUEST_CHECK = custom_request_check` | `EventTypes.kt:30` | FULL | |
| `core/events/event_types.py:26` | `EVENT_DECODING_ERROR = decoding_error` | `EventTypes.kt:31` | FULL | |
| `core/events/event_types.py:27` | `EVENT_EMERGENCY_MODE_BLOCK = emergency_mode_block` | `EventTypes.kt:32` | FULL | |
| `core/events/event_types.py:28` | `EVENT_GEO_LOOKUP_FAILED = geo_lookup_failed` | `EventTypes.kt:33` | FULL | |
| `core/events/event_types.py:29` | `EVENT_PATH_EXCLUDED = path_excluded` | `EventTypes.kt:34` | FULL | |
| `core/events/event_types.py:30` | `EVENT_PATTERN_ADDED = pattern_added` | `EventTypes.kt:35` | FULL | |
| `core/events/event_types.py:31` | `EVENT_PATTERN_REMOVED = pattern_removed` | `EventTypes.kt:36` | FULL | |
| `core/events/event_types.py:32` | `EVENT_RATE_LIMITED = rate_limited` | `EventTypes.kt:37` | FULL | |
| `core/events/event_types.py:33` | `EVENT_RATE_LIMIT_SCRIPT_RELOADED = rate_limit_script_reloaded` | `EventTypes.kt:38` | FULL | |
| `core/events/event_types.py:34` | `EVENT_REDIS_CONNECTION = redis_connection` | `EventTypes.kt:39` | FULL | |
| `core/events/event_types.py:35` | `EVENT_REDIS_ERROR = redis_error` | `EventTypes.kt:40` | FULL | |
| `core/events/event_types.py:36` | `EVENT_ROUTE_UNRESOLVED = route_unresolved` | `EventTypes.kt:41` | FULL | |
| `core/events/event_types.py:37` | `EVENT_SECURITY_BYPASS = security_bypass` | `EventTypes.kt:42` | FULL | |
| `core/events/event_types.py:38` | `EVENT_SECURITY_HEADERS_APPLIED = security_headers_applied` | `EventTypes.kt:43` | FULL | |
| `core/events/event_types.py:39` | `EVENT_USER_AGENT_BLOCKED = user_agent_blocked` | `EventTypes.kt:44` | FULL | |
| `core/events/event_types.py:40` | `EVENT_SUSPICIOUS_REQUEST = suspicious_request` | `EventTypes.kt:45` | FULL | |
| `core/events/event_types.py:41` | `EVENT_DETECTION_ENGINE_CALLBACK_ERROR = detection_engine_callback_error` | `EventTypes.kt:46` | FULL | |
| `core/events/event_types.py:42` | `EVENT_PATTERN_ANOMALY_TIMEOUT = pattern_anomaly_timeout` | `EventTypes.kt:47` | FULL | |
| `core/events/event_types.py:43` | `EVENT_PATTERN_ANOMALY_SLOW_EXECUTION = pattern_anomaly_slow_execution` | `EventTypes.kt:48` | FULL | |
| `core/events/event_types.py:44` | `EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY = pattern_anomaly_statistical_anomaly` | `EventTypes.kt:50` | FULL | |
| `core/events/event_types.py:90` | `METRIC_RESPONSE_TIME = response_time` | `EventTypes.kt:52` | FULL | |
| `core/events/event_types.py:91` | `METRIC_REQUEST_COUNT = request_count` | `EventTypes.kt:53` | FULL | |
| `core/events/event_types.py:92` | `METRIC_ERROR_RATE = error_rate` | `EventTypes.kt:54` | FULL | |
| `core/events/event_types.py:125` | `ENRICHMENT_KEY_PROJECT_ID = guard.project_id` | `EventTypes.kt:131` | FULL | |
| `core/events/event_types.py:126` | `ENRICHMENT_KEY_SERVICE_NAME = guard.service.name` | `EventTypes.kt:132` | FULL | |
| `core/events/event_types.py:127` | `ENRICHMENT_KEY_DEPLOYMENT_ENV = guard.deployment.environment` | `EventTypes.kt:133` | FULL | |
| `core/events/event_types.py:128` | `ENRICHMENT_KEY_THREAT_SCORE = guard.threat_score` | `EventTypes.kt:134` | FULL | |
| `core/events/event_types.py:129` | `ENRICHMENT_KEY_RULE_ID = guard.rule.id` | `EventTypes.kt:135` | FULL | |
| `core/events/event_types.py:130` | `ENRICHMENT_KEY_RULE_VERSION = guard.rule.version` | `EventTypes.kt:136` | FULL | |
| `core/events/event_types.py:131` | `ENRICHMENT_KEY_BEHAVIOR_KEY = guard.behavior.correlation_key` | `EventTypes.kt:137` | FULL | |
| `core/events/event_types.py:132` | `ENRICHMENT_KEY_RECENT_EVENT_COUNT = guard.behavior.recent_event_count` | `EventTypes.kt:138` | FULL | |

## Idiom mappings (syntax, not gaps)

TRUE PORTS rule 26: these are language-level construct mappings; the
behavior behind each mapping is verified by the corpus or the ported
test surface. None of these rows is a parity gap.

| Python construct | JVM construct | Rows | Behavior proof |
|---|---|---|---|
| `async def` + asyncio plumbing | `suspend fun` + structured concurrency (1:1 per impl/jvm.md) | surface-wide | every suite green under the comparison contract |
| unasync `sync/` mirror | `JavaBridges.kt` `xBlocking` (runBlocking confined to entry points) + `xFuture` | bridges | proven from Java source (W4b); sync consumers use xBlocking |
| decorator callables + `*Mixin` composition | `SecurityDecorator` factory methods (25/25); adapter annotations (Boot) / plugin (ktor); `HandlerRouteKey` method identity | 24 | SecurityDecoratorTest 1:1; both adapters' decorator suites |
| pydantic `BaseModel`/`Field` + validators | `SecurityConfig` properties + `ConfigFieldRegistry` `FieldMeta` + builder, byte-matched rejection messages | 129 | W1 field-for-field gate (docs/w1-config-parity.md) |
| `typing.Protocol` (runtime_checkable) | Kotlin interfaces | 61 | adapters implement them over native types (W6) |
| redis-py | Lettuce 6.7.1 | handlers | redis_interop 14/14, section 08 schema byte-exact |
| `re` module | PyRe translation layer (python-grammar fail-closed parser) | detection | pattern ledger 158 as_is / 0 translated; detect 193/193 |
| `logging` | slf4j-style console handlers + ported formatters | utils | logging display tests (W3+) |
| contextvars scan budget | `DetectionScanBudget` over the `DetectionScanContext` seam | utils | cost budgets 9/9 |
| cachetools TTLCache/LRU | `TtlCache`/`LruStore` ports (injectable clock) | handlers | ipban cache tests |
| `pickle._Unpickler` dispatch | explicit opcode table, blocked resolutions raise | detection | SusPatternsUnitTest |
| duck-typed event params | named protocol surfaces (`AgentHandlerProtocol`, envelopes) | core | event_stream envelopes byte-shaped (17-key model) |
| guard-agent Go `context.Context` | coroutine contexts + `AgentContext` (guard-agent-jvm) | agent | 196 JUnit tests, crypto-vector proof |
| User-Agent family suffix | `guard-core-jvm/...` family naming (guard-agent-jvm KNOWN_GAPS G-A rows) | agent | transport tests |

## Ledger cross-reference

The corpus gate is green with 8 ledgered entries
(`guard-core-conformance/src/test/resources/jvm_events_xfail.json` + the
pattern-safety timing ledger). Per the Parity bar these are documented,
verified classes - not unported surface:

1. `evt_geo_lookup_failed_download` - reason string embeds the python
   exception class name (RuntimeError) where the JVM raises
   RuntimeException; the TS floor divergence class.
2. `evt_redis_error_connection_failed` - reason string embeds redis-py
   errno text where Lettuce renders its own; the TS floor class.
3-8. Six pattern-safety timing facts (2 mirror the RS python-re timing
   ledger; 4 boundary/timing flips incl. the Go `safe_05` twin). Verdict
   classes were verified EQUAL against the live reference oracle (W2);
   the ledger entries pin timing-oracle boundaries, fail-closed by
   design (a listed workload that comes back under ceiling FAILS).

KNOWN_GAPS G-1..G-13: all closed or re-scoped with reasons (see that
ledger). G-3's agent registration point is guard-agent-jvm's
`FacadeBridge` (implements `AgentHandlerProtocol`); `toAgentConfig`
short-circuits and the `AgentPackageNotInstalledError` raise are live in
the facade (SecurityConfig.kt:2578).

## Verdict

Parity bar arm 2: SATISFIED. Zero PARTIAL rows, zero MISSING rows.
