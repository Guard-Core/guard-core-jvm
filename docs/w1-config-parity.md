# W1 config parity gate (guard-core-jvm)

Wave 1 proof: SecurityConfig, its field registry, the protocol interfaces and
the util layer ported from the guard-core Python reference (4.3.2). Every row
carries the python file:line and the Kotlin file:line, per the wave gate.

Reference commit: Python/guard-core @ master (4.3.2). JVM branch:
chore/w1-foundation.

## Field-by-field parity (SecurityConfig)

129 of 129 python fields ported, no TODO cells. Column notes:

- python file:line points at the field declaration in
  `guard_core/_security_config_fields.py`.
- validation lists the pydantic `Field` bounds, the `models.py` field
  validator (with its line), and whether the field is a key of
  `_FIELD_REVALIDATORS` (assignment-time revalidation,
  `_security_config_field_validators.py:364-478`).
- kotlin file:line points at the property KDoc (`python_name:` marker) in
  `guard-core/src/main/kotlin/com/guardcore/config/SecurityConfig.kt`; the
  registry row points at the `FieldMeta` entry in `ConfigFieldRegistry.kt`,
  the ported `_security_config_fields.py` table.

| python field | python file:line | default | validation | kotlin prop | registry |
|---|---|---|---|---|---|
| `trusted_proxies` | _security_config_fields.py:22 | `factory tuple` | models.py:159 validate_trusted_proxies; revalidated on assignment | SecurityConfig.kt:94 | ConfigFieldRegistry.kt:68 |
| `trusted_proxy_depth` | _security_config_fields.py:27 | `1` | models.py:165 validate_proxy_depth | SecurityConfig.kt:106 | ConfigFieldRegistry.kt:76 |
| `trust_x_forwarded_proto` | _security_config_fields.py:32 | `False` | typed | SecurityConfig.kt:117 | ConfigFieldRegistry.kt:77 |
| `passive_mode` | _security_config_fields.py:37 | `False` | typed | SecurityConfig.kt:128 | ConfigFieldRegistry.kt:78 |
| `geo_ip_handler` | _security_config_fields.py:42 | `None` | typed | SecurityConfig.kt:139 | ConfigFieldRegistry.kt:79 |
| `enable_redis` | _security_config_fields.py:47 | `True` | typed | SecurityConfig.kt:152 | ConfigFieldRegistry.kt:86 |
| `redis_url` | _security_config_fields.py:52 | `"redis://localhost:6379"` | typed | SecurityConfig.kt:163 | ConfigFieldRegistry.kt:87 |
| `redis_prefix` | _security_config_fields.py:57 | `"guard_core:"` | typed | SecurityConfig.kt:174 | ConfigFieldRegistry.kt:88 |
| `redis_socket_connect_timeout` | _security_config_fields.py:62 | `2.0` | Field(gt=0.0) | SecurityConfig.kt:185 | ConfigFieldRegistry.kt:89 |
| `redis_socket_timeout` | _security_config_fields.py:74 | `2.0` | Field(gt=0.0) | SecurityConfig.kt:196 | ConfigFieldRegistry.kt:96 |
| `redis_health_check_interval` | _security_config_fields.py:85 | `30` | Field(ge=0) | SecurityConfig.kt:207 | ConfigFieldRegistry.kt:103 |
| `redis_max_connections` | _security_config_fields.py:95 | `None` | Field(ge=1) | SecurityConfig.kt:218 | ConfigFieldRegistry.kt:110 |
| `redis_retries` | _security_config_fields.py:103 | `1` | Field(ge=0) | SecurityConfig.kt:229 | ConfigFieldRegistry.kt:117 |
| `whitelist` | _security_config_fields.py:112 | `None` | models.py:155 validate_ip_lists; revalidated on assignment | SecurityConfig.kt:240 | ConfigFieldRegistry.kt:118 |
| `blacklist` | _security_config_fields.py:121 | `factory tuple` | models.py:155 validate_ip_lists; revalidated on assignment | SecurityConfig.kt:253 | ConfigFieldRegistry.kt:125 |
| `exempt_ips` | _security_config_fields.py:129 | `factory tuple` | models.py:155 validate_ip_lists; revalidated on assignment | SecurityConfig.kt:265 | ConfigFieldRegistry.kt:126 |
| `whitelist_countries` | _security_config_fields.py:139 | `factory frozenset` | models.py:171 coerce_country_set; revalidated on assignment | SecurityConfig.kt:282 | ConfigFieldRegistry.kt:127 |
| `blocked_countries` | _security_config_fields.py:149 | `factory frozenset` | models.py:171 coerce_country_set; revalidated on assignment | SecurityConfig.kt:296 | ConfigFieldRegistry.kt:135 |
| `blocked_user_agents` | _security_config_fields.py:154 | `factory list` | models.py:179 validate_blocked_user_agents; revalidated on assignment | SecurityConfig.kt:310 | ConfigFieldRegistry.kt:143 |
| `auto_ban_threshold` | _security_config_fields.py:158 | `10` | Field(ge=1); revalidated on assignment | SecurityConfig.kt:322 | ConfigFieldRegistry.kt:150 |
| `auto_ban_duration` | _security_config_fields.py:164 | `3600` | Field(ge=1); revalidated on assignment | SecurityConfig.kt:334 | ConfigFieldRegistry.kt:158 |
| `threat_ban_config` | _security_config_fields.py:170 | `factory lambda` | models.py:290 validate_threat_ban_config; revalidated on assignment | SecurityConfig.kt:346 | ConfigFieldRegistry.kt:166 |
| `enable_rate_limit_auto_ban` | _security_config_fields.py:180 | `False` | revalidated on assignment | SecurityConfig.kt:358 | ConfigFieldRegistry.kt:173 |
| `global_behavior_rules` | _security_config_fields.py:193 | `factory tuple` | revalidated on assignment | SecurityConfig.kt:371 | ConfigFieldRegistry.kt:180 |
| `behavior_scan_response_body` | _security_config_fields.py:201 | `False` | typed | SecurityConfig.kt:389 | ConfigFieldRegistry.kt:187 |
| `behavior_max_response_body_inspect_bytes` | _security_config_fields.py:220 | `262144` | Field(ge=1024,le=10485760) | SecurityConfig.kt:401 | ConfigFieldRegistry.kt:194 |
| `body_read_timeout` | _security_config_fields.py:241 | `3.0` | Field(gt=0.0,le=30.0) | SecurityConfig.kt:412 | ConfigFieldRegistry.kt:202 |
| `sync_body_read_max_concurrent` | _security_config_fields.py:266 | `64` | Field(ge=1,le=10000) | SecurityConfig.kt:423 | ConfigFieldRegistry.kt:210 |
| `custom_log_file` | _security_config_fields.py:282 | `None` | typed | SecurityConfig.kt:434 | ConfigFieldRegistry.kt:218 |
| `log_suspicious_level` | _security_config_fields.py:287 | `"WARNING"` | typed | SecurityConfig.kt:445 | ConfigFieldRegistry.kt:219 |
| `log_request_level` | _security_config_fields.py:291 | `None` | typed | SecurityConfig.kt:456 | ConfigFieldRegistry.kt:220 |
| `log_country_check_level` | _security_config_fields.py:295 | `"INFO"` | typed | SecurityConfig.kt:467 | ConfigFieldRegistry.kt:221 |
| `log_format` | _security_config_fields.py:307 | `"text"` | typed | SecurityConfig.kt:478 | ConfigFieldRegistry.kt:227 |
| `custom_error_responses` | _security_config_fields.py:312 | `factory dict` | revalidated on assignment | SecurityConfig.kt:489 | ConfigFieldRegistry.kt:228 |
| `rate_limit` | _security_config_fields.py:316 | `10` | revalidated on assignment | SecurityConfig.kt:501 | ConfigFieldRegistry.kt:235 |
| `rate_limit_window` | _security_config_fields.py:320 | `60` | revalidated on assignment | SecurityConfig.kt:513 | ConfigFieldRegistry.kt:236 |
| `enforce_https` | _security_config_fields.py:324 | `False` | typed | SecurityConfig.kt:525 | ConfigFieldRegistry.kt:243 |
| `security_headers` | _security_config_fields.py:328 | `factory lambda` | revalidated on assignment | SecurityConfig.kt:536 | ConfigFieldRegistry.kt:244 |
| `custom_request_check` | _security_config_fields.py:347 | `None` | typed | SecurityConfig.kt:548 | ConfigFieldRegistry.kt:251 |
| `auth_verifier` | _security_config_fields.py:351 | `None` | typed | SecurityConfig.kt:559 | ConfigFieldRegistry.kt:252 |
| `custom_response_modifier` | _security_config_fields.py:361 | `None` | typed | SecurityConfig.kt:570 | ConfigFieldRegistry.kt:253 |
| `enable_cors` | _security_config_fields.py:368 | `False` | typed | SecurityConfig.kt:581 | ConfigFieldRegistry.kt:259 |
| `cors_allow_origins` | _security_config_fields.py:370 | `factory lambda` | revalidated on assignment | SecurityConfig.kt:592 | ConfigFieldRegistry.kt:260 |
| `cors_allow_methods` | _security_config_fields.py:374 | `factory lambda` | revalidated on assignment | SecurityConfig.kt:605 | ConfigFieldRegistry.kt:267 |
| `cors_allow_headers` | _security_config_fields.py:379 | `factory lambda` | revalidated on assignment | SecurityConfig.kt:617 | ConfigFieldRegistry.kt:274 |
| `cors_allow_credentials` | _security_config_fields.py:383 | `False` | typed | SecurityConfig.kt:629 | ConfigFieldRegistry.kt:281 |
| `cors_expose_headers` | _security_config_fields.py:387 | `factory list` | revalidated on assignment | SecurityConfig.kt:640 | ConfigFieldRegistry.kt:282 |
| `cors_max_age` | _security_config_fields.py:391 | `600` | typed | SecurityConfig.kt:652 | ConfigFieldRegistry.kt:289 |
| `block_cloud_providers` | _security_config_fields.py:395 | `None` | models.py:175 validate_cloud_providers; revalidated on assignment | SecurityConfig.kt:663 | ConfigFieldRegistry.kt:290 |
| `cloud_ip_refresh_interval` | _security_config_fields.py:408 | `3600` | Field(ge=60,le=86400) | SecurityConfig.kt:675 | ConfigFieldRegistry.kt:297 |
| `lazy_init` | _security_config_fields.py:415 | `True` | typed | SecurityConfig.kt:686 | ConfigFieldRegistry.kt:305 |
| `geo_ip_db_max_age` | _security_config_fields.py:434 | `86400` | Field(ge=3600,le=604800) | SecurityConfig.kt:697 | ConfigFieldRegistry.kt:306 |
| `cloud_ip_store` | _security_config_fields.py:441 | `None` | typed | SecurityConfig.kt:709 | ConfigFieldRegistry.kt:314 |
| `exclude_paths` | _security_config_fields.py:452 | `factory lambda` | models.py:310 validate_exclude_paths; revalidated on assignment | SecurityConfig.kt:723 | ConfigFieldRegistry.kt:315 |
| `enable_ip_banning` | _security_config_fields.py:464 | `True` | revalidated on assignment | SecurityConfig.kt:735 | ConfigFieldRegistry.kt:322 |
| `enable_rate_limiting` | _security_config_fields.py:468 | `True` | revalidated on assignment | SecurityConfig.kt:747 | ConfigFieldRegistry.kt:329 |
| `enable_penetration_detection` | _security_config_fields.py:472 | `True` | revalidated on assignment | SecurityConfig.kt:759 | ConfigFieldRegistry.kt:336 |
| `fail_secure` | _security_config_fields.py:476 | `True` | typed | SecurityConfig.kt:771 | ConfigFieldRegistry.kt:343 |
| `redis_fail_open` | _security_config_fields.py:486 | `False` | typed | SecurityConfig.kt:782 | ConfigFieldRegistry.kt:344 |
| `route_resolution_strict` | _security_config_fields.py:498 | `False` | typed | SecurityConfig.kt:793 | ConfigFieldRegistry.kt:345 |
| `ipinfo_token` | _security_config_fields.py:513 | `None` | typed | SecurityConfig.kt:804 | ConfigFieldRegistry.kt:346 |
| `ipinfo_db_path` | _security_config_fields.py:519 | `Path("data/ipinfo/country_asn.mmdb"` | typed | SecurityConfig.kt:815 | ConfigFieldRegistry.kt:347 |
| `enable_agent` | _security_config_fields.py:525 | `False` | typed | SecurityConfig.kt:826 | ConfigFieldRegistry.kt:353 |
| `agent_api_key` | _security_config_fields.py:529 | `None` | typed | SecurityConfig.kt:837 | ConfigFieldRegistry.kt:354 |
| `agent_strict` | _security_config_fields.py:533 | `False` | typed | SecurityConfig.kt:848 | ConfigFieldRegistry.kt:355 |
| `on_error` | _security_config_fields.py:542 | `None` | typed | SecurityConfig.kt:859 | ConfigFieldRegistry.kt:356 |
| `on_block` | _security_config_fields.py:552 | `None` | typed | SecurityConfig.kt:870 | ConfigFieldRegistry.kt:357 |
| `agent_endpoint` | _security_config_fields.py:569 | `"https://api.guard-core.com"` | typed | SecurityConfig.kt:881 | ConfigFieldRegistry.kt:358 |
| `agent_project_id` | _security_config_fields.py:574 | `None` | typed | SecurityConfig.kt:892 | ConfigFieldRegistry.kt:359 |
| `agent_buffer_size` | _security_config_fields.py:578 | `100` | typed | SecurityConfig.kt:903 | ConfigFieldRegistry.kt:360 |
| `agent_flush_interval` | _security_config_fields.py:582 | `30` | typed | SecurityConfig.kt:914 | ConfigFieldRegistry.kt:361 |
| `agent_enable_events` | _security_config_fields.py:586 | `True` | typed | SecurityConfig.kt:925 | ConfigFieldRegistry.kt:362 |
| `agent_enable_metrics` | _security_config_fields.py:590 | `True` | typed | SecurityConfig.kt:936 | ConfigFieldRegistry.kt:363 |
| `agent_timeout` | _security_config_fields.py:594 | `30` | typed | SecurityConfig.kt:947 | ConfigFieldRegistry.kt:364 |
| `agent_retry_attempts` | _security_config_fields.py:598 | `3` | typed | SecurityConfig.kt:958 | ConfigFieldRegistry.kt:365 |
| `agent_project_encryption_key` | _security_config_fields.py:602 | `None` | typed | SecurityConfig.kt:969 | ConfigFieldRegistry.kt:366 |
| `agent_guard_version` | _security_config_fields.py:612 | `None` | typed | SecurityConfig.kt:980 | ConfigFieldRegistry.kt:372 |
| `agent_high_watermark_ratio` | _security_config_fields.py:622 | `None` | typed | SecurityConfig.kt:991 | ConfigFieldRegistry.kt:373 |
| `agent_max_concurrent_flushes` | _security_config_fields.py:630 | `None` | typed | SecurityConfig.kt:1002 | ConfigFieldRegistry.kt:379 |
| `agent_buffer_overflow_policy` | _security_config_fields.py:638 | `None` | typed | SecurityConfig.kt:1013 | ConfigFieldRegistry.kt:385 |
| `agent_backoff_factor` | _security_config_fields.py:649 | `None` | typed | SecurityConfig.kt:1024 | ConfigFieldRegistry.kt:391 |
| `agent_sensitive_headers` | _security_config_fields.py:657 | `None` | revalidated on assignment | SecurityConfig.kt:1035 | ConfigFieldRegistry.kt:392 |
| `agent_max_payload_size` | _security_config_fields.py:665 | `None` | typed | SecurityConfig.kt:1047 | ConfigFieldRegistry.kt:399 |
| `agent_compression_enabled` | _security_config_fields.py:673 | `None` | typed | SecurityConfig.kt:1058 | ConfigFieldRegistry.kt:400 |
| `agent_compression_threshold` | _security_config_fields.py:682 | `None` | typed | SecurityConfig.kt:1069 | ConfigFieldRegistry.kt:406 |
| `agent_install_id` | _security_config_fields.py:690 | `None` | typed | SecurityConfig.kt:1080 | ConfigFieldRegistry.kt:412 |
| `agent_payload_signing_secret` | _security_config_fields.py:698 | `None` | typed | SecurityConfig.kt:1091 | ConfigFieldRegistry.kt:413 |
| `enable_dynamic_rules` | _security_config_fields.py:703 | `False` | typed | SecurityConfig.kt:1102 | ConfigFieldRegistry.kt:419 |
| `dynamic_rule_interval` | _security_config_fields.py:707 | `300` | Field(ge=60) | SecurityConfig.kt:1113 | ConfigFieldRegistry.kt:420 |
| `dynamic_rules_cache_path` | _security_config_fields.py:713 | `None` | models.py:314 validate_dynamic_rules_cache_path; revalidated on assignment | SecurityConfig.kt:1124 | ConfigFieldRegistry.kt:421 |
| `agent_status_interval` | _security_config_fields.py:722 | `300` | Field(ge=60,le=86400) | SecurityConfig.kt:1136 | ConfigFieldRegistry.kt:428 |
| `emergency_mode` | _security_config_fields.py:729 | `False` | revalidated on assignment | SecurityConfig.kt:1147 | ConfigFieldRegistry.kt:436 |
| `emergency_whitelist` | _security_config_fields.py:733 | `factory list` | revalidated on assignment | SecurityConfig.kt:1159 | ConfigFieldRegistry.kt:443 |
| `endpoint_rate_limits` | _security_config_fields.py:738 | `factory dict` | revalidated on assignment | SecurityConfig.kt:1171 | ConfigFieldRegistry.kt:450 |
| `detection_compiler_timeout` | _security_config_fields.py:743 | `2.0` | Field(ge=0.1,le=10.0) | SecurityConfig.kt:1183 | ConfigFieldRegistry.kt:457 |
| `detection_pattern_validation_cache_path` | _security_config_fields.py:750 | `None` | typed | SecurityConfig.kt:1194 | ConfigFieldRegistry.kt:465 |
| `detection_max_content_length` | _security_config_fields.py:768 | `10000` | Field(ge=1000,le=100000) | SecurityConfig.kt:1205 | ConfigFieldRegistry.kt:471 |
| `detection_max_body_inspect_bytes` | _security_config_fields.py:783 | `262144` | Field(ge=1024,le=10485760) | SecurityConfig.kt:1216 | ConfigFieldRegistry.kt:479 |
| `detection_max_scan_values` | _security_config_fields.py:814 | `512` | Field(ge=2,le=100_000) | SecurityConfig.kt:1227 | ConfigFieldRegistry.kt:487 |
| `detection_max_scan_chars` | _security_config_fields.py:833 | `65536` | Field(ge=1024,le=262144) | SecurityConfig.kt:1238 | ConfigFieldRegistry.kt:495 |
| `detection_max_json_depth` | _security_config_fields.py:853 | `32` | Field(ge=1,le=1000) | SecurityConfig.kt:1249 | ConfigFieldRegistry.kt:503 |
| `detection_binary_min_run_length` | _security_config_fields.py:871 | `16` | Field(ge=4,le=1024) | SecurityConfig.kt:1260 | ConfigFieldRegistry.kt:511 |
| `detection_preserve_attack_patterns` | _security_config_fields.py:899 | `True` | typed | SecurityConfig.kt:1271 | ConfigFieldRegistry.kt:519 |
| `detection_semantic_threshold` | _security_config_fields.py:904 | `0.7` | Field(ge=0.0,le=1.0) | SecurityConfig.kt:1282 | ConfigFieldRegistry.kt:525 |
| `detection_anomaly_threshold` | _security_config_fields.py:911 | `3.0` | Field(ge=1.0,le=10.0) | SecurityConfig.kt:1293 | ConfigFieldRegistry.kt:533 |
| `detection_slow_pattern_threshold` | _security_config_fields.py:918 | `0.1` | Field(ge=0.01,le=1.0) | SecurityConfig.kt:1304 | ConfigFieldRegistry.kt:541 |
| `detection_monitor_history_size` | _security_config_fields.py:925 | `1000` | Field(ge=100,le=10000) | SecurityConfig.kt:1315 | ConfigFieldRegistry.kt:549 |
| `detection_max_tracked_patterns` | _security_config_fields.py:932 | `1000` | Field(ge=100,le=5000) | SecurityConfig.kt:1326 | ConfigFieldRegistry.kt:557 |
| `detection_anomaly_emission_cooldown` | _security_config_fields.py:939 | `60.0` | Field(ge=1.0,le=3600.0) | SecurityConfig.kt:1337 | ConfigFieldRegistry.kt:565 |
| `detection_min_samples_for_anomaly` | _security_config_fields.py:949 | `30` | Field(ge=10,le=1000) | SecurityConfig.kt:1348 | ConfigFieldRegistry.kt:573 |
| `detection_threat_score_threshold` | _security_config_fields.py:959 | `1.0` | Field(ge=0.0,le=10.0) | SecurityConfig.kt:1359 | ConfigFieldRegistry.kt:581 |
| `muted_event_types` | _security_config_fields.py:966 | `factory frozenset` | models.py:278 validate_muted_event_types; revalidated on assignment | SecurityConfig.kt:1370 | ConfigFieldRegistry.kt:589 |
| `muted_metric_types` | _security_config_fields.py:971 | `factory frozenset` | models.py:282 validate_muted_metric_types; revalidated on assignment | SecurityConfig.kt:1382 | ConfigFieldRegistry.kt:596 |
| `muted_check_logs` | _security_config_fields.py:976 | `factory frozenset` | models.py:294 validate_muted_check_logs; revalidated on assignment | SecurityConfig.kt:1394 | ConfigFieldRegistry.kt:603 |
| `log_sensitive_headers` | _security_config_fields.py:981 | `factory frozenset` | models.py:298 validate_log_sensitive_headers; revalidated on assignment | SecurityConfig.kt:1406 | ConfigFieldRegistry.kt:610 |
| `log_sensitive_params` | _security_config_fields.py:989 | `factory frozenset` | models.py:302 validate_log_sensitive_params; revalidated on assignment | SecurityConfig.kt:1418 | ConfigFieldRegistry.kt:617 |
| `log_sensitive_body_fields` | _security_config_fields.py:998 | `factory frozenset` | models.py:306 validate_log_sensitive_body_fields; revalidated on assignment | SecurityConfig.kt:1430 | ConfigFieldRegistry.kt:624 |
| `enable_otel` | _security_config_fields.py:1008 | `False` | typed | SecurityConfig.kt:1443 | ConfigFieldRegistry.kt:631 |
| `otel_service_name` | _security_config_fields.py:1013 | `"guard-core"` | typed | SecurityConfig.kt:1454 | ConfigFieldRegistry.kt:632 |
| `otel_exporter_endpoint` | _security_config_fields.py:1018 | `None` | typed | SecurityConfig.kt:1465 | ConfigFieldRegistry.kt:633 |
| `otel_resource_attributes` | _security_config_fields.py:1023 | `factory dict` | revalidated on assignment | SecurityConfig.kt:1476 | ConfigFieldRegistry.kt:634 |
| `enable_logfire` | _security_config_fields.py:1031 | `False` | typed | SecurityConfig.kt:1488 | ConfigFieldRegistry.kt:641 |
| `logfire_service_name` | _security_config_fields.py:1036 | `"guard-core"` | typed | SecurityConfig.kt:1499 | ConfigFieldRegistry.kt:642 |
| `enable_enrichment` | _security_config_fields.py:1041 | `False` | typed | SecurityConfig.kt:1510 | ConfigFieldRegistry.kt:643 |
| `excluded_detection_headers` | _security_config_fields.py:1052 | `factory set` | revalidated on assignment | SecurityConfig.kt:1521 | ConfigFieldRegistry.kt:644 |
| `excluded_detection_params` | _security_config_fields.py:1061 | `factory set` | revalidated on assignment | SecurityConfig.kt:1533 | ConfigFieldRegistry.kt:651 |
| `excluded_detection_body_fields` | _security_config_fields.py:1067 | `factory set` | revalidated on assignment | SecurityConfig.kt:1545 | ConfigFieldRegistry.kt:658 |
| `detection_scan_body` | _security_config_fields.py:1075 | `True` | typed | SecurityConfig.kt:1557 | ConfigFieldRegistry.kt:665 |
| `enabled_detection_categories` | _security_config_fields.py:1083 | `factory lambda` | models.py:286 validate_enabled_detection_categories; revalidated on assignment | SecurityConfig.kt:1569 | ConfigFieldRegistry.kt:666 |

Registry statistics: 129 FieldMeta entries, one per python field, in python
declaration order; `ConfigFieldRegistry.revalidatedFieldNames` mirrors
`_FIELD_REVALIDATORS` keys; `geoStateFieldNames` mirrors `_GEO_STATE_FIELDS`
(geo_validators.py:53); `globalBehaviorRuleFieldNames` mirrors
`_GLOBAL_BEHAVIOR_RULE_FIELDS` (field_validators.py:40).

## Cross-field model validators (guard_core/models.py)

| python validator | python file:line | kotlin |
|---|---|---|
| validate_optional_extras_installed | models.py:182 | SecurityConfig.kt (runModelValidators); inert on JVM: pip extras (redis/aiohttp/maxminddb) have no JVM packaging gate - documented below |
| validate_geo_ip_handler_exists | models.py:206 | SecurityConfig.kt resolveGeoIpHandler + ConfigSeams.geoIpHandlerFactory (W3 registers IPInfoManager) |
| warn_country_allowlist_shadows_blocklist | models.py:221 | SecurityConfig.kt (runModelValidators step 3 + setter hook) |
| validate_agent_config | models.py:227 | SecurityConfig.kt (runModelValidators step 4) |
| validate_global_return_pattern_body_scan | models.py:246 | SecurityConfig.kt (runModelValidators step 5) |
| warn_trusted_proxies_prefix_zero | models.py:254 | SecurityConfig.kt (runModelValidators step 6) |
| warn_whitelist_prefix_zero | models.py:260 | SecurityConfig.kt (runModelValidators step 7) |
| warn_exempt_ips_prefix_zero | models.py:266 | SecurityConfig.kt (runModelValidators step 8) |
| warn_empty_enabled_detection_categories | models.py:271 | SecurityConfig.kt (runModelValidators step 9) |
| warn_unknown_fields (kwargs warning with difflib hint) | models.py:133 | SecurityConfigBuilder.fromMap (PyDiffLib.getCloseMatches port) |
| __setattr__ revalidation pipeline | models.py:98 | SecurityConfig.kt property setters (geo hook -> revalidator -> global-rules -> shadow warn -> assign -> revision) |
| revision counter | models.py:90-123 | SecurityConfig.kt revision + setPrevalidated/rawAssign |
| model_copy(update, deep) revalidation | models.py:125 | SecurityConfig.kt copyWith + revalidateCopiedConfig (_security_config_validators.py:153) |
| to_agent_config | models.py:317 | SecurityConfig.kt toAgentConfig + ConfigSeams.agentConfigFactory (W7) |

Field validators ported (guard_core/_security_config_field_validators.py,
_config_field_revalidators.py, _security_config_typed_validators.py,
_security_config_geo_validators.py): ConfigValidators.kt. Shared constants:
ALL_DETECTION_CATEGORIES (DetectionCategories.kt,
_suspatterns_sources.py:89), VALID_CLOUD_PROVIDERS (CloudProviders.kt,
field_validators.py:37), EVENT/METRIC/CHECK value sets (EventTypes.kt,
event_types.py:46/94/102). normalize_url_path (path_matching.py:51) ported as
util/PathMatching.kt for the exclude_paths validator.

## Protocols (guard_core/protocols/, 8 files)

| python file | python lines | kotlin file |
|---|---|---|
| protocols/__init__.py | 22 | protocols/Protocols.kt (re-export map in KDoc) |
| protocols/agent_protocol.py | 48 | protocols/AgentProtocol.kt |
| protocols/cloud_ip_store_protocol.py | 35 | protocols/CloudIpStoreProtocol.kt (+ CloudIpStoreFactory typealias) |
| protocols/geo_ip_protocol.py | 47 | protocols/GeoIpProtocol.kt |
| protocols/middleware_protocol.py | 80 | protocols/MiddlewareProtocol.kt |
| protocols/redis_protocol.py | 47 | protocols/RedisProtocol.kt (+ GuardRedisConnection for the AsyncContextManager yield) |
| protocols/request_protocol.py | 106 | protocols/RequestProtocol.kt (+ RequestState, asBoundedBodyReader) |
| protocols/response_protocol.py | 116 | protocols/ResponseProtocol.kt |

Async python methods map to Kotlin suspend functions; Python properties map
to Kotlin val members; `request.state` attribute bag maps to the RequestState
interface (getAttr/setAttr), preserving the dynamic-attribute contract.

## Utils (guard_core/_utils/, 21 files)

Landed in W1 (12 modules, dependency closure complete):

| python file | python lines | kotlin file |
|---|---|---|
| _utils/identity_hash.py | 5 | util/IdentityHash.kt |
| _utils/lru_store.py | 16 | util/LruStore.kt |
| _utils/pair_value_scan.py | 213 | util/PairValueScan.kt |
| _utils/pair_hidden_assign.py | 254 | util/PairHiddenAssign.kt |
| _utils/pair_redaction.py | 167 | util/PairRedaction.kt |
| _utils/logging_utils.py | 238 | util/LoggingUtils.kt |
| _utils/request_logging.py | 482 | util/RequestLogging.kt |
| _utils/ip_extraction.py | 368 | util/IpExtraction.kt |
| _utils/agent_events.py | 94 | util/AgentEvents.kt |
| _utils/block_events.py | 91 | util/BlockEvents.kt |
| _utils/body_reader.py | 186 | util/BodyReader.kt |
| _utils/access_control.py | 299 | util/AccessControl.kt |

Support ports (python stdlib the reference gets for free; JVM has none):

| surface | python source | kotlin file |
|---|---|---|
| json.loads/dumps subset | CPython Lib/json | util/py/PyJson.kt |
| urllib.parse subset (unquote/quote/urlsplit/urlunsplit) | CPython Lib/urllib/parse.py | util/py/PyUrllib.kt |
| ipaddress subset (ip_address/ip_network/is_* /ipv4_mapped) | CPython Lib/ipaddress.py | util/py/PyIp.kt |
| difflib.get_close_matches + SequenceMatcher | CPython Lib/difflib.py | util/py/PyDiffLib.kt |
| str.isspace + unicodedata.lookup (gap-char set) | CPython | util/py/PyUnicode.kt |
| warnings.warn channel | warnings module | config/ConfigWarnings.kt (JUL "guard_core.models" logger) |
| scan-budget context var (_json_depth_cap_value) | detection_scan.py:46-116 | util/DetectionScanContext.kt (W2 wires live budgets) |

Deferred to the detection-engine wave (W2) with reasons - each is a module
whose dependency closure sits inside the pattern engine, so landing it now
would be dead code rather than a port:

| python file | python lines | blocker |
|---|---|---|
| _utils/detection_config.py | 234 | RouteConfig (decorators, W2) + engine categories resolution |
| _utils/detection_scan.py | 442 | sus_patterns_handler / PatternCompiler (W2) |
| _utils/body_json_scan.py | 291 | detection_scan._scan_value (W2) |
| _utils/body_form_scan.py | 201 | binary_islands + _scan_body_field (W2) |
| _utils/body_content_scan.py | 478 | _scan_component_name / _scan_blob_body (W2) |
| _utils/embedded_json_scan.py | 77 | body_json_scan (W2) |
| _utils/detection_result_builders.py | 43 | DetectionResult (engine model, W2) |
| _utils/penetration_detection.py | 224 | orchestrates the six modules above |

Seam inventory (registered by their owning wave; W1 defaults preserve the
engine-absent behavior):

- ConfigSeams.blockedUserAgentsPatternGate: ReDoS gate for
  blocked_user_agents (field_validators.py:324-340 uses PatternCompiler).
- ConfigSeams.geoIpHandlerFactory: IPInfoManager construction
  (geo_validators.py:86-92).
- ConfigSeams.agentConfigFactory: guard-agent AgentConfig (models.py:317-365).
- BodyReader.straddleOverlapBytesProvider: longest-pattern overlap
  (body_reader.py:46-58; python failure path returns 0, which is the W1
  default).
- AccessControl.userAgentBlockedPatternMatcher: _user_agent_matches_blocked_pattern
  (access_control.py:16).
- AccessControl.cloudIpChecker: cloud_handler is_cloud_ip/details
  (access_control.py:197-215).

## Idiom mappings (behavior-preserving, recorded per house convention)

- ValueError inside validators -> ConfigValidationError (message text is the
  python validator's own message, asserted by the ported tests).
- warnings.warn(UserWarning) -> JUL logger "guard_core.models" at WARNING.
- logging levels: python CRITICAL -> java.util.logging SEVERE.
- Literal[...] -> Kotlin enums carrying pythonName (LogLevel, LogFormat,
  BufferOverflowPolicy, RuleType, RuleAction).
- tuples/frozensets/MappingProxy -> read-only Kotlin List/Set/Map copies.
- contextvars in synchronous redaction paths -> ThreadLocal
  (LoggingUtils.jsonDepthCapHit, DetectionScanContext budget).
- time.monotonic -> System.nanoTime in AgentEvents pipeline timing.
- unasync sync-tree knobs (body_read_timeout sync thread budget) are config
  values only in W1; the sync mirror is a Python packaging artifact.
- asyncio.wait_for -> kotlinx.coroutines.withTimeout (BodyReader.safeRead).

## Test coverage (the gate's check suite)

97 JUnit 5 tests in guard-core/src/test/kotlin, ported from
tests/test_models/, tests/test_protocols/, tests/test_utils/ and
tests/test_public_redaction_helpers.py plus the CPython-behavior probes,
covering: defaults for all 129 fields, registry consistency, every field
validator rejection (messages byte-matched), ge/le bounds, cross-field model
validators, mutation/revalidation/revision, copyWith, fromMap with the
difflib unknown-field hint, ipaddress canonicalization/containment/
classification tables, urllib/json/difflib probe tables, pair-grammar
redaction (public helper gate cases), trusted-proxy IP resolution, access
control verdicts, body-reader capping, LRU/identity-hash/path-matching.
