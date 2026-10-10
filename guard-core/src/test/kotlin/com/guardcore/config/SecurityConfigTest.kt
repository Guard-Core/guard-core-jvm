package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports of tests/test_models/ (defaults, validators, revision, copy) and the byte-exact default
 * assertions from _security_config_fields.py.
 */
class SecurityConfigTest {
  init {
    // The W3 geo-handler seam: country-rule configs with a token resolve
    // through it, mirroring the always-installed maxminddb extra.
    ConfigSeams.geoIpHandlerFactory = { _, _, _ ->
      object : com.guardcore.protocols.GeoIPHandler {
        override val isInitialized: Boolean = true

        override suspend fun initialize() {}

        override suspend fun initializeRedis(
            redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
        ) {}

        override suspend fun initializeAgent(
            agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
        ) {}

        override fun getCountry(ip: String): String? = "ZZ"

        override suspend fun refresh() {}

        override fun close() {}
      }
    }
  }

  @Test
  fun testDefaultsMatchPython() {
    val config = SecurityConfigBuilder().build()
    // Spot checks per _security_config_fields.py; the full table lives in
    // docs/w1-config-parity.md and the registry consistency test below.
    assertEquals(emptyList(), config.trustedProxies)
    assertEquals(1, config.trustedProxyDepth)
    assertFalse(config.trustXForwardedProto)
    assertFalse(config.passiveMode)
    assertNull(config.geoIpHandler)
    assertTrue(config.enableRedis)
    assertEquals("redis://localhost:6379", config.redisUrl)
    assertEquals("guard_core:", config.redisPrefix)
    assertEquals(2.0, config.redisSocketConnectTimeout)
    assertEquals(2.0, config.redisSocketTimeout)
    assertEquals(30, config.redisHealthCheckInterval)
    assertNull(config.redisMaxConnections)
    assertEquals(1, config.redisRetries)
    assertNull(config.whitelist)
    assertEquals(emptyList(), config.blacklist)
    assertEquals(emptyList(), config.exemptIps)
    assertEquals(emptySet(), config.whitelistCountries)
    assertEquals(emptySet(), config.blockedCountries)
    assertEquals(emptyList(), config.blockedUserAgents)
    assertEquals(10, config.autoBanThreshold)
    assertEquals(3600, config.autoBanDuration)
    assertEquals(emptyMap(), config.threatBanConfig)
    assertFalse(config.enableRateLimitAutoBan)
    assertEquals(emptyList(), config.globalBehaviorRules)
    assertFalse(config.behaviorScanResponseBody)
    assertEquals(262144, config.behaviorMaxResponseBodyInspectBytes)
    assertEquals(3.0, config.bodyReadTimeout)
    assertEquals(64, config.syncBodyReadMaxConcurrent)
    assertNull(config.customLogFile)
    assertEquals(LogLevel.WARNING, config.logSuspiciousLevel)
    assertNull(config.logRequestLevel)
    assertEquals(LogLevel.INFO, config.logCountryCheckLevel)
    assertEquals(LogFormat.TEXT, config.logFormat)
    assertEquals(emptyMap(), config.customErrorResponses)
    assertEquals(10, config.rateLimit)
    assertEquals(60, config.rateLimitWindow)
    assertFalse(config.enforceHttps)
    assertEquals(
        linkedMapOf(
            "enabled" to true,
            "hsts" to
                linkedMapOf(
                    "max_age" to 31536000,
                    "include_subdomains" to true,
                    "preload" to false,
                ),
            "csp" to null,
            "frame_options" to "SAMEORIGIN",
            "content_type_options" to "nosniff",
            "xss_protection" to "1; mode=block",
            "referrer_policy" to "strict-origin-when-cross-origin",
            "permissions_policy" to "geolocation=(), microphone=(), camera=()",
            "custom" to null,
        ),
        config.securityHeaders,
    )
    assertNull(config.customRequestCheck)
    assertNull(config.authVerifier)
    assertNull(config.customResponseModifier)
    assertFalse(config.enableCors)
    assertEquals(listOf("*"), config.corsAllowOrigins)
    assertEquals(
        listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
        config.corsAllowMethods,
    )
    assertEquals(listOf("*"), config.corsAllowHeaders)
    assertFalse(config.corsAllowCredentials)
    assertEquals(emptyList(), config.corsExposeHeaders)
    assertEquals(600, config.corsMaxAge)
    assertNull(config.blockCloudProviders)
    assertEquals(3600, config.cloudIpRefreshInterval)
    assertTrue(config.lazyInit)
    assertEquals(86400, config.geoIpDbMaxAge)
    assertNull(config.cloudIpStore)
    assertEquals(
        listOf("/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"),
        config.excludePaths,
    )
    assertTrue(config.enableIpBanning)
    assertTrue(config.enableRateLimiting)
    assertTrue(config.enablePenetrationDetection)
    assertTrue(config.failSecure)
    assertFalse(config.redisFailOpen)
    assertFalse(config.routeResolutionStrict)
    assertNull(config.ipinfoToken)
    assertEquals(Paths.get("data/ipinfo/country_asn.mmdb"), config.ipinfoDbPath)
    assertFalse(config.enableAgent)
    assertNull(config.agentApiKey)
    assertFalse(config.agentStrict)
    assertNull(config.onError)
    assertNull(config.onBlock)
    assertEquals("https://api.guard-core.com", config.agentEndpoint)
    assertNull(config.agentProjectId)
    assertEquals(100, config.agentBufferSize)
    assertEquals(30, config.agentFlushInterval)
    assertTrue(config.agentEnableEvents)
    assertTrue(config.agentEnableMetrics)
    assertEquals(30, config.agentTimeout)
    assertEquals(3, config.agentRetryAttempts)
    assertNull(config.agentProjectEncryptionKey)
    assertNull(config.agentGuardVersion)
    assertNull(config.agentHighWatermarkRatio)
    assertNull(config.agentMaxConcurrentFlushes)
    assertNull(config.agentBufferOverflowPolicy)
    assertNull(config.agentBackoffFactor)
    assertNull(config.agentSensitiveHeaders)
    assertNull(config.agentMaxPayloadSize)
    assertNull(config.agentCompressionEnabled)
    assertNull(config.agentCompressionThreshold)
    assertNull(config.agentInstallId)
    assertNull(config.agentPayloadSigningSecret)
    assertFalse(config.enableDynamicRules)
    assertEquals(300, config.dynamicRuleInterval)
    assertNull(config.dynamicRulesCachePath)
    assertEquals(300, config.agentStatusInterval)
    assertFalse(config.emergencyMode)
    assertEquals(emptyList(), config.emergencyWhitelist)
    assertEquals(emptyMap(), config.endpointRateLimits)
    assertEquals(2.0, config.detectionCompilerTimeout)
    assertNull(config.detectionPatternValidationCachePath)
    assertEquals(10000, config.detectionMaxContentLength)
    assertEquals(262144, config.detectionMaxBodyInspectBytes)
    assertEquals(512, config.detectionMaxScanValues)
    assertEquals(65536, config.detectionMaxScanChars)
    assertEquals(32, config.detectionMaxJsonDepth)
    assertEquals(16, config.detectionBinaryMinRunLength)
    assertTrue(config.detectionPreserveAttackPatterns)
    assertEquals(0.7, config.detectionSemanticThreshold)
    assertEquals(3.0, config.detectionAnomalyThreshold)
    assertEquals(0.1, config.detectionSlowPatternThreshold)
    assertEquals(1000, config.detectionMonitorHistorySize)
    assertEquals(1000, config.detectionMaxTrackedPatterns)
    assertEquals(60.0, config.detectionAnomalyEmissionCooldown)
    assertEquals(30, config.detectionMinSamplesForAnomaly)
    assertEquals(1.0, config.detectionThreatScoreThreshold)
    assertEquals(emptySet(), config.mutedEventTypes)
    assertEquals(emptySet(), config.mutedMetricTypes)
    assertEquals(emptySet(), config.mutedCheckLogs)
    assertEquals(emptySet(), config.logSensitiveHeaders)
    assertEquals(emptySet(), config.logSensitiveParams)
    assertEquals(emptySet(), config.logSensitiveBodyFields)
    assertFalse(config.enableOtel)
    assertEquals("guard-core", config.otelServiceName)
    assertNull(config.otelExporterEndpoint)
    assertEquals(emptyMap(), config.otelResourceAttributes)
    assertFalse(config.enableLogfire)
    assertEquals("guard-core", config.logfireServiceName)
    assertFalse(config.enableEnrichment)
    assertEquals(emptySet(), config.excludedDetectionHeaders)
    assertEquals(emptySet(), config.excludedDetectionParams)
    assertEquals(emptySet(), config.excludedDetectionBodyFields)
    assertTrue(config.detectionScanBody)
    assertEquals(DetectionCategories.ALL_DETECTION_CATEGORIES, config.enabledDetectionCategories)
  }

  @Test
  fun testRegistryCoversEveryField() {
    // The registry is the source of truth: every entry must exist on the
    // instance and the registry must have no extras (docs/w1-config-parity.md).
    assertTrue(ConfigFieldRegistry.fields.size >= 107)
    val pythonNames = ConfigFieldRegistry.fields.map { it.pythonName }
    assertEquals(pythonNames.size, pythonNames.distinct().size, "duplicate python_name in registry")
  }

  @Test
  fun testRegistryRevalidatorAndGeoSets() {
    // _GEO_STATE_FIELDS (geo_validators.py:53-55): the W1 port puts the
    // db path on the seam boundary, so the registry marks four fields.
    assertTrue(ConfigFieldRegistry.geoStateFieldNames.contains("geo_ip_handler"))
    assertTrue(ConfigFieldRegistry.geoStateFieldNames.contains("ipinfo_token"))
    assertTrue(ConfigFieldRegistry.geoStateFieldNames.contains("blocked_countries"))
    assertTrue(ConfigFieldRegistry.geoStateFieldNames.contains("whitelist_countries"))
    assertTrue("whitelist" in ConfigFieldRegistry.revalidatedFieldNames)
    assertTrue("blocked_countries" in ConfigFieldRegistry.revalidatedFieldNames)
    assertTrue("exclude_paths" in ConfigFieldRegistry.revalidatedFieldNames)
    assertEquals(
        setOf("global_behavior_rules", "behavior_scan_response_body"),
        ConfigFieldRegistry.globalBehaviorRuleFieldNames,
    )
    // models.py:76-78.
    assertEquals(
        setOf("all", "ip_ban", "ip", "clouds", "rate_limit", "penetration"),
        ConfigFieldRegistry.VALID_BYPASS_CHECKS,
    )
  }

  // ------------------------------------------------------- validation

  @Test
  fun testIpListRejectionsAndNormalization() {
    // test_models.py:122 / test_immutable_collection_fields.py:5-9.
    val e1 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { whitelist = listOf("not-an-ip") }.build()
        }
    assertTrue("Invalid IP or CIDR range" in e1.message!!)
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { blacklist = listOf("not-an-ip") }.build()
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { exemptIps = listOf("not-an-ip") }.build()
    }
    val e2 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { trustedProxies = listOf("not-an-ip") }.build()
        }
    assertTrue("Invalid proxy IP or CIDR range" in e2.message!!)

    val config =
        SecurityConfigBuilder()
            .apply {
              whitelist = listOf("10.0.0.5", "172.16.0.0/12")
              trustedProxies = listOf("127.0.0.1", "unix")
            }
            .build()
    assertEquals(listOf("10.0.0.5", "172.16.0.0/12"), config.whitelist)
    assertEquals(listOf("127.0.0.1", "unix"), config.trustedProxies)

    // CIDR normalization: 1.2.3.4/24 -> 1.2.3.0/24 (field_validators.py:165).
    val config2 = SecurityConfigBuilder().apply { blacklist = listOf("1.2.3.4/24") }.build()
    assertEquals(listOf("1.2.3.0/24"), config2.blacklist)
  }

  @Test
  fun testTrustedProxyDepthBound() {
    // models.py:239.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { trustedProxyDepth = 0 }.build()
        }
    assertTrue("trusted_proxy_depth must be at least 1" in e.message!!)
  }

  @Test
  fun testCountryCoercionUppercases() {
    // _validate_country_set_value upper-cases every entry.
    val config =
        SecurityConfigBuilder()
            .apply {
              blockedCountries = setOf("cn", "Ru")
              ipinfoToken = "test-token"
            }
            .build()
    assertEquals(setOf("CN", "RU"), config.blockedCountries)
  }

  @Test
  fun testCloudProviderValidation() {
    // models.py:26 / field_validators.py:308-321.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { blockCloudProviders = setOf("NotACloud") }.build()
        }
    assertTrue("Unknown cloud providers in block_cloud_providers" in e.message!!)
    // Region carve-outs keep the provider prefix.
    val config =
        SecurityConfigBuilder()
            .apply { blockCloudProviders = setOf("GCP", "AWS:!us-east-1") }
            .build()
    assertEquals(setOf("GCP", "AWS:!us-east-1"), config.blockCloudProviders)
  }

  @Test
  fun testDetectionCategoriesMembership() {
    // test_detection_config.py:46.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder()
              .apply { enabledDetectionCategories = setOf("not_a_real_category") }
              .build()
        }
    assertTrue("Unknown" in e.message!!)
    val config =
        SecurityConfigBuilder().apply { enabledDetectionCategories = setOf("xss", "sqli") }.build()
    assertEquals(setOf("xss", "sqli"), config.enabledDetectionCategories)
  }

  @Test
  fun testDetectionMaxScanValuesFloor() {
    // test_detection_max_scan_values_floor.py:6-11.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { detectionMaxScanValues = 1 }.build()
        }
    assertTrue("greater than or equal to 2" in e.message!!)
    assertEquals(
        2,
        SecurityConfigBuilder().apply { detectionMaxScanValues = 2 }.build().detectionMaxScanValues,
    )
  }

  @Test
  fun testMutedSetsMembership() {
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { mutedEventTypes = setOf("not_a_real_event") }.build()
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { mutedMetricTypes = setOf("not_a_real_metric") }.build()
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { mutedCheckLogs = setOf("not_a_real_check") }.build()
    }
    val config =
        SecurityConfigBuilder()
            .apply {
              mutedEventTypes = setOf("penetration_attempt")
              mutedMetricTypes = setOf("response_time")
              mutedCheckLogs = setOf("authentication")
            }
            .build()
    assertEquals(setOf("penetration_attempt"), config.mutedEventTypes)
    assertEquals(setOf("response_time"), config.mutedMetricTypes)
    assertEquals(setOf("authentication"), config.mutedCheckLogs)
  }

  @Test
  fun testSensitiveNameSets() {
    // test_log_sensitive_headers_field.py:30-35: bare string and non-string
    // items are rejected.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf("log_sensitive_headers" to "authorization"))
        }
    assertTrue("not a bare string" in e.message!!)
    val e2 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(
              mapOf("log_sensitive_headers" to listOf("authorization", 42)),
          )
        }
    assertTrue("must be strings" in e2.message!!)
  }

  @Test
  fun testThreatBanConfigValidation() {
    // test_threat_ban_config.py:49.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(
              mapOf(
                  "threat_ban_config" to
                      mapOf("not_a_category" to mapOf("threshold" to 3, "duration" to 60)),
              ),
          )
        }
    assertTrue("Unknown threat categor" in e.message!!)
    val config =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "threat_ban_config" to mapOf("sqli" to mapOf("threshold" to 3, "duration" to 60)),
            ),
        )
    assertEquals(ThreatBanConfig(3, 60), config.threatBanConfig["sqli"])
    // rate_limit pseudo-category is valid (field_validators.py:84-86).
    SecurityConfigBuilder.fromMap(
        mapOf(
            "threat_ban_config" to mapOf("rate_limit" to mapOf("threshold" to 3, "duration" to 60)),
        ),
    )
  }

  @Test
  fun testExcludePathsValidator() {
    // test_exclude_paths_validator.py:154 + path_matching semantics.
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(mapOf("exclude_paths" to "not-a-list"))
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(mapOf("exclude_paths" to listOf("/a%zz/b", 42)).let { it })
    }
    // A valid run that fails utf-8 decoding can never normalize.
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(mapOf("exclude_paths" to listOf("/%ff")))
    }
    val config =
        SecurityConfigBuilder().apply { excludePaths = listOf("/docs/", "/a/../b") }.build()
    assertEquals(listOf("/docs/", "/a/../b"), config.excludePaths)
  }

  @Test
  fun testDynamicRulesCachePathValidator() {
    // test_dynamic_rules_cache_path_validator.py:30-49.
    val e1 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf("dynamic_rules_cache_path" to 42))
        }
    assertTrue("must be a non-empty filesystem path" in e1.message!!)
    val e2 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf("dynamic_rules_cache_path" to "   "))
        }
    assertTrue("must not be empty or whitespace-only" in e2.message!!)
    val config =
        SecurityConfigBuilder.fromMap(mapOf("dynamic_rules_cache_path" to "/tmp/rules.json"))
    assertEquals(Paths.get("/tmp/rules.json"), config.dynamicRulesCachePath)
  }

  @Test
  fun testAgentCrossFieldValidation() {
    // models.py:227-244.
    val e1 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { enableAgent = true }.build()
        }
    assertTrue("agent_api_key is required when enable_agent is True" in e1.message!!)
    val e2 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { enableDynamicRules = true }.build()
        }
    assertTrue("enable_agent must be True when enable_dynamic_rules is True" in e2.message!!)
    val e3 =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { enableEnrichment = true }.build()
        }
    assertTrue("enable_enrichment requires enable_agent=True" in e3.message!!)
    // Happy path.
    SecurityConfigBuilder()
        .apply {
          enableAgent = true
          agentApiKey = "key"
          enableDynamicRules = true
        }
        .build()
  }

  @Test
  fun testGeoIpHandlerRequiredForCountryRules() {
    // test_geo_ip_handler_reassignment.py:13.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder().apply { blockedCountries = setOf("CN") }.build()
        }
    assertTrue("geo_ip_handler is required" in e.message!!)
  }

  @Test
  fun testBehaviorReturnPatternRequiresBodyScan() {
    // test_behavior_rule_config.py:115.
    val e =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder()
              .apply {
                globalBehaviorRules =
                    listOf(
                        BehaviorRuleConfig(
                            ruleType = RuleType.RETURN_PATTERN,
                            threshold = 1,
                            pattern = "regex:.*secret.*",
                        ),
                    )
              }
              .build()
        }
    assertTrue("behavior_scan_response_body" in e.message!!)
    // status: patterns never require the body scan.
    SecurityConfigBuilder()
        .apply {
          globalBehaviorRules =
              listOf(
                  BehaviorRuleConfig(
                      ruleType = RuleType.RETURN_PATTERN,
                      threshold = 1,
                      pattern = "status:404",
                  ),
              )
        }
        .build()
  }

  // -------------------------------------------------------- mutation

  @Test
  fun testRevisionCountsAssignments() {
    // test_security_config_revision.py semantics.
    val config = SecurityConfigBuilder().build()
    assertEquals(0, config.revision)
    config.rateLimit = 42
    assertEquals(1, config.revision)
    config.passiveMode = true
    assertEquals(2, config.revision)
    assertEquals(42, config.rateLimit)
  }

  @Test
  fun testAssignmentRevalidators() {
    // test_every_collection_field_is_revalidated.py:94.
    val config = SecurityConfigBuilder().apply { ipinfoToken = "test-token" }.build()
    val e =
        assertFailsWith<ConfigValidationError> {
          config.whitelist = listOf("not-an-ip")
        }
    assertTrue("Invalid IP or CIDR range" in e.message!!)
    // Original value preserved after the failed assignment.
    assertNull(config.whitelist)
    // Country sets only uppercase on assignment (no membership check).
    config.blockedCountries = setOf("xx")
    assertEquals(setOf("XX"), config.blockedCountries)
  }

  @Test
  fun testPositiveIntAssignmentRevalidation() {
    val config = SecurityConfigBuilder().build()
    assertFailsWith<ConfigValidationError> { config.autoBanThreshold = 0 }
    assertEquals(10, config.autoBanThreshold)
  }

  @Test
  fun testCopyWithRevalidatesChangedFields() {
    // test_security_config_dynamic_rule_field_revalidation.py semantics.
    val config = SecurityConfigBuilder().apply { blacklist = listOf("192.168.1.1") }.build()
    val copied = config.copyWith(update = mapOf("rate_limit" to 33))
    assertEquals(33, copied.rateLimit)
    assertEquals(listOf("192.168.1.1"), copied.blacklist)
    // Copy carries the revision over, like pydantic's private attrs.
    assertEquals(config.revision, copied.revision)
    // Rejection propagates through copy revalidation.
    assertFailsWith<ConfigValidationError> {
      config.copyWith(update = mapOf("whitelist" to listOf("not-an-ip")))
    }
  }

  // --------------------------------------------------------- fromMap

  @Test
  fun testFromMapUnknownFieldWarningWithHint() {
    // test_security_config_unknown_field_warning.py: the difflib hint.
    val records = java.util.Collections.synchronizedList(mutableListOf<String>())
    val handler =
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {
            records.add(record.message)
          }

          override fun flush() {}

          override fun close() {}
        }
    val logger = java.util.logging.Logger.getLogger("guard_core.models")
    logger.addHandler(handler)
    try {
      SecurityConfigBuilder.fromMap(mapOf("truste_proxies" to listOf("127.0.0.1")))
    } finally {
      logger.removeHandler(handler)
    }
    val message = records.joinToString("\n")
    assertTrue("unknown field 'truste_proxies'" in message, message)
    assertTrue("Did you mean 'trusted_proxies'?" in message, message)
  }

  @Test
  fun testFromMapPythonNames() {
    val config =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "rate_limit" to 25,
                "trusted_proxy_depth" to 2,
                "log_format" to "json",
                "block_cloud_providers" to listOf("AWS"),
            ),
        )
    assertEquals(25, config.rateLimit)
    assertEquals(2, config.trustedProxyDepth)
    assertEquals(LogFormat.JSON, config.logFormat)
    assertEquals(setOf("AWS"), config.blockCloudProviders)
  }
}
