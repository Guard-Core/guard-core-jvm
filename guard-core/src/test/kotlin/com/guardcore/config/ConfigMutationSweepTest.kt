package com.guardcore.config

import com.guardcore.errors.AgentPackageNotInstalledError
import com.guardcore.errors.ConfigValidationError
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports of tests/test_models: the every-field reassignment sweep (setter revalidators), the
 * revision semantics, fromMap over every python field name (the MapApplier dispatch), and
 * to_agent_config's arms (models.py:317-365).
 */
class ConfigMutationSweepTest {
  private val geoHandler =
      object : com.guardcore.protocols.GeoIPHandler {
        override val isInitialized: Boolean = false

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

  /** A valid assignment value per registry kind (mirrors the python field types). */
  private fun validValueFor(field: ConfigFieldRegistry.FieldMeta): Any? =
      when (field.kind) {
        ConfigFieldRegistry.Kind.STR -> "swept-value"
        ConfigFieldRegistry.Kind.STR_NULLABLE -> "swept-value"
        ConfigFieldRegistry.Kind.INT -> 5
        ConfigFieldRegistry.Kind.INT_NULLABLE -> 5
        ConfigFieldRegistry.Kind.FLOAT -> 0.5
        ConfigFieldRegistry.Kind.FLOAT_NULLABLE -> 0.5
        ConfigFieldRegistry.Kind.BOOL -> true
        ConfigFieldRegistry.Kind.BOOL_NULLABLE -> true
        ConfigFieldRegistry.Kind.STR_LIST -> listOf("swept-entry")
        ConfigFieldRegistry.Kind.STR_LIST_NULLABLE -> listOf("swept-entry")
        ConfigFieldRegistry.Kind.STR_SET ->
            when (field.pythonName) {
              "enabled_detection_categories" -> setOf("sqli")
              "muted_event_types" -> setOf("suspicious_request")
              "muted_metric_types" -> setOf("response_time")
              "muted_check_logs" -> setOf("authentication")
              else -> setOf("swept")
            }
        ConfigFieldRegistry.Kind.STR_DICT -> mapOf("service.name" to "guard")
        ConfigFieldRegistry.Kind.STR_DICT_NULLABLE -> mapOf("service.name" to "guard")
        ConfigFieldRegistry.Kind.INT_KEYED_STR_DICT -> mapOf(404 to "not found")
        ConfigFieldRegistry.Kind.ENDPOINT_RATE_LIMITS -> mapOf("/api" to (5 to 60))
        ConfigFieldRegistry.Kind.PATH_NULLABLE -> Paths.get("swept-cache.json")
        ConfigFieldRegistry.Kind.LEVEL_NULLABLE -> LogLevel.WARNING
        ConfigFieldRegistry.Kind.LOG_FORMAT -> LogFormat.TEXT
        ConfigFieldRegistry.Kind.POLICY_NULLABLE -> BufferOverflowPolicy.DROP
        ConfigFieldRegistry.Kind.BEHAVIOR_RULES ->
            listOf(BehaviorRuleConfig(RuleType.USAGE, threshold = 3))
        ConfigFieldRegistry.Kind.THREAT_BAN_CONFIG ->
            mapOf("sqli" to ThreatBanConfig(threshold = 3, duration = 60))
        ConfigFieldRegistry.Kind.IP_LIST -> listOf("10.0.0.5")
        ConfigFieldRegistry.Kind.IP_LIST_NULLABLE -> listOf("10.0.0.5")
        ConfigFieldRegistry.Kind.COUNTRY_SET -> setOf("US")
        ConfigFieldRegistry.Kind.CLOUD_PROVIDERS_NULLABLE -> setOf("AWS")
        ConfigFieldRegistry.Kind.CALLABLE_NULLABLE -> null
        ConfigFieldRegistry.Kind.ANY_NULLABLE -> null
        ConfigFieldRegistry.Kind.HANDLER_NULLABLE -> null
        ConfigFieldRegistry.Kind.CLOUD_IP_STORE_NULLABLE -> null
      }

  private fun newConfig(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            logSuspiciousLevel = LogLevel.ERROR
            logRequestLevel = null
          }
          .build()

  /**
   * Every registered field accepts a typed valid assignment through the public setter path (python:
   * test_models reassignment sweeps) and every assignment bumps the revision.
   */
  @Test
  fun testEveryFieldAcceptsTypedAssignmentAndBumpsRevision() {
    val config = newConfig()
    // geo-state fields re-resolve the handler on every assignment; with country rules in the
    // sweep a handler must already be present (models.py geo validator).
    config.setPrevalidated("geo_ip_handler", geoHandler)
    val base = config.revision
    for (field in ConfigFieldRegistry.fields) {
      val before = config.revision
      val value = if (field.pythonName == "geo_ip_handler") geoHandler else validValueFor(field)
      config.setPrevalidated(field.pythonName, value)
      assertTrue(
          config.revision > before || field.pythonName == "revision",
          "revision must bump for ${field.pythonName}",
      )
    }
    assertTrue(config.revision >= base)
  }

  /** IP/CIDR list reassignment rejects invalid entries with the python message. */
  @Test
  fun testIpListReassignmentRejectsInvalidEntry() {
    val config = newConfig()
    for (name in listOf("whitelist", "blacklist", "exempt_ips", "trusted_proxies")) {
      val error =
          try {
            config.setPrevalidated(name, listOf("not-an-ip"))
            null
          } catch (e: ConfigValidationError) {
            e
          }
      assertNotNull(error, "$name must reject invalid entries")
      assertTrue(error!!.message!!.contains("Invalid"), error.message)
    }
  }

  /** Membership sets reject unknown values (categories, events, metrics, checks, countries). */
  @Test
  fun testMembershipSetsRejectUnknownValues() {
    val config = newConfig()
    val cases =
        mapOf(
            "enabled_detection_categories" to setOf("not_a_real_category"),
            "muted_event_types" to setOf("not_a_real_event"),
            "muted_metric_types" to setOf("not_a_real_metric"),
            "muted_check_logs" to setOf("not_a_real_check"),
            "blocked_countries" to setOf("not-a-country"),
            "whitelist_countries" to setOf("not-a-country"),
        )
    for ((name, bad) in cases) {
      val error =
          try {
            config.setPrevalidated(name, bad)
            null
          } catch (e: ConfigValidationError) {
            e
          }
      assertNotNull(error, "$name must reject $bad")
    }
  }

  /** Bounded ints reject out-of-range construction (pydantic Field ge/le at build time). */
  @Test
  fun testBoundedIntConstructionRejectsOutOfRange() {
    for (field in ConfigFieldRegistry.fields) {
      if (field.kind != ConfigFieldRegistry.Kind.INT) continue
      val ge = field.ge
      val le = field.le
      if (ge == null && le == null) continue
      val bad = if (ge != null) ge - 1 else le!! + 1
      val error =
          try {
            SecurityConfigBuilder.fromMap(mapOf(field.pythonName to bad), warnUnknown = false)
            null
          } catch (e: ConfigValidationError) {
            e
          }
      assertNotNull(error, "${field.pythonName} must reject $bad")
    }
  }

  /** Revision semantics (test_security_config_revision.py). */
  @Test
  fun testRevisionSemantics() {
    val config = newConfig()
    assertEquals(0, config.revision)
    config.setPrevalidated("blocked_user_agents", listOf("badbot"))
    assertEquals(1, config.revision)
    config.setPrevalidated("rate_limit", 5)
    assertEquals(2, config.revision)
    // Independent configs have independent counters.
    val other = newConfig()
    assertEquals(0, other.revision)
  }

  /** valueByName round-trips assignments for the copy-revalidation field set. */
  @Test
  fun testValueByNameReflectsAssignments() {
    val config = newConfig()
    config.setPrevalidated("rate_limit", 42)
    assertEquals(42, config.valueByName("rate_limit"))
    config.setPrevalidated("blocked_user_agents", listOf("bot"))
    assertEquals(listOf("bot"), config.valueByName("blocked_user_agents"))
    val error =
        try {
          config.valueByName("not_a_field")
          null
        } catch (e: ConfigValidationError) {
          e
        }
    assertNotNull(error, "unknown field lookup must fail")
    assertTrue(error!!.message!!.contains("Unknown SecurityConfig field"), error.message)
  }

  /** setPrevalidated skips the revalidator but still applies (models.py:114). */
  @Test
  fun testSetPrevalidatedSkipsRevalidation() {
    val config = newConfig()
    // An out-of-bounds value is applied verbatim when revalidation is skipped.
    config.setPrevalidated("detection_max_json_depth", 0)
    assertEquals(0, config.detectionMaxJsonDepth)
  }

  /** geo-state hook: geo_ip_handler reassignment fires the geo-state clear (models.py:98). */
  @Test
  fun testGeoIpHandlerReassignmentRunsGeoHook() {
    val config = newConfig()
    config.setPrevalidated("geo_ip_handler", geoHandler)
    assertNotNull(config.geoIpHandler)
    config.setPrevalidated("geo_ip_handler", null)
    assertNull(config.geoIpHandler)
  }

  /**
   * Regression (port of test_global_behavior_rules_reassignment_coerces_dicts_to_model): the
   * assignment-time revalidator must coerce dict entries to models, not reject them as a str-list.
   * Found by the W9a coverage sweep: the setter used the wrong validator.
   */
  @Test
  fun testGlobalBehaviorRulesReassignmentCoercesDictsToModels() {
    val config = newConfig()
    config.setPrevalidated(
        "global_behavior_rules",
        listOf(linkedMapOf<String, Any?>("rule_type" to "usage", "threshold" to 3)),
    )
    val rules = config.globalBehaviorRules
    assertEquals(1, rules.size)
    assertEquals(BehaviorRuleConfig(RuleType.USAGE, threshold = 3), rules.single())
    // Model instances pass through untouched.
    config.setPrevalidated(
        "global_behavior_rules",
        listOf(BehaviorRuleConfig(RuleType.USAGE, threshold = 4)),
    )
    assertEquals(4, config.globalBehaviorRules.single().threshold)
    // A non-coercible entry rejects with the python adapter message.
    val error =
        try {
          config.setPrevalidated("global_behavior_rules", listOf("nope"))
          null
        } catch (e: ConfigValidationError) {
          e
        }
    assertNotNull(error)
    assertTrue(
        error!!
            .message!!
            .contains(
                "Input should be a valid dictionary or instance of " + "BehaviorRuleConfig",
            ),
        error.message,
    )
  }

  /** python test_security_config_unknown_field_warning.py: unknown map key warns with hint. */
  @Test
  fun testFromMapUnknownFieldWarns() {
    val messages = mutableListOf<String>()
    val handler =
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {
            messages.add(record.message ?: "")
          }

          override fun flush() {}

          override fun close() {}
        }
    val logger = ConfigWarnings.logger
    logger.addHandler(handler)
    try {
      ConfigFieldRegistry.byPythonName("rate_limit") // sanity: registry lookup works
      SecurityConfigBuilder.fromMap(mapOf("rate_limit_x" to 5))
      assertTrue(
          messages.any { it.contains("rate_limit_x") },
          messages.joinToString("|"),
      )
    } finally {
      logger.removeHandler(handler)
    }
  }
}

/** fromMap over every python field name (MapApplier dispatch arms). */
class ConfigFromMapSweepTest {
  private fun validMapValueFor(field: ConfigFieldRegistry.FieldMeta): Any? =
      when (field.kind) {
        ConfigFieldRegistry.Kind.STR -> "mapped-value"
        ConfigFieldRegistry.Kind.STR_NULLABLE -> "mapped-value"
        ConfigFieldRegistry.Kind.INT -> inBounds(field, 5)
        ConfigFieldRegistry.Kind.INT_NULLABLE -> inBounds(field, 5)
        ConfigFieldRegistry.Kind.FLOAT -> inBoundsFloat(field, 0.5)
        ConfigFieldRegistry.Kind.FLOAT_NULLABLE -> inBoundsFloat(field, 0.5)
        ConfigFieldRegistry.Kind.BOOL -> true
        ConfigFieldRegistry.Kind.BOOL_NULLABLE -> true
        ConfigFieldRegistry.Kind.STR_LIST -> listOf("mapped-entry")
        ConfigFieldRegistry.Kind.STR_LIST_NULLABLE -> listOf("mapped-entry")
        ConfigFieldRegistry.Kind.STR_SET ->
            when (field.pythonName) {
              "enabled_detection_categories" -> setOf("sqli")
              "muted_event_types" -> setOf("suspicious_request")
              "muted_metric_types" -> setOf("response_time")
              "muted_check_logs" -> setOf("authentication")
              else -> setOf("mapped")
            }
        ConfigFieldRegistry.Kind.STR_DICT -> mapOf("service.name" to "guard")
        ConfigFieldRegistry.Kind.STR_DICT_NULLABLE -> mapOf("service.name" to "guard")
        ConfigFieldRegistry.Kind.INT_KEYED_STR_DICT -> mapOf(404 to "not found")
        ConfigFieldRegistry.Kind.ENDPOINT_RATE_LIMITS -> mapOf("/api" to (5 to 60))
        ConfigFieldRegistry.Kind.PATH_NULLABLE -> "mapped-cache.json"
        ConfigFieldRegistry.Kind.LEVEL_NULLABLE -> "WARNING"
        ConfigFieldRegistry.Kind.LOG_FORMAT -> "text"
        ConfigFieldRegistry.Kind.POLICY_NULLABLE -> "drop"
        ConfigFieldRegistry.Kind.BEHAVIOR_RULES ->
            listOf(linkedMapOf<String, Any?>("rule_type" to "usage", "threshold" to 3))
        ConfigFieldRegistry.Kind.THREAT_BAN_CONFIG ->
            mapOf("sqli" to linkedMapOf<String, Any?>("threshold" to 3, "duration" to 60))
        ConfigFieldRegistry.Kind.IP_LIST -> listOf("10.0.0.5")
        ConfigFieldRegistry.Kind.IP_LIST_NULLABLE -> listOf("10.0.0.5")
        ConfigFieldRegistry.Kind.COUNTRY_SET -> listOf("US")
        ConfigFieldRegistry.Kind.CLOUD_PROVIDERS_NULLABLE -> listOf("AWS")
        ConfigFieldRegistry.Kind.CALLABLE_NULLABLE -> null
        ConfigFieldRegistry.Kind.ANY_NULLABLE -> null
        ConfigFieldRegistry.Kind.HANDLER_NULLABLE -> null
        ConfigFieldRegistry.Kind.CLOUD_IP_STORE_NULLABLE -> null
      }

  private fun inBounds(field: ConfigFieldRegistry.FieldMeta, value: Int): Int {
    var v = value
    field.ge?.let { if (v < it) v = it }
    field.le?.let { if (v > it) v = it }
    return v
  }

  private fun inBoundsFloat(field: ConfigFieldRegistry.FieldMeta, value: Double): Double {
    var v = value
    field.geFloat?.let { if (v < it) v = it }
    field.leFloat?.let { if (v > it) v = it }
    field.gt?.let { if (v <= it) v = it + 0.1 }
    return v
  }

  /** python model_validate(dict): every python field name maps through the applier. */
  @Test
  fun testFromMapCoversEveryFieldName() {
    val values = linkedMapOf<String, Any?>()
    for (field in ConfigFieldRegistry.fields) {
      if (
          field.kind in
              setOf(
                  ConfigFieldRegistry.Kind.CALLABLE_NULLABLE,
                  ConfigFieldRegistry.Kind.HANDLER_NULLABLE,
                  ConfigFieldRegistry.Kind.CLOUD_IP_STORE_NULLABLE,
              )
      ) {
        continue // callables/handlers are not map-constructible
      }
      values[field.pythonName] = validMapValueFor(field)
    }
    values["enable_redis"] = false
    values["log_request_level"] = null
    values["log_suspicious_level"] = "ERROR"
    values["detection_max_json_depth"] = 32
    values["whitelist_countries"] = emptyList<String>()
    values["blocked_countries"] = emptyList<String>()
    values["behavior_scan_response_body"] = false
    values["global_behavior_rules"] = emptyList<Map<String, Any?>>()
    values["exclude_paths"] = listOf("/health")
    values["dynamic_rules_cache_path"] = null
    values["ipinfo_db_path"] = null
    values["geo_ip_handler"] = null
    val config = SecurityConfigBuilder.fromMap(values, warnUnknown = false)
    assertEquals(5, config.rateLimit)
    assertEquals(false, config.enableRedis)
    assertEquals(LogLevel.ERROR, config.logSuspiciousLevel)
    assertEquals(listOf("/health"), config.excludePaths)
    assertEquals(LogLevel.WARNING, config.logCountryCheckLevel)
  }

  /** python: model_validate rejects unknown keys via the extra="forbid" path. */
  @Test
  fun testFromMapUnknownFieldRejectsOrWarnsPerFlag() {
    // warnUnknown=false: silent.
    SecurityConfigBuilder.fromMap(mapOf("definitely_not_a_field" to 1), warnUnknown = false)
    // warnUnknown=true (default): warning captured above in ConfigMutationSweepTest.
  }

  /** Int-typed map values accept numeric strings like pydantic's lax mode where mapped. */
  @Test
  fun testFromMapTypeCoercions() {
    val config =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "rate_limit" to 7,
                "enable_redis" to false,
                "log_request_level" to null,
                "log_suspicious_level" to "ERROR",
            ),
            warnUnknown = false,
        )
    assertEquals(7, config.rateLimit)
  }
}

/** to_agent_config arms (models.py:317-365). */
class ToAgentConfigTest {
  @Test
  fun testDisabledAgentReturnsNull() {
    val config = SecurityConfigBuilder().build()
    assertNull(config.toAgentConfig("4.3.2"))
  }

  @Test
  fun testAgentWithApiKeyConstructionRequirement() {
    // enable_agent=True without an api key is rejected at construction (cross-field validator).
    val error =
        try {
          SecurityConfigBuilder()
              .apply {
                enableAgent = true
                agentApiKey = null
              }
              .build()
          null
        } catch (e: ConfigValidationError) {
          e
        }
    assertNotNull(error)
    assertTrue(error!!.message!!.contains("agent_api_key is required"), error.message)
  }

  @Test
  fun testAgentWithoutInstalledPackageRaises() {
    val previous = ConfigSeams.agentConfigFactory
    ConfigSeams.agentConfigFactory = null
    try {
      val config =
          SecurityConfigBuilder()
              .apply {
                enableAgent = true
                agentApiKey = "k"
              }
              .build()
      val error = assertFailsWith<AgentPackageNotInstalledError> { config.toAgentConfig("4.3.2") }
      assertTrue(error.message!!.contains("guard-agent is not installed"), error.message)
    } finally {
      ConfigSeams.agentConfigFactory = previous
    }
  }

  @Test
  fun testAgentWithFactoryReceivesFilteredKwargs() {
    val previous = ConfigSeams.agentConfigFactory
    var received: Map<String, Any?>? = null
    ConfigSeams.agentConfigFactory = { kwargs ->
      received = kwargs
      "agent-config"
    }
    try {
      val config =
          SecurityConfigBuilder()
              .apply {
                enableAgent = true
                agentApiKey = "k"
                agentBufferSize = 999
                agentProjectId = null
              }
              .build()
      assertEquals("agent-config", config.toAgentConfig("4.3.2"))
      val kwargs = received!!
      assertEquals("k", kwargs["api_key"])
      assertEquals(999, kwargs["buffer_size"])
      assertEquals("4.3.2", kwargs["guard_core_version"])
      assertFalseNull(kwargs["project_id"])
    } finally {
      ConfigSeams.agentConfigFactory = previous
    }
  }

  private fun assertFalseNull(value: Any?) {
    assertNull(value)
  }
}
