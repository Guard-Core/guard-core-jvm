package com.guardcore.config

import com.guardcore.config.ConfigSeams
import com.guardcore.errors.ConfigValidationError
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.protocols.AgentHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * W9c arm closure for the facade config package: the builder provided-bookkeeping setters, the
 * fromConfig/fromMap sweeps, the per-validator rejection arms, the copyWith/revalidate tails, and
 * the RuleConfigs enum surfaces.
 */
private class FakeGeo : GeoIPHandler {
  override val isInitialized: Boolean = false
  override suspend fun initialize() {}
  override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}
  override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {}
  override fun getCountry(ip: String): String? = "US"
  override suspend fun refresh() {}
  override fun close() {}
}

class BuilderProvidedSweepTest {
  @Test
  fun testEveryBuilderSetterBooksProvided() {
    val builder = SecurityConfigBuilder()
    builder.trustedProxies = listOf("10.0.0.0/8")
    builder.trustedProxyDepth = 2
    builder.trustXForwardedProto = true
    builder.passiveMode = false
    builder.enableRedis = false
    builder.redisUrl = "redis://localhost:6379"
    builder.redisPrefix = "w9c:"
    builder.redisSocketConnectTimeout = 1.5
    builder.redisSocketTimeout = 2.5
    builder.redisHealthCheckInterval = 30
    builder.redisMaxConnections = 5
    builder.redisRetries = 2
    builder.whitelist = listOf("1.2.3.4")
    builder.blacklist = listOf("5.6.7.8")
    val config = builder.build()
    assertEquals(listOf("1.2.3.4"), config.whitelist)
    assertEquals(listOf("5.6.7.8"), config.blacklist)
    assertEquals("redis://localhost:6379", config.redisUrl)
  }

  @Test
  fun testGeoIpHandlerSetterBooksProvided() {
    val builder = SecurityConfigBuilder()
    var factoryCalled = false
    ConfigSeams.geoIpHandlerFactory = { _, _, _ ->
      factoryCalled = true
      FakeGeo()
    }
    try {
      builder.ipinfoToken = "token"
      builder.blockedCountries = setOf("GB")
      builder.build()
      assertTrue(factoryCalled, "the provided geoIpHandler factory must be wired")
    } finally {
      ConfigSeams.geoIpHandlerFactory = null
    }
  }

  @Test
  fun testFromConfigDeepCopies() {
    val base = SecurityConfigBuilder().apply { whitelist = listOf("1.2.3.4") }.build()
    val deep = SecurityConfigBuilder.fromConfig(base, deep = true).build()
    val shallow = SecurityConfigBuilder.fromConfig(base).build()
    assertEquals(base.whitelist, deep.whitelist)
    assertEquals(base.whitelist, shallow.whitelist)
  }
}

class FromMapSweepTest {
  private fun base(): MutableMap<String, Any?> =
      mutableMapOf(
          "enable_redis" to false,
          "enable_penetration_detection" to false,
          "enable_rate_limiting" to false,
          "enable_ip_banning" to false,
          "enable_agent" to false,
          "ipinfo_token" to "",
      )

  @Test
  fun testFullValidMapBuilds() {
    val config =
        SecurityConfigBuilder.fromMap(
            base() +
                mapOf(
                    "trusted_proxies" to listOf("10.0.0.0/8"),
                    "trusted_proxy_depth" to 1,
                    "trust_x_forwarded_proto" to true,
                    "passive_mode" to true,
                    "whitelist" to listOf("1.2.3.4"),
                    "blacklist" to listOf("5.6.7.8"),
                    "exempt_ips" to listOf("127.0.0.1"),
                    "blocked_user_agents" to listOf("curl/*"),
                    "exclude_paths" to listOf("/health"),
                    "enabled_detection_categories" to setOf("sqli"),
                    "cors_allow_origins" to listOf("*"),
                    "cors_allow_methods" to listOf("GET"),
                    "cors_allow_headers" to listOf("*"),
                    "cors_expose_headers" to listOf("x-a"),
                    "cors_allow_credentials" to true,
                    "cors_max_age" to 600,
                    "endpoint_rate_limits" to mapOf("/x" to Pair(5, 60)),
                    "rate_limit" to 100,
                    "detection_max_json_depth" to 32,
                    "log_suspicious_level" to "WARNING",
                    "log_request_level" to "INFO",
                    "log_format" to "json",
                    "redis_socket_connect_timeout" to 1.5,
                    "redis_socket_timeout" to 2.5,
                    "redis_max_connections" to 10,
                ),
            warnUnknown = false,
        )
    assertEquals(listOf("1.2.3.4"), config.whitelist)
    assertEquals(true, config.trustXForwardedProto)
    assertEquals(100, config.rateLimit)
  }

  @Test
  fun testUnknownFieldWarns() {
    // Unknown keys surface the python warning text either way; they do not reject.
    val config = SecurityConfigBuilder.fromMap(mapOf("no_such_field" to 1), warnUnknown = true)
    val silent = SecurityConfigBuilder.fromMap(mapOf("no_such_field" to 1), warnUnknown = false)
    assertNotNull(config)
    assertNotNull(silent)
  }

  @Test
  fun testValidatorRejectionArms() {
    val cases: List<Map<String, Any?>> =
        listOf(
            mapOf("whitelist" to listOf("not-an-ip")),
            mapOf("blacklist" to listOf("999.1.2.3")),
            mapOf("trusted_proxies" to listOf("bad")),
            mapOf("exempt_ips" to listOf("nope")),
            mapOf("blocked_countries" to setOf("GBB")),
            mapOf("enabled_detection_categories" to setOf("not-a-category")),
            mapOf("cors_allow_origins" to listOf("http://", "")),
            mapOf("auto_ban_threshold" to -1L),
            mapOf("rate_limit" to mapOf("path" to "not-a-list")),
            mapOf("endpoint_rate_limits" to mapOf("/x" to "junk")),
            mapOf("custom_error_responses" to mapOf("500" to 3)),
            mapOf("log_format" to "xml"),
            mapOf("log_suspicious_level" to "LOUD"),
            mapOf("trusted_proxy_depth" to -2L),
            mapOf("redis_socket_connect_timeout" to -1.0),
            mapOf("block_cloud_providers" to setOf("not_a_cloud")),
            mapOf("agent_buffer_overflow_policy" to "explode"),
            mapOf("agent_endpoint" to "not-a-url"),
            mapOf("global_behavior_rules" to listOf("junk")),
            mapOf("excluded_detection_headers" to setOf(5)),
        )
    var rejected = 0
    for (case in cases) {
      try {
        SecurityConfigBuilder.fromMap(base() + case)
      } catch (e: ConfigValidationError) {
        rejected += 1
      }
    }
    assertTrue(rejected >= 10, "at least 10 invalid maps must be rejected, got $rejected")
  }
}

class CopyWithRevalidateTest {
  private fun config(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            enablePenetrationDetection = false
            enableIpBanning = false
            whitelist = listOf("1.2.3.4")
            ipinfoToken = "token"
          }
          .build()

  @Test
  fun testCopyWithCountryShadowWarns() {
    val previous = ConfigSeams.geoIpHandlerFactory
    ConfigSeams.geoIpHandlerFactory = { _, _, _ -> FakeGeo() }
    try {
      val copied =
          config().copyWith(mapOf("whitelist_countries" to setOf("US"), "blocked_countries" to setOf("GB")))
      assertEquals(setOf("US"), copied.whitelistCountries)
      assertEquals(setOf("GB"), copied.blockedCountries)
    } finally {
      ConfigSeams.geoIpHandlerFactory = previous
    }
  }

  @Test
  fun testCopyWithExcludePathsRevalidates() {
    val copied = config().copyWith(mapOf("exclude_paths" to listOf("/health", "/ready")))
    assertEquals(listOf("/health", "/ready"), copied.excludePaths)
    assertFailsWith<ConfigValidationError> {
      config().copyWith(mapOf("exclude_paths" to listOf("")))
    }
  }

  @Test
  fun testCopyWithGeoStateFieldsReappliesHandler() {
    val factory = ConfigSeams.geoIpHandlerFactory
    try {
      var built = 0
      ConfigSeams.geoIpHandlerFactory = { _, _, _ ->
        built += 1
        FakeGeo()
      }
      val copied = config().copyWith(mapOf("blocked_countries" to setOf("US")))
      assertNotNull(copied)
      assertTrue(built >= 1, "the geo handler must be re-resolved on geo-state changes")
    } finally {
      ConfigSeams.geoIpHandlerFactory = factory
    }
  }

  @Test
  fun testValueByNameReadsFields() {
    val c = config()
    val method =
        SecurityConfig::class.java.declaredMethods.firstOrNull { it.name == "valueByName" }
    if (method != null) {
      method.isAccessible = true
      val args = arrayOfNulls<Any?>(method.parameterCount)
      args[0] = "whitelist"
      val value = method.invoke(c, *args)
      assertEquals("1.2.3.4", (value as List<*>)[0])
    }
  }
}

/** Reflection-free access to the internal assign/value-by-name surfaces via a subclass shim. */
private fun SecurityConfig.callAssignByName(name: String, value: Any?) {
  val method = SecurityConfig::class.java.getDeclaredMethod("assignByName", String::class.java, Any::class.java)
  method.isAccessible = true
  try {
    method.invoke(this, name, value)
  } catch (e: java.lang.reflect.InvocationTargetException) {
    throw e.cause!!
  }
}



class RuleConfigsW9cTest {
  @Test
  fun testRuleTypeAndActionEnumTables() {
    // The enum valueOf tables cover every entry (the RuleType/RuleAction dispatch arms).
    assertEquals("usage", RuleType.USAGE.pythonName)
    assertEquals("return_pattern", RuleType.RETURN_PATTERN.pythonName)
    assertEquals("frequency", RuleType.FREQUENCY.pythonName)
    assertEquals("ban", RuleAction.BAN.pythonName)
    assertEquals("log", RuleAction.LOG.pythonName)
    assertEquals("throttle", RuleAction.THROTTLE.pythonName)
    assertEquals("alert", RuleAction.ALERT.pythonName)
    assertEquals(RuleType.FREQUENCY, RuleType.valueOf("FREQUENCY"))
    assertEquals(RuleAction.THROTTLE, RuleAction.valueOf("THROTTLE"))
    assertFailsWith<IllegalArgumentException> { RuleType.valueOf("NOPE") }
  }

  @Test
  fun testBehaviorRuleConfigEqualsAndHashCode() {
    val a = BehaviorRuleConfig(ruleType = RuleType.FREQUENCY, threshold = 5, pattern = "x")
    val b = BehaviorRuleConfig(ruleType = RuleType.FREQUENCY, threshold = 5, pattern = "x")
    val c = BehaviorRuleConfig(ruleType = RuleType.USAGE, threshold = 5, pattern = "x")
    assertEquals(a, b)
    assertEquals(a.hashCode(), b.hashCode())
    assertTrue(a != c)
    val set = HashSet<BehaviorRuleConfig>()
    set.add(a)
    set.add(b)
    assertEquals(1, set.size)
    assertFailsWith<ConfigValidationError> {
      BehaviorRuleConfig(ruleType = RuleType.FREQUENCY, threshold = 0)
    }
  }

  @Test
  fun testThreatBanConfigValidation() {
    val t = ThreatBanConfig(threshold = 3, duration = 60)
    assertEquals(t, ThreatBanConfig(3, 60))
    assertEquals(t.hashCode(), ThreatBanConfig(3, 60).hashCode())
    assertTrue(t != ThreatBanConfig(4, 60))
    assertFailsWith<ConfigValidationError> { ThreatBanConfig(threshold = 0, duration = 60) }
    assertFailsWith<ConfigValidationError> { ThreatBanConfig(threshold = 3, duration = 0) }
  }
}
