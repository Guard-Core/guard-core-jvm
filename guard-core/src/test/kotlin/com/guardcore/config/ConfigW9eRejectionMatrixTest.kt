package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e batch 4 final config arms: the fromMap wrong-type rejection matrix (every coercion arm the
 * valid sweeps never reach), the SecurityConfig copyWith field-write surface, and the warn/error
 * validator arms.
 */
class ConfigW9eRejectionMatrixTest {
  private fun rejects(field: String, value: Any?) {
    val error =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf(field to value), warnUnknown = false)
        }
    assertTrue(error.message!!.isNotEmpty())
  }

  @Test
  fun `fromMap rejects wrong-typed values across every coercion arm`() {
    rejects("rate_limit", true) // int arm
    rejects("detection_compiler_timeout", false) // double arm
    rejects("enable_redis", "yes") // bool arm
    rejects("ipinfo_token", 42) // string arm
    rejects("whitelist", 42) // list arm
    rejects("excluded_detection_headers", 42) // set arm
    rejects("security_headers", 42) // dict arm
    rejects("endpoint_rate_limits", 42) // int-keyed dict arm
    rejects("custom_error_responses", 42) // str-keyed dict arm
    rejects("dynamic_rules_cache_path", 42) // path arm
    rejects("log_suspicious_level", "NOPE") // log level arm
    rejects("log_format", "xml") // log format arm
    rejects("agent_buffer_overflow_policy", "explode") // policy arm
    rejects("threat_ban_config", 42) // threat ban arm
    rejects("global_behavior_rules", 42) // behavior rules arm
    rejects("global_behavior_rules", listOf(42)) // behavior rule item arm
    rejects(
        "global_behavior_rules",
        listOf(mapOf("rule_type" to "bogus", "threshold" to 1)),
    ) // rule type enum arm
    rejects(
        "global_behavior_rules",
        listOf(mapOf("rule_type" to "usage", "threshold" to 1, "action" to "explode")),
    ) // action enum arm
    rejects("endpoint_rate_limits", mapOf("/api" to listOf("a", "b"))) // endpoint pair arm
    rejects("endpoint_rate_limits", mapOf("/api" to 5)) // endpoint dict arm
    // the int-typed field reached with a wrong string is the Int coercion arm
    rejects("rate_limit", "many")
  }

  @Test
  fun `copyWith walks the full field-write surface`() {
    val base = SecurityConfigBuilder().build()
    val updated =
        base.copyWith(
            mapOf(
                "trusted_proxies" to listOf("10.0.0.1"),
                "whitelist" to listOf("192.0.2.1"),
                "blacklist" to listOf("192.0.2.2"),
                "exempt_ips" to listOf("192.0.2.3"),
                "threat_ban_config" to emptyMap<String, Any?>(),
                "enabled_detection_categories" to setOf("xss"),
                "muted_event_types" to setOf("access_denied"),
                "muted_metric_types" to setOf("error_rate"),
                "muted_check_logs" to setOf("rate_limit"),
                "log_sensitive_headers" to setOf("authorization"),
                "log_sensitive_params" to setOf("token"),
                "log_sensitive_body_fields" to setOf("password"),
                "block_cloud_providers" to setOf("AWS"),
                "rate_limit" to 10,
                "rate_limit_window" to 30,
                "endpoint_rate_limits" to mapOf("/api" to (5 to 60)),
                "blocked_user_agents" to listOf("curl"),
                "enable_penetration_detection" to true,
                "enable_ip_banning" to true,
                "enable_rate_limiting" to true,
                "emergency_mode" to false,
                "emergency_whitelist" to listOf("192.0.2.1"),
                "auto_ban_threshold" to 5,
                "auto_ban_duration" to 60,
                "enable_rate_limit_auto_ban" to false,
                "dynamic_rules_cache_path" to java.nio.file.Path.of("/tmp/w9e-cache.json"),
                "exclude_paths" to listOf("/health"),
                "global_behavior_rules" to emptyList<Any?>(),
                "custom_error_responses" to mapOf(403 to "nope"),
                "security_headers" to mapOf<String, Any?>("enabled" to false),
                "cors_allow_origins" to listOf("https://w9e.example"),
                "cors_allow_methods" to listOf("GET"),
                "cors_allow_headers" to listOf("X-A"),
                "cors_expose_headers" to listOf("X-B"),
                "agent_sensitive_headers" to listOf("authorization"),
                "otel_resource_attributes" to mapOf("a" to "b"),
                "excluded_detection_headers" to setOf("x-internal"),
            ),
        )
    assertEquals(listOf("10.0.0.1"), updated.trustedProxies)
    assertEquals(listOf("192.0.2.1"), updated.whitelist)
    assertEquals(listOf("192.0.2.2"), updated.blacklist)
    assertEquals(listOf("192.0.2.3"), updated.exemptIps)
    assertEquals(setOf("xss"), updated.enabledDetectionCategories)
    assertEquals(10, updated.rateLimit)
    assertEquals(30, updated.rateLimitWindow)
    assertEquals(true, updated.enablePenetrationDetection)
    assertEquals(mapOf("/api" to (5 to 60)), updated.endpointRateLimits)
    assertEquals(listOf("curl"), updated.blockedUserAgents)
    assertEquals(setOf("AWS"), updated.blockCloudProviders)
    assertEquals(listOf("/health"), updated.excludePaths)
    assertEquals(5, updated.autoBanThreshold)
    assertEquals(mapOf(403 to "nope"), updated.customErrorResponses)
    assertEquals(listOf("https://w9e.example"), updated.corsAllowOrigins)
    assertEquals(listOf("authorization"), updated.agentSensitiveHeaders)
    // a default-arg copy
    base.copyWith()
  }

  @Test
  fun `config build warns and errors over the shadow, prefix-zero and geo seams`() {
    val shadowBuilder = SecurityConfigBuilder()
    shadowBuilder.whitelistCountries = setOf("US")
    shadowBuilder.blockedCountries = setOf("CN")
    shadowBuilder.geoIpHandler = null
    // the geo handler requirement wins at build time; the shadow warn ran before it
    assertFailsWith<ConfigValidationError> { shadowBuilder.build() }
    // prefix-zero entries warn without rejecting
    val zero =
        SecurityConfigBuilder()
            .apply {
              trustedProxies = listOf("0.0.0.0/0")
              whitelist = listOf("0.0.0.0/0")
            }
            .build()
    assertEquals(listOf("0.0.0.0/0"), zero.trustedProxies)
    // the geo handler factory seam error carries the requirement text
    val geoError =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf("blocked_countries" to listOf("CN")))
        }
    assertTrue(geoError.message!!.contains("geo_ip_handler is required"), geoError.message)
    // the redis socket timeout arm rejects non-positive values when redis is enabled
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(
          mapOf(
              "enable_redis" to true,
              "redis_socket_timeout" to 0.0,
          ),
      )
    }
    // the copier carries the geo handler through when present
    val withGeo = SecurityConfigBuilder()
    val geoHandler =
        object : com.guardcore.protocols.GeoIPHandler {
          override val isInitialized: Boolean = true

          override fun getCountry(ip: String): String? = null

          override suspend fun initialize() {}

          override suspend fun initializeRedis(
              redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
          ) {}

          override suspend fun initializeAgent(
              agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
          ) {}

          override suspend fun refresh() {}

          override fun close() {}
        }
    withGeo.geoIpHandler = geoHandler
    val geoConfig = withGeo.build()
    assertNotNull(geoConfig.geoIpHandler)
    assertNull(SecurityConfigBuilder().build().geoIpHandler)
  }
}
