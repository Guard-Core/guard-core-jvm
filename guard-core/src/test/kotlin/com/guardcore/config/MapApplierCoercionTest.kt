package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Port of the fromMap invalid-value sweep the W9a worklist pinned (ConfigValidators rejection
 * arms + MapApplier coercion arms): every registered field rejects a junk value with the
 * pydantic-shaped message, and the type-widening coercions (float via Int, set via collection, path
 * via string, enum via name) behave exactly like the reference.
 */
class MapApplierCoercionTest {
  /** The cast-or-null object seams: no reject arm by design. */
  private val seamFields =
      setOf(
          "geo_ip_handler",
          "custom_request_check",
          "auth_verifier",
          "custom_response_modifier",
          "cloud_ip_store",
          "on_error",
          "on_block",
      )

  /** The minimal GeoIPHandler stub the cross-field country validator requires. */
  private class StubGeo : com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = true

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun geoIpHandlerStub(): com.guardcore.protocols.GeoIPHandler = StubGeo()

  private fun expectReject(name: String, values: Map<String, Any?>): String {
    try {
      SecurityConfigBuilder.fromMap(values, warnUnknown = false)
      fail("expected ConfigValidationError for $name")
    } catch (e: ConfigValidationError) {
      return e.message ?: ""
    }
  }

  @Test
  fun everyRegisteredFieldRejectsAJunkValue() {
    val junk =
        object {
          override fun toString(): String = "junk-sentinel"
        }
    var rejected = 0
    for (field in ConfigFieldRegistry.fields) {
      // The object-seam fields (handler/check/verifier/modifier/store) accept
      // any object via cast-or-null: no reject arm by design.
      if (field.pythonName in seamFields) continue
      val message = expectReject(field.pythonName, mapOf(field.pythonName to junk))
      // Every pydantic-shaped rejection names the field.
      assertTrue(
          message.startsWith(field.pythonName),
          "field ${field.pythonName}: $message",
      )
      rejected += 1
    }
    assertEquals(ConfigFieldRegistry.fields.size - seamFields.size, rejected)
  }

  @Test
  fun intFieldsRejectBooleansAndStrings() {
    val err =
        expectReject(
            "rate_limit",
            mapOf("rate_limit" to "lots"),
        )
    assertTrue("Input should be a valid integer" in err, err)
    assertTrue(
        "Input should be a valid integer" in
            expectReject("auto_ban_threshold", mapOf("auto_ban_threshold" to true)),
    )
  }

  @Test
  fun floatFieldsCoerceIntsAndRejectBooleans() {
    // Int -> Double coercion matches python.
    val coerced =
        SecurityConfigBuilder.fromMap(mapOf("redis_socket_timeout" to 7), warnUnknown = false)
    assertEquals(7.0, coerced.redisSocketTimeout)
    assertTrue(
        "Input should be a valid number" in
            expectReject("redis_socket_timeout", mapOf("redis_socket_timeout" to true)),
    )
  }

  @Test
  fun collectionFieldsAcceptListsAndRejectScalars() {
    val handler = geoIpHandlerStub()
    val built =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "geo_ip_handler" to handler,
                "whitelist_countries" to listOf("us", "ca"),
            ),
            warnUnknown = false,
        )
    assertEquals(setOf("US", "CA"), built.whitelistCountries)
    val handler2 = geoIpHandlerStub()
    assertTrue(
        "Input should be a valid set" in
            expectReject(
                "whitelist_countries",
                mapOf("geo_ip_handler" to handler2, "whitelist_countries" to 42),
            ),
    )
  }

  @Test
  fun pathFieldsAcceptStringsAndPaths() {
    val built =
        SecurityConfigBuilder.fromMap(
            mapOf("dynamic_rules_cache_path" to "/tmp/w9b-rules.json"),
            warnUnknown = false,
        )
    assertEquals(java.nio.file.Paths.get("/tmp/w9b-rules.json"), built.dynamicRulesCachePath)
    assertTrue(
        "must be a non-empty filesystem path string or None" in
            expectReject(
                "dynamic_rules_cache_path",
                mapOf("dynamic_rules_cache_path" to listOf("x")),
            ),
    )
  }

  @Test
  fun logLevelAndFormatArms() {
    // log_suspicious_level exercises the LogLevel name lookup arm.
    val built =
        SecurityConfigBuilder.fromMap(mapOf("log_suspicious_level" to "DEBUG"), warnUnknown = false)
    assertEquals(LogLevel.DEBUG, built.logSuspiciousLevel)
    assertTrue(
        "Input should be 'INFO', 'DEBUG', 'WARNING', 'ERROR' or 'CRITICAL'" in
            expectReject("log_suspicious_level", mapOf("log_suspicious_level" to "LOUD")),
    )
    assertTrue(
        "Input should be 'INFO', 'DEBUG', 'WARNING', 'ERROR' or 'CRITICAL'" in
            expectReject("log_suspicious_level", mapOf("log_suspicious_level" to 3)),
    )
  }

  @Test
  fun providedBookkeepingSettersTrackTheirFlags() {
    val built =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "redis_url" to "redis://localhost:6379",
                "redis_socket_connect_timeout" to 1.5,
                "redis_socket_timeout" to 2.5,
                "redis_max_connections" to 10,
                "whitelist" to listOf("10.0.0.1"),
            ),
            warnUnknown = false,
        )
    assertNotNull(built.redisUrl)
    // The geo handler seam tracks assignment the same way.
    val builder = SecurityConfigBuilder()
    builder.geoIpHandler = null
    assertTrue(builder.geoIpHandlerProvided)
    builder.redisUrl = "redis://x"
    assertTrue(builder.redisUrlProvided)
    builder.redisSocketConnectTimeout = 1.0
    assertTrue(builder.redisSocketConnectTimeoutProvided)
    builder.redisSocketTimeout = 1.0
    assertTrue(builder.redisSocketTimeoutProvided)
  }
}
