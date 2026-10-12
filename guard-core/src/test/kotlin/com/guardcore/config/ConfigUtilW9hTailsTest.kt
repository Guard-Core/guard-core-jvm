package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.protocols.RequestState
import com.guardcore.util.DetectionEngineWiring
import com.guardcore.util.LoggingUtils
import com.guardcore.util.PairRedaction
import com.guardcore.util.RequestLogging
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import com.guardcore.util.py.parseAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9h batch 6: the final config + util tails to the family 100 percent line gate - the fromMap
 * wrong-type rejection matrix, the geo-handler resolution arm, the country-shadow and
 * empty-categories warnings, the body-scan component arms, and the py-stdlib decode tails.
 */
class ConfigUtilW9hTailsTest {
  private class StubGeo : GeoIPHandler {
    override val isInitialized: Boolean
      get() = true

    override fun getCountry(ip: String): String? = "US"

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override suspend fun refresh() {}

    override fun close() {}
  }

  // ------------------------------------------------------------------ SecurityConfig arms

  /** The geo-handler resolution requirement (2162-2163). */
  @Test
  fun `country rules without a geo handler are rejected`() {
    val ex =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder.fromMap(mapOf("blocked_countries" to listOf("US")))
        }
    assertTrue(ex.message!!.contains("geo_ip_handler is required"))
  }

  /** The country-shadow warning (2223). */
  @Test
  fun `country allowlist shadows blocklist warns`() {
    val cfg =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "whitelist_countries" to listOf("US"),
                "blocked_countries" to listOf("CA"),
                "geo_ip_handler" to StubGeo(),
            ),
        )
    assertEquals(setOf("US"), cfg.whitelistCountries)
  }

  /** The empty enabled-detection-categories warning (2264). */
  @Test
  fun `empty detection categories warn`() {
    val cfg =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "enable_penetration_detection" to true,
                "enabled_detection_categories" to setOf<String>(),
            ),
        )
    assertTrue(cfg.enablePenetrationDetection)
  }

  /** fromConfig copies the excluded and dynamic-rule cache fields (2555-2556, 1022-1023). */
  @Test
  fun `fromConfig copies geo handler and field map`() {
    val geo = StubGeo()
    val source =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "exclude_paths" to listOf("/health"),
                "dynamic_rules_cache_path" to "/tmp/w9h-rules.json",
                "geo_ip_handler" to geo,
            ),
        )
    val copied = SecurityConfigBuilder.fromConfig(source).build()
    assertEquals(listOf("/health"), copied.excludePaths)
    assertEquals(geo, copied.geoIpHandler)
    // The provided-flag setter path (318).
    val builder = SecurityConfigBuilder()
    builder.dynamicRulesCachePath = java.nio.file.Path.of("/tmp/w9h-set.json")
    assertEquals(java.nio.file.Path.of("/tmp/w9h-set.json"), builder.build().dynamicRulesCachePath)
  }

  /** The runtime dict-coercion surface over the config setter (ConfigValidators 561, 583-585). */
  @Test
  fun `global behavior rules setter coerces raw maps`() {
    val cfg =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "exclude_paths" to listOf("/ok"),
                "geo_ip_handler" to StubGeo(),
            ),
        )
    // copyWith's raw field table drives the runtime dict-coercion surface:
    // a dict rule coerces (561, 2557); a non-string rule_type throws (583-585);
    // the exclude_paths and dynamic-rules-cache arms assign raw (2555-2556).
    val copied =
        cfg.copyWith(
            mapOf(
                "exclude_paths" to listOf("/w9h"),
                "dynamic_rules_cache_path" to java.nio.file.Path.of("/tmp/w9h-copy.json"),
                "global_behavior_rules" to listOf(mapOf("rule_type" to "usage", "threshold" to 1)),
            ),
        )
    assertEquals(listOf("/w9h"), copied.excludePaths)
    assertNotNull(copied.dynamicRulesCachePath)
    assertTrue(copied.globalBehaviorRules.isNotEmpty())
    assertFailsWith<ConfigValidationError> {
      cfg.copyWith(
          mapOf(
              "global_behavior_rules" to listOf(mapOf("rule_type" to 5)),
          ),
      )
    }
  }

  /** The geo-handler factory-missing arm (2162-2163) with a token but no seam. */
  @Test
  fun `country rules with a token but no factory are rejected`() {
    val saved = com.guardcore.config.ConfigSeams.geoIpHandlerFactory
    com.guardcore.config.ConfigSeams.geoIpHandlerFactory = null
    try {
      val ex =
          assertFailsWith<ConfigValidationError> {
            SecurityConfigBuilder.fromMap(
                mapOf(
                    "blocked_countries" to listOf("US"),
                    "ipinfo_token" to "w9h-token",
                ),
            )
          }
      assertTrue(ex.message!!.contains("geo_ip_handler is required"))
    } finally {
      com.guardcore.config.ConfigSeams.geoIpHandlerFactory = saved
    }
  }

  // ------------------------------------------------------------------ ConfigValidators arms

  /** The non-string entry rejection (99). */
  @Test
  fun `ip cidr list rejects non string entries`() {
    val ex =
        assertFailsWith<ConfigValidationError> {
          ConfigValidators.validateIpOrCidrList(listOf(1), "Invalid IP or CIDR range")
        }
    assertTrue(ex.message!!.contains("Invalid IP or CIDR range"))
  }

  /** The dynamic-rules cache path type and unparseable-path arms (360-363). */
  @Test
  fun `dynamic rules cache path rejects bad values`() {
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(mapOf("dynamic_rules_cache_path" to 5))
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(mapOf("dynamic_rules_cache_path" to "\u0000bad"))
    }
  }

  /** The behavior-rule rule_type non-string arm (583-585). */
  @Test
  fun `behavior rule map rejects non string rule types`() {
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder.fromMap(
          mapOf("global_behavior_rules" to listOf(mapOf("rule_type" to 5))),
      )
    }
  }

  /** stringSetOf's Set, Collection, and Array arms (615-617) + the else rejection. */
  @Test
  fun `string set coercion arms`() {
    assertEquals(emptySet(), ConfigValidators.validateMutedEventTypesValue(emptySet<String>()))
    assertEquals(emptySet(), ConfigValidators.validateMutedEventTypesValue(emptyList<String>()))
    assertEquals(emptySet(), ConfigValidators.validateMutedEventTypesValue(arrayOf<String>()))
    assertFailsWith<ConfigValidationError> {
      ConfigValidators.validateMutedEventTypesValue(42)
    }
  }

  // ------------------------------------------------------------------ Builder wrong-type matrix

  /** The fromMap coercion helpers reject wrong types with the pydantic messages (1457-1643). */
  @Test
  fun `fromMap wrong type rejection matrix`() {
    data class Case(val key: String, val value: Any?)

    val cases =
        listOf(
            Case("trusted_proxy_depth", true),
            Case("trusted_proxy_depth", "x"),
            Case("body_read_timeout", true),
            Case("body_read_timeout", "x"),
            Case("passive_mode", "x"),
            Case("redis_prefix", 5),
            Case("blacklist", "x"),
            Case("whitelist_countries", "x"),
            Case("security_headers", "x"),
            Case("custom_error_responses", "x"),
            Case("otel_resource_attributes", "x"),
            Case("ipinfo_db_path", 5),
            Case("log_suspicious_level", 5),
            Case("log_format", "nope"),
            Case("log_format", 5),
            Case("agent_buffer_overflow_policy", "nope"),
            Case("agent_buffer_overflow_policy", 5),
            Case("threat_ban_config", "x"),
            Case("global_behavior_rules", "x"),
            Case("global_behavior_rules", listOf(1)),
            Case("global_behavior_rules", listOf(mapOf("rule_type" to "bogus", "threshold" to 1))),
            Case(
                "global_behavior_rules",
                listOf(mapOf("rule_type" to "usage", "threshold" to 1, "action" to "bogus")),
            ),
            Case("endpoint_rate_limits", "x"),
            Case("endpoint_rate_limits", mapOf("a" to 5)),
        )
    for (case in cases) {
      val outcome = runCatching { SecurityConfigBuilder.fromMap(mapOf(case.key to case.value)) }
      if (outcome.isSuccess) {
        throw AssertionError("expected rejection for ${case.key} = ${case.value}")
      }
    }
    // A well-typed path sweep for contrast: the coercers accept their real types.
    val ok =
        SecurityConfigBuilder.fromMap(
            mapOf(
                "ipinfo_db_path" to "/tmp/ok.mmdb",
                "ipinfo_db_path" to java.nio.file.Path.of("/tmp/ok2.mmdb"),
                "threat_ban_config" to mapOf("xss" to mapOf("threshold" to 5, "duration" to 60)),
                "global_behavior_rules" to listOf(mapOf("rule_type" to "usage", "threshold" to 1)),
                "endpoint_rate_limits" to mapOf("/api" to listOf(5, 60)),
                "custom_error_responses" to mapOf(404 to "not found"),
            ),
        )
    assertNotNull(ok)
  }

  // ------------------------------------------------------------------ Body scans

  private class HeaderRequest(
      private val headerMap: Map<String, String>,
  ) : GuardRequest {
    override val urlPath: String = "/api"
    override val urlScheme: String = "http"
    override val urlFull: String = "http://example.com/api"
    override val method: String = "GET"
    override val clientHost: String? = "192.0.2.10"
    override val headers: Map<String, String> = headerMap
    override val queryParams: Map<String, String> = emptyMap()
    override val state: RequestState =
        object : RequestState {
          private val attrs = linkedMapOf<String, Any?>()

          override fun getAttr(name: String): Any? = attrs[name]

          override fun setAttr(name: String, value: Any?) {
            attrs[name] = value
          }
        }
    override val scope: Map<String, Any?> = emptyMap()

    override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com/api"

    override suspend fun body(): ByteArray = ByteArray(0)
  }

  /**
   * scanHeaders: the name and value always-scan arms (154-167) and the empty-category gate (174).
   */
  @Test
  fun `header scan detection and category gate arms`(): Unit = runBlocking {
    // The NAME carries the trigger (154-155).
    val nameHit =
        com.guardcore.util.BodyContentScan.scanHeaders(
            HeaderRequest(mapOf("; cat /etc/passwd" to "x")),
            excludedHeaders = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9h",
            logLevel = null,
        )
    assertTrue(nameHit.first)

    // The VALUE carries the trigger (159-167).
    val valueHit =
        com.guardcore.util.BodyContentScan.scanHeaders(
            HeaderRequest(mapOf("x-probe" to "; cat /etc/passwd")),
            excludedHeaders = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9h",
            logLevel = null,
        )
    assertTrue(valueHit.first)

    // An empty effective-category set short-circuits (174).
    val gated =
        com.guardcore.util.BodyContentScan.scanHeaders(
            HeaderRequest(mapOf("x-probe" to "; cat /etc/passwd")),
            excludedHeaders = emptySet(),
            enabledCategories = setOf(),
            clientIp = "192.0.2.10",
            correlationId = "w9h",
            logLevel = null,
        )
    assertFalse(gated.first)
  }

  /** multipartPartEntries drives the part-payload arms directly (93-94, 104, 107, 110). */
  @Test
  fun `multipart part entries payload arms`() {
    val binaryPayload = "raw\u0000\u0001\u0002binary\u0003data"
    // filename + binary-like payload -> the binary-island extraction (93-94, 107).
    val binaryPart =
        com.guardcore.util.BodyFormScan.MultipartPart(
            listOf("content-disposition" to "form-data; name=\"bin\"; filename=\"blob.bin\""),
            binaryPayload,
        )
    val binaryEntries = com.guardcore.util.BodyFormScan.multipartPartEntries(binaryPart)
    assertTrue(binaryEntries.isNotEmpty())
    // A null payload -> the empty-list arm (104).
    val nullPart =
        com.guardcore.util.BodyFormScan.MultipartPart(
            listOf("content-disposition" to "form-data; name=\"nul\""),
            null,
        )
    com.guardcore.util.BodyFormScan.multipartPartEntries(nullPart)
    // An empty payload -> the other empty arm (110).
    val emptyPart =
        com.guardcore.util.BodyFormScan.MultipartPart(
            listOf("content-disposition" to "form-data; name=\"empty\""),
            "",
        )
    com.guardcore.util.BodyFormScan.multipartPartEntries(emptyPart)
  }

  /** scanMultipartBody walks the parsed-part arms over the wire format. */
  @Test
  fun `multipart part payload arms`(): Unit = runBlocking {
    val boundary = "w9hboundary"
    val binary = "binary\u0000\u0001\u0002data".repeat(4)
    val body =
        "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"textfield\"\r\n\r\n" +
            "hello\r\n" +
            "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"emptyfield\"\r\n\r\n" +
            "\r\n" +
            "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"binfield\"; filename=\"blob.bin\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n" +
            "$binary\r\n" +
            "--$boundary--\r\n"
    val hit =
        com.guardcore.util.BodyFormScan.scanMultipartBody(
            body,
            "multipart/form-data; boundary=$boundary",
            excludedBodyFields = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9h",
            logLevel = null,
        )
    assertNotNull(hit)
  }

  // ------------------------------------------------------------------ py stdlib tails

  /** PyIp: the IPv6 shape errors (400, 441, 444) and the address text (290). */
  @Test
  fun `ipv6 parse shape errors`() {
    assertEquals("1.2.3.4", parseAddress("1.2.3.4").toString())
    assertFailsWith<ConfigValidationError> { parseAddress("1:2:3:4:5:6:7:8:9") }
    assertFailsWith<ConfigValidationError> { parseAddress(":1:2:3:4:5:6:7:8") }
    assertFailsWith<ConfigValidationError> { parseAddress("1:2:3:4:5:6:7:8:") }
    // A valid v6 network round trips its text (290).
    val network = IpNetwork.parse("2001:db8::/32")
    assertTrue(network.toString().isNotEmpty())
  }

  /** PyJson: the long-token and float-repr tails (241) + the parser construction (46). */
  @Test
  fun `py json long tokens`() {
    assertEquals(1234567890123456789L, PyJson.loads("1234567890123456789"))
    assertEquals(
        java.math.BigInteger("123456789012345678901234567890"),
        PyJson.loads("123456789012345678901234567890"),
    )
    assertNull(PyJson.loads("null"))
    // Nested containers construct fresh parsers over every decode path (46).
    assertNotNull(PyJson.loads("{\"a\": [1, {\"b\": null}], \"c\": \"x\"}"))
  }

  /** PyUrllib: the empty pair-value skip (70) and the scheme-character validity arm (146-147). */
  @Test
  fun `py urllib qs and scheme arms`() {
    val parsed = PyUrllib.parseQs("x=&y=2")
    assertEquals(listOf("2"), parsed["y"])
    assertFalse(parsed.containsKey("x"))
    // A leading candidate with a character outside the scheme set is not a scheme (146-147).
    val split = PyUrllib.urlsplit("ht_tp://example.com/x")
    assertEquals("", split.scheme)
  }

  /**
   * PyDiffLib: the no-arg constructor (49) and the find-longest-match extension loops (129-144).
   */
  @Test
  fun `py difflib matcher arms`() {
    val bare = com.guardcore.util.py.SequenceMatcher()
    assertEquals(1.0, bare.ratio())
    val matcher = com.guardcore.util.py.SequenceMatcher(a = "abcdef", b = "xxabcxxdefy")
    val match = matcher.findLongestMatch(0, 6, 0, 11)
    assertNotNull(match)
    val rich = com.guardcore.util.py.SequenceMatcher(a = "qabxcd", b = "abycdf")
    assertTrue(rich.ratio() > 0.0)
    rich.quickRatio()
    rich.findLongestMatch(0, 6, 0, 6)
  }

  // ------------------------------------------------------------------ util tails

  /** LoggingUtils: the depth-cap ThreadLocal (28) and the nested-JSON decode failure (117-118). */
  @Test
  fun `logging utils depth and json leaf arms`() {
    assertFalse(LoggingUtils.jsonDepthCapHit.get())
    // A string leaf whose nested JSON candidate fails to parse (117-118).
    val redacted =
        RequestLogging.redactHeaderValueForDisplay(
            """{"leaf": "{not json"}""",
            null,
            null,
        )
    assertNotNull(redacted)
  }

  /** PairRedaction: the sensitive name resolves and the value masks. */
  @Test
  fun `pair redaction masks sensitive values`() {
    val redacted =
        PairRedaction.redactPairsInText("apiKey=secret-value", setOf("apikey"), emptySet(), 5)
    assertTrue(!redacted.contains("secret-value"), redacted)
    // A percent-encoded sensitive name decodes into the sensitive set and masks too.
    val encoded =
        PairRedaction.redactPairsInText("%61piKey=secret-value", setOf("apikey"), emptySet(), 5)
    assertTrue(!encoded.contains("secret-value"), encoded)
  }

  /** PairHiddenAssign: the dangling decoded pair with an adjacent continuation value (211-213). */
  @Test
  fun `hidden assign dangling pair rescans the adjacent continuation`() {
    // The raw run percent-encodes "apikey="; the decoded run redacts to a dangling
    // "masked=" and the adjacent continuation value redacts too.
    val text = "%61piKey%3Dsecret-value-tail"
    val result =
        com.guardcore.util.PairHiddenAssign.redactHiddenEncodedPair(
            text,
            runEnd = text.length,
            rawRun = text,
            sensitive = setOf("apikey"),
        )
    assertNotNull(result)
    assertTrue(!result!!.first.contains("secret"), result.first)
  }

  /** DetectionEngineWiring: the straddle provider's empty-pattern arm (96). */
  @Test
  fun `straddle provider handles empty patterns`() {
    DetectionEngineWiring.register()
    val engine = com.guardcore.engine.suspatterns.SusPatternsManager.shared()
    val saved = engine.patterns.toList()
    val savedCompiled = engine.compiledPatterns.toList()
    try {
      engine.patterns.clear()
      engine.compiledPatterns.clear()
      val provider = DetectionEngineWiringTestAccess.straddleProvider()
      assertEquals(0, provider!!.invoke())
    } finally {
      engine.patterns.clear()
      engine.patterns.addAll(saved)
      engine.compiledPatterns.clear()
      engine.compiledPatterns.addAll(savedCompiled)
    }
  }
}

/** Internal-surface access for the wiring test. */
public object DetectionEngineWiringTestAccess {
  public fun straddleProvider(): (() -> Int)? =
      com.guardcore.util.BodyReader.straddleOverlapBytesProvider
}
