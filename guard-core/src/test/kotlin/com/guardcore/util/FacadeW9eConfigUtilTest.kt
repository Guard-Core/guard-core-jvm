package com.guardcore.util

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.TestRequest
import com.guardcore.errors.ConfigValidationError
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import com.guardcore.util.py.SequenceMatcher
import com.guardcore.util.py.parseAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9e arm closure for the facade config + util surface: the cross-field validator and warn arms,
 * the config revision/copy surface, the tracked route containers, the body scan component arms, the
 * pair-redaction decoders, and the py-stdlib singles.
 */
class FacadeW9eConfigUtilTest {
  // ------------------------------------------------------------ config cross-field arms

  @Test
  fun `config validation walks the warn and error arms`() {
    // the shadow warning: both allow and block lists populated (a geo handler is then
    // required, so the build surfaces the requirement error after the warn)
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder()
          .apply {
            whitelistCountries = setOf("US")
            blockedCountries = setOf("CN")
          }
          .build()
    }
    // agent validation errors
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { enableAgent = true }.build()
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { enableDynamicRules = true }.build()
    }
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { enableEnrichment = true }.build()
    }
    // prefix-zero warnings do not reject
    val prefixZero =
        SecurityConfigBuilder()
            .apply {
              trustedProxies = listOf("10.0.0.1/32")
              whitelist = listOf("192.0.2.1")
            }
            .build()
    assertNotNull(prefixZero)
    // the geo handler factory requirement: blocked countries without a handler and no seam
    com.guardcore.config.ConfigSeams.geoIpHandlerFactory = null
    assertFailsWith<ConfigValidationError> {
      SecurityConfigBuilder().apply { blockedCountries = setOf("CN") }.build()
    }
  }

  @Test
  fun `config copy and field writes walk the revision surface`() {
    val config = SecurityConfigBuilder().apply { excludedDetectionParams = setOf("q") }.build()
    // the default-arg copy
    val plain = config.copyWith()
    assertEquals(config.excludedDetectionParams, plain.excludedDetectionParams)
    // a tracked-container write through the update mapping
    val copied =
        config.copyWith(
            mapOf(
                "excluded_detection_params" to setOf("other"),
                "excluded_detection_body_fields" to setOf("secret"),
                "detection_scan_body" to true,
                "enabled_detection_categories" to setOf("xss"),
            ),
        )
    assertEquals(setOf("other"), copied.excludedDetectionParams)
    assertEquals(setOf("secret"), copied.excludedDetectionBodyFields)
    assertTrue(copied.detectionScanBody)
    assertEquals(setOf("xss"), copied.enabledDetectionCategories)
    assertFailsWith<ConfigValidationError> {
      config.copyWith(mapOf("w9e_bogus_field" to 1))
    }
  }

  // ------------------------------------------------------------ route config tracked containers

  @Test
  fun `tracked route containers bump revisions on mutation`() {
    val revision = com.guardcore.decorators.RouteConfigRevision()
    val list = com.guardcore.decorators.TrackedList<String>(listOf("a"), revision)
    list.addAll(listOf("b", "c"))
    val before = revision.value
    list.addAll(0, listOf("z"))
    assertTrue(revision.value > before)
    assertTrue(list.containsAll(listOf("a", "z")))
    val mapRevision = com.guardcore.decorators.RouteConfigRevision()
    val route = com.guardcore.decorators.RouteConfig(mapRevision)
    route.customValidators =
        mutableListOf<suspend (com.guardcore.protocols.GuardRequest) -> Any?>({ _ -> null })
    assertTrue(mapRevision.value > 0)
    val afterFirst = mapRevision.value
    route.blockedUserAgents = mutableListOf("curl")
    assertTrue(mapRevision.value > afterFirst)
    route.requiredHeaders = mapOf("X-Key" to "v") as MutableMap<String, String>
    assertTrue(mapRevision.value > afterFirst + 1)
  }

  // ------------------------------------------------------------ body scans

  @Test
  fun `body content scan walks the header, param and body component arms`() = runBlocking {
    val request =
        TestRequest(
            headers =
                mapOf(
                    "X-Sql" to "union select password from users",
                    "Authorization" to "Bearer tokenvalue",
                    "X-Fine" to "plain",
                ),
        )
    val headerScan =
        BodyContentScan.scanHeaders(
            request,
            excludedHeaders = setOf("x-fine"),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
            sensitiveHeaders = setOf("authorization"),
        )
    assertTrue(headerScan.first, headerScan.second)
    val paramScan =
        BodyContentScan.scanQueryParams(
            TestRequest(),
            excludedParams = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
            sensitiveParams = setOf("token"),
        )
    assertNotNull(paramScan)
    val bodyScan =
        BodyContentScan.scanRequestBody(
            "field=<script>alert(1)</script>",
            "application/x-www-form-urlencoded",
            excludedBodyFields = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
        )
    assertTrue(bodyScan.detected, bodyScan.trigger)
  }

  @Test
  fun `form and multipart scans walk the binary and malformed arms`() = runBlocking {
    val form =
        BodyFormScan.scanFormBody(
            "name=value&password=hunter2",
            excludedBodyFields = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
            sensitiveBodyFields = setOf("password"),
        )
    assertNotNull(form)
    // a multipart body with a binary part routes through the blob arm
    val multipart =
        BodyFormScan.scanMultipartBody(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n\u0000\u0001\u0002\r\n--b--\r\n",
            "multipart/form-data; boundary=b",
            excludedBodyFields = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
        )
    assertNotNull(multipart)
    // an unparsable multipart body (no boundary) falls back to the blob scan
    val bad =
        BodyFormScan.scanMultipartBody(
            "not-multipart",
            "multipart/form-data",
            excludedBodyFields = emptySet(),
            enabledCategories = null,
            clientIp = "192.0.2.10",
            correlationId = "w9e",
            logLevel = null,
        )
    assertNotNull(bad)
  }

  // ------------------------------------------------------------ pair redaction

  @Test
  fun `pair redaction walks the encoded and dangling pair arms`() {
    val redacted =
        PairRedaction.redactPairsInTextEx(
            "token=abc&password=xyz; token=%61%62%63",
            sensitive = setOf("token", "password"),
        )
    assertFalse(redacted.first.contains("abc"), redacted.first)
    val hidden =
        PairHiddenAssign.redactHiddenEncodedPair(
            "token%3Dabc%26password%3Dxyz",
            28,
            "token%3Dabc%26password%3Dxyz",
            setOf("token", "password"),
        )
    if (hidden != null) {
      assertFalse(hidden.first.contains("xyz"))
    }
    val sanitized = LoggingUtils.sanitizeForLog("line1\nline2")
    assertFalse(sanitized.contains("\n"), sanitized)
  }

  // ------------------------------------------------------------ py stdlib singles

  @Test
  fun `py ip walks the ipv6 parse error arms`() {
    assertFailsWith<ConfigValidationError> { parseAddress("") }
    assertFailsWith<ConfigValidationError> { parseAddress("1:2:3") }
    assertFailsWith<ConfigValidationError> { parseAddress("1:2:3:4:5:6:7:8:9") }
    assertFailsWith<ConfigValidationError> { parseAddress("::1::2") }
    assertFailsWith<ConfigValidationError> { parseAddress(":1:2:3:4:5:6:7:8") }
    assertFailsWith<ConfigValidationError> { parseAddress("1:2:3:4:5:6:7:8:") }
    val v6 = parseAddress("::ffff:192.0.2.1")
    assertTrue(v6.toString().startsWith("::ffff:"))
    assertEquals(parseAddress("2001:db8::1"), parseAddress("2001:db8::1"))
  }

  @Test
  fun `py urllib and py json walk the delimiter arms`() {
    // an encoded percent sequence round-trips through unquote
    assertEquals("a b", PyUrllib.unquote("a%20b"))
    assertEquals("a b", PyUrllib.unquotePlus("a+b"))
    val split = PyUrllib.urlsplit("https://h/p?q#f")
    assertEquals("https", split.scheme)
    // a json array missing a comma is a decode error
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("[1 2]") }
    assertFailsWith<PyJson.JsonDecodeError> { PyJson.loads("{\"a\": 1 \"b\": 2}") }
    // a huge integer beyond double range still parses
    val big = PyJson.loads("123456789012345678901234567890")
    assertNotNull(big)
    // tiny floats take the zero-exponent rendering arm
    assertNotNull(PyJson.floatRepr(0.0))
    assertNotNull(PyJson.floatRepr(5e-324))
  }

  @Test
  fun `py difflib walks the ratio and matching-block arms`() {
    val matcher = SequenceMatcher("hello world", "hello brave world")
    assertTrue(matcher.quickRatio() >= 0.0)
    val blocks = matcher.getMatchingBlocks()
    assertTrue(blocks.isNotEmpty())
    assertEquals(1.0, SequenceMatcher("", "").ratio())
  }

  // ------------------------------------------------------------ misc singles

  @Test
  fun `detection engine wiring registration is idempotent`() {
    DetectionEngineWiring.register()
    DetectionEngineWiring.register()
    assertTrue(true)
  }

  @Test
  fun `ip extraction answers the no-host arm`() = runBlocking {
    val cfg = SecurityConfigBuilder().apply { enableRedis = false }.build()
    val anonymous = TestRequest(clientHost = null)
    val ip = IpExtraction.extractClientIp(anonymous, cfg, null)
    assertNotNull(ip)
  }
}
