package com.guardcore.util

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RequestState
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * Ports of the body-scan surface tests: test_structured_json_nosql.py,
 * test_json_body_depth_cap.py, test_body_form_scan.py, test_form_value_embedded_json.py,
 * test_non_utf8_body_scan.py, and the multipart entries helpers.
 */

/** MockGuardRequest analog with full body/header/query-param control. */
public class ScanRequest(
    override val method: String = "GET",
    override val clientHost: String? = "127.0.0.1",
    headers: Map<String, String> = emptyMap(),
    private val bodyBytes: ByteArray = "".encodeToByteArray(),
    override val queryParams: Map<String, String> = emptyMap(),
    override val urlPath: String = "/",
) : GuardRequest {
  override val urlScheme: String = "http"
  override val urlFull: String = "http://example.com$urlPath"

  /** Case-insensitive header map like the adapter protocol implementations. */
  override val headers: Map<String, String> =
      object : Map<String, String> {
        private val backing = headers.mapKeys { it.key.lowercase() }
        override val size: Int get() = backing.size
        override val keys: Set<String> get() = backing.keys
        override val values: Collection<String> get() = backing.values
        override val entries: Set<Map.Entry<String, String>> get() = backing.entries
        override fun isEmpty(): Boolean = backing.isEmpty()
        override fun containsKey(key: String): Boolean = backing.containsKey(key.lowercase())
        override fun containsValue(value: String): Boolean = backing.containsValue(value)
        override fun get(key: String): String? = backing[key.lowercase()]
      }
  override val state: RequestState = object : RequestState {
    private val attrs: MutableMap<String, Any?> = linkedMapOf()

    override fun getAttr(name: String): Any? = attrs[name]

    override fun setAttr(name: String, value: Any?) {
      attrs[name] = value
    }
  }
  override val scope: Map<String, Any?> = emptyMap()

  override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com$urlPath"

  override suspend fun body(): ByteArray = bodyBytes
}

/** Log capture harness (the python caplog fixture over the guard_core logger tree). */
public class LogCapture {
  public val records: MutableList<LogRecord> = mutableListOf()
  private val handler =
      object : java.util.logging.Handler() {
        override fun publish(record: LogRecord) {
          records.add(record)
        }

        override fun flush() {}

        override fun close() {}
      }

  public fun text(): String = records.joinToString("\n") { it.message ?: "" }

  public fun attach(logger: Logger, level: Level = Level.ALL) {
    logger.addHandler(handler)
    logger.level = level
  }

  public fun detach(logger: Logger) {
    logger.removeHandler(handler)
  }
}

/** The shared guard_core logger (python logging.getLogger("guard_core")). */
public val GUARD_LOGGER: Logger = Logger.getLogger("guard_core")

/** SuspPatternsManager configure + seams, mirroring the autouse python fixture. */
public fun forceDetectionConfigured(config: SecurityConfig = defaultScanConfig()) {
  com.guardcore.handlers.HandlerSeams.register()
  DetectionEngineWiring.register()
  PenetrationDetection.configureDetection(config)
}

public fun defaultScanConfig(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig {
  val builder =
      SecurityConfigBuilder().apply {
        enableRedis = false
        logSuspiciousLevel = com.guardcore.config.LogLevel.ERROR
        logRequestLevel = null
      }
  builder.apply(apply)
  return builder.build()
}

public fun scanRunTest(block: suspend () -> Unit) {
  runBlocking { block() }
}

private const val SQLI: String = "' OR 1=1--"
private const val XSS: String = "<script>alert(1)</script>"
private const val MULTIPART_CONTENT_TYPE: String = "multipart/form-data; boundary=B0"

private fun jsonBodyRequest(payload: String, config: SecurityConfig = defaultScanConfig()): ScanRequest {
  val body = payload.encodeToByteArray()
  return ScanRequest(
      method = "POST",
      bodyBytes = body,
      headers =
          mapOf(
              "content-type" to "application/json",
              "content-length" to body.size.toString(),
          ),
  )
}

private fun formBodyRequest(payload: String): ScanRequest {
  val body = "note=${PyUrllib.quote(payload, safe = "")}".encodeToByteArray()
  return ScanRequest(
      method = "POST",
      bodyBytes = body,
      headers =
          mapOf(
              "content-type" to "application/x-www-form-urlencoded",
              "content-length" to body.size.toString(),
          ),
  )
}

private fun multipartBodyRequest(payload: String): ScanRequest {
  val body =
      ("--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n" +
              "$payload\r\n--B0--\r\n")
          .encodeToByteArray()
  return ScanRequest(
      method = "POST",
      bodyBytes = body,
      headers =
          mapOf(
              "content-type" to MULTIPART_CONTENT_TYPE,
              "content-length" to body.size.toString(),
          ),
  )
}

private fun filePartBody(filename: String, content: String = "binary-file-payload"): ByteArray =
    ("--B0\r\nContent-Disposition: form-data; name=\"upload\"; " +
            "filename=\"$filename\"\r\n\r\n$content\r\n--B0--\r\n")
        .encodeToByteArray()

private fun textPartBody(name: String, value: String): ByteArray =
    ("--B0\r\nContent-Disposition: form-data; name=\"$name\"\r\n\r\n" +
            "$value\r\n--B0--\r\n")
        .encodeToByteArray()

private fun multipartRequest(body: ByteArray): ScanRequest =
    ScanRequest(
        method = "POST",
        bodyBytes = body,
        headers =
            mapOf(
                "content-type" to MULTIPART_CONTENT_TYPE,
                "content-length" to body.size.toString(),
            ),
    )

private fun nestedJsonBody(depth: Int, leaf: String): String {
  val leafJson = PyJson.dumps(leaf)
  val prefix = "{\"a\":".repeat(depth)
  val suffix = "}".repeat(depth)
  return prefix + leafJson + suffix
}

private fun nestedJsonValue(depth: Int, leaf: Any?): Any? {
  var value: Any? = leaf
  repeat(depth) { value = linkedMapOf("a" to value) }
  return value
}

/** test_structured_json_nosql.py:38. */
class JsonNosqlScanTest {
  init {
    forceDetectionConfigured()
  }

  private fun assertNosql(payload: String) {
    scanRunTest {
      val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(payload), defaultScanConfig())
      assertTrue(result.isThreat, payload)
      assertEquals(listOf("nosql"), result.threatCategories)
    }
  }

  @Test
  fun testJsonOperatorKeyDetectedAsNosql() {
    assertNosql("{\"username\": {\"\$ne\": null}}")
    assertNosql("{\"\$ne\": 1}")
    assertNosql("{\"\$gt\": \"x\"}")
    assertNosql("{\"a\": {\"\$where\": \"this.x==1\"}}")
    assertNosql("{\"a\": {\"\$regex\": \".*\"}}")
  }

  @Test
  fun testBenignJsonNotDetected() {
    for (payload in
        listOf(
            """{"${'$'}schema": "x", "${'$'}ref": "#/d/x", "${'$'}id": "u", "${'$'}defs": {}, "${'$'}anchor": "y", "${'$'}comment": "z"}""",
            """{"price": 100, "name": "x"}""",
            """{"a": {"b": {"c": {"d": 1}}}}""",
        )) {
      scanRunTest {
        val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(payload), defaultScanConfig())
        assertFalse(result.isThreat, payload)
      }
    }
  }

  @Test
  fun testOperatorQueryJsonTwinFiresNosql() {
    assertNosql("""{"price": {"${'$'}gt": 100}}""")
    assertNosql("""{"age": {"${'$'}ne": null}}""")
  }

  private fun assertQueryParamThreat(payload: String) {
    scanRunTest {
      val request = ScanRequest(queryParams = mapOf("v" to payload))
      val result = PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig())
      assertTrue(result.isThreat, payload)
    }
  }

  @Test
  fun testJsonStructureAttackDetectedOnQueryParam() {
    assertQueryParamThreat("""{"username": {"${'$'}ne": null}}""")
    assertQueryParamThreat("""{"${'$'}where": "1==1"}""")
    assertQueryParamThreat("""{"__proto__": {"isAdmin": true}}""")
  }

  @Test
  fun testJsonStructureAttackSurvivesLeadingNonJsonByte() {
    assertQueryParamThreat("""x={"username":{"${'$'}ne":null}}""")
  }

  /** test_structured_json_nosql.py:100 (direct _scan_json_value call). */
  @Test
  fun testExcludedBodyFieldSuppressesOperatorKey() {
    scanRunTest {
      val hit =
          BodyJsonScan.scanJsonValue(
              value = linkedMapOf<String, Any?>("username" to linkedMapOf<String, Any?>("\$ne" to 1)),
              keyLabel = "",
              excludedBodyFields = setOf("\$ne"),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr-1",
              logLevel = "WARNING",
          )
      assertEquals(false, hit.detected)
      assertEquals("", hit.trigger)
      assertTrue(hit.threats.isEmpty())
    }
  }
}

/** test_json_body_depth_cap.py. */
class JsonDepthCapTest {
  init {
    forceDetectionConfigured()
  }

  @Test
  fun testNestedJsonBodyUnderJsonLoadsLimitScansWithoutException() {
    for (depth in listOf(100, 325, 400)) {
      scanRunTest {
        val body = nestedJsonBody(depth, "benign")
        val result =
            PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
        assertFalse(result.isThreat, "depth=$depth")
      }
    }
  }

  @Test
  fun testNestedJsonBodyBeyondJsonLoadsLimitFallsBackToBlobScan() {
    // CPython's json.loads fails on deep nesting via RecursionError (stack dependent: the
    // reference pins 990 against its ~1000 frame limit); the JVM nests the same guard at
    // PyJson.MAX_PARSE_DEPTH (1000), so the same fallback engages above it.
    for (depth in listOf(1001, 1500)) {
      scanRunTest {
        val body = nestedJsonBody(depth, SQLI)
        val result =
            PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
        assertTrue(result.isThreat, "depth=$depth")
        assertTrue(result.triggerInfo.startsWith("Request body: "), result.triggerInfo)
      }
    }
  }

  @Test
  fun testSqliAtDepthTenMatchesDirectScalarScan() {
    scanRunTest {
      val expected =
          BodyContentScan.scanBodyField(
              SQLI,
              "a",
              null,
              "127.0.0.1",
              "direct-scan-corr",
              "WARNING",
          )
      val body = nestedJsonBody(10, SQLI)
      val result =
          PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
      assertTrue(result.isThreat)
      assertEquals(listOf("sqli"), result.threatCategories)
      assertEquals(expected.trigger, result.triggerInfo)
    }
  }

  @Test
  fun testSqliAtDepthTenDoesNotTripDepthCapWarning() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val body = nestedJsonBody(10, SQLI)
        PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
        assertFalse(capture.text().contains("detection_max_json_depth"))
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testSqliBelowDefaultCapDetectedViaSerializedCappedSubtree() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val body = nestedJsonBody(40, SQLI)
        val result =
            PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
        assertTrue(result.isThreat)
        assertEquals(listOf("sqli"), result.threatCategories)
        assertTrue(capture.text().contains("detection_max_json_depth (32) reached"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testTwoCappedSubtreesWarnOnlyOnce() {
    scanRunTest {
      val config = defaultScanConfig { detectionMaxJsonDepth = 5 }
      val body =
          PyJson.dumps(
              linkedMapOf<String, Any?>(
                  "branch1" to nestedJsonValue(10, "benign"),
                  "branch2" to nestedJsonValue(10, "benign"),
              )
          )
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), config)
        assertFalse(result.isThreat)
        assertEquals(1, Regex("detection_max_json_depth \\(5\\) reached").findAll(capture.text()).count())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testDepthCapWarningResetsBetweenRequests() {
    scanRunTest {
      val config = defaultScanConfig { detectionMaxJsonDepth = 5 }
      val body = nestedJsonBody(10, "benign")
      val request = jsonBodyRequest(body)
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        PenetrationDetection.detectPenetrationAttempt(request, config)
        PenetrationDetection.detectPenetrationAttempt(request, config)
        assertEquals(2, Regex("detection_max_json_depth \\(5\\) reached").findAll(capture.text()).count())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testMaxJsonDepthOfOneScansFlatObjectValuesAsText() {
    scanRunTest {
      val config = defaultScanConfig { detectionMaxJsonDepth = 1 }
      val body = PyJson.dumps(linkedMapOf("a" to "benign", "b" to SQLI))
      val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), config)
      assertTrue(result.isThreat)
      assertTrue(result.triggerInfo.startsWith("Request body field '': "), result.triggerInfo)
    }
  }

  @Test
  fun testOrderingAndFirstHitParityAcrossDictAndNestedList() {
    scanRunTest {
      val config =
          defaultScanConfig { excludedDetectionBodyFields = setOf("excluded_field") }
      val body =
          PyJson.dumps(
              linkedMapOf<String, Any?>(
                  "excluded_field" to SQLI,
                  "safe_key" to "benign",
                  "nested_list" to
                      listOf(
                          linkedMapOf<String, Any?>("inner_scalar" to SQLI),
                          linkedMapOf<String, Any?>("other" to "value"),
                      ),
                  "\$ne" to "operator_value",
                  "trailing_scalar" to XSS,
              )
          )
      val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), config)
      assertTrue(result.isThreat)
      assertTrue(result.triggerInfo.startsWith("Request body field 'inner_scalar': "), result.triggerInfo)
      assertFalse(result.triggerInfo.contains("\$ne"))
      assertFalse(result.triggerInfo.contains("trailing_scalar"))
    }
  }

  @Test
  fun testExcludedKeyWithoutExclusionConfiguredWinsInstead() {
    scanRunTest {
      val body =
          PyJson.dumps(
              linkedMapOf<String, Any?>(
                  "excluded_field" to SQLI,
                  "nested_list" to listOf(linkedMapOf<String, Any?>("inner_scalar" to SQLI)),
              )
          )
      val result =
          PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
      assertTrue(result.isThreat)
      assertTrue(result.triggerInfo.startsWith("Request body field 'excluded_field': "), result.triggerInfo)
    }
  }

  @Test
  fun testDefaultCapNeverTripsOnShallowJsonBody() {
    scanRunTest {
      val body = PyJson.dumps(linkedMapOf("query" to linkedMapOf("filter" to linkedMapOf("active" to true))))
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val result =
            PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), defaultScanConfig())
        assertFalse(result.isThreat)
        assertFalse(capture.text().contains("detection_max_json_depth"))
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testConfigNoneStillUsesDefaultDepthCap() {
    scanRunTest {
      val body = nestedJsonBody(40, SQLI)
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val result = PenetrationDetection.detectPenetrationAttempt(jsonBodyRequest(body), null)
        assertTrue(result.isThreat)
        assertTrue(capture.text().contains("detection_max_json_depth (32) reached"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testDetectionMaxJsonDepthBounds() {
    assertEquals(32, defaultScanConfig().detectionMaxJsonDepth)
    assertEquals(1, defaultScanConfig { detectionMaxJsonDepth = 1 }.detectionMaxJsonDepth)
    assertEquals(1000, defaultScanConfig { detectionMaxJsonDepth = 1000 }.detectionMaxJsonDepth)
    for (bad in listOf(0, 1001)) {
      val error =
          try {
            defaultScanConfig { detectionMaxJsonDepth = bad }
            null
          } catch (e: Exception) {
            e
          }
      assertTrue(error is com.guardcore.errors.ConfigValidationError, "depth $bad must be rejected")
      assertTrue(
          (error!!.message ?: "").contains("greater than or equal to 1") ||
              (error.message ?: "").contains("less than or equal to 1000"),
          error.message,
      )
    }
  }
}

/** test_form_value_embedded_json.py. */
class FormValueEmbeddedJsonTest {
  init {
    forceDetectionConfigured()
  }

  private fun nestedArrayNosqlPayload(): String =
      PyJson.dumps(linkedMapOf<String, Any?>("a" to linkedMapOf<String, Any?>("b" to linkedMapOf<String, Any?>("c" to listOf(linkedMapOf<String, Any?>("\$gt" to 100))))))

  @Test
  fun testNestedArrayNosqlOperatorDetectedOnEverySurface() {
    val payload = nestedArrayNosqlPayload()
    for ((label, request) in
        listOf(
            "json_body" to jsonBodyRequest(payload),
            "header" to ScanRequest(headers = mapOf("x-note" to payload)),
            "form_field" to formBodyRequest(payload),
            "multipart_field" to multipartBodyRequest(payload),
        )) {
      scanRunTest {
        val result = PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig())
        assertTrue(result.isThreat, label)
        assertEquals(listOf("nosql"), result.threatCategories, label)
      }
    }
  }

  @Test
  fun testFormValueJsonPasswordRedactedInDetectionLog() {
    for (surface in listOf("form_field", "multipart_field")) {
      scanRunTest {
        val secret = "SIBLING-SECRET-$surface"
        val payload = PyJson.dumps(linkedMapOf("note" to XSS, "password" to secret))
        val request =
            if (surface == "form_field") formBodyRequest(payload) else multipartBodyRequest(payload)
        val capture = LogCapture()
        capture.attach(GUARD_LOGGER, Level.WARNING)
        try {
          val result = PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig())
          assertTrue(result.isThreat)
          val lines =
              capture.records.map { it.message ?: "" }.filter { it.contains("Potential attack detected") }
          assertTrue(lines.isNotEmpty(), "no detection log line captured")
          assertTrue(lines[0].contains("[REDACTED]"), lines[0])
          assertTrue(lines[0].contains(XSS), lines[0])
          assertFalse(capture.text().contains(secret))
        } finally {
          capture.detach(GUARD_LOGGER)
        }
      }
    }
  }
}

/** test_non_utf8_body_scan.py. */
class NonUtf8BodyScanTest {
  private val config = defaultScanConfig { detectionMaxBodyInspectBytes = 65536 }

  private suspend fun detect(body: ByteArray): Pair<Boolean, String> {
    // _BodyRequest carries a content-length header (test_non_utf8_body_scan.py:15-19); without it
    // the capped reader defers to the bounded-reader capability the mock does not implement.
    val request =
        ScanRequest(
            method = "POST",
            bodyBytes = body,
            headers = mapOf("content-length" to body.size.toString()),
        )
    val result = PenetrationDetection.detectPenetrationAttempt(request, config)
    return result.isThreat to result.triggerInfo
  }

  @Test
  fun testLatin1BodyWithEmbeddedSqliIsDetected() {
    scanRunTest {
      val body = "café 1' OR '1'='1".iso8859_1Bytes()
      val (isThreat, _) = detect(body)
      assertTrue(isThreat)
    }
  }

  @Test
  fun testInvalidUtf8PrefixBeforeXssIsDetected() {
    scanRunTest {
      val (isThreat, _) = detect(byteArrayOf(0xff.toByte(), 0xfe.toByte()) + XSS.encodeToByteArray())
      assertTrue(isThreat)
    }
  }

  @Test
  fun testValidSqliWithTrailingInvalidByteIsDetected() {
    scanRunTest {
      val body = "1' OR '1'='1".encodeToByteArray() + byteArrayOf(0xff.toByte())
      val (isThreat, _) = detect(body)
      assertTrue(isThreat)
    }
  }

  @Test
  fun testBinaryBlobWithEmbeddedBase64SerializedPayloadIsDetected() {
    scanRunTest {
      val body =
          byteArrayOf(0x00, 0x01, 0x02, 0xff.toByte(), 0xfe.toByte()) +
              "rO0ABXNyABFqYXZhLnV0aWw=".encodeToByteArray() +
              byteArrayOf(0x00, 0x01)
      val (isThreat, _) = detect(body)
      assertTrue(isThreat)
    }
  }

  @Test
  fun testBodyOfOnlyInvalidBytesIsNotFalsePositive() {
    scanRunTest {
      val body = ByteArray(50) { 0xff.toByte() }
      val (isThreat, _) = detect(body)
      assertFalse(isThreat)
    }
  }

  @Test
  fun testRealPngBinaryUploadStaysClean() {
    scanRunTest {
      val hex =
          ("89504e470d0a1a0a0000000d4948445200000001000000010806000000" +
              "1f15c4890000000a49444154789c636000000200010" +
              "0ffff030000060005574bb1060000000049454e44ae426082")
      val body = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
      val (isThreat, _) = detect(body)
      assertFalse(isThreat)
    }
  }

  @Test
  fun testLatin1AccentedBenignTextStaysClean() {
    scanRunTest {
      val (isThreat, _) = detect("café résumé naïve".iso8859_1Bytes())
      assertFalse(isThreat)
    }
  }

  @Test
  fun testProtobufLikeBinaryBlobStaysClean() {
    scanRunTest {
      val body =
          byteArrayOf(
              0x08, 0x96.toByte(), 0x01,
              0x12, 0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
              'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
              0x1a, 0x03, 'f'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(),
              0x22, 0x04, 'u'.code.toByte(), 's'.code.toByte(), 'e'.code.toByte(),
              'r'.code.toByte(),
              0x28, 0x01,
              0xff.toByte(), 0xfe.toByte(), 0x00, 0x01, 0x02, 0x03,
          )
      val (isThreat, _) = detect(body)
      assertFalse(isThreat)
    }
  }

  @Test
  fun testDeterministicPseudoRandomBinaryBlobStaysClean() {
    scanRunTest {
      val md = java.security.MessageDigest.getInstance("SHA-256")
      val body = StringBuilder().let { sb ->
        for (i in 0 until 8) {
          val digest = md.digest(i.toString().encodeToByteArray())
          sb.append(String(digest, Charsets.ISO_8859_1))
        }
        sb.toString()
      }.iso8859_1Bytes()
      val (isThreat, _) = detect(body)
      assertFalse(isThreat)
    }
  }
}

/** Latin-1 (python latin-1 encode) helper. */
private fun String.iso8859_1Bytes(): ByteArray = map { it.code and 0xFF }.map { it.toByte() }.toByteArray()

/** test_body_form_scan.py: the multipart entries helpers and scan dispatch. */
class MultipartScanTest {
  init {
    forceDetectionConfigured()
  }

  @Test
  fun testFilenameWithSemicolonAndSingleQuoteStillDetected() {
    val filename = """filename="x=1;NOTE:'benign $XSS';y=2""""
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody(filename)),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  @Test
  fun testFilenameWithPctEncodedEqualsAndSemicolonStillDetected() {
    val filename = """filename%3D"x%3D1;cookie: "benign $XSS";y%3D2""""
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody(filename)),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  @Test
  fun testFilenameWithBareNewlineStillDetected() {
    val filename = "benign $XSS\nx=1\ny=2"
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody(filename)),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  @Test
  fun testFilenameWithBareCrSmuggledHeaderPayloadStillDetected() {
    val filename = "x=1\rcustom-secret-field: '$XSS'\ry=2"
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody(filename)),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  @Test
  fun testWellFormedDangerousFilenameStillDetected() {
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody("shell.php")),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  @Test
  fun testWellFormedBenignFilenameNotDetected() {
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(filePartBody("report.pdf")),
              defaultScanConfig(),
          )
      assertFalse(result.isThreat)
    }
  }

  @Test
  fun testTextFieldWithoutFilenameStillDetectedViaPayload() {
    scanRunTest {
      val result =
          PenetrationDetection.detectPenetrationAttempt(
              multipartRequest(textPartBody("note", XSS)),
              defaultScanConfig(),
          )
      assertTrue(result.isThreat)
    }
  }

  /** test_body_form_scan.py:99. */
  @Test
  fun testMultipartPartEntriesAddsRawContentDispositionWithFilename() {
    val body = filePartBody("report.pdf").decodeToString()
    val parts = BodyFormScan.multipartTextParts(body, MULTIPART_CONTENT_TYPE)
    assertTrue(parts != null)
    val values = parts.map { it.third }
    assertTrue(values.any { it == "filename=\"report.pdf\"" }, values.joinToString("|"))
    assertTrue(values.any { it.startsWith("Content-Disposition:") && it.contains("report.pdf") })
    assertTrue(values.any { it.contains("binary-file-payload") })
  }

  /** test_body_form_scan.py:113. */
  @Test
  fun testMultipartPartEntriesScansContentDispositionWithoutFilename() {
    val body = textPartBody("note", "hello").decodeToString()
    val parts = BodyFormScan.multipartTextParts(body, MULTIPART_CONTENT_TYPE)
    assertEquals(
        listOf(
            Triple("note", "note", "Content-Disposition: form-data; name=\"note\""),
            Triple("note", "note", "hello"),
        ),
        parts,
    )
  }

  /**
   * test_body_form_scan.py:147 (_multipart_part_entries with no extra headers). The python fake
   * part synthesizes get_param results without headers; the JVM part derives name/filename from
   * its header list (the email.parser always supplies Content-Disposition when get_param hits),
   * so the reachable same-path state is disposition-only: filename entry + disposition + payload.
   */
  @Test
  fun testMultipartPartEntriesSkipsRawLinesWhenPartHasNoHeaders() {
    val part =
        BodyFormScan.MultipartPart(
            headers = listOf("Content-Disposition" to "form-data; name=\"upload\"; filename=\"report.pdf\""),
            payload = "payload-text-sample",
        )
    val entries = BodyFormScan.multipartPartEntries(part)
    assertEquals(
        listOf(
            Triple("upload", "upload", "filename=\"report.pdf\""),
            Triple(
                "upload",
                "upload",
                "Content-Disposition: form-data; name=\"upload\"; filename=\"report.pdf\"",
            ),
            Triple("upload", "upload", "payload-text-sample"),
        ),
        entries,
    )
  }

  /** test_body_form_scan.py:158. */
  @Test
  fun testMultipartPartEntriesFallsBackToFileLabelWithoutName() {
    val part =
        BodyFormScan.MultipartPart(
            headers = listOf("Content-Disposition" to "form-data; filename=\"report.pdf\""),
            payload = "payload-text-sample",
        )
    val entries = BodyFormScan.multipartPartEntries(part)
    assertEquals(Triple(null, "file", "filename=\"report.pdf\""), entries[0])
  }

  /** test_body_form_scan.py:166. */
  @Test
  fun testMultipartPartEntriesIncludesEveryPartHeader() {
    val part =
        BodyFormScan.MultipartPart(
            headers =
                listOf(
                    "Content-Disposition" to
                        "form-data; name=\"upload\"; filename=\"report.pdf\"",
                    "Custom-Secret-Field" to "' OR 1=1--",
                ),
            payload = "payload-text-sample",
        )
    val entries = BodyFormScan.multipartPartEntries(part)
    assertEquals(
        listOf(
            Triple("upload", "upload", "filename=\"report.pdf\""),
            Triple(
                "upload",
                "upload",
                "Content-Disposition: form-data; name=\"upload\"; filename=\"report.pdf\"",
            ),
            Triple("upload", "upload", "Custom-Secret-Field: ' OR 1=1--"),
            Triple("upload", "upload", "payload-text-sample"),
        ),
        entries,
    )
  }

  /** Non-multipart content type falls through to the blob scan (body_form_scan.py:163). */
  @Test
  fun testMultipartBodyNonMultipartContentTypeFallsBackToBlobScan() {
    scanRunTest {
      val hit =
          BodyFormScan.scanMultipartBody(
              rawBody = "just some text",
              contentType = "text/plain",
              excludedBodyFields = emptySet(),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr",
              logLevel = null,
          )
      assertEquals(false, hit.detected)
    }
  }

  @Test
  fun testMultipartTextPartsWithoutBoundaryReturnsNull() {
    assertNull(BodyFormScan.multipartTextParts("body", "text/plain"))
  }

  @Test
  fun testMultipartTextPartsWithoutDelimiterReturnsNull() {
    assertNull(BodyFormScan.multipartTextParts("body", "multipart/form-data; boundary=B0"))
  }

  /** Excluded multipart field short-circuits (body_form_scan.py:120). */
  @Test
  fun testScanMultipartPartExcludedFieldReturnsNull() {
    scanRunTest {
      val hit =
          BodyFormScan.scanMultipartPart(
              exclusionKey = "upload",
              label = "upload",
              value = SQLI,
              excludedBodyFields = setOf("upload"),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr",
              logLevel = null,
          )
      assertNull(hit)
    }
  }

  /** The urlencoded form scan (body_form_scan.py:16). */
  @Test
  fun testScanFormBodyDetectsSqliInValue() {
    scanRunTest {
      val hit =
          BodyFormScan.scanFormBody(
              rawBody = "note=" + PyUrllib.quote(SQLI, safe = ""),
              excludedBodyFields = emptySet(),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr",
              logLevel = null,
          )
      assertTrue(hit.detected)
    }
  }

  @Test
  fun testScanFormBodyExcludedFieldIsSkipped() {
    scanRunTest {
      val hit =
          BodyFormScan.scanFormBody(
              rawBody = "note=" + PyUrllib.quote(SQLI, safe = ""),
              excludedBodyFields = setOf("note"),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr",
              logLevel = null,
          )
      assertFalse(hit.detected)
    }
  }

  @Test
  fun testScanFormBodyBlankAndValuelessFieldsTolerated() {
    scanRunTest {
      val hit =
          BodyFormScan.scanFormBody(
              rawBody = "flag&&empty=&novalue",
              excludedBodyFields = emptySet(),
              enabledCategories = null,
              clientIp = "127.0.0.1",
              correlationId = "corr",
              logLevel = null,
          )
      assertFalse(hit.detected)
    }
  }
}
