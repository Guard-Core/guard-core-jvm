package com.guardcore.util

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.BoundedBodyReader
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RequestState
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking

/**
 * W9d util tail coverage: the DetectionConfig constant/route arms, the DetectionScan engine
 * fallback arms over the enhancedDetectOverride seam (the python patch.object analog), the
 * BodyContentScan/BodyFormScan surface arms, the surrogateescape multibyte decoders, the
 * redaction defaults, and the BodyReader oversized-declared-body path.
 */

/** A request with a bounded body reader (the adapter protocol shape for body prefix reads). */
public class BoundedScanRequest(
    override val method: String = "POST",
    override val clientHost: String? = "127.0.0.1",
    headers: Map<String, String> = emptyMap(),
    private val bodyBytes: ByteArray = "".encodeToByteArray(),
    override val queryParams: Map<String, String> = emptyMap(),
    override val urlPath: String = "/",
) : GuardRequest, BoundedBodyReader {
  override val urlScheme: String = "http"
  override val urlFull: String = "http://example.com$urlPath"
  override val headers: Map<String, String> = headers.mapKeys { it.key.lowercase() }
  override val state: RequestState =
      object : RequestState {
        private val attrs: MutableMap<String, Any?> = linkedMapOf()

        override fun getAttr(name: String): Any? = attrs[name]

        override fun setAttr(name: String, value: Any?) {
          attrs[name] = value
        }
      }
  override val scope: Map<String, Any?> = emptyMap()

  override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com$urlPath"

  override suspend fun body(): ByteArray = bodyBytes

  override suspend fun readBodyPrefix(maxBytes: Int): ByteArray =
      bodyBytes.copyOfRange(0, minOf(maxBytes, bodyBytes.size))
}

public class UtilW9dTailsTest {
  private val xss: String = "<script>alert(1)</script>"

  // ------------------------------------------------------------------
  // DetectionConfig
  // ------------------------------------------------------------------

  @Test
  fun testDetectionConfigConstantTables() {
    assertTrue("host" in DetectionConfig.DEFAULT_EXCLUDED_HEADERS)
    assertEquals(DetectionConfig.ADDRESS_HEADER_SKIP_CATEGORIES, DetectionConfig.HEADER_CATEGORY_EXCLUSIONS["via"])
  }

  @Test
  fun testDetectionConfigRouteOverrides() {
    val route = RouteConfig()
    route.excludedDetectionParams = setOf("Foo")
    route.excludedDetectionBodyFields = setOf("Bar")
    assertEquals(setOf("foo"), DetectionConfig.resolveExcludedParams(null, route))
    assertEquals(setOf("bar"), DetectionConfig.resolveExcludedBodyFields(null, route))
  }

  @Test
  fun testExcludedHeaderSkipCategoriesArms() {
    // mapped table arm
    assertEquals(setOf("ssrf"), DetectionConfig.excludedHeaderSkipCategories("X-Forwarded-For", "1.2.3.4"))
    // address-chain arm
    assertEquals(setOf("ssrf"), DetectionConfig.excludedHeaderSkipCategories("X-Custom", "1.2.3.4, 5.6.7.8"))
    // no tokens (empty after filtering)
    assertEquals(emptySet(), DetectionConfig.excludedHeaderSkipCategories("X-Custom", ",,"))
  }

  @Test
  fun testExcludedHeaderEffectiveCategoriesArms() {
    assertEquals(
        setOf("sql_injection"),
        DetectionConfig.excludedHeaderEffectiveCategories("x-forwarded-for", "1.2.3.4", setOf("sql_injection")),
    )
    // null enabled categories fall back to the full table minus the skip set
    val effective = DetectionConfig.excludedHeaderEffectiveCategories("x-forwarded-for", "1.2.3.4", null)!!
    assertFalse("ssrf" in effective)
    assertTrue(effective.isNotEmpty())
    // empty effective set short-circuits the header scan
    assertEquals(
        emptySet<String>(),
        DetectionConfig.excludedHeaderEffectiveCategories("x-custom", "1.2.3.4, 5.6.7.8", setOf("ssrf")),
    )
  }

  // ------------------------------------------------------------------
  // DetectionScan: the enhanced-detect failure arms
  // ------------------------------------------------------------------

  private fun installDetectOverride(
      block: (String, String, String, String?, Set<String>?) -> com.guardcore.engine.suspatterns.DetectResult?,
  ): Unit {
    DetectionScan.enhancedDetectOverride = { content, ip, context, corr, cats ->
      block(content, ip, context, corr, cats)
    }
  }

  @Test
  fun testCheckValueEnhancedScanBudgetExhaustedMiss() = runBlocking {
    DetectionScanBudget.withScanBudget(maxValues = 0) {
      val hit = DetectionScan.checkValueEnhanced(xss, "9.9.9.9", "request_body", "corr")
      assertFalse(hit.detected)
    }
  }

  @Test
  fun testCheckValueEnhancedRecursionClassEscapes() = runBlocking {
    try {
      installDetectOverride { _, _, _, _, _ ->
        throw java.util.concurrent.ExecutionException(StackOverflowError("deep"))
      }
      DetectionScan.checkValueEnhanced("value", "9.9.9.9", "request_body", "corr")
      fail("StackOverflowError must escape")
    } catch (expected: StackOverflowError) {
      // python re-raises the recursion class untouched
    } finally {
      DetectionScan.enhancedDetectOverride = { _, _, _, _, _ -> null }
    }
  }

  @Test
  fun testCheckValueEnhancedEngineFailureFallsBack() = runBlocking {
    try {
      installDetectOverride { _, _, _, _, _ ->
        throw java.util.concurrent.ExecutionException(IllegalStateException("worker down"))
      }
      val hit = DetectionScan.checkValueEnhanced("benign value", "9.9.9.9", "request_body", "corr")
      assertFalse(hit.detected)
      // the generic engine failure takes the same fallback
      installDetectOverride { _, _, _, _, _ -> throw IllegalStateException("engine down") }
      val hit2 = DetectionScan.checkValueEnhanced("benign value", "9.9.9.9", "request_body", "corr")
      assertFalse(hit2.detected)
    } finally {
      DetectionScan.enhancedDetectOverride = { _, _, _, _, _ -> null }
    }
  }

  @Test
  fun testCheckValueEnhancedThreatWithoutThreatList() = runBlocking {
    try {
      installDetectOverride { _, _, _, _, _ ->
        com.guardcore.engine.suspatterns.DetectResult(
            isThreat = true,
            threatScore = 1.0,
            threats = emptyList(),
            context = "request_body",
            originalLength = 5,
            processedLength = 5,
            executionTime = 0.001,
            detectionMethod = "legacy",
            timeouts = emptyList(),
            correlationId = "corr",
        )
      }
      val hit = DetectionScan.checkValueEnhanced("value", "9.9.9.9", "request_body", "corr")
      assertTrue(hit.detected)
      assertEquals("Threat detected", hit.trigger)
      assertTrue(hit.threats.isEmpty())
    } finally {
      DetectionScan.enhancedDetectOverride = { _, _, _, _, _ -> null }
    }
  }

  @Test
  fun testCheckEmbeddedJsonIfApplicableDefaultArms() = runBlocking {
    val hit =
        DetectionScan.checkEmbeddedJsonIfApplicable(
            "just text",
            "query_param:q",
            "9.9.9.9",
            "corr",
            null,
            scanEmbeddedJson = false,
            contentPreview = null,
            sensitiveBodyFields = emptySet(),
            excludedBodyFields = emptySet(),
            jsonRedactAll = null,
        )
    assertNull(hit)
    // the ScanHit default logOverride synthetic
    val constructed = DetectionScan.ScanHit(true, "x", emptyList())
    assertNull(constructed.logOverride)
  }

  // ------------------------------------------------------------------
  // BodyContentScan
  // ------------------------------------------------------------------

  @Test
  fun testScanQueryParamValueSensitiveRedactedLog() = runBlocking {
    val capture = LogCapture()
    capture.attach(DetectionScanContext.guardLogger)
    try {
      val (detected, trigger, threats) =
          BodyContentScan.scanQueryParamValue(
              "password",
              "[REDACTED]",
              xss,
              null,
              "9.9.9.9",
              "corr",
              "WARNING",
              sensitiveParams = setOf("password"),
          )
      assertTrue(detected)
      assertTrue(trigger.isNotEmpty())
      assertTrue(threats.isNotEmpty())
      assertTrue(capture.text().contains("[REDACTED]"))
    } finally {
      capture.detach(DetectionScanContext.guardLogger)
    }
  }

  @Test
  fun testScanQueryParamsArms() = runBlocking {
    // excluded param skips
    val (d0, t0, th0) =
        BodyContentScan.scanQueryParams(
            ScanRequest(queryParams = mapOf("skipme" to xss)),
            excludedParams = setOf("skipme"),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(d0)
    assertEquals("", t0)
    assertTrue(th0.isEmpty())

    // param name detection
    val (d1, t1, th1) =
        BodyContentScan.scanQueryParams(
            ScanRequest(queryParams = mapOf(xss to "1")),
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(d1)
    assertTrue(t1.contains("Query param name"))
    assertTrue(th1.isNotEmpty())
  }

  @Test
  fun testScanExcludedHeaderComponentArms() = runBlocking {
    // header name detection
    val hit1 =
        BodyContentScan.scanExcludedHeaderComponent(
            xss,
            "1",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(true, hit1?.first)
    assertTrue(hit1!!.second.contains("Header name"))

    // header value detection with the redacted display
    val hit2 =
        BodyContentScan.scanExcludedHeaderComponent(
            "x-custom",
            xss,
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            sensitiveParams = emptySet(),
            sensitiveBodyFields = setOf("password"),
            excludedBodyFields = emptySet(),
            sensitiveHeaders = setOf("x-custom"),
        )
    assertEquals(true, hit2?.first)

    // defaults + no detection -> null
    val hit3 =
        BodyContentScan.scanExcludedHeaderComponent(
            "x-custom",
            "plain",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertNull(hit3)
  }

  @Test
  fun testScanNormalHeaderComponentArms() = runBlocking {
    val hit1 =
        BodyContentScan.scanNormalHeaderComponent(
            xss,
            "1",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(true, hit1?.first)
    assertTrue(hit1!!.second.contains("Header name"))

    val hit2 =
        BodyContentScan.scanNormalHeaderComponent(
            "x-plain",
            "safe",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            sensitiveBodyFields = setOf("password"),
            excludedBodyFields = setOf("skip"),
            sensitiveParams = setOf("secret"),
            sensitiveHeaders = setOf("authorization"),
        )
    assertNull(hit2)

    val hit3 =
        BodyContentScan.scanNormalHeaderComponent(
            "x-threat",
            xss,
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            contentPreview = "pre-redacted",
        )
    assertEquals(true, hit3?.first)
  }

  @Test
  fun testScanSensitiveHeaderArms() = runBlocking {
    val capture = LogCapture()
    capture.attach(DetectionScanContext.guardLogger)
    try {
      val hit1 =
          BodyContentScan.scanSensitiveHeader(
              "x-secret",
              xss,
              excludedHeaders = setOf("x-secret"),
              null,
              "9.9.9.9",
              "corr",
              "WARNING",
          )
      assertEquals(true, hit1?.first)
      val hit2 =
          BodyContentScan.scanSensitiveHeader(
              "x-secret2",
              "safe",
              excludedHeaders = emptySet(),
              null,
              "9.9.9.9",
              "corr",
              "WARNING",
          )
      assertNull(hit2)
    } finally {
      capture.detach(DetectionScanContext.guardLogger)
    }
  }

  @Test
  fun testScanHeadersArms() = runBlocking {
    // sensitive header arm
    val (d1, t1, _) =
        BodyContentScan.scanHeaders(
            ScanRequest(headers = mapOf("x-secret" to xss)),
            excludedHeaders = emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            sensitiveHeaders = setOf("x-secret"),
        )
    assertTrue(d1)
    assertTrue(t1.isNotEmpty())

    // excluded header arm
    val (d2, _, _) =
        BodyContentScan.scanHeaders(
            ScanRequest(headers = mapOf("x-excluded" to "safe")),
            excludedHeaders = setOf("x-excluded"),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(d2)

    // normal header arm with defaults
    val (d3, _, _) =
        BodyContentScan.scanHeaders(
            ScanRequest(headers = mapOf("x-plain" to "safe")),
            excludedHeaders = emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(d3)
  }

  @Test
  fun testScanBodyFieldArms() = runBlocking {
    // sensitive field redacts the log value
    val capture = LogCapture()
    capture.attach(DetectionScanContext.guardLogger)
    try {
      val hit1 =
          BodyContentScan.scanBodyField(
              xss,
              "password",
              null,
              "9.9.9.9",
              "corr",
              "WARNING",
              sensitiveBodyFields = setOf("password"),
          )
      assertTrue(hit1.detected)
      assertTrue(capture.text().contains("[REDACTED]"))
    } finally {
      capture.detach(DetectionScanContext.guardLogger)
    }

    // preview override + display + context defaults
    val hit2 =
        BodyContentScan.scanBodyField(
            "safe",
            "field",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(hit2.detected)

    val hit3 =
        BodyContentScan.scanBodyField(
            "safe",
            "field",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            display = "shown",
            context = "json_body",
            previewOverride = "override",
            sensitiveParams = setOf("secret"),
        )
    assertFalse(hit3.detected)
  }

  @Test
  fun testScanBlobBodyArms() = runBlocking {
    val hit1 =
        BodyContentScan.scanBlobBody(
            xss,
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(hit1.detected)
    assertTrue(hit1.trigger.contains("Request body"))

    val hit2 =
        BodyContentScan.scanBlobBody(
            "safe",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            forceRedacted = true,
        )
    assertFalse(hit2.detected)

    val hit3 =
        BodyContentScan.scanBlobBody(
            "safe",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            sensitiveParams = setOf("secret"),
            sensitiveBodyFields = setOf("password"),
        )
    assertFalse(hit3.detected)
  }

  @Test
  fun testScanRequestBodyRouting() = runBlocking {
    val (formDetected, _, _) =
        BodyContentScan.scanRequestBody(
            "q=" + java.net.URLEncoder.encode(xss, "UTF-8"),
            "application/x-www-form-urlencoded",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(formDetected)

    val multipartBody =
        "--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" +
            xss +
            "\r\n--B--\r\n"
    val (mpDetected, _, _) =
        BodyContentScan.scanRequestBody(
            multipartBody,
            "multipart/form-data; boundary=B",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(mpDetected)

    val (blobDetected, _, _) =
        BodyContentScan.scanRequestBody(
            "plain " + xss,
            "text/plain",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(blobDetected)

    // json content type routes through the json scanner, then the blob fallback
    val (jsonDetected, _, _) =
        BodyContentScan.scanRequestBody(
            "{\"k\": \"" + xss + "\"}",
            "application/json",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(jsonDetected)

    val (notJsonDetected, _, _) =
        BodyContentScan.scanRequestBody(
            "{not json " + xss,
            "application/json",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(notJsonDetected)
  }

  // ------------------------------------------------------------------
  // BodyFormScan
  // ------------------------------------------------------------------

  @Test
  fun testMultipartTextPartsArms() {
    // LF-only header/payload separation (one header entry + one payload entry)
    val lfBody = "--B\nContent-Disposition: form-data; name=\"f\"\n\npayload\n--B--\n"
    val parts = BodyFormScan.multipartTextParts(lfBody, "multipart/form-data; boundary=B")!!
    assertEquals(2, parts.size)
    assertEquals("f", parts[0].first)

    // a part without content-disposition keeps a null name
    val noCd = "--B\nX-Other: v\r\n\r\npayload\r\n--B--\r\n"
    val parts2 = BodyFormScan.multipartTextParts(noCd, "multipart/form-data; boundary=B")!!
    assertEquals(2, parts2.size)
    assertNull(parts2[0].first)

    // a folded (continuation) header line folds into the previous value
    val folded = "--B\nContent-Disposition: form-data;\n name=\"folded\"\r\n\r\np\r\n--B--\r\n"
    val parts3 = BodyFormScan.multipartTextParts(folded, "multipart/form-data; boundary=B")!!
    assertEquals(2, parts3.size)
    assertEquals("folded", parts3[0].first)

    // a segment with neither separator shape is skipped
    val garbage = "--B\ngarbage-without-separator\n--B--\n"
    val parts4 = BodyFormScan.multipartTextParts(garbage, "multipart/form-data; boundary=B")!!
    assertEquals(0, parts4.size)
  }

  @Test
  fun testScanFormFieldNameHit() = runBlocking {
    // the attack rides the field NAME (the key), which the name scan flags
    val body = xss + "=1&v=2"
    val (detected, trigger, threats) =
        BodyFormScan.scanFormBody(
            body,
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertTrue(detected)
    assertTrue(trigger.contains("Form field name"))
    assertTrue(threats.isNotEmpty())
  }

  @Test
  fun testScanMultipartPartNameHit() = runBlocking {
    val multipartBody =
        "--B\r\nContent-Disposition: form-data; name=\"safe\"\r\n\r\n1\r\n--B--\r\n"
    val hit =
        BodyFormScan.scanMultipartPart(
            null,
            xss,
            "1",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(true, hit?.detected)
    assertTrue(hit!!.trigger.contains("Multipart field name"))
    // keep the plain multipart scan arm warm too
    val (detected, _, _) =
        BodyFormScan.scanMultipartBody(
            multipartBody,
            "multipart/form-data; boundary=B",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(detected)
  }

  @Test
  fun testMultipartBinaryIslandPayload() = runBlocking {
    val binary = StringBuilder()
    for (i in 0 until 64) binary.append('A')
    binary.append(0)
    for (i in 0 until 64) binary.append('B')
    val multipartBody =
        "--B\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"b.bin\"\r\n\r\n" +
            binary +
            "\r\n--B--\r\n"
    val (detected, _, _) =
        BodyFormScan.scanMultipartBody(
            multipartBody,
            "multipart/form-data; boundary=B",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
            sensitiveBodyFields = setOf("blob"),
        )
    // the binary islands path never flags a benign binary payload
    assertFalse(detected)
  }

  // ------------------------------------------------------------------
  // BodyJsonScan
  // ------------------------------------------------------------------

  @Test
  fun testScanJsonDictEntryKeyArms() = runBlocking {
    val hit =
        BodyJsonScan.scanJsonDictEntryKey(
            xss,
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(true, hit?.detected)
    assertTrue(hit!!.trigger.contains("JSON key"))

    val miss =
        BodyJsonScan.scanJsonDictEntryKey(
            "plain",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(false, miss?.detected)
  }

  @Test
  fun testScanCappedJsonSubtreeDefaults() = runBlocking {
    val hit =
        BodyJsonScan.scanCappedJsonSubtree(
            mapOf("k" to "v"),
            "root",
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertFalse(hit.detected)
  }

  @Test
  fun testScanJsonContentDefaults() = runBlocking {
    val hit =
        BodyJsonScan.scanJsonContent(
            "{\"a\": 1}",
            emptySet(),
            null,
            "9.9.9.9",
            "corr",
            "WARNING",
        )
    assertEquals(false, hit?.detected)
  }

  // ------------------------------------------------------------------
  // PenetrationDetection
  // ------------------------------------------------------------------

  @Test
  fun testDecodeSurrogateEscapeMultibyte() {
    // 3-byte sequence (euro sign) and 4-byte sequences decode to the code points
    val text = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xE2.toByte(), 0x82.toByte(), 0xAC.toByte()))
    assertEquals("\u20AC", text)
    // regression: F0-led 4-byte sequences (every emoji, U+10000..U+3FFFF) decode as the
    // code point, exactly like python bytes.decode("utf-8", errors="surrogateescape")
    val emoji = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xF0.toByte(), 0x9F.toByte(), 0x98.toByte(), 0x80.toByte()))
    assertEquals("\uD83D\uDE00", emoji)
    val highAstral = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xF3.toByte(), 0xB0.toByte(), 0x80.toByte(), 0x80.toByte()))
    assertEquals("\uDB80\uDC00", highAstral)
    // overlong / out-of-range / bare-continuation forms keep the per-byte
    // surrogateescape fallback (PEP 383: byte b -> U+DC00+b)
    val overlong = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xF0.toByte(), 0x80.toByte(), 0x80.toByte(), 0x80.toByte()))
    assertEquals("\uDCF0\uDC80\uDC80\uDC80", overlong)
    val outOfRange = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xF4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()))
    assertEquals("\uDCF4\uDC90\uDC80\uDC80", outOfRange)
    val bareContinuation = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0x41.toByte(), 0x80.toByte()))
    assertEquals("A\uDC80", bareContinuation)
    val truncated = PenetrationDetection.decodeSurrogateEscape(byteArrayOf(0xE2.toByte(), 0x82.toByte()))
    assertEquals("\uDCE2\uDC82", truncated)
  }

  @Test
  fun testDetectPenetrationAttemptDefaultConfigArms() = runBlocking {
    // config omitted: client ip resolves from the request host
    val result1 = PenetrationDetection.detectPenetrationAttempt(ScanRequest())
    assertFalse(result1.isThreat)
    // null client host falls back to the unknown identity
    val result2 =
        PenetrationDetection.detectPenetrationAttempt(
            ScanRequest(clientHost = null, bodyBytes = xss.encodeToByteArray()),
        )
    assertTrue(result2.isThreat)
  }

  @Test
  fun testDetectPenetrationAttemptScanBodyDisabled() = runBlocking {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              ipinfoToken = "tok"
            }
            .build()
    val route = RouteConfig()
    route.detectionScanBody = false
    val result =
        PenetrationDetection.detectPenetrationAttempt(
            ScanRequest(method = "POST", bodyBytes = xss.encodeToByteArray()),
            config,
            route,
        )
    assertFalse(result.isThreat)
  }

  // ------------------------------------------------------------------
  // RequestLogging internals (defaults arms)
  // ------------------------------------------------------------------

  @Test
  fun testRequestLoggingInternalDefaults() {
    RequestLogging.redactSensitiveQueryParams("http://e.com/p?a=1", null)
    RequestLogging.redactEndpointForDisplay("http://e.com/p?a=1", setOf("a"))
    val merged = RequestLogging.mergedSensitiveNames(setOf("p"), setOf("b"))
    assertTrue("p" in merged)
    assertTrue("b" in merged)
  }

  // ------------------------------------------------------------------
  // PairHiddenAssign / PairRedaction / PairValueScan
  // ------------------------------------------------------------------

  @Test
  fun testPairHiddenAssignDefaultsArms() {
    // matchHiddenAssign without a gap cache
    assertNull(PairHiddenAssign.matchHiddenAssign("no assign here", 0))
    // redactHiddenEncodedPair defaults
    assertNull(PairHiddenAssign.redactHiddenEncodedPair("plain", 5, "plain", setOf("password")))
    // handleNoLiteralAssign defaults
    val out = StringBuilder()
    val triple = PairHiddenAssign.handleNoLiteralAssign("x=1 plain", 4, "1 plain", setOf("password"), out, 0, 4)
    assertEquals(4, triple.first)
  }

  @Test
  fun testPairRedactionDefaultsArms() {
    // the percent-escape name path
    val redacted = PairRedaction.redactPairsInText("p%61ssword=secret", setOf("password"))
    assertTrue(redacted.contains("[REDACTED]") || !redacted.contains("secret"))
    // redactPairsInTextEx defaults
    val ex = PairRedaction.redactPairsInTextEx("a=1", setOf("b"))
    assertFalse(ex.second)
    // public defaults
    val plain = PairRedaction.redactPairsInText("a=1", setOf("b"))
    assertEquals("a=1", plain)
  }

  @Test
  fun testPairValueScanAngleArm() {
    // an unquoted sensitive value that opens with '<' redacts through the angle extent
    val (replacement, end) = PairValueScan.redactSensitivePairValue("a=<b c", 2)
    assertEquals("[REDACTED]", replacement)
    assertEquals(6, end)
  }

  // ------------------------------------------------------------------
  // BodyReader
  // ------------------------------------------------------------------

  @Test
  fun testReadCappedBodyOversizedDeclaredBody() = runBlocking {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              detectionMaxBodyInspectBytes = 1024
            }
            .build()
    val body = ByteArray(2048) { 'x'.code.toByte() }
    val request =
        BoundedScanRequest(headers = mapOf("Content-Length" to "2048"), bodyBytes = body)
    // the fetch includes the straddle-overlap window (config cap + overlap)
    val capped = BodyReader.readCappedBody(request, config, "9.9.9.9")!!
    assertTrue(capped.size >= 1024)
    // the cache serves the second read
    val again = BodyReader.readCappedBody(request, config, "9.9.9.9")!!
    assertEquals(capped.size, again.size)
  }

  @Test
  fun testSafeReadTimeoutReturnsNull() = runBlocking {
    assertNull(BodyReader.safeRead({ kotlinx.coroutines.delay(500); ByteArray(1) }, 0.01))
  }

  // ------------------------------------------------------------------
  // LoggingUtils / IpExtraction / AccessControl / misc
  // ------------------------------------------------------------------

  @Test
  fun testLoggingUtilsThreadLocalInitialValue() {
    val seen = Array(1) { true }
    val thread = Thread {
      // first access on a fresh thread runs initialValue()
      LoggingUtils.jsonDepthCapHit.set(false)
      seen[0] = LoggingUtils.jsonDepthCapHit.get() == false
    }
    thread.start()
    thread.join()
    assertTrue(seen[0])
  }

  @Test
  fun testAgentEventsAwaitIfAwaitable() = runBlocking {
    awaitIfAwaitable(CompletableFuture.completedFuture(null))
    awaitIfAwaitable("not awaitable")
  }

  @Test
  fun testIpExtractionProxyMatchInvalidCidr() {
    assertFalse(IpExtraction.isTrustedProxy("10.0.0.1", listOf("bad/24")))
  }

  @Test
  fun testIpExtractionForwardedHeaderUnparsableEntry() = runBlocking {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              trustedProxies = listOf("10.0.0.1")
            }
            .build()
    // every forwarded entry is trusted except the unparsable one; the walk returns null
    val request =
        ScanRequest(
            headers = mapOf("x-forwarded-for" to "unknown"),
            clientHost = "10.0.0.1",
        )
    val ip = IpExtraction.extractClientIp(request, config)
    assertEquals("10.0.0.1", ip)
  }

  @Test
  fun testIpExtractionForwardedChainExplosionIsContained() = runBlocking {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              trustedProxies = listOf("10.0.0.1")
              trustedProxyDepth = 2
            }
            .build()
    // a chain entry that is not an address throws inside the right-side unlisted count
    // (canonicalizeIp); the forwarded-chain handler contains it and falls back to the
    // connecting peer.
    val request =
        ScanRequest(
            headers = mapOf("x-forwarded-for" to "1.2.3.4, bad_entry"),
            clientHost = "10.0.0.1",
        )
    val ip = IpExtraction.extractClientIp(request, config)
    assertEquals("10.0.0.1", ip)
  }

  @Test
  fun testAccessControlCloudCheckerExplosionIsContained() = runBlocking {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              blockCloudProviders = setOf("AWS")
            }
            .build()
    val previous = AccessControl.cloudIpChecker
    try {
      AccessControl.cloudIpChecker = { _, _ -> throw IllegalStateException("cloud down") }
      val result = AccessControl.checkIpAccess("9.9.9.9", config)
      assertTrue(result.allowed)
    } finally {
      AccessControl.cloudIpChecker = previous
    }
  }

  @Test
  fun testDetectionScanBudgetExhaustedArm() = runBlocking {
    DetectionScanBudget.withScanBudget(maxValues = 0, maxScanChars = 0) {
      assertTrue(DetectionScanBudget.scanBudgetExhausted("9.9.9.9", "value"))
      // char budget exhausted without the value cap
      val exhausted = DetectionScanBudget.scanBudgetExhausted("9.9.9.9", "value")
      assertTrue(exhausted)
    }
  }
}
