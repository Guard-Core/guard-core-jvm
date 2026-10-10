package com.guardcore.engine.detection

import com.guardcore.engine.suspatterns.SusPatternsWeights
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Behavioral core of test_monitor.py, test_base64_view.py, and the preprocessor tests. */
class SusPatternsUnitTest {
  // ---- monitor (test_monitor.py core) ----

  @Test
  fun recordMetricTracksStats() {
    val monitor = PerformanceMonitor()
    repeat(5) { monitor.recordMetric("p", 0.1, 100, matched = true) }
    val report = monitor.getPatternReport("p")!!
    assertEquals(5, report["total_executions"])
    assertEquals(5, report["total_matches"])
    assertEquals(1.0, report["match_rate"])
  }

  @Test
  fun timeoutAnomalyDetected() {
    val monitor = PerformanceMonitor()
    var anomaly: Map<String, Any>? = null
    monitor.registerAnomalyCallback { anomaly = it }
    monitor.recordMetric("slowpat", 5.0, 1000, matched = false, timeout = true)
    assertEquals("timeout", anomaly?.get("type"))
  }

  @Test
  fun slowExecutionAnomalyDetected() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.1)
    var anomaly: Map<String, Any>? = null
    monitor.registerAnomalyCallback { anomaly = it }
    monitor.recordMetric("pat", 0.5, 100, matched = false)
    assertEquals("slow_execution", anomaly?.get("type"))
  }

  @Test
  fun patternTruncationAt100Chars() {
    val monitor = PerformanceMonitor()
    val long = "x".repeat(150)
    // record_metric truncates the key to 100 + "...[truncated]"; the report then caps the
    // display pattern at 50 + "..." (python ground truth: 53 chars).
    monitor.recordMetric(long, 0.001, 10, matched = false)
    val report = monitor.getPatternReport(long + "...[truncated]")!!
    assertEquals(53, (report["pattern"] as String).length)
  }

  @Test
  fun summaryStatsEmpty() {
    val monitor = PerformanceMonitor()
    val summary = monitor.getSummaryStats()
    assertEquals(0, summary["total_executions"])
    assertEquals(0.0, summary["avg_execution_time"])
  }

  @Test
  fun clearStatsRemovesEverything() {
    val monitor = PerformanceMonitor()
    monitor.recordMetric("p", 0.1, 10, matched = false)
    monitor.clearStats()
    assertEquals(null, monitor.getPatternReport("p"))
  }

  // ---- base64 view (test_base64_view.py core) ----

  @Test
  fun shortBase64ViewSkipsSubMinimumTokens() {
    val pre = ContentPreprocessor()
    // python ground truth: '=' is not in the token class so "e30" is only 3 chars, below
    // the {4,} run minimum, and "prefix" does not decode: the view is empty.
    assertEquals("", pre.preprocessShortBase64AdditiveView("prefix e30= suffix"))
    // python ground truth: the aae30=aa variant is also empty ('=' splits the run and the
    // 5-char remainder is invalid base64).
    assertEquals("", pre.preprocessShortBase64AdditiveView("aae30=aa"))
  }

  @Test
  fun shortBase64ViewSkipsLongRuns() {
    val pre = ContentPreprocessor()
    val long = "a".repeat(20)
    assertEquals("", pre.preprocessShortBase64AdditiveView(long))
  }

  @Test
  fun shortBase64ViewEmptyContent() {
    val pre = ContentPreprocessor()
    assertEquals("", pre.preprocessShortBase64AdditiveView(""))
  }

  // ---- preprocessor (test_preprocessor.py core) ----

  @Test
  fun normalizeUnicodeLookalikes() {
    val pre = ContentPreprocessor()
    assertEquals("a/b", pre.normalizeUnicode("a\u2044b"))
    assertEquals("i", pre.normalizeUnicode("\u0131"))
    assertEquals("ab", pre.normalizeUnicode("a\u200bb"))
  }

  @Test
  fun removeNullBytesAndControlChars() {
    val pre = ContentPreprocessor()
    val out = pre.removeNullBytes("a\u0000b\u0001c\td")
    assertEquals("abc\td", out)
  }

  @Test
  fun stripSqlComments() {
    val pre = ContentPreprocessor()
    // python ground truth: the block body keeps its surrounding spaces; the line marker
    // becomes one space in place.
    assertEquals(" comment SELECT x", pre.stripSqlComments("/*comment*/SELECT x"))
    assertEquals("a   comment", pre.stripSqlComments("a -- comment"))
  }

  @Test
  fun decodePercentEncoding() {
    val pre = ContentPreprocessor()
    val processed = pre.preprocess("hello%20world%3Cscript%3E")
    assertTrue(processed.contains("hello world"))
    assertTrue(processed.contains("<script>"))
  }

  @Test
  fun decodeHexEscapes() {
    assertEquals("<", EncodingDecoders.decodeHexEscapes("\\x3c"))
    assertEquals("a\\xzz", EncodingDecoders.decodeHexEscapes("a\\xzz"))
  }

  @Test
  fun decodePercentUEscapes() {
    assertEquals("<", EncodingDecoders.decodePercentUEscapes("%u003c"))
  }

  @Test
  fun truncateSafelyCapsAtLimit() {
    val pre = ContentPreprocessor(maxContentLength = 10000, maxFullScanBytes = 100)
    val out = pre.truncateSafely("a".repeat(500))
    // cap_with_tail: head (100-96) + tail 96... the exact split: cap=100, tail=min(4096,100)=96
    assertTrue(out.length < 500)
    assertTrue(out.startsWith("a"))
  }

  @Test
  fun looksLikeBinaryDetection() {
    assertTrue(looksLikeBinaryContent("\u0000\u0001\u0002\u0003text"))
    assertFalse(looksLikeBinaryContent("plain text only"))
    assertFalse(looksLikeBinaryContent(""))
  }

  // ---- weights ----

  @Test
  fun resolvePatternWeightOverrides() {
    // The select-from row carries a 0.5 override; unknown rows fall back to the category.
    val selectFrom = SusPatternsWeights.PATTERN_WEIGHT_OVERRIDES.entries.first().key
    assertEquals(0.5, SusPatternsWeights.resolvePatternWeight(selectFrom, "sqli"))
    assertEquals(1.0, SusPatternsWeights.resolvePatternWeight("unknown_pattern", "sqli"))
  }
}
