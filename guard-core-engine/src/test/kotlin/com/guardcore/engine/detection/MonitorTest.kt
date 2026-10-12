package com.guardcore.engine.detection

import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_sus_patterns/test_monitor.py: the performance monitor, its anomaly detectors,
 * event builders, reporting helpers, and callback error path.
 */
class MonitorTest {
  private fun metric(
      time: Double = 0.01,
      timeout: Boolean = false,
      matched: Boolean = true,
      pattern: String = "p",
      contentLength: Int = 10,
  ): PerformanceMetric =
      PerformanceMetric(
          pattern = pattern,
          executionTime = time,
          contentLength = contentLength,
          timestamp = Date(),
          matched = matched,
          timeout = timeout,
      )

  @Test
  fun timeoutAnomalyDetection() {
    val anomaly = detectTimeoutAnomaly(metric(timeout = true))
    assertNotNull(anomaly)
    assertEquals("timeout", anomaly["type"])
    assertNull(detectTimeoutAnomaly(metric(timeout = false)))
  }

  @Test
  fun slowExecutionAnomalyDetection() {
    val anomaly = detectSlowExecutionAnomaly(metric(time = 2.0), 1.0)
    assertNotNull(anomaly)
    assertEquals("slow_execution", anomaly["type"])
    assertEquals(2.0, anomaly["execution_time"])
    assertNull(detectSlowExecutionAnomaly(metric(time = 0.5), 1.0))
    // A timeout metric is never also a slow execution.
    assertNull(detectSlowExecutionAnomaly(metric(time = 2.0, timeout = true), 1.0))
  }

  @Test
  fun statisticalAnomalyDetectionArms() {
    // No stats, too few samples.
    assertNull(detectStatisticalAnomaly(metric(), null, 5, 3.0))
    val stats = PatternStats("p")
    assertNull(detectStatisticalAnomaly(metric(), stats, 5, 3.0))
    stats.recentTimes.addLast(1.0)
    assertNull(detectStatisticalAnomaly(metric(), stats, 1, 3.0))
    stats.recentTimes.addLast(1.0)
    stats.recentTimes.addLast(1.0)
    stats.recentTimes.addLast(1.0)
    // Metric at the average: nothing.
    assertNull(detectStatisticalAnomaly(metric(time = 1.0), stats, 1, 3.0))
    // A negative threshold forces the z-score path even at the average.
    assertNull(detectStatisticalAnomaly(metric(time = 1.0), stats, 1, -1.0))
    // Zero variance: nothing.
    assertNull(detectStatisticalAnomaly(metric(time = 9.0), stats, 1, 3.0))
    // Real variance with an outlier z-score.
    stats.recentTimes.removeLast()
    stats.recentTimes.addLast(3.0)
    val anomaly = detectStatisticalAnomaly(metric(time = 10.0), stats, 1, 1.0)
    assertNotNull(anomaly)
    assertEquals("statistical_anomaly", anomaly["type"])
    assertEquals("p", anomaly["pattern"])
    // Under the threshold: nothing.
    assertNull(detectStatisticalAnomaly(metric(time = 2.0), stats, 1, 99.0))
  }

  @Test
  fun sanitizeAnomalyDataRedactsLongPatterns() {
    val short = sanitizeAnomalyData(mapOf("pattern" to "abc", "type" to "timeout"))
    assertEquals("abc", short["pattern"])
    assertNotNull(short["pattern_hash"])
    val long = sanitizeAnomalyData(mapOf("pattern" to "x".repeat(80)))
    assertEquals(53, (long["pattern"] as String).length)
    assertTrue((long["pattern"] as String).endsWith("..."))
    // No pattern key: unchanged apart from the copy.
    val bare = sanitizeAnomalyData(mapOf("type" to "timeout"))
    assertEquals("timeout", bare["type"])
    assertFalse(bare.containsKey("pattern_hash"))
  }

  @Test
  fun anomalyEventTypeMapsEachKind() {
    assertEquals("pattern_anomaly_timeout", anomalyEventType("timeout"))
    assertEquals("pattern_anomaly_slow_execution", anomalyEventType("slow_execution"))
    assertEquals("pattern_anomaly_statistical_anomaly", anomalyEventType("other"))
  }

  @Test
  fun buildAnomalyEventDataShapesTheEnvelope() {
    val event = buildAnomalyEventData(mapOf("type" to "timeout", "pattern" to "secret"), "corr-1")
    assertEquals("pattern_anomaly_timeout", event["event_type"])
    assertEquals("system", event["ip_address"])
    assertEquals("anomaly_detected", event["action_taken"])
    assertEquals("Pattern performance anomaly: timeout", event["reason"])
    val metadata = event["metadata"] as Map<*, *>
    assertEquals("PerformanceMonitor", metadata["component"])
    assertEquals("corr-1", metadata["correlation_id"])
    assertEquals("secret", metadata["pattern"])
    // The redaction seam applies to the pattern.
    val redacted =
        buildAnomalyEventData(
            mapOf("type" to "timeout", "pattern" to "secret"),
            null,
        ) {
          "<redacted>"
        }
    val redactedMetadata = redacted["metadata"] as Map<*, *>
    assertEquals("<redacted>", redactedMetadata["pattern"])
    // An anomaly without a pattern key builds the same envelope.
    val bare = buildAnomalyEventData(mapOf("type" to "slow_execution"), null)
    assertEquals("pattern_anomaly_slow_execution", bare["event_type"])
  }

  @Test
  fun buildCallbackErrorEventDataCarriesTheError() {
    val event =
        buildCallbackErrorEventData(
            IllegalStateException("boom"),
            mapOf("type" to "timeout"),
            "corr-9",
        )
    assertEquals("detection_engine_callback_error", event["event_type"])
    assertEquals("logged", event["action_taken"])
    assertEquals("Anomaly callback failed: boom", event["reason"])
    val metadata = event["metadata"] as Map<*, *>
    assertEquals("boom", metadata["callback_error"])
    assertEquals("timeout", metadata["anomaly_type"])
  }

  @Test
  fun patternReportShapesAndRound4() {
    val stats = PatternStats("short")
    stats.totalExecutions = 4
    stats.totalMatches = 2
    stats.totalTimeouts = 1
    stats.avgExecutionTime = 1.23456
    stats.maxExecutionTime = 9.87654
    stats.minExecutionTime = 0.12345
    val report = buildPatternReport("short", stats)
    assertEquals("short", report["pattern"])
    assertEquals(0.5, report["match_rate"])
    assertEquals(0.25, report["timeout_rate"])
    assertEquals(1.2346, report["avg_execution_time"])
    assertEquals(9.8765, report["max_execution_time"])
    assertEquals(0.1235, report["min_execution_time"])
    // An untouched stats object has an infinite min rendered as 0.0.
    val fresh = buildPatternReport("fresh", PatternStats("fresh"))
    assertEquals(0.0, fresh["min_execution_time"])
    // Long patterns truncate to 50 chars + ellipsis.
    val longReport = buildPatternReport("y".repeat(80), PatternStats("y".repeat(80)))
    assertEquals(53, (longReport["pattern"] as String).length)
  }

  @Test
  fun collectSlowPatternsSortsAndHonorsLimitAndNullReports() {
    val a = PatternStats("a")
    a.avgExecutionTime = 1.0
    a.recentTimes.addLast(1.0)
    val b = PatternStats("b")
    b.avgExecutionTime = 5.0
    b.recentTimes.addLast(5.0)
    val stats = mapOf("a" to a, "b" to b)
    val reports = collectSlowPatterns(stats, { buildPatternReport(it, stats[it]!!) }, 1)
    assertEquals(listOf("b"), reports.map { it["pattern"] })
    // A null report skips the pattern.
    val none = collectSlowPatterns(stats, { null }, 5)
    assertTrue(none.isEmpty())
  }

  @Test
  fun collectProblematicPatternsClassifiesBothIssues() {
    val fast = PatternStats("fast")
    fast.totalExecutions = 10
    val timeouty = PatternStats("timeouty")
    timeouty.totalExecutions = 10
    timeouty.totalTimeouts = 2
    timeouty.totalMatches = 8
    timeouty.avgExecutionTime = 0.01
    timeouty.recentTimes.addLast(0.01)
    val slow = PatternStats("slow")
    slow.totalExecutions = 10
    slow.avgExecutionTime = 9.0
    slow.recentTimes.addLast(9.0)
    val stats = mapOf("fast" to fast, "timeouty" to timeouty, "slow" to slow)
    val problematic =
        collectProblematicPatterns(stats, { buildPatternReport(it, stats[it]!!) }, 0.5)
    val issuesByPattern = problematic.associate { it["pattern"] to it["issue"] }
    assertEquals("high_timeout_rate", issuesByPattern["timeouty"])
    assertEquals("consistently_slow", issuesByPattern["slow"])
    assertFalse("fast" in issuesByPattern)
    // A zero-execution stats object is skipped entirely.
    val empty = collectProblematicPatterns(mapOf("z" to PatternStats("z")), { null }, 0.5)
    assertTrue(empty.isEmpty())
  }

  @Test
  fun emptySummaryAndSummaryDict() {
    assertEquals(
        mapOf(
            "total_executions" to 0,
            "avg_execution_time" to 0.0,
            "timeout_rate" to 0.0,
            "match_rate" to 0.0,
        ),
        emptySummary(),
    )
    val summary = buildSummaryDict(4, 2, listOf(1.0, 3.0), 1, 2)
    assertEquals(4, summary["total_executions"])
    assertEquals(2.0, summary["avg_execution_time"])
    assertEquals(3.0, summary["max_execution_time"])
    assertEquals(1.0, summary["min_execution_time"])
    assertEquals(0.25, summary["timeout_rate"])
    assertEquals(0.5, summary["match_rate"])
    assertEquals(2, summary["total_patterns"])
    val empty = buildSummaryDict(0, 0, emptyList(), 0, 0)
    assertEquals(0.0, empty["avg_execution_time"])
  }

  @Test
  fun extractMetricComponentsSplitsTimes() {
    val (times, timeouts, matches) =
        extractMetricComponents(
            listOf(
                metric(time = 1.0, timeout = false, matched = true),
                metric(time = 2.0, timeout = true, matched = false),
                metric(time = 3.0, timeout = false, matched = true),
            ),
        )
    assertEquals(listOf(1.0, 3.0), times)
    assertEquals(1, timeouts)
    assertEquals(2, matches)
  }

  // ---- PerformanceMonitor lifecycle ----

  @Test
  fun monitorConstructorClampsConfiguration() {
    val monitor =
        PerformanceMonitor(
            anomalyThreshold = 100.0,
            slowPatternThreshold = 0.0,
            historySize = 1,
            maxTrackedPatterns = 1,
            anomalyEmissionCooldown = 0.0,
            minSamplesForAnomaly = 1,
        )
    assertEquals(10.0, monitor.anomalyThreshold)
    assertEquals(0.01, monitor.slowPatternThreshold)
    assertEquals(100, monitor.historySize)
    assertEquals(100, monitor.maxTrackedPatterns)
    assertEquals(1.0, monitor.anomalyEmissionCooldown)
    assertEquals(10, monitor.minSamplesForAnomaly)
  }

  @Test
  fun recordMetricTruncatesAndClamps() {
    val monitor = PerformanceMonitor()
    monitor.recordMetric("z".repeat(140), -1.0, -5, matched = false)
    val report = monitor.getPatternReport("z".repeat(100) + "...[truncated]")
    assertNotNull(report)
    assertEquals(1, report["total_executions"])
    assertEquals(0.0, report["avg_execution_time"])
    assertNull(monitor.getPatternReport("never-recorded"))
  }

  @Test
  fun monitorEvictsOldestPatternBeyondTheTrackedLimit() {
    val monitor = PerformanceMonitor(maxTrackedPatterns = 100)
    monitor.recordMetric("p1", 0.1, 10, matched = true)
    for (i in 0 until 100) {
      monitor.recordMetric("bulk$i", 0.1, 10, matched = true)
    }
    assertNull(monitor.getPatternReport("p1"))
    assertNotNull(monitor.getPatternReport("bulk99"))
  }

  @Test
  fun monitorTimeoutAndSlowAnomaliesReachTheAgentSink() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.01)
    val events = ArrayList<Map<String, Any?>>()
    val sink = AnomalyEventSink { events.add(it) }
    monitor.recordMetric("tp", 0.5, 10, matched = true, timeout = true, agentHandler = sink)
    monitor.recordMetric("sp", 5.0, 10, matched = true, agentHandler = sink, correlationId = "c1")
    val types = events.map { it["event_type"] }
    assertTrue("pattern_anomaly_timeout" in types, types.toString())
    assertTrue("pattern_anomaly_slow_execution" in types, types.toString())
    val slowEvent = events.first { it["event_type"] == "pattern_anomaly_slow_execution" }
    assertEquals("c1", (slowEvent["metadata"] as Map<*, *>)["correlation_id"])
  }

  @Test
  fun monitorAnomalyEmissionCooldownReservesPerPattern() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.01, anomalyEmissionCooldown = 3600.0)
    val events = ArrayList<Map<String, Any?>>()
    val sink = AnomalyEventSink { events.add(it) }
    monitor.recordMetric("cd", 5.0, 10, matched = true, agentHandler = sink)
    monitor.recordMetric("cd", 5.0, 10, matched = true, agentHandler = sink)
    assertEquals(1, events.size)
  }

  @Test
  fun monitorCallbackFailureEmitsCallbackErrorEvent() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.01)
    val events = ArrayList<Map<String, Any?>>()
    val sink = AnomalyEventSink { events.add(it) }
    monitor.registerAnomalyCallback { throw IllegalStateException("cb boom") }
    monitor.recordMetric("cb", 5.0, 10, matched = true, agentHandler = sink)
    val types = events.map { it["event_type"] }
    assertTrue("detection_engine_callback_error" in types, types.toString())
  }

  @Test
  fun monitorSinkSendFailureIsSwallowedAndCallbacksStillRun() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.01)
    val seen = ArrayList<Map<String, Any>>()
    monitor.registerAnomalyCallback { seen.add(it) }
    val failingSink = AnomalyEventSink { error("send exploded") }
    monitor.recordMetric("sw", 5.0, 10, matched = true, agentHandler = failingSink)
    // The callback still saw the anomaly despite the sink failure.
    assertEquals(1, seen.size)
  }

  @Test
  fun monitorStatisticalAnomalyEmitsAfterEnoughSamples() {
    val monitor = PerformanceMonitor(minSamplesForAnomaly = 10, anomalyThreshold = 2.0)
    val events = ArrayList<Map<String, Any?>>()
    val sink = AnomalyEventSink { events.add(it) }
    // Seed the history directly: the first record's slow anomaly reserves the
    // per-pattern cooldown, which would otherwise suppress this event.
    val seeded = PatternStats("st")
    repeat(12) { i -> seeded.recentTimes.addLast(1.0) }
    monitor.patternStats["st"] = seeded
    monitor.recordMetric("st", 50.0, 10, matched = true, agentHandler = sink)
    val types = events.map { it["event_type"] }
    assertTrue("pattern_anomaly_statistical_anomaly" in types, types.toString())
  }

  @Test
  fun monitorSlowAndProblematicPatternQueries() {
    val monitor = PerformanceMonitor(slowPatternThreshold = 0.01)
    monitor.recordMetric("quiet", 0.001, 10, matched = true)
    monitor.recordMetric("slow", 9.0, 10, matched = true)
    assertTrue(monitor.getSlowPatterns(5).map { it["pattern"] }.contains("slow"))
    val problematic = monitor.getProblematicPatterns()
    assertTrue(problematic.map { it["pattern"] }.contains("slow"))
    monitor.recordMetric("tout", 0.0, 10, matched = false, timeout = true)
    monitor.clearStats()
    assertTrue(monitor.patternStats.isEmpty())
    assertTrue(monitor.getSlowPatterns().isEmpty())
    assertTrue(monitor.getSummaryStats()["total_executions"] == 0)
  }

  @Test
  fun monitorSummaryStatsReflectRecentMetrics() {
    val monitor = PerformanceMonitor()
    monitor.recordMetric("s1", 1.0, 10, matched = true)
    monitor.recordMetric("s2", 3.0, 10, matched = false, timeout = true)
    val summary = monitor.getSummaryStats()
    assertEquals(2, summary["total_executions"])
    // The timeout metric is excluded from the time aggregate (extract_metric_components).
    assertEquals(1.0, summary["avg_execution_time"])
    assertEquals(1.0, summary["max_execution_time"])
    assertEquals(1.0, summary["min_execution_time"])
    assertEquals(0.5, summary["timeout_rate"])
    assertEquals(0.5, summary["match_rate"])
    assertEquals(2, summary["total_patterns"])
  }

  @Test
  fun monitorRemovePatternStatsDropsOnePattern() {
    val monitor = PerformanceMonitor()
    monitor.recordMetric("gone", 1.0, 10, matched = true)
    monitor.recordMetric("kept", 1.0, 10, matched = true)
    monitor.removePatternStats("gone")
    assertNull(monitor.getPatternReport("gone"))
    assertNotNull(monitor.getPatternReport("kept"))
  }
}
