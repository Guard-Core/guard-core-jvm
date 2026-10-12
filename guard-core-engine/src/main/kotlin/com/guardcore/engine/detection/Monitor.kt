package com.guardcore.engine.detection

import java.util.Date
import kotlin.math.sqrt

/**
 * PerformanceMonitor: per-pattern stats, recent metrics, and anomaly detection.
 *
 * Port of guard_core/detection_engine/monitor_types.py, monitor_anomalies.py, monitor_reporting.py,
 * and monitor.py (the anomaly emission seam notifies registered callbacks and sends the
 * anomaly/callback-error event data to the agent sink - monitor.py:150-176,
 * monitor_anomalies.py:93-133).
 */
public const val DEFAULT_RECENT_TIMES_WINDOW: Int = 100

/**
 * The agent send seam of `monitor.py` (`await agent_handler.send_event(event)`, monitor.py:155):
 * the engine builds the anomaly/callback-error event data maps and hands them to this sink; the
 * facade's capturing/agent handlers implement it.
 */
public fun interface AnomalyEventSink {
  public fun sendEvent(event: Map<String, Any?>)
}

public class PerformanceMetric(
    public val pattern: String,
    public val executionTime: Double,
    public val contentLength: Int,
    public val timestamp: Date,
    public val matched: Boolean,
    public val timeout: Boolean = false,
)

public class PatternStats(public val pattern: String) {
  public var totalExecutions: Int = 0
  public var totalMatches: Int = 0
  public var totalTimeouts: Int = 0
  public var avgExecutionTime: Double = 0.0
  public var maxExecutionTime: Double = 0.0
  public var minExecutionTime: Double = Double.POSITIVE_INFINITY
  public val recentTimes: ArrayDeque<Double> = ArrayDeque()
  public var lastAnomalyEmittedAt: Double? = null

  public fun recentTimesSnapshot(): List<Double> = recentTimes.toList()
}

// monitor_anomalies

public fun detectTimeoutAnomaly(metric: PerformanceMetric): Map<String, Any>? =
    if (metric.timeout) {
      mapOf(
          "type" to "timeout",
          "pattern" to metric.pattern,
          "content_length" to metric.contentLength,
      )
    } else {
      null
    }

public fun detectSlowExecutionAnomaly(
    metric: PerformanceMetric,
    slowPatternThreshold: Double,
): Map<String, Any>? =
    if (!metric.timeout && metric.executionTime > slowPatternThreshold) {
      mapOf(
          "type" to "slow_execution",
          "pattern" to metric.pattern,
          "execution_time" to metric.executionTime,
          "content_length" to metric.contentLength,
      )
    } else {
      null
    }

/** math.fsum analog: Kahan compensated summation over the same order. */
private fun fsum(values: List<Double>): Double {
  var sum = 0.0
  var compensation = 0.0
  for (value in values) {
    val adjusted = value - compensation
    val total = sum + adjusted
    compensation = (total - sum) - adjusted
    sum = total
  }
  return sum
}

public fun detectStatisticalAnomaly(
    metric: PerformanceMetric,
    stats: PatternStats?,
    minSamplesForAnomaly: Int,
    anomalyThreshold: Double,
): Map<String, Any>? {
  if (stats == null || stats.recentTimes.size < minSamplesForAnomaly) return null

  val recentTimes = stats.recentTimesSnapshot()
  val sampleCount = recentTimes.size
  if (sampleCount < 2) return null

  val avgTime = fsum(recentTimes) / sampleCount
  if (anomalyThreshold >= 0 && metric.executionTime <= avgTime) return null

  val variance = fsum(recentTimes.map { (it - avgTime) * (it - avgTime) }) / (sampleCount - 1)
  val stdTime = sqrt(variance)
  if (stdTime <= 0) return null

  val zScore = (metric.executionTime - avgTime) / stdTime
  if (zScore > anomalyThreshold) {
    return mapOf(
        "type" to "statistical_anomaly",
        "pattern" to metric.pattern,
        "execution_time" to metric.executionTime,
        "z_score" to zScore,
        "avg_time" to avgTime,
        "std_time" to stdTime,
    )
  }
  return null
}

public fun sanitizeAnomalyData(anomaly: Map<String, Any>): Map<String, Any> {
  val safeAnomaly = anomaly.toMutableMap()
  val pattern = safeAnomaly["pattern"]
  if (pattern != null) {
    val redacted = pattern.toString()
    safeAnomaly["pattern"] = if (redacted.length > 50) redacted.take(50) + "..." else redacted
    safeAnomaly["pattern_hash"] = Integer.toHexString(redacted.hashCode()).take(8)
  }
  return safeAnomaly
}

/** Port of `_anomaly_event_type` (monitor_anomalies.py:81). */
public fun anomalyEventType(anomalyType: String): String =
    when (anomalyType) {
      "timeout" -> "pattern_anomaly_timeout"
      "slow_execution" -> "pattern_anomaly_slow_execution"
      else -> "pattern_anomaly_statistical_anomaly"
    }

/**
 * Port of `build_anomaly_event_data` (monitor_anomalies.py:93). The python builder redacts the
 * pattern through `_redact_pattern_source` (detection_scan.py:154, a facade-seam util over the
 * suspatterns sensitive unions); the engine takes it as the [redactPatternSource] seam so the
 * engine/stdlib boundary holds - with empty unions the reference redaction is the identity, which
 * is the default here.
 */
public fun buildAnomalyEventData(
    anomaly: Map<String, Any>,
    correlationId: String?,
    redactPatternSource: (String) -> String = { it },
): Map<String, Any?> {
  val eventType = anomalyEventType(anomaly["type"] as String)
  val safeAnomaly = anomaly.toMutableMap()
  if (safeAnomaly.containsKey("pattern")) {
    safeAnomaly["pattern"] = redactPatternSource(safeAnomaly["pattern"].toString())
  }
  val metadata = LinkedHashMap<String, Any?>()
  metadata["component"] = "PerformanceMonitor"
  metadata["correlation_id"] = correlationId
  metadata.putAll(safeAnomaly)
  return mapOf(
      "event_type" to eventType,
      "ip_address" to "system",
      "action_taken" to "anomaly_detected",
      "reason" to "Pattern performance anomaly: ${anomaly["type"]}",
      "metadata" to metadata,
  )
}

/** Port of `build_callback_error_event_data` (monitor_anomalies.py:114). */
public fun buildCallbackErrorEventData(
    error: Throwable,
    safeAnomaly: Map<String, Any>,
    correlationId: String?,
): Map<String, Any?> {
  val metadata = LinkedHashMap<String, Any?>()
  metadata["component"] = "PerformanceMonitor"
  metadata["correlation_id"] = correlationId
  metadata["callback_error"] = error.message ?: error.toString()
  metadata["anomaly_type"] = safeAnomaly["type"] ?: "unknown"
  return mapOf(
      "event_type" to "detection_engine_callback_error",
      "ip_address" to "system",
      "action_taken" to "logged",
      "reason" to "Anomaly callback failed: ${error.message ?: error.toString()}",
      "metadata" to metadata,
  )
}

// monitor_reporting

public fun buildPatternReport(pattern: String, stats: PatternStats): Map<String, Any> {
  val redactedPattern = pattern
  val safePattern =
      if (redactedPattern.length > 50) redactedPattern.take(50) + "..." else redactedPattern
  return mapOf(
      "pattern" to safePattern,
      "pattern_hash" to Integer.toHexString(redactedPattern.hashCode()).take(8),
      "total_executions" to stats.totalExecutions,
      "total_matches" to stats.totalMatches,
      "total_timeouts" to stats.totalTimeouts,
      "match_rate" to stats.totalMatches.toDouble() / maxOf(stats.totalExecutions, 1),
      "timeout_rate" to stats.totalTimeouts.toDouble() / maxOf(stats.totalExecutions, 1),
      "avg_execution_time" to round4(stats.avgExecutionTime),
      "max_execution_time" to round4(stats.maxExecutionTime),
      "min_execution_time" to
          round4(
              if (stats.minExecutionTime == Double.POSITIVE_INFINITY) 0.0
              else stats.minExecutionTime,
          ),
  )
}

private fun round4(value: Double): Double = Math.round(value * 10000.0) / 10000.0

public fun collectSlowPatterns(
    patternStats: Map<String, PatternStats>,
    reportFn: (String) -> Map<String, Any>?,
    limit: Int,
): List<Map<String, Any>> {
  val patternsWithTimes =
      patternStats
          .filter { it.value.recentTimes.isNotEmpty() }
          .map { it.value.avgExecutionTime to it.key }
  val sorted = patternsWithTimes.sortedWith(compareByDescending<Pair<Double, String>> { it.first })
  val reports = ArrayList<Map<String, Any>>()
  for ((_, pattern) in sorted.take(limit)) {
    val report = reportFn(pattern) ?: continue
    reports.add(report)
  }
  return reports
}

public fun collectProblematicPatterns(
    patternStats: Map<String, PatternStats>,
    reportFn: (String) -> Map<String, Any>?,
    slowPatternThreshold: Double,
): List<Map<String, Any>> {
  val problematic = ArrayList<Map<String, Any>>()
  for ((_, stats) in patternStats) {
    if (stats.totalExecutions == 0) continue
    val timeoutRate = stats.totalTimeouts.toDouble() / stats.totalExecutions
    if (timeoutRate > 0.1) {
      val report = reportFn(stats.pattern) ?: continue
      val out = report.toMutableMap()
      out["issue"] = "high_timeout_rate"
      problematic.add(out)
    } else if (stats.avgExecutionTime > slowPatternThreshold) {
      val report = reportFn(stats.pattern) ?: continue
      val out = report.toMutableMap()
      out["issue"] = "consistently_slow"
      problematic.add(out)
    }
  }
  return problematic
}

public fun emptySummary(): Map<String, Any> =
    mapOf(
        "total_executions" to 0,
        "avg_execution_time" to 0.0,
        "timeout_rate" to 0.0,
        "match_rate" to 0.0,
    )

public fun extractMetricComponents(
    recentMetrics: List<PerformanceMetric>,
): Triple<List<Double>, Int, Int> {
  val recentTimes = recentMetrics.filter { !it.timeout }.map { it.executionTime }
  val timeouts = recentMetrics.count { it.timeout }
  val matches = recentMetrics.count { it.matched }
  return Triple(recentTimes, timeouts, matches)
}

public fun buildSummaryDict(
    totalMetrics: Int,
    totalPatterns: Int,
    recentTimes: List<Double>,
    timeouts: Int,
    matches: Int,
): Map<String, Any> =
    mapOf(
        "total_executions" to totalMetrics,
        "avg_execution_time" to (if (recentTimes.isNotEmpty()) recentTimes.average() else 0.0),
        "max_execution_time" to (if (recentTimes.isNotEmpty()) recentTimes.max() else 0.0),
        "min_execution_time" to (if (recentTimes.isNotEmpty()) recentTimes.min() else 0.0),
        "timeout_rate" to timeouts.toDouble() / totalMetrics,
        "match_rate" to matches.toDouble() / totalMetrics,
        "total_patterns" to totalPatterns,
    )

// monitor.py

public class PerformanceMonitor(
    anomalyThreshold: Double = 3.0,
    slowPatternThreshold: Double = 0.1,
    historySize: Int = 1000,
    maxTrackedPatterns: Int = 1000,
    anomalyEmissionCooldown: Double = 60.0,
    minSamplesForAnomaly: Int = 30,
) {
  public val anomalyThreshold: Double = maxOf(1.0, minOf(10.0, anomalyThreshold))
  public val slowPatternThreshold: Double = maxOf(0.01, minOf(10.0, slowPatternThreshold))
  public val historySize: Int = maxOf(100, minOf(10000, historySize))
  public val maxTrackedPatterns: Int = maxOf(100, minOf(5000, maxTrackedPatterns))
  public val anomalyEmissionCooldown: Double = maxOf(1.0, minOf(3600.0, anomalyEmissionCooldown))
  public val minSamplesForAnomaly: Int = maxOf(10, minOf(1000, minSamplesForAnomaly))
  private val recentTimesMaxlen = maxOf(minSamplesForAnomaly, DEFAULT_RECENT_TIMES_WINDOW)

  public val patternStats: MutableMap<String, PatternStats> = LinkedHashMap()
  private val recentMetrics = ArrayDeque<PerformanceMetric>()
  public val anomalyCallbacks: MutableList<(Map<String, Any>) -> Unit> = ArrayList()
  private val lock = Any()

  /** record_metric. */
  public fun recordMetric(
      patternIn: String,
      executionTimeIn: Double,
      contentLengthIn: Int,
      matched: Boolean,
      timeout: Boolean = false,
      agentHandler: AnomalyEventSink? = null,
      correlationId: String? = null,
  ) {
    val maxPatternLength = 100
    var pattern = patternIn
    if (pattern.length > maxPatternLength)
        pattern = pattern.take(maxPatternLength) + "...[truncated]"

    val executionTime = maxOf(0.0, executionTimeIn)
    val contentLength = maxOf(0, contentLengthIn)

    val metric =
        PerformanceMetric(
            pattern = pattern,
            executionTime = executionTime,
            contentLength = contentLength,
            timestamp = Date(),
            matched = matched,
            timeout = timeout,
        )

    var statisticalAnomaly: Map<String, Any>? = null
    synchronized(lock) {
      if (recentMetrics.size >= historySize) recentMetrics.removeFirst()
      recentMetrics.addLast(metric)

      if (!patternStats.containsKey(pattern)) {
        if (patternStats.size >= maxTrackedPatterns) {
          val oldest = patternStats.keys.first()
          patternStats.remove(oldest)
        }
        patternStats[pattern] = PatternStats(pattern)
      }

      val stats = patternStats[pattern]!!
      stats.totalExecutions += 1
      if (matched) stats.totalMatches += 1
      if (timeout) {
        stats.totalTimeouts += 1
      } else {
        if (stats.recentTimes.size >= recentTimesMaxlen) stats.recentTimes.removeFirst()
        stats.recentTimes.addLast(executionTime)
        stats.maxExecutionTime = maxOf(stats.maxExecutionTime, executionTime)
        stats.minExecutionTime = minOf(stats.minExecutionTime, executionTime)
        stats.avgExecutionTime =
            if (stats.recentTimes.isNotEmpty()) {
              fsum(stats.recentTimesSnapshot()) / stats.recentTimes.size
            } else {
              stats.avgExecutionTime
            }
      }

      statisticalAnomaly =
          detectStatisticalAnomaly(metric, stats, minSamplesForAnomaly, anomalyThreshold)
    }

    checkAnomalies(metric, statisticalAnomaly, agentHandler, correlationId)
  }

  private fun checkAnomalies(
      metric: PerformanceMetric,
      statisticalAnomaly: Map<String, Any>?,
      agentHandler: AnomalyEventSink? = null,
      correlationId: String? = null,
  ) {
    val anomalies = ArrayList<Map<String, Any>>()

    val timeoutAnomaly = detectTimeoutAnomaly(metric)
    if (timeoutAnomaly != null) {
      anomalies.add(timeoutAnomaly)
    } else {
      val slowAnomaly = detectSlowExecutionAnomaly(metric, slowPatternThreshold)
      if (slowAnomaly != null) anomalies.add(slowAnomaly)
    }

    if (statisticalAnomaly != null) anomalies.add(statisticalAnomaly)

    if (agentHandler != null && anomalies.isNotEmpty() && reserveAnomalyEmission(metric.pattern)) {
      for (anomaly in anomalies) {
        // Port of `_send_anomaly_event` (monitor.py:149): build the event data and send.
        val event = buildAnomalyEventData(anomaly, correlationId)
        try {
          agentHandler.sendEvent(event)
        } catch (e: Exception) {
          System.err.println("Failed to send anomaly event to agent: $e")
        }
      }
    }

    for (anomaly in anomalies) {
      notifyCallbacks(anomaly, agentHandler, correlationId)
    }
  }

  private fun notifyCallbacks(
      anomaly: Map<String, Any>,
      agentHandler: AnomalyEventSink? = null,
      correlationId: String? = null,
  ) {
    val safeAnomaly = sanitizeAnomalyData(anomaly)
    for (callback in anomalyCallbacks.toList()) {
      try {
        callback(safeAnomaly)
      } catch (e: Exception) {
        // Port of `_send_callback_error_event` (monitor.py:163): the callback failure emits
        // detection_engine_callback_error to the agent sink; engine-side there is no logger.
        if (agentHandler != null) {
          val event = buildCallbackErrorEventData(e, safeAnomaly, correlationId)
          try {
            agentHandler.sendEvent(event)
          } catch (sendError: Exception) {
            // monitor.py:173 swallows the nested send failure the same way.
          }
        }
      }
    }
  }

  private fun reserveAnomalyEmission(pattern: String): Boolean {
    // time.monotonic() analog in SECONDS: the cooldown is in seconds, and the
    // raw nanotime value made the window 1e9x too small to ever suppress.
    val now = System.nanoTime().toDouble() / 1_000_000_000.0
    synchronized(lock) {
      val stats = patternStats[pattern] ?: return true
      val lastEmittedAt = stats.lastAnomalyEmittedAt
      if (lastEmittedAt != null && now - lastEmittedAt < anomalyEmissionCooldown) return false
      stats.lastAnomalyEmittedAt = now
      return true
    }
  }

  /** get_pattern_report. */
  public fun getPatternReport(patternIn: String): Map<String, Any>? {
    val maxPatternLength = 100
    var pattern = patternIn
    if (pattern.length > maxPatternLength)
        pattern = pattern.take(maxPatternLength) + "...[truncated]"
    val stats = synchronized(lock) { patternStats[pattern] } ?: return null
    return buildPatternReport(pattern, stats)
  }

  /** get_slow_patterns. */
  public fun getSlowPatterns(limit: Int = 10): List<Map<String, Any>> {
    val snapshot = synchronized(lock) { patternStats.toMap() }
    val reports = collectSlowPatterns(snapshot, { getPatternReport(it) }, limit)
    return reports
  }

  /** get_problematic_patterns. */
  public fun getProblematicPatterns(): List<Map<String, Any>> {
    val snapshot = synchronized(lock) { patternStats.toMap() }
    return collectProblematicPatterns(snapshot, { getPatternReport(it) }, slowPatternThreshold)
  }

  /** get_summary_stats. */
  public fun getSummaryStats(): Map<String, Any> {
    val (snapshot, totalPatterns) =
        synchronized(lock) {
          if (recentMetrics.isEmpty()) return emptySummary()
          Pair(recentMetrics.toList(), patternStats.size)
        }
    val (recentTimes, timeouts, matches) = extractMetricComponents(snapshot)
    return buildSummaryDict(snapshot.size, totalPatterns, recentTimes, timeouts, matches)
  }

  public fun registerAnomalyCallback(callback: (Map<String, Any>) -> Unit) {
    anomalyCallbacks.add(callback)
  }

  public fun clearStats() {
    synchronized(lock) {
      patternStats.clear()
      recentMetrics.clear()
    }
  }

  public fun removePatternStats(pattern: String) {
    synchronized(lock) { patternStats.remove(pattern) }
  }
}
