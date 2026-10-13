package com.guardcore.core.events

import com.guardcore.config.SecurityConfig
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.RequestLogging
import java.util.logging.Logger

/** One SecurityMetric envelope (the agent's SecurityMetric fields, W7 model pending). */
public data class SecurityMetricEnvelope(
    val timestamp: String,
    val metricType: String,
    val value: Double,
    val tags: Map<String, String>,
)

/**
 * Port of `guard_core/core/events/metrics.py`: MetricsCollector (metrics.py:16) with `send_metric`
 * (metrics.py:28) and `collect_request_metrics` (metrics.py:49). Gated on agent handler +
 * `agent_enable_metrics`, exactly like metrics.py:31-32.
 */
public class MetricsCollector(
    public val agentHandler: HandlerAgentSink?,
    public val config: SecurityConfig,
    public val eventFilter: EventFilter = EventFilter(),
) {
  public val logger: Logger = Logger.getLogger("guard_core.core.events.metrics")

  /** Port of `send_metric` (metrics.py:28). */
  public suspend fun sendMetric(
      metricType: String,
      value: Double,
      tags: Map<String, String>? = null,
  ) {
    if (agentHandler == null || !config.agentEnableMetrics) {
      return
    }
    if (!eventFilter.isMetricAllowed(metricType)) {
      return
    }
    try {
      val metric =
          SecurityMetricEnvelope(
              timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString(),
              metricType = metricType,
              value = value,
              tags = tags ?: emptyMap(),
          )
      agentHandler.sendMetric(
          linkedMapOf(
              "timestamp" to metric.timestamp,
              "metric_type" to metric.metricType,
              "value" to metric.value,
              "tags" to metric.tags,
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send metric to agent: $e")
    }
  }

  /** Port of `collect_request_metrics` (metrics.py:49). */
  public suspend fun collectRequestMetrics(
      request: GuardRequest,
      responseTime: Double,
      statusCode: Int,
  ) {
    if (agentHandler == null || !config.agentEnableMetrics) {
      return
    }
    val endpoint =
        RequestLogging.redactEndpointForDisplay(
            request.urlPath,
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    val method = request.method
    sendMetric(
        EventTypes.METRIC_RESPONSE_TIME,
        responseTime,
        linkedMapOf("endpoint" to endpoint, "method" to method, "status" to statusCode.toString()),
    )
    sendMetric(
        EventTypes.METRIC_REQUEST_COUNT,
        1.0,
        linkedMapOf("endpoint" to endpoint, "method" to method),
    )
    if (statusCode >= 400) {
      sendMetric(
          EventTypes.METRIC_ERROR_RATE,
          1.0,
          linkedMapOf(
              "endpoint" to endpoint,
              "method" to method,
              "status" to statusCode.toString(),
          ),
      )
    }
  }
}
