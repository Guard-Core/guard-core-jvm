package com.guardcore.core.events

import java.util.logging.Logger

/**
 * Port of `guard_core/core/events/otel_handler.py`: OtelHandler (otel_handler.py:50).
 *
 * The python module try-imports the opentelemetry SDK and flips to `_otel_available = False` on
 * ImportError (otel_handler.py:9-38). The JVM artifact carries no opentelemetry dependency (the
 * engine dependency set is locked), so the SDK surface is the [OtelSurface] seam: absent by
 * default, which selects exactly the python not-installed branch - `start` logs "opentelemetry-sdk
 * not installed, OTEL handler disabled" and the handler stays inert; `health_check` reports the
 * availability flag. A host that provides an OTel runtime registers it through
 * [OtelHandler.installSurface]; the span/attribute/metric dispatch below is the ported
 * otel_handler.py logic over that seam.
 */
public class OtelHandler(
    private val config: ProviderConfig,
) : AgentTelemetryMember {
  /** The SecurityConfig surface otel_handler.py reads (otel_service_name + the two otel knobs). */
  public interface ProviderConfig {
    public val otelServiceName: String

    public val otelResourceAttributes: Map<String, String>

    public val otelExporterEndpoint: String?
  }

  /**
   * The opentelemetry API surface otel_handler.py drives: tracer/meter acquisition, span and
   * instrument recording. `null` mirrors python's `_otel_available = False`.
   */
  public interface OtelSurface {
    public fun startSpan(name: String, attributes: Map<String, Any?>, parentContext: Any?)

    public fun recordHistogram(name: String, value: Double, attributes: Map<String, Any?>)

    public fun recordCounterAdd(name: String, value: Double, attributes: Map<String, Any?>)

    public fun extractTraceContext(carrier: Map<String, String>): Any?
  }

  public companion object {
    private val logger: Logger = Logger.getLogger("guard_core")

    @Volatile public var surface: OtelSurface? = null

    /**
     * Port of `_otel_available` (otel_handler.py:26/38): true only while a surface is installed.
     */
    public val otelAvailable: Boolean
      get() = surface != null

    /** Port of `_EVENT_SPAN_ATTRS` (otel_handler.py:41). */
    internal val EVENT_SPAN_ATTRS: List<Pair<String, String>> =
        listOf(
            "guard.ip_address" to "ip_address",
            "guard.action_taken" to "action_taken",
            "guard.reason" to "reason",
            "guard.endpoint" to "endpoint",
            "guard.method" to "method",
        )

    /**
     * Port of `_otlp_signal_endpoint` (otel_handler.py:157): strip a known signal suffix, append
     * the requested one.
     */
    public fun otlpSignalEndpoint(endpoint: String?, signalPath: String): String? {
      if (endpoint == null) {
        return null
      }
      var base = endpoint.trimEnd('/')
      for (knownSignal in listOf("/v1/traces", "/v1/metrics", "/v1/logs")) {
        if (base.endsWith(knownSignal)) {
          base = base.substring(0, base.length - knownSignal.length)
          break
        }
      }
      return base + signalPath
    }
  }

  @Volatile private var started: Boolean = false

  /** Port of `start` (otel_handler.py:62). */
  override suspend fun start() {
    val otel = surface
    if (otel == null) {
      logger.warning("opentelemetry-sdk not installed, OTEL handler disabled")
      return
    }
    if (started) {
      return
    }
    started = true
  }

  /** Port of `stop` (otel_handler.py:126). */
  override suspend fun stop() {
    started = false
  }

  /** Port of `send_event` (otel_handler.py:143). */
  override suspend fun sendEvent(event: Map<String, Any?>) {
    val otel = surface
    if (otel == null || !started) {
      return
    }
    val eventType = (event["event_type"] as? String) ?: "unknown"
    @Suppress("UNCHECKED_CAST")
    val metadata = (event["metadata"] as? Map<String, Any?>) ?: emptyMap()
    val attributes = LinkedHashMap<String, Any?>()
    attributes["guard.event_type"] = eventType
    for ((attrKey, eventAttr) in EVENT_SPAN_ATTRS) {
      attributes[attrKey] = event[eventAttr] ?: ""
    }
    val statusCode = event["status_code"] as? Int
    if (statusCode != null && statusCode != 0) {
      attributes["guard.status_code"] = statusCode
    }
    forwardEnrichmentMetadata(attributes, metadata)
    otel.startSpan(
        "guard.event.$eventType",
        attributes,
        extractParentContext(otel, metadata),
    )
  }

  /** Port of `_extract_parent_context` (otel_handler.py:167). */
  private fun extractParentContext(
      otel: OtelSurface,
      metadata: Map<String, Any?>,
  ): Any? {
    val traceparent = metadata["traceparent"] as? String
    if (traceparent.isNullOrEmpty()) {
      return null
    }
    val carrier = linkedMapOf("traceparent" to traceparent)
    val tracestate = metadata["tracestate"] as? String
    if (!tracestate.isNullOrEmpty()) {
      carrier["tracestate"] = tracestate
    }
    return try {
      otel.extractTraceContext(carrier)
    } catch (e: Exception) {
      null
    }
  }

  /** Port of `_forward_enrichment_metadata` (otel_handler.py:190). */
  internal fun forwardEnrichmentMetadata(
      attributes: MutableMap<String, Any?>,
      metadata: Map<String, Any?>,
  ) {
    for ((key, value) in metadata) {
      if (key.startsWith("guard.") && key !in setOf("traceparent", "tracestate") && value != null) {
        attributes[key] = value
      }
    }
  }

  /** Port of `send_metric` (otel_handler.py:201). */
  override suspend fun sendMetric(metric: Map<String, Any?>) {
    val otel = surface
    if (otel == null || !started) {
      return
    }
    val metricType = (metric["metric_type"] as? String) ?: "unknown"
    val value = (metric["value"] as? Number)?.toDouble() ?: 0.0
    val endpoint = (metric["endpoint"] as? String) ?: ""
    @Suppress("UNCHECKED_CAST") val tags = (metric["tags"] as? Map<String, Any?>) ?: emptyMap()
    val attrs = LinkedHashMap<String, Any?>()
    attrs["endpoint"] = endpoint
    attrs.putAll(tags)
    when {
      metricType == "response_time" -> otel.recordHistogram("guard.request.duration", value, attrs)
      metricType == "request_count" -> otel.recordCounterAdd("guard.request.count", value, attrs)
      metricType == "error_rate" -> otel.recordCounterAdd("guard.error.count", value, attrs)
      else -> logger.warning("Unknown OTEL metric type $metricType - no instrument recorded")
    }
  }

  /** Port of `initialize_redis` (otel_handler.py:220). */
  override suspend fun initializeRedis(redisHandler: Any?) {}

  /** Port of `flush_buffer` (otel_handler.py:223). */
  override suspend fun flushBuffer() {}

  /** Port of `get_dynamic_rules` (otel_handler.py:226). */
  override suspend fun getDynamicRules(): Any? = null

  /** Port of `health_check` (otel_handler.py:229). */
  override suspend fun healthCheck(): Boolean = otelAvailable
}
